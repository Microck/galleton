package core

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	defaultMaxRequestBody  = 1 << 20
	defaultMaxResponseBody = 4 << 20
	maxManagedBody         = 64 << 20
	maxPause               = 24 * time.Hour
)

// newUpstreamClient never consults environment proxies and never follows
// redirects. A configured proxy is the only route: when it is unreachable the
// request fails, it is not retried directly. Without keepAlive every request
// opens a fresh connection, so the transport cannot invisibly replay a
// credential-bearing request on a reused connection.
func newUpstreamClient(proxy *url.URL, keepAlive bool) *http.Client {
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 10 * time.Second, MaxResponseHeaderBytes: 64 << 10, DisableKeepAlives: !keepAlive}
	if proxy != nil {
		transport.Proxy = http.ProxyURL(proxy)
	}
	if keepAlive {
		transport.MaxIdleConnsPerHost = 4
		transport.IdleConnTimeout = 60 * time.Second
	}
	return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// parseProxy validates an egress proxy URL. Error messages never echo the
// value, which may contain proxy credentials.
func parseProxy(raw string, allowCredentials bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || strings.ContainsAny(raw, "\r\n\t ") {
		return nil, errors.New("proxy must be an absolute URL such as socks5h://127.0.0.1:1080 without a path or query")
	}
	switch u.Scheme {
	case "http", "https":
	case "socks5", "socks5h":
		if u.Port() == "" {
			return nil, errors.New("SOCKS proxies need an explicit port")
		}
	default:
		return nil, errors.New("proxy scheme must be http, https, socks5 or socks5h")
	}
	if u.User != nil && !allowCredentials {
		return nil, errors.New("proxy credentials are not accepted in the configuration file; use proxy_env")
	}
	u.Path = ""
	return u, nil
}

// gate paces upstream calls of one provider across all of its sessions and
// carries the pause clients set through the API. Both are in memory only.
type gate struct {
	mu          sync.Mutex
	next        time.Time
	pausedUntil time.Time
}

func (g *gate) paused(now time.Time) (time.Time, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.pausedUntil, now.Before(g.pausedUntil)
}

// pause extends, never shortens, the current pause.
func (g *gate) pause(until time.Time) time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	if until.After(g.pausedUntil) {
		g.pausedUntil = until
	}
	return g.pausedUntil
}

func (g *gate) resume() {
	g.mu.Lock()
	g.pausedUntil = time.Time{}
	g.mu.Unlock()
}

func pausedProblem(until time.Time) *Problem {
	p := problem(503, "provider_paused", "Upstream calls for this provider are paused by a local client.")
	p.RetryAt = until
	return p
}

// reserve claims the next upstream slot and waits for it. It refuses instead
// of waiting longer than maxWait, and claims nothing in that case.
func (g *gate) reserve(interval, maxWait time.Duration) *Problem {
	g.mu.Lock()
	now := time.Now().UTC()
	if now.Before(g.pausedUntil) {
		until := g.pausedUntil
		g.mu.Unlock()
		return pausedProblem(until)
	}
	if interval <= 0 {
		g.mu.Unlock()
		return nil
	}
	slot := now
	if g.next.After(slot) {
		slot = g.next
	}
	wait := slot.Sub(now)
	if wait > maxWait {
		g.mu.Unlock()
		p := problem(503, "retry_later", "The provider's minimum interval between upstream calls is not over yet.")
		p.RetryAt = slot
		return p
	}
	g.next = slot.Add(interval)
	g.mu.Unlock()
	if wait > 0 {
		time.Sleep(wait)
	}
	return nil
}

func (p *Provider) reserve() *Problem {
	return p.gate.reserve(time.Duration(p.MinIntervalMS)*time.Millisecond, time.Duration(p.TimeoutSeconds)*time.Second)
}

// markSent restarts the interval when a call is actually dispatched, after the
// local checkpoint write, so disk latency cannot shorten the gap to the next
// call reserved by the same caller.
func (p *Provider) markSent() {
	if p.MinIntervalMS <= 0 {
		return
	}
	p.gate.mu.Lock()
	if next := time.Now().UTC().Add(time.Duration(p.MinIntervalMS) * time.Millisecond); next.After(p.gate.next) {
		p.gate.next = next
	}
	p.gate.mu.Unlock()
}

// blocked reports whether a non-2xx response matches a configured
// bot-protection signature.
func (p *Provider) blocked(resp *http.Response, body []byte, isJSON bool) bool {
	for _, sig := range p.BlockSignatures {
		statusMatch := false
		for _, status := range sig.Status {
			statusMatch = statusMatch || status == resp.StatusCode
		}
		if !statusMatch || sig.NotJSON && isJSON || sig.BodyContains != "" && !bytes.Contains(body, []byte(sig.BodyContains)) {
			continue
		}
		if sig.Header != "" {
			values := resp.Header.Values(sig.Header)
			if len(values) == 0 || sig.HeaderContains != "" && !strings.Contains(strings.Join(values, "\n"), sig.HeaderContains) {
				continue
			}
		}
		return true
	}
	return false
}

func validateBlockSignatures(signatures []BlockSignature) error {
	if len(signatures) > 16 {
		return errors.New("at most 16 block_signatures")
	}
	for _, sig := range signatures {
		if len(sig.Status) == 0 || len(sig.Status) > 8 {
			return errors.New("each block signature needs 1–8 status codes")
		}
		for _, status := range sig.Status {
			// 401 always means the credential was rejected; 2xx/3xx are not refusals.
			if status < 400 || status > 599 || status == 401 {
				return errors.New("block signature status codes must be 400–599, excluding 401")
			}
		}
		if sig.BodyContains == "" && sig.Header == "" && !sig.NotJSON {
			return errors.New("a block signature needs body_contains, header or not_json; status alone would hide revocations")
		}
		if len(sig.BodyContains) > 256 || len(sig.HeaderContains) > 256 {
			return errors.New("block signature markers are limited to 256 bytes")
		}
		if sig.HeaderContains != "" && sig.Header == "" {
			return errors.New("header_contains needs header")
		}
		if sig.Header != "" && !validHeader(sig.Header, "") {
			return errors.New("invalid block signature header name")
		}
	}
	return nil
}
