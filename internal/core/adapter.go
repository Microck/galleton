package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

func newUpstreamClient() *http.Client {
	// No environment proxy, redirects, or reused connections. In particular, do
	// not let the transport invisibly replay a refresh on a reused connection.
	return &http.Client{
		Transport:     &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 20 * time.Second, MaxResponseHeaderBytes: 64 << 10, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func substitute(input string, s *State, p *Provider, u *url.URL) (string, error) {
	var out strings.Builder
	for {
		start := strings.Index(input, "${")
		if start < 0 {
			out.WriteString(input)
			break
		}
		out.WriteString(input[:start])
		input = input[start+2:]
		end := strings.IndexByte(input, '}')
		if end < 0 {
			return "", errors.New("unterminated template")
		}
		name := input[:end]
		input = input[end+1:]
		value := ""
		found := false
		switch name {
		case "access_token":
			value = s.AccessToken
			found = value != ""
		case "refresh_token":
			value = s.RefreshToken
			found = value != ""
		default:
			if strings.HasPrefix(name, "secret.") {
				value, found = s.Secrets[strings.TrimPrefix(name, "secret.")]
			}
			if strings.HasPrefix(name, "cookie.") {
				cookies, _ := http.ParseCookie(cookieHeaders(s.Cookies, u, time.Now()))
				for _, c := range cookies {
					if c.Name == strings.TrimPrefix(name, "cookie.") {
						value = c.Value
						found = true
						break
					}
				}
			}
		}
		if !found {
			return "", errors.New("template credential is unavailable")
		}
		out.WriteString(value)
	}
	return out.String(), nil
}

func makeRefreshRequest(ctx context.Context, s *State, p *Provider) (*http.Request, error) {
	u, err := p.allowed(p.RefreshURL)
	if err != nil {
		return nil, err
	}
	method := p.RefreshMethod
	headers := make(http.Header)
	var body []byte
	if p.Kind == "oauth2" {
		if s.RefreshToken == "" {
			return nil, errors.New("OAuth refresh token is missing")
		}
		method = "POST"
		values := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {s.RefreshToken}}
		if p.ClientAuth != "basic" && p.ClientID != "" {
			values.Set("client_id", p.ClientID)
		}
		if p.ClientAuth == "body" {
			values.Set("client_secret", p.secret)
		}
		body = []byte(values.Encode())
		headers.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		values := map[string]string{}
		for k, v := range p.Body {
			expanded, err := substitute(v, s, p, u)
			if err != nil {
				return nil, err
			}
			values[k] = expanded
		}
		switch p.BodyFormat {
		case "json":
			body, err = json.Marshal(values)
			headers.Set("Content-Type", "application/json")
		case "form":
			form := url.Values{}
			for k, v := range values {
				form.Set(k, v)
			}
			body = []byte(form.Encode())
			headers.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		if err != nil {
			return nil, err
		}
		for k, v := range p.RefreshHeaders {
			expanded, err := substitute(v, s, p, u)
			if err != nil || !validHeader(k, expanded) {
				return nil, errors.New("invalid template header")
			}
			headers.Set(k, expanded)
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.GetBody = nil // A refresh is not automatically replayable.
	req.Header = headers
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Galleton/"+Version)
	if value := cookieHeaders(s.Cookies, u, time.Now()); value != "" {
		req.Header.Set("Cookie", value)
	}
	if p.Kind == "oauth2" && p.ClientAuth == "basic" {
		req.SetBasicAuth(url.QueryEscape(p.ClientID), url.QueryEscape(p.secret))
	}
	return req, nil
}

func pointer(doc any, path string) (any, bool) {
	if path == "" {
		return nil, false
	}
	if !strings.HasPrefix(path, "/") {
		return nil, false
	}
	current := doc
	for _, part := range strings.Split(path[1:], "/") {
		// RFC 6901 permits only ~0 and ~1 escapes.
		for i := 0; i < len(part); i++ {
			if part[i] == '~' {
				if i+1 >= len(part) || (part[i+1] != '0' && part[i+1] != '1') {
					return nil, false
				}
				i++
			}
		}
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		switch v := current.(type) {
		case map[string]any:
			var ok bool
			current, ok = v[part]
			if !ok {
				return nil, false
			}
		case []any:
			if part == "" || len(part) > 1 && part[0] == '0' {
				return nil, false
			}
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(v) {
				return nil, false
			}
			current = v[i]
		default:
			return nil, false
		}
	}
	return current, true
}
func tokenAt(doc any, path string) (string, bool) {
	v, ok := pointer(doc, path)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok && s != "" && len(s) <= 64<<10 && validHeader("Authorization", s) && !strings.ContainsAny(s, "\r\n")
}
func durationAt(doc any, path string) (time.Duration, bool) {
	v, ok := pointer(doc, path)
	if !ok {
		return 0, false
	}
	var raw string
	switch n := v.(type) {
	case json.Number:
		raw = string(n)
	case string:
		raw = n
	default:
		return 0, false
	}
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || seconds <= 0 || seconds > 365*86400 {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}
func parseJSON(b []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var doc any
	if err := d.Decode(&doc); err != nil {
		return nil, err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, errors.New("multiple JSON values")
	}
	return doc, nil
}

func transientOrUncertain(p *Provider) *Problem {
	if p.RetrySafe {
		return problem(503, "retry_later", "Renewal temporarily failed; the adapter explicitly permits retrying it.")
	}
	return problem(409, "renewal_uncertain", "The outcome of renewal is unknown. A single-use credential may have rotated; automatic replay is paused.")
}
func parseRetryAfter(value string, now time.Time) time.Time {
	if n, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && n >= 0 {
		if n > 86400 {
			n = 86400
		}
		return now.Add(time.Duration(n) * time.Second)
	}
	if t, err := http.ParseTime(value); err == nil && t.After(now) {
		if t.After(now.Add(24 * time.Hour)) {
			return now.Add(24 * time.Hour)
		}
		return t
	}
	return time.Time{}
}

// performRefresh mutates a working copy. Even partial replacement credentials
// are retained before a protocol error, rather than reverting to an old token.
func performRefresh(s *State, p *Provider, client *http.Client, req *http.Request) *Problem {
	// With the built-in Go transport, no credential-bearing request can have
	// been sent before GotConn. DNS/dial/TLS-establishment failures are safe
	// to retry, unlike a lost response after obtaining a connection.
	var connected atomic.Bool
	trace := &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { connected.Store(true) }}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	resp, err := client.Do(req)
	if err != nil {
		if !connected.Load() {
			return problem(503, "retry_later", "No upstream connection was established; renewal will retry after backoff.")
		}
		return transientOrUncertain(p)
	}
	defer resp.Body.Close()
	now := time.Now().UTC()
	cookies, accepted, cookieErr := updateCookies(s.Cookies, req.URL, resp.Cookies(), now)
	if cookieErr == nil {
		s.Cookies = cookies
	}
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if readErr != nil || len(raw) > 1<<20 {
		return transientOrUncertain(p)
	}
	doc, jsonErr := parseJSON(raw)
	if resp.StatusCode == 429 {
		e := problem(503, "retry_later", "The provider rate-limited renewal.")
		e.RetryAt = parseRetryAfter(resp.Header.Get("Retry-After"), now)
		return e
	}
	if resp.StatusCode >= 500 {
		return transientOrUncertain(p)
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return problem(502, "protocol_error", "The provider redirected renewal; redirects are intentionally not followed.")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		code, _ := tokenAt(doc, "/error")
		if p.Kind == "oauth2" && code == "invalid_grant" {
			return problem(401, "reauth_required", "The provider rejected the refresh credential.")
		}
		if p.Kind == "oauth2" && (code == "invalid_client" || code == "unauthorized_client") {
			return problem(409, "configuration_error", "The provider rejected the OAuth client configuration.")
		}
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			return problem(401, "reauth_required", "The provider denied session renewal.")
		}
		return problem(502, "protocol_error", "The provider rejected the renewal request.")
	}
	if cookieErr != nil {
		return problem(502, "protocol_error", "The provider returned more cookies than the session limit.")
	}
	mapping := p.Response
	if p.Kind == "oauth2" {
		mapping = ResponseMapping{AccessToken: "/access_token", RefreshToken: "/refresh_token", ExpiresIn: "/expires_in"}
	}
	needsJSON := mapping.AccessToken != "" || mapping.RefreshToken != "" || mapping.ExpiresIn != "" || mapping.ExpiresAt != "" || mapping.Success != ""
	if needsJSON && jsonErr != nil {
		return problem(502, "protocol_error", "Expected a JSON renewal response.")
	}
	if replacement, ok := tokenAt(doc, mapping.RefreshToken); ok {
		s.RefreshToken = replacement
	}
	token, hasToken := tokenAt(doc, mapping.AccessToken)
	if hasToken {
		s.AccessToken = token
		s.AccessExpiresAt = time.Time{}
	}
	if mapping.AccessToken != "" && !hasToken {
		return problem(502, "protocol_error", "The configured access-token field is missing or invalid.")
	}
	if p.Kind == "oauth2" {
		typ, ok := tokenAt(doc, "/token_type")
		if !ok || !strings.EqualFold(typ, "Bearer") {
			return problem(502, "protocol_error", "Only OAuth Bearer access tokens are supported.")
		}
	}
	if mapping.ExpiresIn != "" {
		if _, present := pointer(doc, mapping.ExpiresIn); present {
			d, ok := durationAt(doc, mapping.ExpiresIn)
			if !ok {
				return problem(502, "protocol_error", "Invalid token lifetime.")
			}
			s.AccessExpiresAt = now.Add(d)
		}
	}
	if mapping.ExpiresAt != "" {
		raw, ok := tokenAt(doc, mapping.ExpiresAt)
		if !ok {
			return problem(502, "protocol_error", "Missing absolute token expiry.")
		}
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil || !t.After(now) {
			return problem(502, "protocol_error", "Invalid absolute token expiry.")
		}
		s.AccessExpiresAt = t
	}
	success := false
	if mapping.Success != "" {
		v, ok := pointer(doc, mapping.Success)
		success = ok && v == true
		if !success {
			return problem(502, "protocol_error", "The adapter's success check did not pass.")
		}
	}
	if mapping.RequireSetCookie && accepted == 0 {
		return problem(502, "protocol_error", "The adapter requires a valid Set-Cookie renewal response.")
	}
	if !hasToken && accepted == 0 && !success {
		return problem(502, "protocol_error", "No renewal evidence: configure a token field, a success field, or require replacement cookies.")
	}
	return nil
}
