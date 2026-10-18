package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func LoadConfig(path string) (Config, error) {
	var c Config
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, fmt.Errorf("invalid adapter configuration: %w", err)
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, errors.New("configuration must contain one JSON object")
	}
	return c, nil
}

func canonicalURL(raw string) (*url.URL, string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" || u.User != nil || u.Fragment != "" || strings.ContainsAny(raw, "\r\n\t") {
		return nil, "", invalid("An absolute HTTP(S) URL without user information or fragments is required.")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, "", invalid("Only HTTP(S) URLs are supported.")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.HasSuffix(host, ".") || strings.Contains(host, "%") {
		return nil, "", invalid("Invalid host.")
	}
	for _, c := range host {
		if c > 127 {
			return nil, "", invalid("Use ASCII/punycode hostnames.")
		}
	}
	port := u.Port()
	if port == "443" && u.Scheme == "https" || port == "80" && u.Scheme == "http" {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host = net.JoinHostPort(strings.Trim(host, "[]"), port)
	}
	u.Host = host
	return u, u.Scheme + "://" + host, nil
}
func loopbackHost(host string) bool { ip := net.ParseIP(host); return ip != nil && ip.IsLoopback() }

func (p *Provider) allowed(raw string) (*url.URL, error) {
	u, origin, err := canonicalURL(raw)
	if err != nil {
		return nil, err
	}
	found := false
	for _, o := range p.Origins {
		if o == origin {
			found = true
			break
		}
	}
	if !found {
		return nil, problem(403, "origin_not_allowed", "URL origin is not allowlisted by this provider.")
	}
	if u.Scheme == "http" && !(p.AllowHTTPLoopback && loopbackHost(u.Hostname())) {
		return nil, invalid("Provider endpoints require HTTPS, except explicit loopback demos.")
	}
	return u, nil
}

func compileProviders(c Config) (map[string]*Provider, error) {
	out := make(map[string]*Provider)
	for _, original := range c.Providers {
		p := original
		if err := checkID(p.Name); err != nil {
			return nil, fmt.Errorf("invalid provider name: %w", err)
		}
		if _, exists := out[p.Name]; exists {
			return nil, errors.New("duplicate provider name")
		}
		if p.Kind != "http" && p.Kind != "oauth2" {
			return nil, fmt.Errorf("provider %s: kind must be http or oauth2", p.Name)
		}
		if len(p.Origins) == 0 || len(p.Origins) > 32 {
			return nil, errors.New("a provider needs 1–32 explicit origins")
		}
		p.Origins = append([]string(nil), p.Origins...)
		seen := map[string]bool{}
		for i, o := range p.Origins {
			u, origin, err := canonicalURL(o)
			if err != nil {
				return nil, err
			}
			if u.Path != "" && u.Path != "/" || u.RawQuery != "" {
				return nil, errors.New("origins cannot include a path or query")
			}
			if seen[origin] {
				return nil, errors.New("duplicate provider origin")
			}
			seen[origin] = true
			p.Origins[i] = origin
		}
		if _, err := p.allowed(p.RefreshURL); err != nil {
			return nil, fmt.Errorf("provider %s refresh URL: %w", p.Name, err)
		}
		if p.RefreshIntervalSeconds < 1 || p.RefreshIntervalSeconds > 86400*30 {
			return nil, errors.New("refresh_interval_seconds must be 1–2592000")
		}
		if p.RefreshBeforeSeconds == 0 {
			p.RefreshBeforeSeconds = 60
		}
		if p.RefreshBeforeSeconds < 0 || p.RefreshBeforeSeconds > 86400 {
			return nil, errors.New("invalid refresh_before_seconds")
		}
		if p.TimeoutSeconds == 0 {
			p.TimeoutSeconds = 20
		}
		if p.TimeoutSeconds < 1 || p.TimeoutSeconds > 120 {
			return nil, errors.New("timeout_seconds must be 1–120")
		}
		if p.Kind == "oauth2" {
			if p.RefreshMethod != "" || len(p.RefreshHeaders) > 0 || p.BodyFormat != "" || len(p.Body) > 0 || p.Response != (ResponseMapping{}) {
				return nil, errors.New("oauth2 uses its standard request and response; use kind http for custom flows")
			}
			if p.ClientAuth == "" {
				p.ClientAuth = "none"
			}
			if p.ClientAuth != "none" && p.ClientAuth != "basic" && p.ClientAuth != "body" {
				return nil, errors.New("invalid client_auth")
			}
			if p.ClientAuth != "none" && (p.ClientID == "" || p.ClientSecretEnv == "") {
				return nil, errors.New("confidential OAuth clients need client_id and client_secret_env")
			}
			if p.ClientSecretEnv != "" {
				p.secret = os.Getenv(p.ClientSecretEnv)
				if p.secret == "" {
					return nil, fmt.Errorf("provider %s: client secret environment variable is missing", p.Name)
				}
			}
		} else {
			if p.RefreshMethod == "" {
				p.RefreshMethod = "POST"
			}
			if p.RefreshMethod != "POST" && p.RefreshMethod != "GET" {
				return nil, errors.New("refresh_method must be GET or POST")
			}
			if p.BodyFormat == "" {
				p.BodyFormat = "none"
			}
			if p.BodyFormat != "none" && p.BodyFormat != "form" && p.BodyFormat != "json" {
				return nil, errors.New("body_format must be none, form or json")
			}
			if p.BodyFormat == "none" && len(p.Body) > 0 || p.RefreshMethod == "GET" && p.BodyFormat != "none" {
				return nil, errors.New("request body configuration conflicts with refresh method")
			}
			for _, pointer := range []string{p.Response.AccessToken, p.Response.RefreshToken, p.Response.ExpiresIn, p.Response.ExpiresAt, p.Response.Success} {
				if pointer != "" && !strings.HasPrefix(pointer, "/") {
					return nil, errors.New("response selectors must be RFC 6901 JSON pointers starting with /")
				}
			}
			for k, v := range p.RefreshHeaders {
				if forbiddenHeader(k) || strings.EqualFold(k, "Cookie") || !validHeader(k, v) {
					return nil, errors.New("invalid refresh header")
				}
			}
		}
		if err := compileScope(&p); err != nil {
			return nil, fmt.Errorf("provider %s: %w", p.Name, err)
		}
		if err := compileEgress(&p); err != nil {
			return nil, fmt.Errorf("provider %s: %w", p.Name, err)
		}
		// Egress, pacing, size limits and block signatures do not change what a
		// stored credential means or where it may be sent; changing them does
		// not invalidate sessions. Every other field does.
		hashable := p
		hashable.Proxy, hashable.ProxyEnv, hashable.KeepAlive, hashable.MinIntervalMS = "", "", false, 0
		hashable.MaxRequestBodyBytes, hashable.MaxResponseBodyBytes, hashable.BlockSignatures = 0, 0, nil
		raw, _ := json.Marshal(hashable)
		sum := sha256.Sum256(raw)
		p.hash = hex.EncodeToString(sum[:])
		out[p.Name] = &p
	}
	return out, nil
}

func validCookieName(name string) bool {
	return name != "" && len(name) <= 256 && (&http.Cookie{Name: name, Value: "x"}).Valid() == nil
}

// compileScope validates where credentials may be stored and sent.
func compileScope(p *Provider) error {
	if p.CookieDomain != "" {
		domain := strings.ToLower(strings.TrimPrefix(p.CookieDomain, "."))
		if domain == "" || strings.HasSuffix(domain, ".") || !strings.Contains(domain, ".") || net.ParseIP(domain) != nil || strings.Trim(domain, "abcdefghijklmnopqrstuvwxyz0123456789.-") != "" || strings.Contains(domain, "..") {
			return errors.New("cookie_domain must be an ASCII DNS name with at least two labels, such as .www.example.com")
		}
		matched := false
		for _, o := range p.Origins {
			matched = matched || domainMatch(originHost(o), domain)
		}
		if !matched {
			return errors.New("cookie_domain must contain at least one listed origin")
		}
		p.cookieDomain = domain
	}
	if len(p.ProtectedCookies) > 32 {
		return errors.New("at most 32 protected_cookies")
	}
	p.protected = map[string]bool{}
	for _, name := range p.ProtectedCookies {
		if !validCookieName(name) || p.protected[name] {
			return errors.New("protected_cookies must be distinct valid cookie names")
		}
		p.protected[name] = true
	}
	if p.JWTSubjectCookie != "" && !p.protected[p.JWTSubjectCookie] {
		return errors.New("jwt_subject_cookie must also be listed in protected_cookies")
	}
	switch p.Authorization {
	case "", "bearer", "none":
		if p.AuthorizationCookie != "" {
			return errors.New("authorization_cookie requires authorization cookie_bearer")
		}
	case "cookie_bearer":
		if !validCookieName(p.AuthorizationCookie) {
			return errors.New("authorization cookie_bearer needs a valid authorization_cookie")
		}
	default:
		return errors.New("authorization must be bearer, none or cookie_bearer")
	}
	if p.Kind == "oauth2" && p.Authorization != "" && p.Authorization != "bearer" {
		return errors.New("oauth2 access tokens are always sent as Bearer")
	}
	return nil
}

// compileEgress builds the provider's upstream clients. A configured proxy
// that cannot be read stops startup: there is no direct-connection fallback.
func compileEgress(p *Provider) error {
	var proxy *url.URL
	var err error
	switch {
	case p.Proxy != "" && p.ProxyEnv != "":
		return errors.New("use proxy or proxy_env, not both")
	case p.Proxy != "":
		proxy, err = parseProxy(p.Proxy, false)
	case p.ProxyEnv != "":
		value := os.Getenv(p.ProxyEnv)
		if value == "" {
			return errors.New("proxy environment variable is missing; refusing to fall back to a direct connection")
		}
		proxy, err = parseProxy(value, true)
	}
	if err != nil {
		return err
	}
	if p.MinIntervalMS < 0 || p.MinIntervalMS > 3600000 {
		return errors.New("min_interval_ms must be 0–3600000")
	}
	p.maxRequest, p.maxResponse = defaultMaxRequestBody, defaultMaxResponseBody
	if p.MaxRequestBodyBytes != 0 {
		if p.MaxRequestBodyBytes < 1 || p.MaxRequestBodyBytes > maxManagedBody {
			return errors.New("max_request_body_bytes must be 1–67108864")
		}
		p.maxRequest = p.MaxRequestBodyBytes
	}
	if p.MaxResponseBodyBytes != 0 {
		if p.MaxResponseBodyBytes < 1 || p.MaxResponseBodyBytes > maxManagedBody {
			return errors.New("max_response_body_bytes must be 1–67108864")
		}
		p.maxResponse = p.MaxResponseBodyBytes
	}
	if err := validateBlockSignatures(p.BlockSignatures); err != nil {
		return err
	}
	p.renewal = newUpstreamClient(proxy, false)
	p.resource = p.renewal
	if p.KeepAlive {
		p.resource = newUpstreamClient(proxy, true)
	}
	p.gate = &gate{}
	return nil
}
func validHeader(name, value string) bool {
	if name == "" || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", r)) {
			return false
		}
	}
	for _, r := range value {
		if r < 32 && r != '\t' || r == 127 {
			return false
		}
	}
	return true
}
func forbiddenHeader(k string) bool {
	k = http.CanonicalHeaderKey(k)
	switch k {
	case "Host", "Connection", "Content-Length", "Transfer-Encoding", "Upgrade", "Trailer", "Te", "Keep-Alive", "Proxy-Authorization", "Proxy-Connection":
		return true
	}
	return strings.HasPrefix(strings.ToLower(k), "proxy-")
}
