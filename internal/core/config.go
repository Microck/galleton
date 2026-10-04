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
		raw, _ := json.Marshal(p)
		sum := sha256.Sum256(raw)
		p.hash = hex.EncodeToString(sum[:])
		out[p.Name] = &p
	}
	return out, nil
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
