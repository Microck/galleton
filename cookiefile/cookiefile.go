// Package cookiefile converts common browser cookie exports into structured
// cookies that a Galleton daemon can import. It only parses; it never decides
// which origins may receive a cookie. The daemon applies the provider allowlist.
package cookiefile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Supported formats. Auto inspects the input and picks one of the others.
const (
	Auto     = "auto"
	Netscape = "netscape" // cookies.txt, including #HttpOnly_ lines
	JSON     = "json"     // Cookie-Editor / EditThisCookie array or {"url", "cookies"} wrapper
	Header   = "header"   // a Cookie request header or "a=b; c=d"
)

// MaxCookies bounds parser output; exports of a whole browser profile are
// expected to be filtered down to one provider by the daemon.
const MaxCookies = 4096

// MaxInput bounds the export size Parse accepts. A browser-wide cookies.txt is
// a few megabytes at most.
const MaxInput = 16 << 20

// Cookie is the wire shape of a structured cookie import.
//
// Domain is the cookie's domain without a leading dot. An empty Domain means
// the cookie belongs to the import's cookie_origin. HostOnly marks cookies
// that were set without a Domain attribute; a cookie with an empty Domain and
// HostOnly false came from a source without scope information (a Cookie
// header), and the daemon may scope it to the adapter's cookie_domain.
type Cookie struct {
	Name     string     `json:"name"`
	Value    string     `json:"value"`
	Domain   string     `json:"domain,omitempty"`
	HostOnly bool       `json:"host_only,omitempty"`
	Path     string     `json:"path,omitempty"`
	Expires  *time.Time `json:"expires,omitempty"`
	Secure   bool       `json:"secure,omitempty"`
	HTTPOnly bool       `json:"http_only,omitempty"`
	SameSite string     `json:"same_site,omitempty"` // lax, strict, none
}

var errTooMany = fmt.Errorf("more than %d cookies in input", MaxCookies)

// NormalizeFormat maps user-facing names to a supported format.
func NormalizeFormat(format string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", Auto:
		return Auto, nil
	case Netscape, "cookies.txt":
		return Netscape, nil
	case JSON, "cookie-editor":
		return JSON, nil
	case Header, "cookie":
		return Header, nil
	}
	return "", fmt.Errorf("unknown cookie format %q; use auto, netscape, json or header", format)
}

// Detect guesses the format of data. It never returns Auto.
func Detect(data []byte) string {
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")))
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		return JSON
	}
	for _, line := range strings.Split(string(trimmed), "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "# netscape http cookie file") || strings.HasPrefix(lower, "# http cookie file") || strings.HasPrefix(line, "#HttpOnly_") {
			return Netscape
		}
		if line != "" && !strings.HasPrefix(line, "#") && strings.Count(line, "\t") >= 6 {
			return Netscape
		}
	}
	return Header
}

// Parse converts data in the given format (or Auto) into cookies. It returns
// the format that was used.
func Parse(data []byte, format string) ([]Cookie, string, error) {
	format, err := NormalizeFormat(format)
	if err != nil {
		return nil, "", err
	}
	if len(data) > MaxInput {
		return nil, format, fmt.Errorf("cookie export is larger than %d MiB", MaxInput>>20)
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if format == Auto {
		format = Detect(data)
	}
	var out []Cookie
	switch format {
	case Netscape:
		out, err = parseNetscape(string(data))
	case JSON:
		out, err = parseJSON(data)
	case Header:
		out, err = parseHeader(string(data))
	}
	if err != nil {
		return nil, format, err
	}
	if len(out) == 0 {
		return nil, format, fmt.Errorf("no cookies found in %s input", format)
	}
	return out, format, nil
}

func parseNetscape(text string) ([]Cookie, error) {
	var out []Cookie
	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, "\r")
		httpOnly := false
		if strings.HasPrefix(line, "#HttpOnly_") {
			httpOnly = true
			line = strings.TrimPrefix(line, "#HttpOnly_")
		}
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(out) == MaxCookies {
			return nil, errTooMany
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 7 {
			// Some copy-paste paths turn tabs into spaces; the value is the remainder.
			fields = strings.SplitN(strings.Join(strings.Fields(line), " "), " ", 7)
		}
		if len(fields) < 7 {
			return nil, fmt.Errorf("cookies.txt line %d: expected 7 tab-separated fields", i+1)
		}
		if len(fields) > 7 {
			fields[6] = strings.Join(fields[6:], "\t")
		}
		domain := strings.TrimSpace(fields[0])
		subdomains, err := netscapeBool(fields[1])
		if err != nil {
			return nil, fmt.Errorf("cookies.txt line %d: include-subdomains flag: %w", i+1, err)
		}
		secure, err := netscapeBool(fields[3])
		if err != nil {
			return nil, fmt.Errorf("cookies.txt line %d: secure flag: %w", i+1, err)
		}
		expiry, err := strconv.ParseFloat(strings.TrimSpace(fields[4]), 64)
		if err != nil || math.IsNaN(expiry) || math.IsInf(expiry, 0) {
			return nil, fmt.Errorf("cookies.txt line %d: invalid expiry", i+1)
		}
		c := Cookie{Name: strings.TrimSpace(fields[5]), Value: strings.TrimSpace(fields[6]), Path: strings.TrimSpace(fields[2]), Secure: secure, HTTPOnly: httpOnly, Expires: epoch(expiry)}
		c.Domain, c.HostOnly = scope(domain, !subdomains && !strings.HasPrefix(domain, "."))
		if c.Name == "" {
			return nil, fmt.Errorf("cookies.txt line %d: empty cookie name", i+1)
		}
		out = append(out, c)
	}
	return out, nil
}

func netscapeBool(raw string) (bool, error) {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "TRUE":
		return true, nil
	case "FALSE":
		return false, nil
	}
	return false, errors.New("expected TRUE or FALSE")
}

// epoch converts seconds since 1970 to an expiry. Zero and negative values
// (cookies.txt and DevTools session markers) mean a session cookie. Callers
// reject non-finite values first.
func epoch(seconds float64) *time.Time {
	if seconds <= 0 {
		return nil
	}
	if seconds > 253402300799 { // Year 9999; clamp absurd expiries.
		seconds = 253402300799
	}
	whole, frac := math.Modf(seconds)
	t := time.Unix(int64(whole), int64(frac*1e9)).UTC()
	return &t
}

// scope strips a leading dot and decides host-only status.
func scope(domain string, hostOnly bool) (string, bool) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if strings.HasPrefix(domain, ".") {
		return strings.TrimLeft(domain, "."), false
	}
	return domain, hostOnly
}

// jsonCookie accepts the field spellings of Cookie-Editor and EditThisCookie
// (expirationDate, hostOnly) and of DevTools or Playwright (expires).
type jsonCookie struct {
	Name           *string         `json:"name"`
	Value          *string         `json:"value"`
	Domain         string          `json:"domain"`
	Path           string          `json:"path"`
	HostOnly       *bool           `json:"hostOnly"`
	Secure         bool            `json:"secure"`
	HTTPOnly       bool            `json:"httpOnly"`
	Session        bool            `json:"session"`
	SameSite       string          `json:"sameSite"`
	ExpirationDate json.RawMessage `json:"expirationDate"`
	Expires        json.RawMessage `json:"expires"`
}

func (j jsonCookie) cookie(defaultHost string) (Cookie, error) {
	if j.Name == nil || *j.Name == "" {
		return Cookie{}, errors.New("cookie without a name")
	}
	if j.Value == nil {
		return Cookie{}, fmt.Errorf("cookie %q has no value", *j.Name)
	}
	c := Cookie{Name: *j.Name, Value: *j.Value, Path: j.Path, Secure: j.Secure, HTTPOnly: j.HTTPOnly, SameSite: sameSite(j.SameSite)}
	switch {
	case j.Domain != "":
		// Exports without a hostOnly flag mark a domain cookie with a
		// leading dot, and a host-only cookie by its absence.
		hostOnly := !strings.HasPrefix(j.Domain, ".")
		if j.HostOnly != nil {
			hostOnly = *j.HostOnly
		}
		c.Domain, c.HostOnly = scope(j.Domain, hostOnly)
	case defaultHost != "":
		c.Domain, c.HostOnly = defaultHost, true
	}
	if !j.Session {
		for _, raw := range []json.RawMessage{j.ExpirationDate, j.Expires} {
			expires, err := jsonExpiry(raw)
			if err != nil {
				return Cookie{}, fmt.Errorf("cookie %q: %w", c.Name, err)
			}
			if expires != nil {
				c.Expires = expires
				break
			}
		}
	}
	return c, nil
}

func jsonExpiry(raw json.RawMessage) (*time.Time, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var number float64
	if json.Unmarshal(raw, &number) == nil {
		if number > 1e11 { // Milliseconds, as in some extension exports.
			number /= 1000
		}
		return epoch(number), nil
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		if text == "" || strings.EqualFold(text, "session") {
			return nil, nil
		}
		for _, layout := range []string{time.RFC3339Nano, http.TimeFormat, time.RFC1123} {
			if t, err := time.Parse(layout, text); err == nil {
				t = t.UTC()
				return &t, nil
			}
		}
		if seconds, err := strconv.ParseFloat(text, 64); err == nil && !math.IsNaN(seconds) && !math.IsInf(seconds, 0) {
			return epoch(seconds), nil
		}
	}
	return nil, errors.New("unrecognized expiry")
}

func sameSite(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "lax":
		return "lax"
	case "strict":
		return "strict"
	case "none", "no_restriction":
		return "none"
	}
	return ""
}

// parseJSON streams the cookie array, so an export with millions of entries
// fails at MaxCookies instead of being decoded whole first.
func parseJSON(data []byte) ([]Cookie, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	start, err := d.Token()
	if err != nil {
		return nil, errors.New("invalid JSON cookie export")
	}
	var out []Cookie
	switch start {
	case json.Delim('['):
		if out, err = decodeCookies(d, ""); err != nil {
			return nil, err
		}
	case json.Delim('{'):
		// {"url": ..., "cookies": [...]}: the URL supplies a missing domain,
		// so it must be known before the array is read.
		var rawCookies json.RawMessage
		host := ""
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return nil, errors.New("invalid JSON cookie export")
			}
			switch key {
			case "url":
				var raw string
				if d.Decode(&raw) != nil {
					return nil, errors.New("invalid url in JSON cookie export")
				}
				u, err := url.Parse(raw)
				if err != nil || u.Hostname() == "" {
					return nil, errors.New("invalid url in JSON cookie export")
				}
				host = strings.ToLower(u.Hostname())
			case "cookies":
				if d.Decode(&rawCookies) != nil {
					return nil, errors.New("invalid JSON cookie export")
				}
			default:
				var skip json.RawMessage
				if d.Decode(&skip) != nil {
					return nil, errors.New("invalid JSON cookie export")
				}
			}
		}
		if len(rawCookies) == 0 {
			return nil, errors.New(`JSON cookie export needs an array or an object with a "cookies" array`)
		}
		inner := json.NewDecoder(bytes.NewReader(rawCookies))
		if t, err := inner.Token(); err != nil || t != json.Delim('[') {
			return nil, errors.New(`JSON cookie export needs an array or an object with a "cookies" array`)
		}
		if out, err = decodeCookies(inner, host); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New(`JSON cookie export needs an array or an object with a "cookies" array`)
	}
	return out, nil
}

// decodeCookies reads array elements after the opening bracket.
func decodeCookies(d *json.Decoder, defaultHost string) ([]Cookie, error) {
	var out []Cookie
	for d.More() {
		if len(out) == MaxCookies {
			return nil, errTooMany
		}
		var j jsonCookie
		if err := d.Decode(&j); err != nil {
			return nil, errors.New("invalid JSON cookie entry")
		}
		c, err := j.cookie(defaultHost)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if _, err := d.Token(); err != nil {
		return nil, errors.New("invalid JSON cookie array")
	}
	return out, nil
}

func parseHeader(text string) ([]Cookie, error) {
	var parts []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if name, rest, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(name), "cookie") {
			line = rest
		}
		parts = append(parts, strings.TrimSpace(line))
	}
	header := strings.Join(parts, "; ")
	if strings.Count(header, ";") >= MaxCookies {
		return nil, errTooMany
	}
	parsed, err := http.ParseCookie(header)
	if err != nil {
		return nil, errors.New("invalid Cookie header")
	}
	out := make([]Cookie, 0, len(parsed))
	for _, c := range parsed {
		out = append(out, Cookie{Name: c.Name, Value: c.Value})
	}
	return out, nil
}

// Read reads at most MaxInput bytes from r and parses them.
func Read(r io.Reader, format string) ([]Cookie, string, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxInput+1))
	if err != nil {
		return nil, "", err
	}
	return Parse(data, format)
}
