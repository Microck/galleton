// Package cookiefile converts common cookie exports into structured cookies
// that a Galleton daemon can import. It only parses; it never decides which
// origins may receive a cookie. The daemon applies the provider allowlist.
package cookiefile

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Supported formats. Auto inspects the input and picks one of the others.
const (
	Auto      = "auto"
	Netscape  = "netscape"   // cookies.txt, including #HttpOnly_ lines
	JSON      = "json"       // Cookie-Editor, EditThisCookie, DevTools/CDP, Playwright
	Header    = "header"     // a Cookie request header or "a=b; c=d"
	SetCookie = "set-cookie" // one Set-Cookie value per line
	HAR       = "har"        // HTTP Archive: request and response cookies
)

// MaxCookies bounds parser output; exports of a whole browser profile are
// expected to be filtered down to one provider by the daemon.
const MaxCookies = 4096

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

// NormalizeFormat maps user-facing names and aliases to a supported format.
func NormalizeFormat(format string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", Auto:
		return Auto, nil
	case Netscape, "cookies.txt", "cookies-txt", "txt":
		return Netscape, nil
	case JSON, "cookie-editor", "editthiscookie", "devtools", "cdp", "playwright":
		return JSON, nil
	case Header, "cookie", "cookie-header":
		return Header, nil
	case SetCookie, "setcookie", "set-cookie-header":
		return SetCookie, nil
	case HAR:
		return HAR, nil
	}
	return "", fmt.Errorf("unknown cookie format %q; use auto, netscape, json, header, set-cookie or har", format)
}

// Detect guesses the format of data. It never returns Auto.
func Detect(data []byte) string {
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")))
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		var probe map[string]json.RawMessage
		if trimmed[0] == '{' && json.Unmarshal(trimmed, &probe) == nil {
			if _, ok := probe["log"]; ok {
				return HAR
			}
		}
		return JSON
	}
	lines := nonEmptyLines(string(trimmed))
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "# netscape http cookie file") || strings.HasPrefix(lower, "# http cookie file") || strings.HasPrefix(line, "#HttpOnly_") {
			return Netscape
		}
		if !strings.HasPrefix(line, "#") && strings.Count(line, "\t") >= 6 {
			return Netscape
		}
	}
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "set-cookie:") {
			return SetCookie
		}
	}
	if len(lines) > 1 && !strings.HasPrefix(strings.ToLower(lines[0]), "cookie:") {
		return SetCookie
	}
	for _, line := range lines {
		if hasCookieAttribute(line) {
			return SetCookie
		}
	}
	return Header
}

// Parse converts data in the given format (or Auto) into cookies. It returns
// the format that was used. now resolves Max-Age attributes.
func Parse(data []byte, format string, now time.Time) ([]Cookie, string, error) {
	format, err := NormalizeFormat(format)
	if err != nil {
		return nil, "", err
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
	case SetCookie:
		out, err = parseSetCookieLines(nonEmptyLines(string(data)), "", now)
	case HAR:
		out, err = parseHAR(data, now)
	}
	if err != nil {
		return nil, format, err
	}
	if len(out) == 0 {
		return nil, format, fmt.Errorf("no cookies found in %s input", format)
	}
	if len(out) > MaxCookies {
		return nil, format, fmt.Errorf("more than %d cookies in input", MaxCookies)
	}
	return out, format, nil
}

var cookieAttributes = map[string]bool{"path": true, "domain": true, "expires": true, "max-age": true, "samesite": true, "secure": true, "httponly": true, "partitioned": true}

func hasCookieAttribute(line string) bool {
	parts := strings.Split(line, ";")
	for _, part := range parts[1:] {
		name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
		if cookieAttributes[strings.ToLower(strings.TrimSpace(name))] {
			return true
		}
	}
	return false
}

func nonEmptyLines(text string) []string {
	var out []string
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 64<<10), 16<<20)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			out = append(out, line)
		}
	}
	return out
}

func parseNetscape(text string) ([]Cookie, error) {
	var out []Cookie
	for i, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line := strings.TrimRight(raw, "\r")
		httpOnly := false
		if strings.HasPrefix(line, "#HttpOnly_") {
			httpOnly = true
			line = strings.TrimPrefix(line, "#HttpOnly_")
		}
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
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
		if err != nil {
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
// (cookies.txt and DevTools session markers) mean a session cookie.
func epoch(seconds float64) *time.Time {
	if seconds <= 0 || math.IsNaN(seconds) || math.IsInf(seconds, 0) {
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
	if domain == "" {
		return "", hostOnly
	}
	return domain, hostOnly
}

// jsonCookie accepts the field spellings used by Cookie-Editor, EditThisCookie,
// Chrome DevTools Protocol (Network.getAllCookies), Playwright and HAR.
type jsonCookie struct {
	Name           *string         `json:"name"`
	Value          *string         `json:"value"`
	Domain         string          `json:"domain"`
	Host           string          `json:"host"`
	Path           string          `json:"path"`
	HostOnly       *bool           `json:"hostOnly"`
	Secure         bool            `json:"secure"`
	HTTPOnly       bool            `json:"httpOnly"`
	HTTPOnlyAlt    bool            `json:"http_only"`
	Session        bool            `json:"session"`
	SameSite       string          `json:"sameSite"`
	ExpirationDate json.RawMessage `json:"expirationDate"`
	Expires        json.RawMessage `json:"expires"`
	Expiry         json.RawMessage `json:"expiry"`
}

func (j jsonCookie) cookie(defaultHost string) (Cookie, error) {
	if j.Name == nil || *j.Name == "" {
		return Cookie{}, errors.New("cookie without a name")
	}
	if j.Value == nil {
		return Cookie{}, fmt.Errorf("cookie %q has no value", *j.Name)
	}
	c := Cookie{Name: *j.Name, Value: *j.Value, Path: j.Path, Secure: j.Secure, HTTPOnly: j.HTTPOnly || j.HTTPOnlyAlt, SameSite: sameSite(j.SameSite)}
	domain := j.Domain
	if domain == "" {
		domain = j.Host
	}
	switch {
	case domain != "":
		// DevTools/Playwright exports have no hostOnly flag: a leading dot marks
		// a domain cookie, and its absence a host-only cookie.
		hostOnly := !strings.HasPrefix(domain, ".")
		if j.HostOnly != nil {
			hostOnly = *j.HostOnly
		}
		c.Domain, c.HostOnly = scope(domain, hostOnly)
	case defaultHost != "":
		c.Domain, c.HostOnly = defaultHost, true
	}
	if !j.Session {
		for _, raw := range []json.RawMessage{j.ExpirationDate, j.Expires, j.Expiry} {
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
		if seconds, err := strconv.ParseFloat(text, 64); err == nil {
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

func parseJSON(data []byte) ([]Cookie, error) {
	trimmed := bytes.TrimSpace(data)
	var list []jsonCookie
	defaultHost := ""
	if len(trimmed) > 0 && trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &list); err != nil {
			return nil, errors.New("invalid JSON cookie array")
		}
	} else {
		var wrapper struct {
			URL     string       `json:"url"`
			Cookies []jsonCookie `json:"cookies"`
			Log     any          `json:"log"`
		}
		if err := json.Unmarshal(trimmed, &wrapper); err != nil {
			return nil, errors.New("invalid JSON cookie export")
		}
		if wrapper.Log != nil {
			return nil, errors.New("this is a HAR file; use format har")
		}
		if wrapper.Cookies == nil {
			return nil, errors.New(`JSON cookie export needs an array or an object with a "cookies" array`)
		}
		list = wrapper.Cookies
		if wrapper.URL != "" {
			u, err := url.Parse(wrapper.URL)
			if err != nil || u.Hostname() == "" {
				return nil, errors.New("invalid url in JSON cookie export")
			}
			defaultHost = strings.ToLower(u.Hostname())
		}
	}
	out := make([]Cookie, 0, len(list))
	for _, j := range list {
		c, err := j.cookie(defaultHost)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

func parseHeader(text string) ([]Cookie, error) {
	var parts []string
	for _, line := range nonEmptyLines(text) {
		if name, rest, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(name), "cookie") {
			line = rest
		}
		parts = append(parts, strings.TrimSpace(line))
	}
	header := strings.Join(parts, "; ")
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

// parseSetCookieLines parses Set-Cookie values. host, when known, is the host
// that sent them; otherwise cookies without Domain belong to cookie_origin.
func parseSetCookieLines(lines []string, host string, now time.Time) ([]Cookie, error) {
	out := make([]Cookie, 0, len(lines))
	for i, line := range lines {
		if name, rest, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(name), "set-cookie") {
			line = strings.TrimSpace(rest)
		}
		c, err := http.ParseSetCookie(line)
		if err != nil {
			return nil, fmt.Errorf("Set-Cookie line %d is invalid", i+1)
		}
		out = append(out, fromHTTP(c, host, now))
	}
	return out, nil
}

func fromHTTP(c *http.Cookie, host string, now time.Time) Cookie {
	out := Cookie{Name: c.Name, Value: c.Value, Path: c.Path, Secure: c.Secure, HTTPOnly: c.HttpOnly}
	if c.Domain != "" {
		out.Domain, out.HostOnly = scope(c.Domain, false)
	} else {
		out.Domain, out.HostOnly = host, true
	}
	switch {
	case c.MaxAge < 0:
		past := time.Unix(1, 0).UTC()
		out.Expires = &past
	case c.MaxAge > 0:
		t := now.Add(time.Duration(c.MaxAge) * time.Second).UTC()
		out.Expires = &t
	case !c.Expires.IsZero():
		t := c.Expires.UTC()
		out.Expires = &t
	}
	switch c.SameSite {
	case http.SameSiteLaxMode:
		out.SameSite = "lax"
	case http.SameSiteStrictMode:
		out.SameSite = "strict"
	case http.SameSiteNoneMode:
		out.SameSite = "none"
	}
	return out
}

type harNameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type harMessage struct {
	URL     string         `json:"url"`
	Headers []harNameValue `json:"headers"`
	Cookies []jsonCookie   `json:"cookies"`
}

// parseHAR replays the archive in order: cookies a request carried, then the
// cookies its response set. Later values replace earlier ones.
func parseHAR(data []byte, now time.Time) ([]Cookie, error) {
	var har struct {
		Log *struct {
			Entries []struct {
				StartedDateTime string     `json:"startedDateTime"`
				Request         harMessage `json:"request"`
				Response        harMessage `json:"response"`
			} `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(data, &har); err != nil || har.Log == nil {
		return nil, errors.New("invalid HAR file")
	}
	entries := har.Log.Entries
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].StartedDateTime < entries[j].StartedDateTime })
	type key struct{ name, domain, path string }
	index := map[key]int{}
	var out []Cookie
	put := func(c Cookie) {
		k := key{c.Name, c.Domain, c.Path}
		if i, ok := index[k]; ok {
			out[i] = c
			return
		}
		index[k] = len(out)
		out = append(out, c)
	}
	for _, entry := range entries {
		u, err := url.Parse(entry.Request.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if len(entry.Request.Cookies) > 0 {
			for _, j := range entry.Request.Cookies {
				if j.Name == nil || j.Value == nil || *j.Name == "" {
					continue
				}
				// A request cookie carries no scope; it was valid for this host.
				put(Cookie{Name: *j.Name, Value: *j.Value, Domain: host, HostOnly: true, Path: "/", Secure: u.Scheme == "https"})
			}
		} else {
			for _, h := range entry.Request.Headers {
				if !strings.EqualFold(h.Name, "cookie") {
					continue
				}
				parsed, err := http.ParseCookie(h.Value)
				if err != nil {
					continue
				}
				for _, c := range parsed {
					put(Cookie{Name: c.Name, Value: c.Value, Domain: host, HostOnly: true, Path: "/", Secure: u.Scheme == "https"})
				}
			}
		}
		// Prefer raw Set-Cookie headers: they keep every attribute.
		var lines []string
		for _, h := range entry.Response.Headers {
			if strings.EqualFold(h.Name, "set-cookie") {
				for _, line := range strings.Split(h.Value, "\n") {
					if line = strings.TrimSpace(line); line != "" {
						lines = append(lines, line)
					}
				}
			}
		}
		if len(lines) > 0 {
			for _, line := range lines {
				c, err := http.ParseSetCookie(line)
				if err != nil {
					continue
				}
				put(withDefaultPath(fromHTTP(c, host, now), u.Path))
			}
			continue
		}
		for _, j := range entry.Response.Cookies {
			c, err := j.cookie(host)
			if err != nil {
				continue
			}
			put(withDefaultPath(c, u.Path))
		}
	}
	return out, nil
}

// withDefaultPath applies the RFC 6265 default-path rule for Set-Cookie
// values that omitted Path, so HAR replay keys match the daemon's.
func withDefaultPath(c Cookie, requestPath string) Cookie {
	if c.Path != "" && strings.HasPrefix(c.Path, "/") {
		return c
	}
	c.Path = "/"
	if i := strings.LastIndex(requestPath, "/"); i > 0 && strings.HasPrefix(requestPath, "/") {
		c.Path = requestPath[:i]
	}
	return c
}
