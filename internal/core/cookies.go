package core

import (
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strings"
	"time"
)

// All cookies are pinned to an exact origin. Returning the entire domain as a
// public suffix additionally prevents the standard jar from widening scope.
type exactSuffix struct{}

func (exactSuffix) PublicSuffix(domain string) string { return domain }
func (exactSuffix) String() string                    { return "Galleton exact-origin isolation" }

func defaultCookiePath(path string) string {
	if !strings.HasPrefix(path, "/") {
		return "/"
	}
	i := strings.LastIndex(path, "/")
	if i <= 0 {
		return "/"
	}
	return path[:i]
}
func cookieHeaders(cookies []StoredCookie, u *url.URL, now time.Time) string {
	_, origin, _ := canonicalURL(u.String())
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: exactSuffix{}})
	entries := append([]StoredCookie(nil), cookies...)
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].CreatedAt.Before(entries[j].CreatedAt) })
	for _, e := range entries {
		if e.Origin != origin || !e.Cookie.Expires.IsZero() && !e.Cookie.Expires.After(now) {
			continue
		}
		c := e.Cookie
		c.MaxAge = 0
		c.Domain = ""
		jar.SetCookies(u, []*http.Cookie{&c})
	}
	req := &http.Request{Header: make(http.Header)}
	for _, c := range jar.Cookies(u) {
		req.AddCookie(c)
	}
	return req.Header.Get("Cookie")
}

func updateCookies(existing []StoredCookie, u *url.URL, incoming []*http.Cookie, now time.Time) ([]StoredCookie, int, error) {
	_, origin, _ := canonicalURL(u.String())
	out := make([]StoredCookie, 0, len(existing)+len(incoming))
	for _, e := range existing {
		if e.Cookie.Expires.IsZero() || e.Cookie.Expires.After(now) {
			out = append(out, e)
		}
	}
	accepted := 0
	for _, raw := range incoming {
		c := *raw
		if c.Valid() != nil || c.Partitioned {
			continue
		} // No browser partition context exists in a daemon.
		if c.Secure && u.Scheme != "https" {
			continue
		}
		domain := strings.ToLower(strings.TrimPrefix(c.Domain, "."))
		host := strings.ToLower(u.Hostname())
		if domain != "" && domain != host && (net.ParseIP(host) != nil || !strings.HasSuffix(host, "."+domain)) {
			continue
		}
		if strings.HasPrefix(c.Name, "__Secure-") && (!c.Secure || u.Scheme != "https") {
			continue
		}
		if strings.HasPrefix(c.Name, "__Host-") && (!c.Secure || u.Scheme != "https" || c.Domain != "" || c.Path != "/") {
			continue
		}
		c.Domain = "" // Narrow Domain cookies; do not expand them to sibling origins.
		if c.Path == "" || c.Path[0] != '/' {
			c.Path = defaultCookiePath(u.Path)
		}
		if c.MaxAge > 0 {
			seconds := int64(c.MaxAge)
			if seconds > int64(10*365*86400) {
				seconds = int64(10 * 365 * 86400)
			}
			c.Expires = now.Add(time.Duration(seconds) * time.Second)
		}
		remove := c.MaxAge < 0 || !c.Expires.IsZero() && !c.Expires.After(now)
		c.MaxAge = 0
		c.Raw = ""
		c.RawExpires = ""
		c.Unparsed = nil
		created := now
		filtered := out[:0]
		for _, old := range out {
			if old.Origin == origin && old.Cookie.Name == c.Name && old.Cookie.Path == c.Path {
				created = old.CreatedAt
				continue
			}
			filtered = append(filtered, old)
		}
		out = filtered
		if !remove {
			out = append(out, StoredCookie{origin, c, created})
		}
		accepted++
	}
	if len(out) > 256 {
		return nil, 0, invalid("A session may contain at most 256 cookies.")
	}
	return out, accepted, nil
}
func parseSetCookies(lines []string) ([]*http.Cookie, error) {
	out := make([]*http.Cookie, 0, len(lines))
	if len(lines) > 256 {
		return nil, invalid("Too many cookies.")
	}
	for _, line := range lines {
		c, err := http.ParseSetCookie(line)
		if err != nil {
			return nil, invalid("Invalid Set-Cookie value.")
		}
		if c.Partitioned {
			return nil, invalid("Partitioned browser cookies are not supported.")
		}
		out = append(out, c)
	}
	return out, nil
}
