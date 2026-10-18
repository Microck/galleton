package core

import (
	"encoding/base64"
	"encoding/json"
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

// domainMatch implements RFC 6265 section 5.1.3 for an already lowercased,
// dot-free domain. IP addresses only match themselves.
func domainMatch(host, domain string) bool {
	host = strings.ToLower(host)
	return host == domain || domain != "" && net.ParseIP(host) == nil && strings.HasSuffix(host, "."+domain)
}

func originHost(origin string) string {
	u, err := url.Parse(origin)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// cookieHeaders returns the Cookie header for u. Callers only pass URLs that
// the provider allowlists, so domain-scoped cookies never leave the listed
// origins inside the adapter's cookie_domain.
func cookieHeaders(cookies []StoredCookie, u *url.URL, now time.Time) string {
	_, origin, _ := canonicalURL(u.String())
	host := strings.ToLower(u.Hostname())
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: exactSuffix{}})
	entries := append([]StoredCookie(nil), cookies...)
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].CreatedAt.Before(entries[j].CreatedAt) })
	for _, e := range entries {
		if e.Domain == "" && e.Origin != origin || e.Domain != "" && !domainMatch(host, e.Domain) {
			continue
		}
		if !e.Cookie.Expires.IsZero() && !e.Cookie.Expires.After(now) {
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

// cookieValue returns the value of the named cookie that would be sent to u.
func cookieValue(cookies []StoredCookie, u *url.URL, name string, now time.Time) (string, time.Time, bool) {
	parsed, _ := http.ParseCookie(cookieHeaders(cookies, u, now))
	for _, c := range parsed {
		if c.Name != name {
			continue
		}
		var expires time.Time
		for _, e := range cookies {
			if e.Cookie.Name == name && e.Cookie.Value == c.Value {
				expires = e.Cookie.Expires
				break
			}
		}
		return c.Value, expires, true
	}
	return "", time.Time{}, false
}

func updateCookies(existing []StoredCookie, u *url.URL, incoming []*http.Cookie, now time.Time) ([]StoredCookie, int, int, error) {
	return updateCookiesIn(existing, u, incoming, now, "")
}

// updateCookiesIn applies Set-Cookie values received from u. A Domain
// attribute equal to cookieDomain keeps that scope; any other Domain is
// narrowed to the exact issuing origin.
func updateCookiesIn(existing []StoredCookie, u *url.URL, incoming []*http.Cookie, now time.Time, cookieDomain string) ([]StoredCookie, int, int, error) {
	_, origin, _ := canonicalURL(u.String())
	out := pruneExpired(existing, now)
	accepted := 0
	retained := 0
	host := strings.ToLower(u.Hostname())
	for _, raw := range incoming {
		c := *raw
		if c.Valid() != nil {
			continue
		}
		domain := strings.ToLower(strings.TrimPrefix(c.Domain, "."))
		if domain != "" && domain != host && (net.ParseIP(host) != nil || !strings.HasSuffix(host, "."+domain)) {
			continue
		}
		scope := ""
		if domain != "" && domain == cookieDomain {
			scope = cookieDomain
		}
		var ok, kept bool
		out, ok, kept = placeCookie(out, u, origin, c, scope, now)
		if ok {
			accepted++
		}
		if kept {
			retained++
		}
	}
	if len(out) > 256 {
		return nil, 0, 0, invalid("A session may contain at most 256 cookies.")
	}
	return out, accepted, retained, nil
}

func pruneExpired(existing []StoredCookie, now time.Time) []StoredCookie {
	out := make([]StoredCookie, 0, len(existing))
	for _, e := range existing {
		if e.Cookie.Expires.IsZero() || e.Cookie.Expires.After(now) {
			out = append(out, e)
		}
	}
	return out
}

// placeCookie validates one cookie as set by u and stores it, replacing the
// cookie it supersedes. A scoped (domain) cookie also supersedes host-only
// copies of the same name and path inside its domain, so an imported
// host-only cookie cannot shadow its rotated replacement.
func placeCookie(out []StoredCookie, u *url.URL, origin string, c http.Cookie, scope string, now time.Time) ([]StoredCookie, bool, bool) {
	if c.Partitioned { // No browser partition context exists in a daemon.
		return out, false, false
	}
	if c.Secure && u.Scheme != "https" {
		return out, false, false
	}
	if strings.HasPrefix(c.Name, "__Secure-") && (!c.Secure || u.Scheme != "https") {
		return out, false, false
	}
	if strings.HasPrefix(c.Name, "__Host-") && (!c.Secure || u.Scheme != "https" || c.Domain != "" || scope != "" || c.Path != "/") {
		return out, false, false
	}
	c.Domain = ""
	if c.Valid() != nil {
		return out, false, false
	}
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
	replaced := false
	filtered := out[:0]
	for _, old := range out {
		same := old.Cookie.Name == c.Name && old.Cookie.Path == c.Path
		if scope == "" {
			same = same && old.Domain == "" && old.Origin == origin
		} else {
			same = same && (old.Domain == scope || old.Domain == "" && domainMatch(originHost(old.Origin), scope))
		}
		if same {
			if !replaced {
				created = old.CreatedAt
				replaced = true
			}
			continue
		}
		filtered = append(filtered, old)
	}
	out = filtered
	if remove {
		return out, true, false
	}
	return append(out, StoredCookie{Origin: origin, Cookie: c, CreatedAt: created, Domain: scope}), true, true
}

// withoutProtected drops Set-Cookie values for credential cookies that only a
// successful renewal may set. They are ignored, not rejected: a guest page
// issuing anonymous tokens is not a protocol failure of the real session.
func withoutProtected(cookies []*http.Cookie, protected map[string]bool) []*http.Cookie {
	if len(protected) == 0 {
		return cookies
	}
	out := cookies[:0:0]
	for _, c := range cookies {
		if !protected[c.Name] {
			out = append(out, c)
		}
	}
	return out
}

// importCookies stores structured cookies for the provider's origins. Cookies
// for domains outside every listed origin are skipped, so a whole-browser
// export can be imported without widening the allowlist.
func importCookies(p *Provider, existing []StoredCookie, origin *url.URL, list []ImportCookie, now time.Time) ([]StoredCookie, int, error) {
	out := pruneExpired(existing, now)
	skipped := 0
	type target struct {
		u     *url.URL
		scope string
	}
	for _, ic := range list {
		c := http.Cookie{Name: ic.Name, Value: ic.Value, Path: ic.Path, Secure: ic.Secure, HttpOnly: ic.HTTPOnly}
		if ic.Expires != nil {
			c.Expires = ic.Expires.UTC()
		}
		switch strings.ToLower(ic.SameSite) {
		case "":
		case "lax":
			c.SameSite = http.SameSiteLaxMode
		case "strict":
			c.SameSite = http.SameSiteStrictMode
		case "none":
			c.SameSite = http.SameSiteNoneMode
		default:
			return nil, 0, invalid("Cookie same_site must be lax, strict or none.")
		}
		domain := strings.ToLower(strings.Trim(strings.TrimSpace(ic.Domain), "."))
		var targets []target
		switch {
		case domain == "":
			if origin == nil {
				return nil, 0, invalid("Cookies without a domain need cookie_origin.")
			}
			scope := ""
			if !ic.HostOnly && p.cookieDomain != "" && domainMatch(origin.Hostname(), p.cookieDomain) {
				scope = p.cookieDomain
			}
			targets = append(targets, target{origin, scope})
		case !ic.HostOnly && domain == p.cookieDomain:
			// One scoped cookie; prefer an HTTPS origin as its issuer.
			var best *url.URL
			for _, o := range p.Origins {
				u, _ := url.Parse(o)
				if domainMatch(u.Hostname(), domain) && (best == nil || best.Scheme != "https" && u.Scheme == "https") {
					best = u
				}
			}
			c.Domain = domain
			targets = append(targets, target{best, domain})
		default:
			for _, o := range p.Origins {
				u, _ := url.Parse(o)
				if h := strings.ToLower(u.Hostname()); h == domain || !ic.HostOnly && domainMatch(h, domain) {
					targets = append(targets, target{u, ""})
				}
			}
		}
		if len(targets) == 0 || targets[0].u == nil {
			skipped++
			continue
		}
		for _, t := range targets {
			_, o, _ := canonicalURL(t.u.String())
			var ok bool
			out, ok, _ = placeCookie(out, t.u, o, c, t.scope, now)
			if !ok {
				return nil, 0, invalid("One or more cookies are not valid for the provider origins they target.")
			}
		}
	}
	if len(out) > 256 {
		return nil, 0, invalid("A session may contain at most 256 cookies.")
	}
	return out, skipped, nil
}

// jwtSubject reads the unverified "sub" claim. It is a consistency check that
// the provider issued tokens for the imported account, not authentication.
func jwtSubject(token string) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return "", false
	}
	var claims map[string]json.RawMessage
	if json.Unmarshal(payload, &claims) != nil {
		return "", false
	}
	raw, ok := claims["sub"]
	if !ok {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s, s != ""
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		return n.String(), true
	}
	return "", false
}

// cookieSubject returns the subject shared by every stored cookie with the
// given name. found is false when no such cookie exists.
func cookieSubject(cookies []StoredCookie, name string) (subject string, found, ok bool) {
	for _, c := range cookies {
		if c.Cookie.Name != name {
			continue
		}
		sub, valid := jwtSubject(c.Cookie.Value)
		if !valid || found && sub != subject {
			return "", true, false
		}
		subject, found = sub, true
	}
	return subject, found, found
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

func parseSetCookiesPartial(lines []string) ([]*http.Cookie, bool) {
	if len(lines) > 256 {
		return nil, true
	}
	out := make([]*http.Cookie, 0, len(lines))
	rejected := false
	for _, line := range lines {
		c, err := http.ParseSetCookie(line)
		if err != nil || c.Partitioned {
			rejected = true
			continue
		}
		out = append(out, c)
	}
	return out, rejected
}
