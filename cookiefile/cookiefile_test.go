package cookiefile

import (
	"strings"
	"testing"
	"time"
)

// All values below are synthetic.
var now = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func parse(t *testing.T, input, format string) ([]Cookie, string) {
	t.Helper()
	cookies, used, err := Parse([]byte(input), format, now)
	if err != nil {
		t.Fatalf("%s: %v", format, err)
	}
	return cookies, used
}

func find(t *testing.T, cookies []Cookie, name string) Cookie {
	t.Helper()
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("cookie %s missing from %#v", name, cookies)
	return Cookie{}
}

func TestNetscapeCookiesTxt(t *testing.T) {
	input := "# Netscape HTTP Cookie File\n" +
		"# comment\n\n" +
		".www.example.test\tTRUE\t/\tTRUE\t1893456000\tsession_a\tvalue-a\n" +
		"#HttpOnly_www.example.test\tFALSE\t/api\tFALSE\t0\tsession_b\tvalue b\n"
	cookies, used := parse(t, input, Auto)
	if used != Netscape || len(cookies) != 2 {
		t.Fatalf("%s %#v", used, cookies)
	}
	a := find(t, cookies, "session_a")
	if a.Domain != "www.example.test" || a.HostOnly || a.Path != "/" || !a.Secure || a.HTTPOnly || a.Expires == nil || a.Expires.Unix() != 1893456000 {
		t.Fatalf("%#v", a)
	}
	b := find(t, cookies, "session_b")
	if b.Domain != "www.example.test" || !b.HostOnly || b.Path != "/api" || b.Secure || !b.HTTPOnly || b.Expires != nil || b.Value != "value b" {
		t.Fatalf("%#v", b)
	}
	if _, _, err := Parse([]byte("example.test\tMAYBE\t/\tTRUE\t0\tx\ty\n"), Netscape, now); err == nil {
		t.Fatal("invalid flag accepted")
	}
}

func TestCookieEditorArrayAndWrapper(t *testing.T) {
	array := `[{"domain":".www.example.test","expirationDate":1893456000.5,"hostOnly":false,"httpOnly":true,"name":"session_a","path":"/","sameSite":"no_restriction","secure":true,"session":false,"storeId":"0","value":"value-a"},
	{"domain":"api.example.test","hostOnly":true,"httpOnly":false,"name":"session_b","path":"/","sameSite":"lax","secure":false,"session":true,"value":"value-b"}]`
	cookies, used := parse(t, array, Auto)
	if used != JSON || len(cookies) != 2 {
		t.Fatalf("%s %#v", used, cookies)
	}
	a := find(t, cookies, "session_a")
	if a.Domain != "www.example.test" || a.HostOnly || !a.HTTPOnly || !a.Secure || a.SameSite != "none" || a.Expires == nil || a.Expires.Unix() != 1893456000 {
		t.Fatalf("%#v", a)
	}
	b := find(t, cookies, "session_b")
	if b.Domain != "api.example.test" || !b.HostOnly || b.SameSite != "lax" || b.Expires != nil {
		t.Fatalf("%#v", b)
	}
	wrapper := `{"url":"https://www.example.test/items","cookies":[{"name":"session_c","value":"value-c","path":"/","secure":true,"httpOnly":true,"expirationDate":1893456000}]}`
	cookies, _ = parse(t, wrapper, "cookie-editor")
	c := find(t, cookies, "session_c")
	if c.Domain != "www.example.test" || !c.HostOnly || !c.Secure {
		t.Fatalf("%#v", c)
	}
}

func TestEditThisCookieAndDevToolsExports(t *testing.T) {
	editThisCookie := `[{"domain":"www.example.test","expirationDate":1893456000,"hostOnly":true,"httpOnly":true,"name":"etc","path":"/","sameSite":"strict","secure":true,"session":false,"storeId":"0","value":"v","id":1}]`
	cookies, _ := parse(t, editThisCookie, Auto)
	if c := find(t, cookies, "etc"); !c.HostOnly || c.SameSite != "strict" || !c.HTTPOnly {
		t.Fatalf("%#v", c)
	}
	// Chrome DevTools Protocol Network.getAllCookies: no hostOnly; the leading
	// dot decides scope, and expires -1 marks a session cookie.
	devtools := `{"cookies":[{"name":"cdp_domain","value":"v1","domain":".example.test","path":"/","expires":1893456000.25,"size":10,"httpOnly":false,"secure":true,"session":false,"sameSite":"Lax","priority":"Medium"},
	{"name":"cdp_host","value":"v2","domain":"www.example.test","path":"/","expires":-1,"size":10,"httpOnly":true,"secure":true,"session":true}]}`
	cookies, _ = parse(t, devtools, "devtools")
	if c := find(t, cookies, "cdp_domain"); c.HostOnly || c.Domain != "example.test" || c.SameSite != "lax" || c.Expires == nil {
		t.Fatalf("%#v", c)
	}
	if c := find(t, cookies, "cdp_host"); !c.HostOnly || c.Expires != nil || !c.HTTPOnly {
		t.Fatalf("%#v", c)
	}
}

func TestCookieHeaderForms(t *testing.T) {
	for _, input := range []string{"Cookie: a=1; b=2", "a=1; b=2", "  a=1;b=2\n"} {
		cookies, used := parse(t, input, Auto)
		if used != Header || len(cookies) != 2 || cookies[0].Domain != "" || cookies[0].HostOnly {
			t.Fatalf("%q: %s %#v", input, used, cookies)
		}
	}
}

func TestSetCookieLines(t *testing.T) {
	input := "Set-Cookie: session_a=value-a; Domain=.www.example.test; Path=/; Max-Age=3600; Secure; HttpOnly; SameSite=Lax\n" +
		"session_b=value-b; Path=/api; Expires=Wed, 01 Jan 2031 00:00:00 GMT\n"
	cookies, used := parse(t, input, Auto)
	if used != SetCookie || len(cookies) != 2 {
		t.Fatalf("%s %#v", used, cookies)
	}
	a := find(t, cookies, "session_a")
	if a.Domain != "www.example.test" || a.HostOnly || !a.Secure || !a.HTTPOnly || a.SameSite != "lax" || !a.Expires.Equal(now.Add(time.Hour)) {
		t.Fatalf("%#v", a)
	}
	b := find(t, cookies, "session_b")
	if b.Domain != "" || !b.HostOnly || b.Path != "/api" || b.Expires.Year() != 2031 {
		t.Fatalf("%#v", b)
	}
	if one, used := parse(t, "only=1; Path=/", Auto); used != SetCookie || len(one) != 1 {
		t.Fatalf("single Set-Cookie line detected as %s", used)
	}
}

func TestHARReplaysRequestAndResponseCookies(t *testing.T) {
	har := `{"log":{"version":"1.2","entries":[
	{"startedDateTime":"2026-01-01T00:00:01Z","request":{"url":"https://www.example.test/items","headers":[],"cookies":[{"name":"session_a","value":"old"},{"name":"other","value":"x"}]},
	 "response":{"headers":[{"name":"Set-Cookie","value":"session_a=new; Domain=.www.example.test; Path=/; Secure; HttpOnly"}],"cookies":[]}},
	{"startedDateTime":"2026-01-01T00:00:00Z","request":{"url":"https://api.example.test/v1","headers":[{"name":"Cookie","value":"api_cookie=1"}]},
	 "response":{"headers":[],"cookies":[{"name":"from_cookies_array","value":"2","domain":".example.test","path":"/","httpOnly":true,"secure":true,"expires":"2031-01-01T00:00:00.000Z"}]}},
	{"startedDateTime":"2026-01-01T00:00:02Z","request":{"url":"data:text/plain,ignored","cookies":[{"name":"ignored","value":"1"}]},"response":{}}
	]}}`
	cookies, used := parse(t, har, Auto)
	if used != HAR {
		t.Fatal(used)
	}
	names := map[string]bool{}
	for _, c := range cookies {
		names[c.Name] = true
	}
	if names["ignored"] || !names["other"] || !names["api_cookie"] {
		t.Fatalf("%#v", cookies)
	}
	// The response replaced the cookie the request carried, and set its scope.
	if c := find(t, cookies, "session_a"); c.HostOnly || c.Value != "new" || !c.HTTPOnly || c.Domain != "www.example.test" {
		t.Fatalf("%#v", c)
	}
	if c := find(t, cookies, "from_cookies_array"); c.Domain != "example.test" || c.HostOnly || c.Expires == nil || c.Expires.Year() != 2031 {
		t.Fatalf("%#v", c)
	}
	if _, _, err := Parse([]byte(har), JSON, now); err == nil || !strings.Contains(err.Error(), "HAR") {
		t.Fatalf("HAR parsed as cookie JSON: %v", err)
	}
}

func TestFormatOverrideAndErrors(t *testing.T) {
	if _, err := NormalizeFormat("yaml"); err == nil {
		t.Fatal("unknown format accepted")
	}
	// A Set-Cookie looking line forced to header format is read as a header.
	cookies, used := parse(t, "a=1; Path=/", Header)
	if used != Header || len(cookies) != 2 {
		t.Fatalf("%s %#v", used, cookies)
	}
	for _, bad := range []string{"", "[]", `{"nothing":1}`, `[{"value":"x"}]`} {
		if _, _, err := Parse([]byte(bad), Auto, now); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
