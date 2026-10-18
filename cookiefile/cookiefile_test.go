package cookiefile

import (
	"fmt"
	"strings"
	"testing"
)

// All values below are synthetic.
func parse(t *testing.T, input, format string) ([]Cookie, string) {
	t.Helper()
	cookies, used, err := Parse([]byte(input), format)
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
	if _, _, err := Parse([]byte("example.test\tMAYBE\t/\tTRUE\t0\tx\ty\n"), Netscape); err == nil {
		t.Fatal("invalid flag accepted")
	}
	for _, expiry := range []string{"NaN", "+Inf", "-Inf", "1e400"} {
		line := "example.test\tFALSE\t/\tTRUE\t" + expiry + "\tx\ty\n"
		if _, _, err := Parse([]byte(line), Netscape); err == nil {
			t.Fatalf("expiry %s accepted", expiry)
		}
	}
}

func TestNetscapeLongLinesAreNotTruncated(t *testing.T) {
	// A line longer than any scanner buffer must not end the parse early.
	input := "www.example.test\tFALSE\t/\tTRUE\t0\tfirst\t1\n" +
		"www.example.test\tFALSE\t/\tTRUE\t0\tbig\t" + strings.Repeat("x", 1<<20) + "\n" +
		"www.example.test\tFALSE\t/\tTRUE\t0\tlast\t3\n"
	cookies, _ := parse(t, input, Auto)
	if len(cookies) != 3 || find(t, cookies, "last").Value != "3" {
		t.Fatalf("got %d cookies", len(cookies))
	}
}

func TestCookieCountAndSizeLimits(t *testing.T) {
	var lines, header, array strings.Builder
	array.WriteString("[")
	for i := 0; i <= MaxCookies; i++ {
		fmt.Fprintf(&lines, "www.example.test\tFALSE\t/\tTRUE\t0\tc%d\tv\n", i)
		fmt.Fprintf(&header, "c%d=v; ", i)
		if i > 0 {
			array.WriteString(",")
		}
		fmt.Fprintf(&array, `{"name":"c%d","value":"v"}`, i)
	}
	array.WriteString("]")
	for format, input := range map[string]string{Netscape: lines.String(), Header: header.String(), JSON: array.String(), "wrapper": `{"cookies":` + array.String() + `}`} {
		if format == "wrapper" {
			format = JSON
		}
		if _, _, err := Parse([]byte(input), format); err == nil || !strings.Contains(err.Error(), "more than") {
			t.Fatalf("%s: %v", format, err)
		}
	}
	if _, _, err := Read(strings.NewReader(strings.Repeat(" ", MaxInput+1)), Auto); err == nil {
		t.Fatal("oversized export accepted")
	}
}

func TestHostsNarrowLargeExports(t *testing.T) {
	// A whole-profile export with more unrelated cookies than MaxCookies still
	// imports the provider's cookies; the limit counts only cookies kept.
	var lines, array strings.Builder
	array.WriteString("[")
	for i := 0; i <= MaxCookies; i++ {
		fmt.Fprintf(&lines, ".other%d.test\tTRUE\t/\tTRUE\t0\tc\tv\n", i)
		fmt.Fprintf(&array, `{"name":"c","value":"v","domain":".other%d.test"},`, i)
	}
	lines.WriteString(".www.example.test\tTRUE\t/\tTRUE\t0\tsession\ts1\n")
	lines.WriteString("example.test\tFALSE\t/\tTRUE\t0\thost_only_parent\tx\n")
	lines.WriteString(".example.test\tTRUE\t/\tTRUE\t0\twide\tw1\n")
	array.WriteString(`{"name":"session","value":"s1","domain":".www.example.test"}]`)
	cookies, _, err := Parse([]byte(lines.String()), Netscape, "www.example.test", "API.www.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(cookies) != 2 || find(t, cookies, "session").Value != "s1" || find(t, cookies, "wide").Value != "w1" {
		t.Fatalf("%#v", cookies)
	}
	if cookies, _, err = Parse([]byte(array.String()), JSON, "www.example.test"); err != nil || len(cookies) != 1 {
		t.Fatalf("%v %#v", err, cookies)
	}
	if _, _, err := Parse([]byte(".other.test\tTRUE\t/\tTRUE\t0\tc\tv\n"), Netscape, "www.example.test"); err == nil || !strings.Contains(err.Error(), "www.example.test") {
		t.Fatalf("empty result not reported: %v", err)
	}
	if cookies, _, err = Parse([]byte("a=1; b=2"), Header, "www.example.test"); err != nil || len(cookies) != 2 {
		t.Fatalf("header cookies have no domain and must be kept: %v", err)
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

func TestDevToolsStyleExport(t *testing.T) {
	// DevTools and Playwright exports have no hostOnly: the leading dot
	// decides scope, and expires -1 marks a session cookie.
	devtools := `{"cookies":[{"name":"cdp_domain","value":"v1","domain":".example.test","path":"/","expires":1893456000.25,"httpOnly":false,"secure":true,"session":false,"sameSite":"Lax"},
	{"name":"cdp_host","value":"v2","domain":"www.example.test","path":"/","expires":-1,"httpOnly":true,"secure":true,"session":true}],"origins":[]}`
	cookies, _ := parse(t, devtools, Auto)
	if c := find(t, cookies, "cdp_domain"); c.HostOnly || c.Domain != "example.test" || c.SameSite != "lax" || c.Expires == nil {
		t.Fatalf("%#v", c)
	}
	if c := find(t, cookies, "cdp_host"); !c.HostOnly || c.Expires != nil || !c.HTTPOnly {
		t.Fatalf("%#v", c)
	}
	if _, _, err := Parse([]byte(`[{"name":"x","value":"y","expires":"NaN"}]`), JSON); err == nil {
		t.Fatal("NaN expiry accepted")
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

func TestFormatOverrideAndErrors(t *testing.T) {
	for _, gone := range []string{"yaml", "har", "set-cookie"} {
		if _, err := NormalizeFormat(gone); err == nil {
			t.Fatalf("format %s accepted", gone)
		}
	}
	for _, bad := range []string{"", "[]", `{"nothing":1}`, `[{"value":"x"}]`, `{"cookies":{}}`, `[{"name":"a","value":"b"}`,
		`{"cookies":[{"name":"a","value":"b"}]`, `{"cookies":[{"name":"a","value":"b"}]} []`, `[{"name":"a","value":"b"}] {"x":1}`} {
		if _, _, err := Parse([]byte(bad), Auto); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
