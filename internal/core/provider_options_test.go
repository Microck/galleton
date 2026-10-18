package core

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Every credential in this file is synthetic.

func fakeJWT(sub string) string {
	enc := base64.RawURLEncoding
	payload, _ := json.Marshal(map[string]any{"sub": sub, "exp": time.Now().Add(time.Hour).Unix()})
	return enc.EncodeToString([]byte(`{"alg":"none"}`)) + "." + enc.EncodeToString(payload) + ".c2ln"
}

func cookieProvider(raw string) Provider {
	p := providerFor(raw)
	p.Kind = "http"
	p.RefreshURL = raw + "/refresh"
	p.RefreshMethod = "POST"
	p.Response = ResponseMapping{RequireSetCookie: true}
	return p
}

// routeTo sends every upstream connection of a provider to server, so tests
// can exercise real host names over TLS without DNS.
func routeTo(t *testing.T, m *Manager, name string, server *httptest.Server) {
	t.Helper()
	addr := server.Listener.Addr().String()
	client := func(keepAlive bool) *http.Client {
		transport := &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // Test server only.
			DisableKeepAlives: !keepAlive,
		}
		return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	p := m.providers[name]
	p.renewal = client(false)
	p.resource = client(p.KeepAlive)
}

func TestEmptyJSONBodyIsExactlyEmptyObject(t *testing.T) {
	var body atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body.Store(r.Header.Get("Content-Type") + " " + string(raw))
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "next", Path: "/"})
		fmt.Fprint(w, `{"access_token":"a1"}`)
	}))
	defer server.Close()
	p := cookieProvider(server.URL)
	p.BodyFormat = "json"
	p.Response.AccessToken = "/access_token"
	m, _, _ := managerFor(t, p)
	if _, err := m.Import("alice", Import{Provider: "test", CookieOrigin: server.URL, CookieHeader: "sid=seed"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Refresh("alice"); err != nil {
		t.Fatal(err)
	}
	if got := body.Load(); got != "application/json {}" {
		t.Fatalf("renewal body = %q", got)
	}
}

func TestJSONAndSetCookieAreBothRequiredRenewalProof(t *testing.T) {
	for _, tc := range []struct {
		name          string
		json, cookie  bool
		wantErrorCode string
	}{{"both", true, true, ""}, {"json only", true, false, "protocol_error"}, {"cookie only", false, true, "protocol_error"}} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.cookie {
					http.SetCookie(w, &http.Cookie{Name: "refresh_token_web", Value: "r1", Path: "/"})
				}
				if tc.json {
					fmt.Fprint(w, `{"access_token":"a1","refresh_token":"r1","expires_in":3600}`)
				} else {
					fmt.Fprint(w, `{}`)
				}
			}))
			defer server.Close()
			p := cookieProvider(server.URL)
			p.BodyFormat = "json"
			p.Response = ResponseMapping{AccessToken: "/access_token", RefreshToken: "/refresh_token", ExpiresIn: "/expires_in", RequireSetCookie: true}
			m, _, _ := managerFor(t, p)
			if _, err := m.Import("alice", Import{Provider: "test", CookieOrigin: server.URL, CookieHeader: "refresh_token_web=r0"}); err != nil {
				t.Fatal(err)
			}
			_, err := m.Refresh("alice")
			if tc.wantErrorCode == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			wantCode(t, err, tc.wantErrorCode)
		})
	}
}

func TestBlockSignatureIsTemporaryRefusalNotReauth(t *testing.T) {
	var mode atomic.Value
	mode.Store("challenge")
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch mode.Load() {
		case "challenge":
			// A challenge page may try to set credential cookies; they must not stick.
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "guest", Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "bot", Value: "marker", Path: "/"})
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(403)
			fmt.Fprint(w, `<html><script src="https://ct.captcha-delivery.com/c.js"></script></html>`)
		case "html403":
			w.WriteHeader(403)
			fmt.Fprint(w, `<html>Access denied</html>`)
		case "json403":
			w.WriteHeader(403)
			fmt.Fprint(w, `{"code":"invalid_authentication_token"}`)
		case "401":
			w.WriteHeader(401)
			fmt.Fprint(w, `<html>captcha-delivery.com</html>`)
		}
	}))
	defer server.Close()
	p := cookieProvider(server.URL)
	p.ProtectedCookies = []string{"sid"}
	p.BlockSignatures = []BlockSignature{{Status: []int{403}, BodyContains: "captcha-delivery.com"}, {Status: []int{403}, NotJSON: true}}
	m, v, _ := managerFor(t, p)
	importSeed := func() {
		t.Helper()
		_ = m.Forget("alice")
		if _, err := m.Import("alice", Import{Provider: "test", CookieOrigin: server.URL, CookieHeader: "sid=seed"}); err != nil {
			t.Fatal(err)
		}
	}
	importSeed()
	started := time.Now()
	_, err := m.Refresh("alice")
	wantCode(t, err, "upstream_blocked")
	if p := AsProblem(err); p.RetryAt.Before(started.Add(119 * time.Second)) {
		t.Fatalf("Retry-After not honoured: %v", p.RetryAt)
	}
	meta, _ := m.Status("alice")
	if meta.Status != "retry_wait" {
		t.Fatalf("status %s", meta.Status)
	}
	states, _ := v.LoadAll()
	values := map[string]string{}
	for _, c := range states[0].Cookies {
		values[c.Cookie.Name] = c.Cookie.Value
	}
	if values["sid"] != "seed" || values["bot"] != "marker" {
		t.Fatalf("cookies after block: %v", values)
	}
	// Still-usable credentials are served while renewal waits.
	if h, err := m.Headers("alice", server.URL+"/me"); err != nil || !strings.Contains(h.Headers["Cookie"], "sid=seed") {
		t.Fatalf("%v %#v", err, h)
	}
	if calls.Load() != 1 {
		t.Fatal("blocked renewal was retried before its deadline")
	}
	mode.Store("html403")
	importSeed()
	_, err = m.Refresh("alice")
	wantCode(t, err, "upstream_blocked")
	mode.Store("json403")
	importSeed()
	_, err = m.Refresh("alice")
	wantCode(t, err, "reauth_required")
	mode.Store("401")
	importSeed()
	_, err = m.Refresh("alice")
	wantCode(t, err, "reauth_required")
}

func TestBlockSignatureDoesNotHideInvalidGrant(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"error":"invalid_grant","hint":"captcha-delivery.com"}`)
	}))
	defer server.Close()
	p := providerFor(server.URL)
	p.BlockSignatures = []BlockSignature{{Status: []int{400}, BodyContains: "captcha-delivery.com"}}
	m, _, _ := managerFor(t, p)
	importOAuth(t, m)
	_, err := m.Refresh("alice")
	wantCode(t, err, "reauth_required")
}

func TestBlockSignatureTurnsChallenge5xxIntoBackoff(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cf-Mitigated", "challenge")
		w.WriteHeader(503)
		fmt.Fprint(w, `<html>Just a moment</html>`)
	}))
	defer server.Close()
	p := providerFor(server.URL)
	p.BlockSignatures = []BlockSignature{{Status: []int{403, 503}, Header: "Cf-Mitigated", HeaderContains: "challenge"}}
	m, _, _ := managerFor(t, p)
	importOAuth(t, m)
	_, err := m.Refresh("alice")
	wantCode(t, err, "upstream_blocked")
	if meta, _ := m.Status("alice"); meta.Status != "retry_wait" {
		t.Fatalf("challenge 503 became %s instead of a retry", meta.Status)
	}
}

func TestBlockSignatureValidation(t *testing.T) {
	for _, sigs := range [][]BlockSignature{
		{{Status: []int{403}}},
		{{Status: []int{401}, NotJSON: true}},
		{{Status: []int{200}, NotJSON: true}},
		{{Status: nil, NotJSON: true}},
		{{Status: []int{403}, HeaderContains: "x"}},
	} {
		p := providerFor("http://127.0.0.1:11111")
		p.BlockSignatures = sigs
		if _, err := compileProviders(Config{Providers: []Provider{p}}); err == nil {
			t.Fatalf("accepted %#v", sigs)
		}
	}
}

func TestHTTPProxyCarriesRenewalsAndRequests(t *testing.T) {
	var direct atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		direct.Add(1)
		jsonOK(w, "a1", "r1")
	}))
	defer upstream.Close()
	var proxied atomic.Int32
	var proxyAuth atomic.Value
	proxyAuth.Store("")
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied.Add(1)
		proxyAuth.Store(r.Header.Get("Proxy-Authorization"))
		r.RequestURI = ""
		r.Header.Del("Proxy-Authorization")
		resp, err := http.DefaultTransport.RoundTrip(r)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		defer resp.Body.Close()
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	defer proxy.Close()
	proxyURL, _ := url.Parse(proxy.URL)
	proxyURL.User = url.UserPassword("egress-user", "egress-pass")
	t.Setenv("GALLETON_TEST_PROXY", proxyURL.String())
	p := providerFor(upstream.URL)
	p.ProxyEnv = "GALLETON_TEST_PROXY"
	m, _, dir := managerFor(t, p)
	importOAuth(t, m)
	if _, err := m.Request("alice", RequestInput{URL: upstream.URL + "/me"}); err != nil {
		t.Fatal(err)
	}
	if proxied.Load() != 2 || direct.Load() != 2 {
		t.Fatalf("proxied=%d upstream=%d", proxied.Load(), direct.Load())
	}
	if !strings.HasPrefix(proxyAuth.Load().(string), "Basic ") {
		t.Fatal("proxy credentials from proxy_env were not used")
	}
	// The provider listing reports egress without exposing the proxy URL.
	token, _ := ReadAPIToken(dir)
	api := httptest.NewServer(Handler(m, token))
	defer api.Close()
	req, _ := http.NewRequest("GET", api.URL+"/v1/providers", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(raw), `"proxied":true`) || strings.Contains(string(raw), "egress-pass") || strings.Contains(string(raw), proxyURL.Host) {
		t.Fatalf("provider listing: %s", raw)
	}
}

func TestUnreachableProxyFailsClosed(t *testing.T) {
	var direct atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		direct.Add(1)
		jsonOK(w, "a1", "r1")
	}))
	defer upstream.Close()
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := dead.Addr().String()
	dead.Close()
	for _, scheme := range []string{"http", "socks5h"} {
		t.Run(scheme, func(t *testing.T) {
			p := providerFor(upstream.URL)
			p.Proxy = scheme + "://" + deadAddr
			m, _, _ := managerFor(t, p)
			importOAuth(t, m)
			_, err := m.Refresh("alice")
			wantCode(t, err, "retry_later")
			if meta, _ := m.Status("alice"); meta.Status != "retry_wait" {
				t.Fatalf("status %s", meta.Status)
			}
			if direct.Load() != 0 {
				t.Fatal("request fell back to a direct connection")
			}
			if strings.Contains(err.Error(), deadAddr) {
				t.Fatal("error exposes proxy address")
			}
		})
	}
}

// socks5Server is a minimal RFC 1928 server (no auth, CONNECT only) that
// records the requested destination host.
func socks5Server(t *testing.T) (string, *atomic.Value) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	var target atomic.Value
	target.Store("")
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				r := bufio.NewReader(conn)
				head := make([]byte, 2)
				if _, err := io.ReadFull(r, head); err != nil {
					return
				}
				methods := make([]byte, head[1])
				io.ReadFull(r, methods)
				conn.Write([]byte{5, 0})
				req := make([]byte, 4)
				if _, err := io.ReadFull(r, req); err != nil {
					return
				}
				var host string
				switch req[3] {
				case 1:
					ip := make([]byte, 4)
					io.ReadFull(r, ip)
					host = net.IP(ip).String()
				case 3:
					n, _ := r.ReadByte()
					name := make([]byte, n)
					io.ReadFull(r, name)
					host = string(name)
				default:
					return
				}
				portBytes := make([]byte, 2)
				io.ReadFull(r, portBytes)
				port := binary.BigEndian.Uint16(portBytes)
				address := net.JoinHostPort(host, strconv.Itoa(int(port)))
				target.Store(address)
				up, err := net.Dial("tcp", address)
				if err != nil {
					conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				go io.Copy(up, r)
				io.Copy(conn, up)
			}(conn)
		}
	}()
	return listener.Addr().String(), &target
}

func TestSOCKS5HProxyCarriesRenewal(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { jsonOK(w, "a1", "r1") }))
	defer upstream.Close()
	addr, target := socks5Server(t)
	p := providerFor(upstream.URL)
	p.Proxy = "socks5h://" + addr
	m, _, _ := managerFor(t, p)
	importOAuth(t, m)
	if _, err := m.Refresh("alice"); err != nil {
		t.Fatal(err)
	}
	if target.Load() != upstream.Listener.Addr().String() {
		t.Fatalf("SOCKS target %q", target.Load())
	}
}

func TestProxyConfigurationValidation(t *testing.T) {
	base := providerFor("http://127.0.0.1:11111")
	for _, tc := range []struct{ proxy, env string }{
		{"http://user:secret@127.0.0.1:3128", ""},
		{"ftp://127.0.0.1:21", ""},
		{"socks5h://127.0.0.1", ""},
		{"http://127.0.0.1:3128/path", ""},
		{"", "GALLETON_TEST_PROXY_UNSET"},
	} {
		p := base
		p.Proxy, p.ProxyEnv = tc.proxy, tc.env
		_, err := compileProviders(Config{Providers: []Provider{p}})
		if err == nil {
			t.Fatalf("accepted %#v", tc)
		}
		if strings.Contains(err.Error(), "secret") {
			t.Fatal("configuration error echoes proxy credentials")
		}
	}
	os.Unsetenv("GALLETON_TEST_PROXY_UNSET")
	p := base
	p.Proxy = "socks5://127.0.0.1:1080"
	if _, err := compileProviders(Config{Providers: []Provider{p}}); err != nil {
		t.Fatal(err)
	}
}

func TestOperationalFieldsDoNotInvalidateSessions(t *testing.T) {
	base := providerFor("http://127.0.0.1:11111")
	compiled, err := compileProviders(Config{Providers: []Provider{base}})
	if err != nil {
		t.Fatal(err)
	}
	original := compiled["test"].hash
	operational := base
	operational.Proxy = "socks5h://127.0.0.1:1080"
	operational.KeepAlive = true
	operational.MinIntervalMS = 500
	operational.MaxRequestBodyBytes = 8 << 20
	operational.MaxResponseBodyBytes = 8 << 20
	operational.BlockSignatures = []BlockSignature{{Status: []int{403}, NotJSON: true}}
	compiled, err = compileProviders(Config{Providers: []Provider{operational}})
	if err != nil {
		t.Fatal(err)
	}
	if compiled["test"].hash != original {
		t.Fatal("egress or pacing change invalidates stored sessions")
	}
	scope := base
	scope.Kind = "http"
	scope.Origins = []string{"https://www.example.test"}
	scope.RefreshURL = "https://www.example.test/refresh"
	scope.Response.RequireSetCookie = true
	first, _ := compileProviders(Config{Providers: []Provider{scope}})
	scope.CookieDomain = ".www.example.test"
	second, err := compileProviders(Config{Providers: []Provider{scope}})
	if err != nil {
		t.Fatal(err)
	}
	if first["test"].hash == second["test"].hash {
		t.Fatal("cookie scope change must invalidate stored sessions")
	}
}

func TestCookieDomainScopesWithinListedOrigins(t *testing.T) {
	now := time.Now().UTC()
	www, _ := url.Parse("https://www.example.test/web/api/auth/refresh")
	api, _ := url.Parse("https://api.www.example.test/searches")
	parent, _ := url.Parse("https://example.test/")
	cookies := []*http.Cookie{
		{Name: "session", Value: "s1", Domain: ".www.example.test", Path: "/", Secure: true},
		{Name: "wide", Value: "w1", Domain: ".example.test", Path: "/", Secure: true},
	}
	saved, accepted, retained, err := updateCookiesIn(nil, www, cookies, now, "www.example.test")
	if err != nil || accepted != 2 || retained != 2 {
		t.Fatalf("%v %d %d", err, accepted, retained)
	}
	if got := cookieHeaders(saved, api, now); got != "session=s1" {
		t.Fatalf("api origin got %q", got)
	}
	if got := cookieHeaders(saved, www, now); !strings.Contains(got, "session=s1") || !strings.Contains(got, "wide=w1") {
		t.Fatalf("www origin got %q", got)
	}
	if got := cookieHeaders(saved, parent, now); got != "" {
		t.Fatalf("cookie escaped the declared domain: %q", got)
	}
	// Without a declared domain, parent-domain cookies stay narrowed.
	narrow, _, _, _ := updateCookies(nil, www, cookies, now)
	if got := cookieHeaders(narrow, api, now); got != "" {
		t.Fatalf("undeclared domain widened: %q", got)
	}
	// A rotated domain cookie replaces imported host-only copies.
	hostOnly := []StoredCookie{{Origin: "https://www.example.test", Cookie: http.Cookie{Name: "session", Value: "old", Path: "/", Secure: true}, CreatedAt: now}}
	rotated, _, _, _ := updateCookiesIn(hostOnly, www, cookies[:1], now, "www.example.test")
	if len(rotated) != 1 || rotated[0].Cookie.Value != "s1" || rotated[0].Domain != "www.example.test" {
		t.Fatalf("%#v", rotated)
	}
}

func TestCookieDomainConfigValidation(t *testing.T) {
	base := cookieProvider("https://www.example.test")
	base.AllowHTTPLoopback = false
	for _, domain := range []string{"com", ".other.test", "www.example.test.", "127.0.0.1", "exa mple.test", "a..test"} {
		p := base
		p.CookieDomain = domain
		if _, err := compileProviders(Config{Providers: []Provider{p}}); err == nil {
			t.Fatalf("accepted cookie_domain %q", domain)
		}
	}
	p := base
	p.CookieDomain = ".www.example.test"
	if _, err := compileProviders(Config{Providers: []Provider{p}}); err != nil {
		t.Fatal(err)
	}
	p.JWTSubjectCookie = "access"
	if _, err := compileProviders(Config{Providers: []Provider{p}}); err == nil {
		t.Fatal("jwt_subject_cookie outside protected_cookies accepted")
	}
}

func TestProtectedCookiesOnlyRenewalMaySet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/refresh":
			http.SetCookie(w, &http.Cookie{Name: "access", Value: "renewed", Path: "/"})
			fmt.Fprint(w, `{}`)
		default:
			// An HTML page that does not recognize the session issues guest tokens.
			http.SetCookie(w, &http.Cookie{Name: "access", Value: "guest", Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "theme", Value: "dark", Path: "/"})
			fmt.Fprint(w, `<html></html>`)
		}
	}))
	defer server.Close()
	p := cookieProvider(server.URL)
	p.ProtectedCookies = []string{"access"}
	m, _, _ := managerFor(t, p)
	if _, err := m.Import("alice", Import{Provider: "test", CookieOrigin: server.URL, CookieHeader: "access=imported"}); err != nil {
		t.Fatal(err)
	}
	e, _ := m.get("alice")
	e.state.NextRefresh = time.Now().Add(time.Hour)
	if _, err := m.Request("alice", RequestInput{URL: server.URL + "/catalog"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Capture("alice", server.URL+"/catalog", []string{"access=guest2; Path=/"}); err != nil {
		t.Fatal(err)
	}
	h, err := m.Headers("alice", server.URL+"/me")
	if err != nil || !strings.Contains(h.Headers["Cookie"], "access=imported") || !strings.Contains(h.Headers["Cookie"], "theme=dark") {
		t.Fatalf("%v %#v", err, h)
	}
	if meta, _ := m.Status("alice"); meta.Status != "ready" {
		t.Fatalf("ignoring a protected cookie must not pause the session: %s", meta.Status)
	}
	if _, err := m.Refresh("alice"); err != nil {
		t.Fatal(err)
	}
	if h, _ := m.Headers("alice", server.URL+"/me"); !strings.Contains(h.Headers["Cookie"], "access=renewed") {
		t.Fatalf("renewal could not set protected cookie: %#v", h)
	}
}

func TestJWTSubjectMustMatchImportedAccount(t *testing.T) {
	var sub atomic.Value
	sub.Store("1001")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "access", Value: fakeJWT(sub.Load().(string)), Path: "/"})
		fmt.Fprint(w, `{}`)
	}))
	defer server.Close()
	p := cookieProvider(server.URL)
	p.ProtectedCookies = []string{"access"}
	p.JWTSubjectCookie = "access"
	m, v, _ := managerFor(t, p)
	_, err := m.Import("alice", Import{Provider: "test", CookieOrigin: server.URL, CookieHeader: "access=not-a-jwt"})
	wantCode(t, err, "invalid_request")
	imported := fakeJWT("1001")
	if _, err := m.Import("alice", Import{Provider: "test", CookieOrigin: server.URL, CookieHeader: "access=" + imported}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Refresh("alice"); err != nil {
		t.Fatal(err)
	}
	sub.Store("guest-42")
	_, err = m.Refresh("alice")
	wantCode(t, err, "reauth_required")
	states, _ := v.LoadAll()
	for _, c := range states[0].Cookies {
		if s, _ := jwtSubject(c.Cookie.Value); c.Cookie.Name == "access" && s != "1001" {
			t.Fatal("foreign-subject token replaced the imported one")
		}
	}
	metadata, _ := json.Marshal(states[0].metadata())
	if strings.Contains(string(metadata), "1001") {
		t.Fatal("subject leaked into metadata")
	}
}

func TestAuthorizationStyles(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()
	for _, tc := range []struct{ style, cookie, want string }{
		{"", "", "Bearer a0"},
		{"bearer", "", "Bearer a0"},
		{"none", "", ""},
		{"cookie_bearer", "access", "Bearer from-cookie"},
	} {
		p := cookieProvider(server.URL)
		p.Authorization, p.AuthorizationCookie = tc.style, tc.cookie
		m, _, _ := managerFor(t, p)
		if _, err := m.Import("alice", Import{Provider: "test", AccessToken: "a0", CookieOrigin: server.URL, CookieHeader: "access=from-cookie"}); err != nil {
			t.Fatal(err)
		}
		e, _ := m.get("alice")
		e.state.NextRefresh = time.Now().Add(time.Hour)
		h, err := m.Headers("alice", server.URL+"/me")
		if err != nil || h.Headers["Authorization"] != tc.want {
			t.Fatalf("%s: %v %#v", tc.style, err, h)
		}
	}
	bad := providerFor(server.URL)
	bad.Authorization = "none"
	if _, err := compileProviders(Config{Providers: []Provider{bad}}); err == nil {
		t.Fatal("oauth2 accepted a non-bearer authorization style")
	}
	bad = cookieProvider(server.URL)
	bad.Authorization = "cookie_bearer"
	if _, err := compileProviders(Config{Providers: []Provider{bad}}); err == nil {
		t.Fatal("cookie_bearer without authorization_cookie accepted")
	}
}

func TestPerAdapterManagedSizeLimits(t *testing.T) {
	big := strings.Repeat("x", 5<<20)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		if r.URL.Path == "/big" {
			fmt.Fprint(w, big)
			return
		}
		fmt.Fprint(w, n)
	}))
	defer server.Close()
	p := providerFor(server.URL)
	m, _, dir := managerFor(t, p)
	importOAuth(t, m)
	e, _ := m.get("alice")
	e.state.AccessToken, e.state.NextRefresh = "a0", time.Now().Add(time.Hour)
	body := base64.StdEncoding.EncodeToString(make([]byte, 2<<20))
	_, err := m.Request("alice", RequestInput{URL: server.URL + "/upload", Method: "POST", BodyBase64: body})
	wantCode(t, err, "body_too_large")
	_, err = m.Request("alice", RequestInput{URL: server.URL + "/big"})
	wantCode(t, err, "response_too_large")

	p.MaxRequestBodyBytes, p.MaxResponseBodyBytes = 3<<20, 6<<20
	m2, _, dir2 := managerFor(t, p)
	_ = dir
	importOAuth(t, m2)
	e, _ = m2.get("alice")
	e.state.AccessToken, e.state.NextRefresh = "a0", time.Now().Add(time.Hour)
	// The API envelope grows with the adapter limit.
	token, _ := ReadAPIToken(dir2)
	api := httptest.NewServer(Handler(m2, token))
	defer api.Close()
	payload, _ := json.Marshal(RequestInput{URL: server.URL + "/upload", Method: "POST", BodyBase64: body})
	req, _ := http.NewRequest("POST", api.URL+"/v1/sessions/alice/request", strings.NewReader(string(payload)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var result RequestResult
	_ = json.NewDecoder(resp.Body).Decode(&result)
	resp.Body.Close()
	raw, _ := base64.StdEncoding.DecodeString(result.BodyBase64)
	if resp.StatusCode != 200 || string(raw) != fmt.Sprint(2<<20) {
		t.Fatalf("status %d body %q", resp.StatusCode, raw)
	}
	if r, err := m2.Request("alice", RequestInput{URL: server.URL + "/big"}); err != nil || r.Status != 200 {
		t.Fatalf("%v", err)
	}
	for _, limit := range []int64{-1, 64<<20 + 1} {
		bad := providerFor(server.URL)
		bad.MaxRequestBodyBytes = limit
		if _, err := compileProviders(Config{Providers: []Provider{bad}}); err == nil {
			t.Fatalf("accepted request limit %d", limit)
		}
	}
}

func TestMinIntervalPacesRenewalsAndRequests(t *testing.T) {
	var mu sync.Mutex
	var times []time.Time
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		times = append(times, time.Now())
		mu.Unlock()
		jsonOK(w, "a1", "r1")
	}))
	defer server.Close()
	p := providerFor(server.URL)
	p.MinIntervalMS = 400
	m, _, _ := managerFor(t, p)
	importOAuth(t, m)
	if _, err := m.Request("alice", RequestInput{URL: server.URL + "/one"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Request("alice", RequestInput{URL: server.URL + "/two"}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(times) != 3 {
		t.Fatalf("%d upstream calls", len(times))
	}
	for i := 1; i < len(times); i++ {
		// Dispatch-to-arrival latency varies a little per connection.
		if gap := times[i].Sub(times[i-1]); gap < 300*time.Millisecond {
			t.Fatalf("calls %d and %d only %v apart", i-1, i, gap)
		}
	}
}

func TestPauseHoldsRenewalsAndManagedRequests(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		jsonOK(w, "a1", "r1")
	}))
	defer server.Close()
	m, _, dir := managerFor(t, providerFor(server.URL))
	if _, err := m.Import("alice", Import{Provider: "test", AccessToken: "a0", RefreshToken: "r0"}); err != nil {
		t.Fatal(err)
	}
	token, _ := ReadAPIToken(dir)
	api := httptest.NewServer(Handler(m, token))
	defer api.Close()
	call := func(method, path, body string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, api.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(raw)
	}
	if status, _ := call("POST", "/v1/providers/test/pause", `{"seconds":0}`); status != 400 {
		t.Fatalf("invalid pause accepted: %d", status)
	}
	if status, _ := call("POST", "/v1/providers/missing/pause", `{"seconds":60}`); status != 404 {
		t.Fatalf("unknown provider: %d", status)
	}
	status, body := call("POST", "/v1/providers/test/pause", `{"seconds":600}`)
	if status != 200 || !strings.Contains(body, `"paused_until"`) {
		t.Fatalf("%d %s", status, body)
	}
	// A shorter pause does not shorten the current one.
	short, _ := m.Pause("test", 5)
	if time.Until(short.PausedUntil) < 590*time.Second {
		t.Fatal("pause was shortened")
	}
	_, err := m.Request("alice", RequestInput{URL: server.URL + "/me"})
	wantCode(t, err, "provider_paused")
	if AsProblem(err).RetryAt.IsZero() {
		t.Fatal("paused response lacks retry_at")
	}
	_, err = m.Refresh("alice")
	wantCode(t, err, "provider_paused")
	// Renewal is due, but the current access token is served instead.
	h, err := m.Headers("alice", server.URL+"/me")
	if err != nil || h.Headers["Authorization"] != "Bearer a0" {
		t.Fatalf("%v %#v", err, h)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.RunScheduler(ctx); close(done) }()
	time.Sleep(600 * time.Millisecond)
	cancel()
	<-done
	if calls.Load() != 0 {
		t.Fatalf("%d upstream calls during pause", calls.Load())
	}
	if _, body := call("GET", "/v1/providers", ""); !strings.Contains(body, `"paused_until"`) {
		t.Fatalf("listing hides pause: %s", body)
	}
	if status, body := call("DELETE", "/v1/providers/test/pause", ""); status != 200 || strings.Contains(body, "paused_until") {
		t.Fatalf("%d %s", status, body)
	}
	if _, err := m.Request("alice", RequestInput{URL: server.URL + "/me"}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("%d upstream calls after resume", calls.Load())
	}
}

func TestKeepAlivePoolsManagedRequestsButNotRenewals(t *testing.T) {
	for _, keepAlive := range []bool{false, true} {
		var conns atomic.Int32
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { jsonOK(w, "a1", "r1") }))
		server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
			if state == http.StateNew {
				conns.Add(1)
			}
		}
		server.Start()
		p := providerFor(server.URL)
		p.KeepAlive = keepAlive
		m, _, _ := managerFor(t, p)
		importOAuth(t, m)
		if _, err := m.Refresh("alice"); err != nil {
			t.Fatal(err)
		}
		for range 3 {
			if _, err := m.Request("alice", RequestInput{URL: server.URL + "/me"}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := m.Refresh("alice"); err != nil {
			t.Fatal(err)
		}
		// Two renewals always open fresh connections; three requests share one with keep_alive.
		want := int32(5)
		if keepAlive {
			want = 3
		}
		if conns.Load() != want {
			t.Fatalf("keep_alive=%v: %d connections, want %d", keepAlive, conns.Load(), want)
		}
		server.Close()
	}
}

func TestStructuredAndTextCookieImports(t *testing.T) {
	p := cookieProvider("https://www.example.test")
	p.Origins = []string{"https://www.example.test", "https://api.www.example.test"}
	p.AllowHTTPLoopback = false
	p.CookieDomain = ".www.example.test"
	m, _, _ := managerFor(t, p)
	text := "# Netscape HTTP Cookie File\n" +
		".www.example.test\tTRUE\t/\tTRUE\t0\tsession\ts1\n" +
		"#HttpOnly_.example.test\tTRUE\t/\tTRUE\t0\twide\tw1\n" +
		".unrelated.test\tTRUE\t/\tTRUE\t0\tforeign\tf1\n"
	meta, err := m.Import("alice", Import{Provider: "test", CookieText: text})
	if err != nil {
		t.Fatal(err)
	}
	// session: one scoped cookie; wide: narrowed copies on both origins; foreign: skipped.
	if meta.CookieCount != 3 {
		t.Fatalf("cookie_count %d", meta.CookieCount)
	}
	e, _ := m.get("alice")
	api, _ := url.Parse("https://api.www.example.test/x")
	if got := cookieHeaders(e.state.Cookies, api, time.Now()); !strings.Contains(got, "session=s1") || !strings.Contains(got, "wide=w1") || strings.Contains(got, "foreign") {
		t.Fatalf("api got %q", got)
	}
	_, err = m.Import("bob", Import{Provider: "test", CookieText: ".unrelated.test\tTRUE\t/\tTRUE\t0\tforeign\tf1\n"})
	wantCode(t, err, "invalid_request")
	if !strings.Contains(err.Error(), "belong") {
		t.Fatal(err)
	}
	// A bare Cookie header on an origin inside cookie_domain is scoped to it.
	if _, err := m.Import("carol", Import{Provider: "test", CookieOrigin: "https://www.example.test", CookieHeader: "session=s2"}); err != nil {
		t.Fatal(err)
	}
	e, _ = m.get("carol")
	if got := cookieHeaders(e.state.Cookies, api, time.Now()); got != "session=s2" {
		t.Fatalf("bare header not scoped: %q", got)
	}
	// Structured cookies without a domain need cookie_origin.
	_, err = m.Import("dave", Import{Provider: "test", Cookies: []ImportCookie{{Name: "x", Value: "y"}}})
	wantCode(t, err, "invalid_request")
	_, err = m.Import("erin", Import{Provider: "test", CookieFormat: "json"})
	wantCode(t, err, "invalid_request")
}

func TestVintedExampleAdapter(t *testing.T) {
	cfg, err := LoadConfig("../../examples/adapters.vinted.json")
	if err != nil {
		t.Fatal(err)
	}
	var renewals atomic.Int32
	var block atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Host == "www.vinted.com" && r.URL.Path == "/web/api/auth/refresh":
			if block.Load() {
				w.WriteHeader(403)
				fmt.Fprint(w, `<html><script src="https://ct.captcha-delivery.com/c.js"></script></html>`)
				return
			}
			raw, _ := io.ReadAll(r.Body)
			access, _ := r.Cookie("access_token_web")
			refresh, _ := r.Cookie("refresh_token_web")
			n := renewals.Add(1)
			if r.Method != "POST" || string(raw) != "{}" || access == nil || refresh == nil || refresh.Value != fmt.Sprintf("refresh-%d", n-1) {
				t.Errorf("unexpected renewal: %s %q", r.Method, raw)
				w.WriteHeader(400)
				return
			}
			nextAccess := fakeJWT("1001")
			nextRefresh := fmt.Sprintf("refresh-%d", n)
			http.SetCookie(w, &http.Cookie{Name: "access_token_web", Value: nextAccess, Domain: ".www.vinted.com", Path: "/", Secure: true, HttpOnly: true, MaxAge: 7200})
			http.SetCookie(w, &http.Cookie{Name: "refresh_token_web", Value: nextRefresh, Domain: ".www.vinted.com", Path: "/", Secure: true, HttpOnly: true, MaxAge: 604800})
			http.SetCookie(w, &http.Cookie{Name: "__cf_bm", Value: "edge", Domain: ".vinted.com", Path: "/", Secure: true})
			json.NewEncoder(w).Encode(map[string]any{"access_token": nextAccess, "refresh_token": nextRefresh, "expires_in": 3600})
		case r.Host == "api.www.vinted.com":
			refresh, _ := r.Cookie("refresh_token_web")
			if r.Header.Get("Authorization") != "" {
				t.Error("authorization none sent a bearer token")
			}
			if refresh == nil {
				w.WriteHeader(401)
				return
			}
			fmt.Fprintf(w, `{"saved_searches":[],"refresh":%q}`, refresh.Value)
		case r.Host == "www.vinted.com":
			// Server-rendered pages issue guest tokens for unrecognized sessions.
			http.SetCookie(w, &http.Cookie{Name: "access_token_web", Value: fakeJWT("guest"), Domain: ".www.vinted.com", Path: "/", Secure: true})
			fmt.Fprint(w, `<html>catalog</html>`)
		default:
			t.Errorf("unexpected host %s", r.Host)
		}
	}))
	defer server.Close()
	v, _ := openTestVault(t)
	m, err := NewManager(v, cfg)
	if err != nil {
		t.Fatal(err)
	}
	routeTo(t, m, "vinted", server)
	m.providers["vinted"].MinIntervalMS = 0
	cookies := "access_token_web=" + fakeJWT("1001") + "; refresh_token_web=refresh-0; anon_id=synthetic"
	if _, err := m.Import("me", Import{Provider: "vinted", CookieOrigin: "https://www.vinted.com", CookieHeader: cookies}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Refresh("me"); err != nil {
		t.Fatal(err)
	}
	r, err := m.Request("me", RequestInput{URL: "https://api.www.vinted.com/api/v2/saved_searches"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(r.BodyBase64)
	if r.Status != 200 || !strings.Contains(string(raw), `"refresh-1"`) {
		t.Fatalf("api host did not get rotated cookies: %d %s", r.Status, raw)
	}
	if _, err := m.Request("me", RequestInput{URL: "https://www.vinted.com/catalog"}); err != nil {
		t.Fatal(err)
	}
	e, _ := m.get("me")
	if sub, _, _ := cookieSubject(e.state.Cookies, "access_token_web"); sub != "1001" {
		t.Fatalf("guest page replaced the session token (subject %q)", sub)
	}
	block.Store(true)
	_, err = m.Refresh("me")
	wantCode(t, err, "upstream_blocked")
	block.Store(false)
	e.state.NextRefresh = time.Now().Add(-time.Second)
	e.state.Status = "ready"
	if _, err := m.Refresh("me"); err != nil {
		t.Fatal(err)
	}
	if renewals.Load() != 2 {
		t.Fatalf("%d renewals", renewals.Load())
	}
}
