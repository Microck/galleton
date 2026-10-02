package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func openTestVault(t *testing.T) (*Vault, string) {
	t.Helper()
	dir := t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatal(err)
	}
	v, err := OpenVault(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	return v, dir
}
func providerFor(raw string) Provider {
	return Provider{Name: "test", Kind: "oauth2", Origins: []string{raw}, RefreshURL: raw + "/token", RefreshIntervalSeconds: 3600, AllowHTTPLoopback: true}
}
func managerFor(t *testing.T, p Provider) (*Manager, *Vault, string) {
	t.Helper()
	v, dir := openTestVault(t)
	m, err := NewManager(v, Config{Providers: []Provider{p}})
	if err != nil {
		t.Fatal(err)
	}
	return m, v, dir
}
func importOAuth(t *testing.T, m *Manager) {
	t.Helper()
	if _, err := m.Import("alice", Import{Provider: "test", RefreshToken: "r0"}); err != nil {
		t.Fatal(err)
	}
}
func jsonOK(w http.ResponseWriter, access, refresh string) {
	w.Header().Set("Content-Type", "application/json")
	out := map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": 3600}
	if refresh != "" {
		out["refresh_token"] = refresh
	}
	_ = json.NewEncoder(w).Encode(out)
}
func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got nil", code)
	}
	if p := AsProblem(err); p.Code != code {
		t.Fatalf("expected %s, got %v", code, err)
	}
}
func due(m *Manager) {
	e, _ := m.get("alice")
	e.mu.Lock()
	e.state.NextRefresh = time.Now().Add(-time.Second)
	e.mu.Unlock()
}

func TestOAuthRotationPersistsAcrossRestart(t *testing.T) {
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := count.Add(1)
		_ = r.ParseForm()
		if r.Form.Get("refresh_token") != fmt.Sprintf("r%d", n-1) {
			t.Errorf("wrong rotating credential")
			w.WriteHeader(400)
			return
		}
		jsonOK(w, fmt.Sprintf("a%d", n), fmt.Sprintf("r%d", n))
	}))
	defer server.Close()
	p := providerFor(server.URL)
	m, v, dir := managerFor(t, p)
	importOAuth(t, m)
	h, err := m.Headers("alice", server.URL+"/me")
	if err != nil || h.Headers["Authorization"] != "Bearer a1" {
		t.Fatalf("%v %#v", err, h)
	}
	if err = v.Close(); err != nil {
		t.Fatal(err)
	}
	v2, err := OpenVault(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()
	m2, err := NewManager(v2, Config{Providers: []Provider{p}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m2.Refresh("alice"); err != nil {
		t.Fatal(err)
	}
	if count.Load() != 2 {
		t.Fatal("wrong refresh count")
	}
	states, _ := v2.LoadAll()
	if states[0].RefreshToken != "r2" {
		t.Fatal("rotation was not persisted")
	}
}
func TestOAuthRetainsRefreshTokenWhenOmitted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("refresh_token") != "r0" {
			t.Error("refresh token was discarded")
		}
		jsonOK(w, "a", " ")
	}))
	defer server.Close()
	// Whitespace is technically an opaque token, so explicitly omit it here.
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("refresh_token") != "r0" {
			t.Error("refresh token was discarded")
		}
		jsonOK(w, "a", "")
	})
	m, _, _ := managerFor(t, providerFor(server.URL))
	importOAuth(t, m)
	for i := 0; i < 2; i++ {
		if _, err := m.Refresh("alice"); err != nil {
			t.Fatal(err)
		}
	}
}
func TestConcurrentHeadersSingleRefresh(t *testing.T) {
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		time.Sleep(20 * time.Millisecond)
		jsonOK(w, "a", "r1")
	}))
	defer server.Close()
	m, _, _ := managerFor(t, providerFor(server.URL))
	importOAuth(t, m)
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := m.Headers("alice", server.URL+"/me"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if count.Load() != 1 {
		t.Fatalf("%d refresh requests", count.Load())
	}
}
func TestConcurrentForcedRefreshCoalesces(t *testing.T) {
	var count atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if count.Add(1) == 1 {
			close(entered)
			<-release
		}
		jsonOK(w, "a", "r1")
	}))
	defer server.Close()
	m, _, _ := managerFor(t, providerFor(server.URL))
	importOAuth(t, m)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := m.Refresh("alice")
		if err != nil {
			t.Error(err)
		}
	}()
	<-entered
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := m.Refresh("alice")
			if err != nil {
				t.Error(err)
			}
		}()
	}
	time.Sleep(30 * time.Millisecond)
	close(release)
	wg.Wait()
	if count.Load() != 1 {
		t.Fatalf("forced refresh storm: %d", count.Load())
	}
}
func TestInvalidGrantStopsUntilReconnect(t *testing.T) {
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(400)
		fmt.Fprint(w, `{"error":"invalid_grant","error_description":"DO NOT ECHO SECRET"}`)
	}))
	defer server.Close()
	m, _, _ := managerFor(t, providerFor(server.URL))
	importOAuth(t, m)
	_, err := m.Refresh("alice")
	wantCode(t, err, "reauth_required")
	_, err = m.Headers("alice", server.URL)
	wantCode(t, err, "reauth_required")
	if count.Load() != 1 {
		t.Fatal("terminal credential replayed")
	}
	if strings.Contains(err.Error(), "DO NOT ECHO") {
		t.Fatal("provider response leaked")
	}
	previous, _ := m.Status("alice")
	_, err = m.Import("alice", Import{Provider: "test", RefreshToken: "new", Replace: true, ExpectedRevision: &previous.Revision})
	if err != nil {
		t.Fatal(err)
	}
	meta, _ := m.Status("alice")
	if meta.Status != "ready" {
		t.Fatal(meta.Status)
	}
}
func TestRateLimitRespectsRetryAfter(t *testing.T) {
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if count.Add(1) == 1 {
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(429)
			return
		}
		jsonOK(w, "a", "r1")
	}))
	defer server.Close()
	m, _, _ := managerFor(t, providerFor(server.URL))
	importOAuth(t, m)
	_, err := m.Refresh("alice")
	wantCode(t, err, "retry_later")
	meta, _ := m.Status("alice")
	if time.Until(meta.NextRefresh) < 55*time.Second {
		t.Fatal("Retry-After ignored")
	}
	_, err = m.Refresh("alice")
	wantCode(t, err, "retry_later")
	if count.Load() != 1 {
		t.Fatal("rate limit ignored")
	}
	due(m)
	if _, err = m.Refresh("alice"); err != nil {
		t.Fatal(err)
	}
}
func TestLostResponseIsNotReplayed(t *testing.T) {
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
	}))
	defer server.Close()
	m, _, _ := managerFor(t, providerFor(server.URL))
	importOAuth(t, m)
	_, err := m.Refresh("alice")
	wantCode(t, err, "renewal_uncertain")
	_, err = m.Refresh("alice")
	wantCode(t, err, "renewal_uncertain")
	if count.Load() != 1 {
		t.Fatal("ambiguous refresh replayed")
	}
}
func TestExplicitSafeRetry(t *testing.T) {
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if count.Add(1) == 1 {
			w.WriteHeader(503)
			return
		}
		jsonOK(w, "a", "r1")
	}))
	defer server.Close()
	p := providerFor(server.URL)
	p.RetrySafe = true
	m, _, _ := managerFor(t, p)
	importOAuth(t, m)
	_, err := m.Refresh("alice")
	wantCode(t, err, "retry_later")
	due(m)
	if _, err = m.Refresh("alice"); err != nil {
		t.Fatal(err)
	}
}
func TestPendingCheckpointAfterCrashIsUncertain(t *testing.T) {
	p := providerFor("http://127.0.0.1:11111")
	m, v, dir := managerFor(t, p)
	importOAuth(t, m)
	e, _ := m.get("alice")
	e.state.PendingRefresh = true
	e.state.Status = "refreshing"
	if err := v.Save(e.state); err != nil {
		t.Fatal(err)
	}
	v.Close()
	v2, err := OpenVault(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()
	m2, err := NewManager(v2, Config{Providers: []Provider{p}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = m2.Refresh("alice")
	wantCode(t, err, "renewal_uncertain")
}
func TestFailedPreflightWriteDoesNotSendRequest(t *testing.T) {
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { count.Add(1); jsonOK(w, "a", "r1") }))
	defer server.Close()
	m, v, _ := managerFor(t, providerFor(server.URL))
	importOAuth(t, m)
	v.saveHook = func(s *State) error {
		if s.PendingRefresh {
			return errors.New("disk fault")
		}
		return nil
	}
	_, err := m.Refresh("alice")
	wantCode(t, err, "storage_failure")
	if count.Load() != 0 {
		t.Fatal("request sent without checkpoint")
	}
	v.saveHook = nil
	if _, err = m.Refresh("alice"); err != nil {
		t.Fatal(err)
	}
	if count.Load() != 1 {
		t.Fatal("wrong refresh count")
	}
}
func TestFailedRotationSaveRetriesWriteNotNetwork(t *testing.T) {
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { count.Add(1); jsonOK(w, "a", "r1") }))
	defer server.Close()
	m, v, _ := managerFor(t, providerFor(server.URL))
	importOAuth(t, m)
	v.saveHook = func(s *State) error {
		if !s.PendingRefresh && !s.LastRefresh.IsZero() {
			return errors.New("disk fault")
		}
		return nil
	}
	_, err := m.Refresh("alice")
	wantCode(t, err, "storage_failure")
	meta, _ := m.Status("alice")
	if meta.Status != "storage_error" {
		t.Fatal("write failure hidden")
	}
	v.saveHook = nil
	h, err := m.Headers("alice", server.URL)
	if err != nil || h.Headers["Authorization"] != "Bearer a" {
		t.Fatal(err)
	}
	if count.Load() != 1 {
		t.Fatal("rotating request was repeated instead of retrying local save")
	}
	states, err := v.LoadAll()
	if err != nil || states[0].RefreshToken != "r1" {
		t.Fatal("fresh credential was lost")
	}
}
func TestMalformedResponseRetainsPartialRefreshToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"refresh_token":"r1","token_type":"Bearer"}`)
	}))
	defer server.Close()
	m, v, _ := managerFor(t, providerFor(server.URL))
	importOAuth(t, m)
	_, err := m.Refresh("alice")
	wantCode(t, err, "protocol_error")
	states, _ := v.LoadAll()
	if states[0].RefreshToken != "r1" {
		t.Fatal("partial credential discarded")
	}
}
func TestCookieHTTPAdapterAndProxyCapture(t *testing.T) {
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/session" {
			count.Add(1)
			c, err := r.Cookie("sid")
			if err != nil || c.Value != "seed" {
				t.Error("bootstrap cookie missing")
			}
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "rotated", Path: "/", MaxAge: 3600, HttpOnly: true})
			fmt.Fprint(w, `{}`)
			return
		}
		c, err := r.Cookie("sid")
		if err != nil || c.Value != "rotated" {
			t.Error("rotated cookie not attached")
		}
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "resource-update", Path: "/", MaxAge: 3600})
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer server.Close()
	p := providerFor(server.URL)
	p.Kind = "http"
	p.RefreshURL = server.URL + "/session"
	p.RefreshMethod = "GET"
	p.Response.RequireSetCookie = true
	m, v, _ := managerFor(t, p)
	if _, err := m.Import("alice", Import{Provider: "test", CookieOrigin: server.URL, CookieHeader: "sid=seed"}); err != nil {
		t.Fatal(err)
	}
	result, err := m.Request("alice", RequestInput{URL: server.URL + "/me"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(result.BodyBase64)
	if string(raw) != `{"ok":true}` || result.Status != 200 {
		t.Fatal(result)
	}
	if result.Headers.Get("Set-Cookie") != "" {
		t.Fatal("managed cookies unnecessarily returned")
	}
	h, err := m.Headers("alice", server.URL+"/me")
	if err != nil || !strings.Contains(h.Headers["Cookie"], "resource-update") {
		t.Fatalf("%v %#v", err, h)
	}
	states, _ := v.LoadAll()
	if len(states[0].Cookies) != 1 || states[0].Cookies[0].Cookie.Value != "resource-update" {
		t.Fatal("resource cookie not persisted")
	}
	if count.Load() != 1 {
		t.Fatal("unnecessary renewal")
	}
}
func TestCookieScopeExpiryDeletionAndPrefixes(t *testing.T) {
	now := time.Now().UTC()
	u, _ := url.Parse("https://a.example.test/api/session")
	cookies := []*http.Cookie{
		{Name: "sid", Value: "one", Domain: ".example.test", Path: "/api", Secure: true, MaxAge: 60},
		{Name: "unrelated", Value: "bad", Domain: "other.test", Path: "/"},
		{Name: "__Host-bad", Value: "bad", Domain: "example.test", Path: "/", Secure: true},
		{Name: "partition", Value: "bad", Partitioned: true, Secure: true},
		{Name: "__Host-good", Value: "good", Path: "/", Secure: true},
	}
	saved, accepted, retained, err := updateCookies(nil, u, cookies, now)
	if err != nil || accepted != 2 || retained != 2 {
		t.Fatalf("%v %d %d", err, accepted, retained)
	}
	if saved[0].Cookie.MaxAge != 0 || !saved[0].Cookie.Expires.Equal(now.Add(time.Minute)) {
		t.Fatal("Max-Age not converted to absolute expiry")
	}
	sibling, _ := url.Parse("https://b.example.test/api/me")
	if cookieHeaders(saved, sibling, now) != "" {
		t.Fatal("cookie leaked to sibling origin")
	}
	wrongPort, _ := url.Parse("https://a.example.test:8443/api/me")
	if cookieHeaders(saved, wrongPort, now) != "" {
		t.Fatal("cookie leaked to another port")
	}
	wrongPath, _ := url.Parse("https://a.example.test/apix/me")
	if strings.Contains(cookieHeaders(saved, wrongPath, now), "sid=") {
		t.Fatal("cookie path widened")
	}
	deleteCookie := &http.Cookie{Name: "sid", Value: "", Path: "/api", MaxAge: -1}
	saved, accepted, retained, err = updateCookies(saved, u, []*http.Cookie{deleteCookie}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if accepted != 1 || retained != 0 {
		t.Fatalf("deletion accounting: accepted=%d retained=%d", accepted, retained)
	}
	if strings.Contains(cookieHeaders(saved, u, now.Add(2*time.Second)), "sid=") {
		t.Fatal("deleted cookie resurrected")
	}
}
func TestCookieDefaultPathAndSecure(t *testing.T) {
	u, _ := url.Parse("https://example.test/a/b")
	saved, _, _, _ := updateCookies(nil, u, []*http.Cookie{{Name: "x", Value: "v", Secure: true}}, time.Now())
	if saved[0].Cookie.Path != "/a" {
		t.Fatal(saved[0].Cookie.Path)
	}
	plain, _ := url.Parse("http://example.test/a/b")
	if cookieHeaders(saved, plain, time.Now()) != "" {
		t.Fatal("secure cookie leaked to HTTP")
	}
}
func TestVaultEncryptionTamperAndBinding(t *testing.T) {
	v, dir := openTestVault(t)
	s := &State{ID: "alice", RefreshToken: "HIGH_ENTROPY_TEST_SECRET"}
	if err := v.Save(s); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, sessionFilename("alice"))
	b, _ := os.ReadFile(path)
	if bytes.Contains(b, []byte(s.RefreshToken)) {
		t.Fatal("plaintext credential on disk")
	}
	if err := os.WriteFile(filepath.Join(dir, "bob.session"), b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := v.LoadAll(); err == nil {
		t.Fatal("ciphertext was not bound to its session ID")
	}
	os.Remove(filepath.Join(dir, "bob.session"))
	b[len(b)-1] ^= 1
	_ = os.WriteFile(path, b, 0600)
	if _, err := v.LoadAll(); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}
func TestVaultExclusiveLockAndPermissions(t *testing.T) {
	v, dir := openTestVault(t)
	if other, err := OpenVault(dir); err == nil {
		other.Close()
		t.Fatal("second writer acquired vault")
	}
	v.Close()
	other, err := OpenVault(dir)
	if err != nil {
		t.Fatal(err)
	}
	other.Close()
	if runtime.GOOS == "windows" {
		return
	} // Windows secrecy depends on ACLs, not Unix mode bits.
	for _, name := range []string{"master.key", "api.token"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0077 != 0 {
			t.Fatal("secret file is world/group accessible")
		}
	}
}
func TestChangedAdapterBlocksStoredCredentials(t *testing.T) {
	p := providerFor("http://127.0.0.1:11111")
	m, v, dir := managerFor(t, p)
	importOAuth(t, m)
	v.Close()
	p.RefreshURL = "http://127.0.0.1:11111/changed"
	v2, err := OpenVault(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()
	m2, err := NewManager(v2, Config{Providers: []Provider{p}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = m2.Refresh("alice")
	wantCode(t, err, "configuration_error")
}
func TestOriginAllowlistBeforeRenewal(t *testing.T) {
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { count.Add(1); jsonOK(w, "a", "r1") }))
	defer server.Close()
	m, _, _ := managerFor(t, providerFor(server.URL))
	importOAuth(t, m)
	_, err := m.Headers("alice", "https://not-allowed.test/")
	wantCode(t, err, "origin_not_allowed")
	if count.Load() != 0 {
		t.Fatal("renewal sent before origin validation")
	}
	_, err = m.Request("alice", RequestInput{URL: server.URL, Headers: map[string]string{"Authorization": "override"}})
	wantCode(t, err, "invalid_request")
}
func TestRedirectsNotFollowedAndPostsNotRetried(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(302)
	}))
	defer source.Close()
	m, _, _ := managerFor(t, providerFor(source.URL))
	importOAuth(t, m)
	_, err := m.Refresh("alice")
	wantCode(t, err, "protocol_error")
	if redirected.Load() != 0 {
		t.Fatal("refresh redirect followed")
	}
}
func TestGenericTemplatesAndPointers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Csrf") != "csrf-value" {
			t.Error("secret template missing")
		}
		_ = r.ParseForm()
		if r.Form.Get("credential") != "r0" {
			t.Error("form template missing")
		}
		fmt.Fprint(w, `{"result":{"token":"a1","refresh":"r1","ttl":3600,"ok":true}}`)
	}))
	defer server.Close()
	p := providerFor(server.URL)
	p.Kind = "http"
	p.BodyFormat = "form"
	p.Body = map[string]string{"credential": "${refresh_token}"}
	p.RefreshHeaders = map[string]string{"X-Csrf": "${secret.csrf}"}
	p.Response = ResponseMapping{AccessToken: "/result/token", RefreshToken: "/result/refresh", ExpiresIn: "/result/ttl", Success: "/result/ok"}
	m, _, _ := managerFor(t, p)
	_, err := m.Import("alice", Import{Provider: "test", RefreshToken: "r0", Secrets: map[string]string{"csrf": "csrf-value"}})
	if err != nil {
		t.Fatal(err)
	}
	h, err := m.Headers("alice", server.URL)
	if err != nil || h.Headers["Authorization"] != "Bearer a1" {
		t.Fatal(err)
	}
}
func TestSchedulerRenewsWithoutClientRequests(t *testing.T) {
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { n := count.Add(1); jsonOK(w, "a", fmt.Sprintf("r%d", n)) }))
	defer server.Close()
	p := providerFor(server.URL)
	p.RefreshIntervalSeconds = 1
	m, _, _ := managerFor(t, p)
	importOAuth(t, m)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.RunScheduler(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(4 * time.Second)
	for count.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if count.Load() < 2 {
		t.Fatal("scheduler did not renew independently")
	}
}
func TestAPIAuthenticationBrowserBlockingAndSanitization(t *testing.T) {
	m, _, dir := managerFor(t, providerFor("http://127.0.0.1:11111"))
	token, _ := ReadAPIToken(dir)
	api := httptest.NewServer(Handler(m, token))
	defer api.Close()
	cases := []struct {
		token, origin, host string
		want                int
	}{{"", "", "", 401}, {token, "https://web.example", "", 403}, {token, "", "attacker.example", 403}, {token, "", "", 200}}
	for _, tc := range cases {
		req, _ := http.NewRequest("GET", api.URL+"/v1/health", nil)
		req.Header.Set("Authorization", "Bearer "+tc.token)
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		if tc.host != "" {
			req.Host = tc.host
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Fatalf("got %d want %d", resp.StatusCode, tc.want)
		}
		if resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("secret API is cacheable")
		}
	}
}
func TestAPICRUDAndUnknownFields(t *testing.T) {
	m, _, dir := managerFor(t, providerFor("http://127.0.0.1:11111"))
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
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	status, _ := call("PUT", "/v1/sessions/alice", `{"provider":"test","refresh_token":"secret","unknown":1}`)
	if status != 400 {
		t.Fatal(status)
	}
	status, body := call("PUT", "/v1/sessions/alice", `{"provider":"test","refresh_token":"secret"}`)
	if status != 201 || strings.Contains(body, "secret") {
		t.Fatalf("%d %s", status, body)
	}
	status, _ = call("PUT", "/v1/sessions/alice", `{"provider":"test","refresh_token":"secret"}`)
	if status != 409 {
		t.Fatal(status)
	}
	status, body = call("GET", "/v1/sessions", "")
	if status != 200 || strings.Contains(body, "refresh_token") {
		t.Fatal("metadata leaked credential fields")
	}
	status, _ = call("DELETE", "/v1/sessions/alice", "")
	if status != 200 {
		t.Fatal(status)
	}
	status, _ = call("GET", "/v1/sessions/alice", "")
	if status != 404 {
		t.Fatal(status)
	}
}
func TestConfigAndCredentialValidation(t *testing.T) {
	p := providerFor("http://127.0.0.1:11111")
	for _, bad := range []string{"https://user:pass@example.test/x", "file:///etc/passwd", "https://example.test/#x", "https://example.test./x"} {
		if _, _, err := canonicalURL(bad); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	bad := p
	bad.AllowHTTPLoopback = false
	if _, err := compileProviders(Config{Providers: []Provider{bad}}); err == nil {
		t.Fatal("insecure endpoint accepted")
	}
	bad = p
	bad.Origins = []string{"https://example.test/path"}
	if _, err := compileProviders(Config{Providers: []Provider{bad}}); err == nil {
		t.Fatal("origin path accepted")
	}
	m, _, _ := managerFor(t, p)
	_, err := m.Import("../bad", Import{Provider: "test", RefreshToken: "x"})
	wantCode(t, err, "invalid_request")
	_, err = m.Import("alice", Import{Provider: "test", AccessToken: "x"})
	wantCode(t, err, "invalid_request")
	_, err = m.Import("alice", Import{Provider: "test", RefreshToken: "x\r\nInjected: yes"})
	wantCode(t, err, "invalid_request")
}
func TestJSONPointerEscapingAndArrays(t *testing.T) {
	doc, _ := parseJSON([]byte(`{"a/b":{"~key":["zero","one"]}}`))
	v, ok := pointer(doc, "/a~1b/~0key/1")
	if !ok || v != "one" {
		t.Fatal(v, ok)
	}
	for _, p := range []string{"bad", "/a~2b", "/a~1b/~0key/01", "/a~1b/~0key/-1"} {
		if _, ok := pointer(doc, p); ok {
			t.Fatal("invalid pointer accepted")
		}
	}
}
func FuzzCanonicalURL(f *testing.F) {
	for _, s := range []string{"https://example.test/path", "http://127.0.0.1:1234/", "file:///x", "https://a@b/", "https://[::1]/"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		u, origin, err := canonicalURL(raw)
		if err == nil {
			if u == nil || origin == "" || u.User != nil || u.Fragment != "" {
				t.Fatal("broken canonical URL invariant")
			}
		}
	})
}

func TestShutdownRejectsQueuedRenewal(t *testing.T) {
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { count.Add(1); jsonOK(w, "a", "r1") }))
	defer server.Close()
	m, _, _ := managerFor(t, providerFor(server.URL))
	importOAuth(t, m)
	m.BeginShutdown()
	_, err := m.Refresh("alice")
	wantCode(t, err, "shutting_down")
	if count.Load() != 0 {
		t.Fatal("renewal began during shutdown")
	}
}

func TestProfilesKeepCredentialsIsolated(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		user := r.Form.Get("refresh_token")
		jsonOK(w, "access-"+user, "")
	}))
	defer server.Close()
	m, v, _ := managerFor(t, providerFor(server.URL))
	for _, id := range []string{"alice", "bob"} {
		if _, err := m.Import(id, Import{Provider: "test", RefreshToken: id}); err != nil {
			t.Fatal(err)
		}
		h, err := m.Headers(id, server.URL)
		if err != nil || h.Headers["Authorization"] != "Bearer access-"+id {
			t.Fatal("profile isolation failure", err)
		}
	}
	states, err := v.LoadAll()
	if err != nil || len(states) != 2 {
		t.Fatal("profile persistence failure")
	}
}

func TestOversizedImportRejectedBeforePersistence(t *testing.T) {
	m, _, _ := managerFor(t, providerFor("http://127.0.0.1:11111"))
	secrets := map[string]string{}
	for i := 0; i < 17; i++ {
		secrets[fmt.Sprintf("s%d", i)] = strings.Repeat("x", 64<<10)
	}
	_, err := m.Import("alice", Import{Provider: "test", RefreshToken: "r", Secrets: secrets})
	wantCode(t, err, "invalid_request")
	if len(m.List()) != 0 {
		t.Fatal("invalid import created a profile")
	}
}

func TestConnectionFailureRetriesWithoutReimport(t *testing.T) {
	initial := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	origin := initial.URL
	initial.Close()
	m, _, _ := managerFor(t, providerFor(origin))
	importOAuth(t, m)
	_, err := m.Refresh("alice")
	wantCode(t, err, "retry_later")
	meta, _ := m.Status("alice")
	if meta.Status != "retry_wait" {
		t.Fatal("safe pre-connection failure became terminal")
	}
	listener, err := net.Listen("tcp", strings.TrimPrefix(origin, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("refresh_token") != "r0" {
			t.Error("unexpected credential")
		}
		jsonOK(w, "a", "r1")
	})}
	defer server.Close()
	go func() { _ = server.Serve(listener) }()
	due(m)
	h, err := m.Headers("alice", origin)
	if err != nil || h.Headers["Authorization"] != "Bearer a" {
		t.Fatalf("failed to recover without reimport: %v", err)
	}
}
