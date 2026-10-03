package core

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestUnchangedCookieExpiryDoesNotTriggerRenewalBurst(t *testing.T) {
	var renewals atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		renewals.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}))
	defer server.Close()

	p := providerFor(server.URL)
	p.Kind = "http"
	p.RefreshURL = server.URL + "/token"
	p.RefreshMethod = "POST"
	p.Response = ResponseMapping{Success: "/ok"}
	p.RefreshIntervalSeconds = 3600
	p.RefreshBeforeSeconds = 60
	m, _, _ := managerFor(t, p)
	if _, err := m.Import("alice", Import{
		Provider:     "test",
		CookieOrigin: server.URL,
		SetCookies:   []string{"side=unchanged; Max-Age=1; Path=/"},
	}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	m.RunScheduler(ctx)
	if got := renewals.Load(); got != 1 {
		t.Fatalf("unchanged side-cookie expiry caused %d renewals, want 1", got)
	}
}

func TestShortLivedRotatedCredentialDoesNotLoop(t *testing.T) {
	var renewals atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		renewals.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "short-lived", "token_type": "Bearer", "expires_in": 30,
		})
	}))
	defer server.Close()
	m, _, _ := managerFor(t, providerFor(server.URL))
	if _, err := m.Import("alice", Import{Provider: "test", RefreshToken: "r0"}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	m.RunScheduler(ctx)
	if got := renewals.Load(); got != 1 {
		t.Fatalf("short-lived rotated credential caused %d renewals, want 1", got)
	}
}

func TestDecodeBodyAcceptsCaseInsensitiveJSONMediaType(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"value":7}`))
	req.Header.Set("Content-Type", "Application/JSON; charset=UTF-8")
	w := httptest.NewRecorder()
	var body struct {
		Value int `json:"value"`
	}
	if !decodeBody(w, req, &body) {
		t.Fatalf("case-variant JSON media type rejected: status=%d body=%s", w.Code, w.Body.String())
	}
	if body.Value != 7 {
		t.Fatalf("decoded value = %d, want 7", body.Value)
	}
}

func TestSystemdInstallerRestartsUpdatedUnit(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "install-systemd.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	enable := strings.Index(script, "systemctl --user enable galleton.service")
	restart := strings.Index(script, "systemctl --user restart galleton.service")
	if enable < 0 || restart < 0 || restart < enable {
		t.Fatalf("installer does not enable then restart the updated unit: %q", script)
	}
}

func TestServiceStopTimeoutsExceedShutdownBudget(t *testing.T) {
	systemd, err := os.ReadFile(filepath.Join("..", "..", "deploy", "install-systemd.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(systemd), "TimeoutStopSec=330") {
		t.Fatalf("systemd stop deadline does not exceed the daemon's five-minute shutdown budget")
	}
	launchd, err := os.ReadFile(filepath.Join("..", "..", "deploy", "install-launchd.py"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(launchd), `"ExitTimeOut": 330`) {
		t.Fatalf("launchd stop deadline does not exceed the daemon's five-minute shutdown budget")
	}
}

func TestRetryWaitUsesCredentialsForRequestedOrigin(t *testing.T) {
	cookieServer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer cookieServer.Close()
	var resourceHits atomic.Int32
	resourceServer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		resourceHits.Add(1)
	}))
	defer resourceServer.Close()

	p := providerFor(cookieServer.URL)
	p.Origins = append(p.Origins, resourceServer.URL)
	m, _, _ := managerFor(t, p)
	if _, err := m.Import("alice", Import{
		Provider:        "test",
		AccessToken:     "expired",
		RefreshToken:    "r0",
		AccessExpiresAt: time.Now().Add(-time.Minute),
		CookieOrigin:    cookieServer.URL,
		CookieHeader:    "sid=live",
	}); err != nil {
		t.Fatal(err)
	}
	e, err := m.get("alice")
	if err != nil {
		t.Fatal(err)
	}
	retryAt := time.Now().UTC().Add(time.Hour)
	e.state.Status = "retry_wait"
	e.state.NextRefresh = retryAt

	_, err = m.Headers("alice", resourceServer.URL+"/headers")
	if p := AsProblem(err); p.Code != "retry_later" || !p.RetryAt.Equal(retryAt) {
		t.Fatalf("Headers error = %#v, want retry_later at %s", p, retryAt)
	}
	_, err = m.Request("alice", RequestInput{URL: resourceServer.URL + "/request"})
	if p := AsProblem(err); p.Code != "retry_later" || !p.RetryAt.Equal(retryAt) {
		t.Fatalf("Request error = %#v, want retry_later at %s", p, retryAt)
	}
	if got := resourceHits.Load(); got != 0 {
		t.Fatalf("resource origin was contacted %d times during retry_wait", got)
	}

	e.state.Status = "ready"
	e.state.AccessToken = ""
	e.state.AccessExpiresAt = time.Time{}
	e.state.NextRefresh = time.Now().UTC().Add(time.Hour)
	_, err = m.Headers("alice", resourceServer.URL+"/headers")
	wantCode(t, err, "no_credentials_for_origin")
}

func TestExpiredBearerIsDroppedAfterCookieOnlyRenewal(t *testing.T) {
	var renewals atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		renewals.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}))
	defer server.Close()

	p := providerFor(server.URL)
	p.Kind = "http"
	p.RefreshURL = server.URL + "/token"
	p.RefreshMethod = "POST"
	p.Response = ResponseMapping{Success: "/ok"}
	p.RefreshIntervalSeconds = 3600
	m, _, _ := managerFor(t, p)
	if _, err := m.Import("alice", Import{
		Provider:        "test",
		AccessToken:     "expired",
		AccessExpiresAt: time.Now().Add(-time.Minute),
		CookieOrigin:    server.URL,
		CookieHeader:    "sid=live",
	}); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 2; i++ {
		got, err := m.Headers("alice", server.URL+"/resource")
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := got.Headers["Authorization"]; ok {
			t.Fatalf("expired bearer token survived renewal: %#v", got.Headers)
		}
		if got.Headers["Cookie"] != "sid=live" {
			t.Fatalf("usable cookie missing: %#v", got.Headers)
		}
	}
	if got := renewals.Load(); got != 1 {
		t.Fatalf("cookie-only adapter renewed %d times, want 1", got)
	}
}

func TestRetryWaitOmitsExpiredBearerWhenCookieIsUsable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	m, _, _ := managerFor(t, providerFor(server.URL))
	if _, err := m.Import("alice", Import{
		Provider:        "test",
		AccessToken:     "expired",
		RefreshToken:    "r0",
		AccessExpiresAt: time.Now().Add(-time.Minute),
		CookieOrigin:    server.URL,
		CookieHeader:    "sid=live",
	}); err != nil {
		t.Fatal(err)
	}
	e, err := m.get("alice")
	if err != nil {
		t.Fatal(err)
	}
	e.state.Status = "retry_wait"
	e.state.NextRefresh = time.Now().Add(time.Hour)

	got, err := m.Headers("alice", server.URL+"/resource")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.Headers["Authorization"]; ok {
		t.Fatalf("expired bearer token was returned: %#v", got.Headers)
	}
	if got.Headers["Cookie"] != "sid=live" {
		t.Fatalf("usable cookie missing: %#v", got.Headers)
	}
}
