package core

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
