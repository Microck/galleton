package core

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRetryWaitRequiresUsableCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("backoff request reached upstream") }))
	defer server.Close()
	for _, cookies := range []string{"", "sid=expired"} {
		t.Run(cookies, func(t *testing.T) {
			m, _, _ := managerFor(t, providerFor(server.URL))
			in := Import{Provider: "test", RefreshToken: "r0"}
			if cookies != "" {
				in.CookieOrigin, in.CookieHeader = server.URL, cookies
			}
			if _, err := m.Import("alice", in); err != nil {
				t.Fatal(err)
			}
			e, _ := m.get("alice")
			e.state.Status = "retry_wait"
			e.state.NextRefresh = time.Now().Add(time.Minute)
			for i := range e.state.Cookies {
				e.state.Cookies[i].Cookie.Expires = time.Now().Add(-time.Second)
			}
			_, err := m.Headers("alice", server.URL)
			wantCode(t, err, "retry_later")
			var p *Problem
			if !errors.As(err, &p) || !p.RetryAt.Equal(e.state.NextRefresh) {
				t.Fatal("retry deadline missing")
			}
			_, err = m.Request("alice", RequestInput{URL: server.URL})
			wantCode(t, err, "retry_later")
		})
	}
}

func TestRetryWaitAllowsUnexpiredCookies(t *testing.T) {
	const rawURL = "http://127.0.0.1:9999"
	m, _, _ := managerFor(t, providerFor(rawURL))
	if _, err := m.Import("alice", Import{Provider: "test", RefreshToken: "r0", CookieOrigin: rawURL, CookieHeader: "sid=live"}); err != nil {
		t.Fatal(err)
	}
	e, _ := m.get("alice")
	e.state.Status = "retry_wait"
	e.state.NextRefresh = time.Now().Add(time.Minute)
	e.state.Cookies[0].Cookie.Expires = time.Now().Add(time.Hour)
	got, err := m.Headers("alice", rawURL)
	if err != nil || got.Headers["Cookie"] != "sid=live" {
		t.Fatalf("usable cookie blocked: %#v %v", got, err)
	}
}
