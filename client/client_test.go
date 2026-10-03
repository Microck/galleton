package client_test

import (
	"context"
	"errors"
	"github.com/Microck/galleton/client"
	"github.com/Microck/galleton/internal/core"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGoClientRoundTrip(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token":"a","refresh_token":"r1","token_type":"Bearer","expires_in":3600}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer a" {
			w.WriteHeader(401)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer provider.Close()
	dir := t.TempDir()
	if err := core.Init(dir); err != nil {
		t.Fatal(err)
	}
	v, err := core.OpenVault(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	m, err := core.NewManager(v, core.Config{Providers: []core.Provider{{Name: "test", Kind: "oauth2", Origins: []string{provider.URL}, RefreshURL: provider.URL + "/token", RefreshIntervalSeconds: 3600, AllowHTTPLoopback: true}}})
	if err != nil {
		t.Fatal(err)
	}
	token, _ := core.ReadAPIToken(dir)
	api := httptest.NewServer(core.Handler(m, token))
	defer api.Close()
	c, err := client.FromDir(api.URL, dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err = c.Connect(ctx, "alice", client.Credentials{Provider: "test", RefreshToken: "r0"}); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Status(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Refresh(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	h, err := c.Headers(ctx, "alice", provider.URL)
	if err != nil || h.Headers["Authorization"] != "Bearer a" {
		t.Fatal(err)
	}
	if _, err = c.Capture(ctx, "alice", provider.URL, []string{"sid=123; Path=/"}); err != nil {
		t.Fatal(err)
	}
	response, err := c.Request(ctx, "alice", "GET", provider.URL+"/me", nil, nil)
	if err != nil || response.Status != 200 {
		t.Fatal(err)
	}
	var body map[string]bool
	if err = response.JSON(&body); err != nil || !body["ok"] {
		t.Fatal(err)
	}
	sessions, err := c.List(ctx)
	if err != nil || len(sessions) != 1 {
		t.Fatal(err)
	}
	if err = c.Forget(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Status(ctx, "alice"); err == nil {
		t.Fatal("forgotten session found")
	}
	bad, err := client.New(api.URL, "wrong")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = bad.List(ctx); err == nil {
		t.Fatal("bad token accepted")
	}
}
func TestGoClientRejectsUnsafeInputs(t *testing.T) {
	for _, url := range []string{"http://example.com", "http://localhost:8766", "http://u:p@127.0.0.1:8766", "file:///tmp/x"} {
		if _, err := client.New(url, "x"); err == nil {
			t.Fatal("unsafe daemon URL accepted")
		}
	}
	c, err := client.New("", "x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Status(context.Background(), "../bad"); err == nil {
		t.Fatal("invalid session ID accepted")
	}
}

func TestGoClientReturnsTypedInvalidResponse(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{name: "malformed JSON", body: []byte("{")},
		{name: "oversized response", body: make([]byte, (8<<20)+1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(tc.body)
			}))
			defer server.Close()
			c, err := client.New(server.URL, "local-token")
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.Status(context.Background(), "alice")
			var typed *client.Error
			if !errors.As(err, &typed) {
				t.Fatalf("error = %T %v, want *client.Error", err, err)
			}
			if typed.Code != "invalid_response" || typed.Status != http.StatusOK {
				t.Fatalf("typed error = %#v, want invalid_response with status 200", typed)
			}
		})
	}
}
