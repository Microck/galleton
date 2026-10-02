package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDeletionCookieIsNotRenewalEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", Path: "/", MaxAge: -1})
		_, _ = fmt.Fprint(w, "{}")
	}))
	defer server.Close()
	p := providerFor(server.URL)
	p.Kind = "http"
	p.RefreshURL = server.URL
	p.RefreshMethod = "POST"
	p.Response.RequireSetCookie = true
	m, v, _ := managerFor(t, p)
	if _, err := m.Import("alice", Import{Provider: "test", CookieOrigin: server.URL, CookieHeader: "sid=seed"}); err != nil {
		t.Fatal(err)
	}
	_, err := m.Refresh("alice")
	wantCode(t, err, "protocol_error")
	states, loadErr := v.LoadAll()
	if loadErr != nil || len(states) != 1 {
		t.Fatalf("load state: %v", loadErr)
	}
	if states[0].Status != "protocol_error" || len(states[0].Cookies) != 0 {
		t.Fatalf("deletion-only response was accepted as renewal: %#v", states[0])
	}
}

func TestMalformedExternalCapturePersistsUncertainty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	m, v, _ := managerFor(t, providerFor(server.URL))
	if _, err := m.Import("alice", Import{Provider: "test", AccessToken: "a0", RefreshToken: "r0"}); err != nil {
		t.Fatal(err)
	}
	_, err := m.Capture("alice", server.URL, []string{"not a cookie"})
	wantCode(t, err, "renewal_uncertain")
	_, err = m.Headers("alice", server.URL)
	wantCode(t, err, "renewal_uncertain")
	states, loadErr := v.LoadAll()
	if loadErr != nil || len(states) != 1 || states[0].Status != "uncertain" {
		t.Fatalf("malformed capture was not durably quarantined: %#v %v", states, loadErr)
	}
}

func boundaryCredentials(t *testing.T, m *Manager, id string) Import {
	t.Helper()
	now := time.Now().UTC()
	secrets := map[string]string{"padding": ""}
	for i := 0; i < 15; i++ {
		secrets[fmt.Sprintf("s%02d", i)] = strings.Repeat("x", 64<<10)
	}
	s := &State{
		ID: id, Provider: "test", ConfigHash: m.providers["test"].hash,
		Status: "ready", CreatedAt: now, UpdatedAt: now, NextRefresh: now,
		RefreshToken: "r", Secrets: secrets,
	}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	padding := (1 << 20) - len(raw)
	if padding < 1 || padding > 64<<10 {
		t.Fatalf("unexpected boundary padding %d", padding)
	}
	secrets["padding"] = strings.Repeat("x", padding)
	raw, err = json.Marshal(s)
	if err != nil || len(raw) != 1<<20 {
		t.Fatalf("boundary setup produced %d bytes: %v", len(raw), err)
	}
	return Import{Provider: "test", RefreshToken: "r", Secrets: secrets}
}

func TestImportChecksFinalRevisionSizedState(t *testing.T) {
	t.Run("new", func(t *testing.T) {
		m, _, _ := managerFor(t, providerFor("http://127.0.0.1:11111"))
		_, err := m.Import("alice", boundaryCredentials(t, m, "alice"))
		wantCode(t, err, "invalid_request")
		if len(m.List()) != 0 {
			t.Fatal("boundary import installed an unpersistable session")
		}
	})
	t.Run("replacement", func(t *testing.T) {
		m, v, _ := managerFor(t, providerFor("http://127.0.0.1:11111"))
		meta, err := m.Import("alice", Import{Provider: "test", RefreshToken: "old"})
		if err != nil {
			t.Fatal(err)
		}
		in := boundaryCredentials(t, m, "alice")
		in.Replace = true
		in.ExpectedRevision = &meta.Revision
		_, err = m.Import("alice", in)
		wantCode(t, err, "invalid_request")
		e, _ := m.get("alice")
		if e.state.RefreshToken != "old" || e.dirty {
			t.Fatal("invalid replacement changed in-memory credentials")
		}
		states, loadErr := v.LoadAll()
		if loadErr != nil || len(states) != 1 || states[0].RefreshToken != "old" {
			t.Fatalf("invalid replacement changed durable credentials: %#v %v", states, loadErr)
		}
	})
}

func TestOversizedRenewalPersistsBoundedUncertainty(t *testing.T) {
	largeToken := strings.Repeat("a", 64<<10)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": largeToken, "token_type": "Bearer", "expires_in": 3600,
		})
	}))
	defer server.Close()
	m, v, _ := managerFor(t, providerFor(server.URL))
	secrets := map[string]string{}
	for i := 0; i < 15; i++ {
		secrets[fmt.Sprintf("s%02d", i)] = strings.Repeat("x", 64<<10)
	}
	if _, err := m.Import("alice", Import{Provider: "test", RefreshToken: "r0", Secrets: secrets}); err != nil {
		t.Fatal(err)
	}
	_, err := m.Refresh("alice")
	wantCode(t, err, "renewal_uncertain")
	_, err = m.Headers("alice", server.URL)
	wantCode(t, err, "renewal_uncertain")
	states, loadErr := v.LoadAll()
	if loadErr != nil || len(states) != 1 {
		t.Fatalf("load state: %v", loadErr)
	}
	if states[0].Status != "uncertain" || states[0].PendingRefresh || !stateFitsVault(states[0]) {
		t.Fatalf("oversized renewal was not durably bounded: %#v", states[0])
	}
}

func TestWindowsTaskHasRecurringRecoveryTrigger(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "install-windows.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	for _, required := range []string{
		"$RecoveryTrigger", "-RepetitionInterval", "@($LogonTrigger, $RecoveryTrigger)",
		"-MultipleInstances IgnoreNew",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("Windows recovery configuration missing %q", required)
		}
	}
}

func TestRejectedManagedCookieRotationPersistsUncertainty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "replacement", Path: "/", Secure: true})
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer server.Close()
	m, v, _ := managerFor(t, providerFor(server.URL))
	if _, err := m.Import("alice", Import{
		Provider: "test", RefreshToken: "r0", CookieOrigin: server.URL, CookieHeader: "sid=old",
	}); err != nil {
		t.Fatal(err)
	}
	e, _ := m.get("alice")
	e.state.NextRefresh = time.Now().Add(time.Hour)
	_, err := m.Request("alice", RequestInput{URL: server.URL})
	wantCode(t, err, "renewal_uncertain")
	_, err = m.Headers("alice", server.URL)
	wantCode(t, err, "renewal_uncertain")
	states, loadErr := v.LoadAll()
	if loadErr != nil || len(states) != 1 || states[0].Status != "uncertain" {
		t.Fatalf("rejected managed rotation was not quarantined: %#v %v", states, loadErr)
	}
}

func TestStartupRecoveryBoundsTerminalMetadata(t *testing.T) {
	m, v, dir := managerFor(t, providerFor("http://127.0.0.1:11111"))
	now := time.Now().UTC()
	s := &State{
		ID: "alice", Provider: "test", ConfigHash: m.providers["test"].hash,
		Status: "ready", Revision: 1, CreatedAt: now, UpdatedAt: now,
		PendingRequest: true, Secrets: map[string]string{"padding": ""},
	}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	s.Secrets["padding"] = strings.Repeat("x", (1<<20)-len(raw))
	raw, err = json.Marshal(s)
	if err != nil || len(raw) != 1<<20 {
		t.Fatalf("boundary setup produced %d bytes: %v", len(raw), err)
	}
	if err = v.Save(s); err != nil {
		t.Fatal(err)
	}
	if err = v.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenVault(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recovered, err := NewManager(reopened, Config{Providers: []Provider{providerFor("http://127.0.0.1:11111")}})
	if err != nil {
		t.Fatal(err)
	}
	e, err := recovered.get("alice")
	if err != nil {
		t.Fatal(err)
	}
	if e.state.Status != "uncertain" || e.state.PendingRequest || len(e.state.Secrets) != 0 || !stateFitsVault(e.state) {
		t.Fatalf("startup recovery did not persist bounded uncertainty: %#v", e.state)
	}
}

func TestRejectedExternalCapturePersistsUncertainty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	m, v, _ := managerFor(t, providerFor(server.URL))
	if _, err := m.Import("alice", Import{
		Provider: "test", RefreshToken: "r0", CookieOrigin: server.URL, CookieHeader: "sid=old",
	}); err != nil {
		t.Fatal(err)
	}
	_, err := m.Capture("alice", server.URL, []string{"sid=replacement; Secure; Path=/"})
	wantCode(t, err, "renewal_uncertain")
	_, err = m.Headers("alice", server.URL)
	wantCode(t, err, "renewal_uncertain")
	states, loadErr := v.LoadAll()
	if loadErr != nil || len(states) != 1 || states[0].Status != "uncertain" {
		t.Fatalf("rejected external capture was not quarantined: %#v %v", states, loadErr)
	}
}

func TestRejectedRenewalCookieRotationIsTerminal(t *testing.T) {
	for _, setCookie := range []string{"sid=replacement; Secure; Path=/", "not a cookie"} {
		t.Run(setCookie, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Add("Set-Cookie", setCookie)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"access_token": "a1", "refresh_token": "r1",
					"token_type": "Bearer", "expires_in": 3600,
				})
			}))
			defer server.Close()
			m, v, _ := managerFor(t, providerFor(server.URL))
			if _, err := m.Import("alice", Import{
				Provider: "test", RefreshToken: "r0", CookieOrigin: server.URL, CookieHeader: "sid=old",
			}); err != nil {
				t.Fatal(err)
			}
			_, err := m.Refresh("alice")
			wantCode(t, err, "protocol_error")
			_, err = m.Headers("alice", server.URL)
			wantCode(t, err, "protocol_error")
			states, loadErr := v.LoadAll()
			if loadErr != nil || len(states) != 1 || states[0].Status != "protocol_error" || states[0].RefreshToken != "r1" {
				t.Fatalf("rejected renewal rotation was not terminal: %#v %v", states, loadErr)
			}
		})
	}
}
