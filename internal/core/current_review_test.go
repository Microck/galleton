package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
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
	cases := []struct {
		name       string
		setCookies []string
		wantCookie string
	}{
		{"rejected", []string{"sid=replacement; Secure; Path=/"}, "old"},
		{"malformed", []string{"not a cookie"}, "old"},
		{"mixed", []string{"sid=replacement; Path=/", "not a cookie"}, "replacement"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for _, line := range tc.setCookies {
					w.Header().Add("Set-Cookie", line)
				}
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
			if loadErr != nil || len(states) != 1 || states[0].Status != "protocol_error" ||
				states[0].RefreshToken != "r1" || len(states[0].Cookies) != 1 ||
				states[0].Cookies[0].Cookie.Value != tc.wantCookie {
				t.Fatalf("rejected renewal rotation was not terminal: %#v %v", states, loadErr)
			}
		})
	}
}

func TestCookieDeletionCanAccompanyValidTokenRenewal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", Path: "/", MaxAge: -1})
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
	if _, err := m.Refresh("alice"); err != nil {
		t.Fatal(err)
	}
	states, err := v.LoadAll()
	if err != nil || len(states) != 1 || states[0].Status != "ready" ||
		states[0].RefreshToken != "r1" || len(states[0].Cookies) != 0 {
		t.Fatalf("valid token renewal with deletion was rejected: %#v %v", states, err)
	}
}

func TestCookieDeletionIsAcceptedByCaptureAndManagedRequest(t *testing.T) {
	t.Run("capture", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		defer server.Close()
		m, v, _ := managerFor(t, providerFor(server.URL))
		if _, err := m.Import("alice", Import{
			Provider: "test", AccessToken: "a0", RefreshToken: "r0",
			CookieOrigin: server.URL, CookieHeader: "sid=old",
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Capture("alice", server.URL, []string{"sid=; Max-Age=0; Path=/"}); err != nil {
			t.Fatal(err)
		}
		states, err := v.LoadAll()
		if err != nil || len(states) != 1 || states[0].Status != "ready" || len(states[0].Cookies) != 0 {
			t.Fatalf("capture deletion was not accepted: %#v %v", states, err)
		}
	})

	t.Run("managed request", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", Path: "/", MaxAge: -1})
			_, _ = fmt.Fprint(w, "ok")
		}))
		defer server.Close()
		m, v, _ := managerFor(t, providerFor(server.URL))
		if _, err := m.Import("alice", Import{
			Provider: "test", AccessToken: "a0", RefreshToken: "r0",
			CookieOrigin: server.URL, CookieHeader: "sid=old",
		}); err != nil {
			t.Fatal(err)
		}
		e, _ := m.get("alice")
		e.state.NextRefresh = time.Now().Add(time.Hour)
		result, err := m.Request("alice", RequestInput{URL: server.URL})
		if err != nil || result.Status != http.StatusOK {
			t.Fatalf("managed deletion failed: %#v %v", result, err)
		}
		states, loadErr := v.LoadAll()
		if loadErr != nil || len(states) != 1 || states[0].Status != "ready" || len(states[0].Cookies) != 0 {
			t.Fatalf("managed deletion was not accepted: %#v %v", states, loadErr)
		}
	})
}

func TestImportRejectsCookieOutsideOrigin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	m, _, _ := managerFor(t, providerFor(server.URL))
	_, err := m.Import("alice", Import{
		Provider:     "test",
		RefreshToken: "r0",
		CookieOrigin: server.URL,
		SetCookies:   []string{"sid=x; Domain=other.test; Path=/"},
	})
	wantCode(t, err, "invalid_request")
	if len(m.List()) != 0 {
		t.Fatal("rejected import created a session")
	}
}

func TestStateFitsVaultReservesCheckpointSpace(t *testing.T) {
	const limit = 1 << 20
	s := &State{
		ID: "alice", Provider: "test", ConfigHash: "hash", Status: "ready",
		CreatedAt: time.Now().UTC(), Secrets: map[string]string{"padding": ""},
	}
	readySize := func(n int) int {
		probe := cloneState(s)
		probe.UpdatedAt = time.Date(2000, 1, 1, 0, 0, 0, 999999999, time.UTC)
		probe.Secrets["padding"] = strings.Repeat("x", n)
		raw, err := json.Marshal(probe)
		if err != nil {
			t.Fatal(err)
		}
		return len(raw)
	}
	low, high := 0, limit+1
	for low+1 < high {
		mid := low + (high-low)/2
		if readySize(mid) <= limit {
			low = mid
		} else {
			high = mid
		}
	}
	s.Secrets["padding"] = strings.Repeat("x", low)
	checkpoint := cloneState(s)
	checkpoint.UpdatedAt = time.Date(2000, 1, 1, 0, 0, 0, 999999999, time.UTC)
	checkpoint.PendingRefresh = true
	checkpoint.PendingRequest = true
	checkpoint.Status = "refreshing"
	raw, err := json.Marshal(checkpoint)
	if err != nil || readySize(low) > limit || len(raw) <= limit {
		t.Fatalf("invalid boundary fixture: ready=%d checkpoint=%d err=%v", readySize(low), len(raw), err)
	}
	if stateFitsVault(s) {
		t.Fatal("state accepted without room for its pre-send checkpoint")
	}
}

func TestFailedCheckpointDoesNotMarkCleanStateDirty(t *testing.T) {
	m, v, _ := managerFor(t, providerFor("http://127.0.0.1:11111"))
	importOAuth(t, m)
	v.saveHook = func(s *State) error {
		if s.PendingRefresh {
			return fmt.Errorf("checkpoint fault")
		}
		return nil
	}
	_, err := m.Refresh("alice")
	wantCode(t, err, "storage_failure")
	e, getErr := m.get("alice")
	if getErr != nil {
		t.Fatal(getErr)
	}
	if e.dirty {
		t.Fatal("failed pre-send checkpoint marked unchanged state dirty")
	}
}

func TestPostResponseSaveFailureWarnsAgainstRetry(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer server.Close()
	m, v, _ := managerFor(t, providerFor(server.URL))
	if _, err := m.Import("alice", Import{
		Provider: "test", AccessToken: "a0", RefreshToken: "r0", AccessExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	e, err := m.get("alice")
	if err != nil {
		t.Fatal(err)
	}
	e.state.NextRefresh = time.Now().Add(time.Hour)
	v.saveHook = func(s *State) error {
		if !s.PendingRequest {
			return fmt.Errorf("post-response save fault")
		}
		return nil
	}
	_, err = m.Request("alice", RequestInput{URL: server.URL, Method: "POST", BodyBase64: "e30="})
	wantCode(t, err, "storage_failure")
	p := AsProblem(err)
	if !strings.Contains(p.Message, "request was sent") || !strings.Contains(p.Message, "do not retry") {
		t.Fatalf("post-response storage failure is ambiguous: %q", p.Message)
	}
	if hits.Load() != 1 {
		t.Fatalf("upstream hit count = %d, want 1", hits.Load())
	}
}

func TestConfigurationErrorPersistsAtVaultBoundary(t *testing.T) {
	p := providerFor("http://127.0.0.1:11111")
	p.Kind = "http"
	p.RefreshMethod = "POST"
	p.BodyFormat = "form"
	p.Body = map[string]string{"credential": "${secret.missing}"}
	m, v, _ := managerFor(t, p)
	now := time.Now().UTC()
	s := &State{
		ID: "alice", Provider: "test", ConfigHash: m.providers["test"].hash,
		Status: "ready", Revision: 1, CreatedAt: now, UpdatedAt: now,
		Secrets: map[string]string{"padding": ""},
	}
	for i := 0; i < 15; i++ {
		s.Secrets[fmt.Sprintf("s%02d", i)] = strings.Repeat("x", 64<<10)
	}
	low, high := 0, 64<<10
	for low+1 < high {
		mid := low + (high-low)/2
		s.Secrets["padding"] = strings.Repeat("x", mid)
		if stateFitsVault(s) {
			low = mid
		} else {
			high = mid
		}
	}
	s.Secrets["padding"] = strings.Repeat("x", low)
	terminal := cloneState(s)
	terminal.Status = "configuration_error"
	terminal.LastError = problem(409, "configuration_error", "Missing refresh credentials or invalid adapter template.")
	if !stateFitsVault(s) || stateFitsVault(terminal) {
		t.Fatal("invalid boundary fixture")
	}
	if err := v.Save(s); err != nil {
		t.Fatal(err)
	}
	m.entries["alice"] = &entry{state: s}
	_, err := m.Refresh("alice")
	wantCode(t, err, "configuration_error")
	states, loadErr := v.LoadAll()
	if loadErr != nil || len(states) != 1 || states[0].Status != "configuration_error" || !stateFitsVault(states[0]) {
		t.Fatalf("configuration error was not durably bounded: %#v %v", states, loadErr)
	}
	e, getErr := m.get("alice")
	if getErr != nil || e.dirty {
		t.Fatalf("configuration error left a dirty entry: %v", getErr)
	}
}

func TestRetryWaitCookieCapturePreservesDeadline(t *testing.T) {
	for _, operation := range []string{"capture", "request"} {
		t.Run(operation, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.SetCookie(w, &http.Cookie{Name: "sid", Value: "from-request", Path: "/"})
				_, _ = fmt.Fprint(w, "ok")
			}))
			defer server.Close()
			p := providerFor(server.URL)
			p.RefreshIntervalSeconds = 60
			m, _, _ := managerFor(t, p)
			if _, err := m.Import("alice", Import{
				Provider: "test", RefreshToken: "r0", CookieOrigin: server.URL, CookieHeader: "sid=old",
			}); err != nil {
				t.Fatal(err)
			}
			e, err := m.get("alice")
			if err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().UTC().Add(time.Hour)
			e.state.Status = "retry_wait"
			e.state.NextRefresh = deadline
			switch operation {
			case "capture":
				if _, err = m.Capture("alice", server.URL, []string{"sid=from-capture; Path=/"}); err != nil {
					t.Fatal(err)
				}
			case "request":
				if _, err = m.Request("alice", RequestInput{URL: server.URL}); err != nil {
					t.Fatal(err)
				}
			}
			if e.state.Status != "retry_wait" || !e.state.NextRefresh.Equal(deadline) {
				t.Fatalf("%s shortened retry deadline: status=%s got=%s want=%s", operation, e.state.Status, e.state.NextRefresh, deadline)
			}
		})
	}
}
