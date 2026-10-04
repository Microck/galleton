package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestShutdownFlushPreservesDirtyRotation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { jsonOK(w, "a1", "r1") }))
	defer server.Close()
	m, v, dir := managerFor(t, providerFor(server.URL))
	importOAuth(t, m)
	failed := false
	v.saveHook = func(s *State) error {
		if !s.PendingRefresh && s.RefreshToken == "r1" && !failed {
			failed = true
			return errors.New("transient disk failure")
		}
		return nil
	}
	_, err := m.Refresh("alice")
	wantCode(t, err, "storage_failure")
	m.BeginShutdown()
	if err := m.FlushAll(); err != nil { t.Fatal(err) }
	if err := v.Close(); err != nil { t.Fatal(err) }
	reopened, err := OpenVault(dir)
	if err != nil { t.Fatal(err) }
	defer reopened.Close()
	next, err := NewManager(reopened, Config{Providers: []Provider{providerFor(server.URL)}})
	if err != nil { t.Fatal(err) }
	e, _ := next.get("alice")
	if e.state.RefreshToken != "r1" || e.state.PendingRefresh || e.state.Status != "ready" { t.Fatal("rotation lost at shutdown") }
}

func TestShutdownReportsUnflushedCredentials(t *testing.T) {
	m, v, _ := managerFor(t, providerFor("http://127.0.0.1:9999"))
	importOAuth(t, m)
	e, _ := m.get("alice")
	e.dirty = true
	v.saveHook = func(*State) error { return errors.New("disk unavailable") }
	m.BeginShutdown()
	wantCode(t, m.FlushAll(), "storage_failure")
}

func TestReplacementImportRejectsStaleRetries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { jsonOK(w, "a1", "rotated") }))
	defer server.Close()
	m, _, _ := managerFor(t, providerFor(server.URL))
	importOAuth(t, m)
	meta, _ := m.Status("alice")
	in := Import{Provider: "test", RefreshToken: "replacement", Replace: true, ExpectedRevision: &meta.Revision}
	if _, err := m.Import("alice", in); err != nil { t.Fatal(err) }
	if _, err := m.Refresh("alice"); err != nil { t.Fatal(err) }
	_, err := m.Import("alice", in)
	wantCode(t, err, "revision_conflict")
	e, _ := m.get("alice")
	if e.state.RefreshToken != "rotated" { t.Fatal("replayed import overwrote rotation") }
	_, err = m.Import("alice", Import{Provider: "test", RefreshToken: "old", Replace: true})
	wantCode(t, err, "revision_conflict")
	if err := m.Forget("alice"); err != nil { t.Fatal(err) }
	_, err = m.Import("alice", in)
	wantCode(t, err, "revision_conflict")
}

func TestBusySessionMutationsDoNotBlockOtherSessions(t *testing.T) {
	for _, operation := range []string{"replace", "forget"} {
		t.Run(operation, func(t *testing.T) {
			m, _, _ := managerFor(t, providerFor("http://127.0.0.1:9999"))
			importOAuth(t, m)
			if _, err := m.Import("bob", Import{Provider: "test", RefreshToken: "r0"}); err != nil { t.Fatal(err) }
			e, _ := m.get("alice")
			e.mu.Lock()
			revision := e.state.Revision
			done := make(chan error, 1)
			go func() {
				if operation == "forget" { done <- m.Forget("alice"); return }
				_, err := m.Import("alice", Import{Provider: "test", RefreshToken: "r1", Replace: true, ExpectedRevision: &revision})
				done <- err
			}()
			time.Sleep(20 * time.Millisecond)
			other := make(chan error, 1)
			go func() { _, err := m.Status("bob"); other <- err }()
			blocked := false
			select {
			case err := <-other: if err != nil { t.Error(err) }
			case <-time.After(time.Second): blocked = true
			}
			e.mu.Unlock()
			if err := <-done; err != nil { t.Fatal(err) }
			if blocked { t.Fatal("busy session blocked unrelated status") }
		})
	}
}

func TestRetryWaitAllowsValidCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "resource") }))
	defer server.Close()
	for _, expiry := range []time.Time{{}, time.Now().Add(time.Hour)} {
		m, _, _ := managerFor(t, providerFor(server.URL))
		if _, err := m.Import("alice", Import{Provider: "test", AccessToken: "a1", RefreshToken: "r0", AccessExpiresAt: expiry}); err != nil { t.Fatal(err) }
		e, _ := m.get("alice")
		e.state.Status = "retry_wait"
		e.state.NextRefresh = time.Now().Add(time.Minute)
		if _, err := m.Headers("alice", server.URL); err != nil { t.Fatal(err) }
		if _, err := m.Request("alice", RequestInput{URL: server.URL}); err != nil { t.Fatal(err) }
		_, err := m.Refresh("alice")
		wantCode(t, err, "retry_later")
		e.state.AccessExpiresAt = time.Now().Add(-time.Second)
		_, err = m.Headers("alice", server.URL)
		wantCode(t, err, "retry_later")
	}
}

func TestCookieOverflowStopsCredentialReuse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "rotated", Path: "/"})
		for i := 0; i < 256; i++ { http.SetCookie(w, &http.Cookie{Name: fmt.Sprintf("c%d", i), Value: "v", Path: "/"}) }
		fmt.Fprint(w, "resource")
	}))
	defer server.Close()
	m, v, _ := managerFor(t, providerFor(server.URL))
	if _, err := m.Import("alice", Import{Provider: "test", RefreshToken: "r0", CookieOrigin: server.URL, CookieHeader: "sid=old"}); err != nil { t.Fatal(err) }
	e, _ := m.get("alice")
	e.state.NextRefresh = time.Now().Add(time.Hour)
	_, err := m.Request("alice", RequestInput{URL: server.URL})
	wantCode(t, err, "renewal_uncertain")
	_, err = m.Headers("alice", server.URL)
	wantCode(t, err, "renewal_uncertain")
	states, err := v.LoadAll()
	if err != nil || states[0].Status != "uncertain" { t.Fatal("capture failure not persisted") }
}

func TestVaultFilenamesPreserveCaseAndAvoidDeviceNames(t *testing.T) {
	v, dir := openTestVault(t)
	ids := []string{"Alice", "alice", "CON", "NUL", "aux"}
	names := map[string]bool{}
	for _, id := range ids {
		name := strings.ToLower(sessionFilename(id))
		if names[name] { t.Fatal("case-insensitive collision") }
		names[name] = true
		if err := v.Save(&State{ID: id, RefreshToken: "test-" + id}); err != nil { t.Fatal(err) }
		if _, err := os.Stat(filepath.Join(dir, sessionFilename(id))); err != nil { t.Fatal(err) }
	}
	states, err := v.LoadAll()
	if err != nil || len(states) != len(ids) { t.Fatalf("reload: %v", err) }
	if err := v.Delete("Alice"); err != nil { t.Fatal(err) }
	states, err = v.LoadAll()
	if err != nil || len(states) != len(ids)-1 { t.Fatal("delete collided") }
	for _, s := range states { if s.ID == "Alice" { t.Fatal("deleted session survived") } }
}

func TestInvalidReplacementRefreshTokensAreTerminal(t *testing.T) {
	for _, value := range []any{"", "bad\r\ntoken", strings.Repeat("x", (64<<10)+1), 42, nil} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "a1", "token_type": "Bearer", "refresh_token": value})
		}))
		m, _, _ := managerFor(t, providerFor(server.URL))
		importOAuth(t, m)
		_, err := m.Refresh("alice")
		wantCode(t, err, "protocol_error")
		_, err = m.Headers("alice", server.URL)
		wantCode(t, err, "protocol_error")
		server.Close()
	}
}

func TestAbsentTimestampsOmittedAndPresentValuesRoundTrip(t *testing.T) {
	for _, value := range []any{State{}, Metadata{}, Problem{}, HeadersResult{}} {
		raw, err := json.Marshal(value)
		if err != nil { t.Fatal(err) }
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil { t.Fatal(err) }
		for _, key := range []string{"last_refresh", "next_refresh", "access_expires_at", "retry_at", "expires_at"} {
			if _, exists := fields[key]; exists { t.Fatalf("zero %s present: %s", key, raw) }
		}
	}
	now := time.Now().UTC()
	raw, err := json.Marshal(State{LastRefresh: now, NextRefresh: now, AccessExpiresAt: now})
	if err != nil { t.Fatal(err) }
	var state State
	if err := json.Unmarshal(raw, &state); err != nil { t.Fatal(err) }
	if !state.LastRefresh.Equal(now) || !state.NextRefresh.Equal(now) || !state.AccessExpiresAt.Equal(now) { t.Fatal("timestamps changed") }
}

func TestUpstreamHeaderWaitUsesRequestContext(t *testing.T) {
	transport := newUpstreamClient().Transport.(*http.Transport)
	if transport.ResponseHeaderTimeout != 0 { t.Fatal("shared transport overrides provider context timeout") }
}

func TestAmbiguousResourceRequestPausesCredentialReuse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil { t.Error(err); return }
		_ = conn.Close()
	}))
	defer server.Close()
	m, v, _ := managerFor(t, providerFor(server.URL))
	if _, err := m.Import("alice", Import{Provider: "test", AccessToken: "a0", RefreshToken: "r0"}); err != nil {
		t.Fatal(err)
	}
	e, _ := m.get("alice")
	e.state.NextRefresh = time.Now().Add(time.Hour)
	_, err := m.Request("alice", RequestInput{URL: server.URL + "/resource"})
	wantCode(t, err, "renewal_uncertain")
	_, err = m.Headers("alice", server.URL)
	wantCode(t, err, "renewal_uncertain")
	states, err := v.LoadAll()
	if err != nil || len(states) != 1 || states[0].Status != "uncertain" {
		t.Fatalf("ambiguous resource failure was not persisted: %v", err)
	}
}

func TestPreConnectionResourceFailureRemainsRetryable(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	rawURL := "http://" + listener.Addr().String()
	if err := listener.Close(); err != nil { t.Fatal(err) }
	m, _, _ := managerFor(t, providerFor(rawURL))
	if _, err := m.Import("alice", Import{Provider: "test", AccessToken: "a0", RefreshToken: "r0"}); err != nil {
		t.Fatal(err)
	}
	e, _ := m.get("alice")
	e.state.NextRefresh = time.Now().Add(time.Hour)
	_, err = m.Request("alice", RequestInput{URL: rawURL + "/resource"})
	wantCode(t, err, "upstream_request_failed")
	meta, err := m.Status("alice")
	if err != nil || meta.Status != "ready" {
		t.Fatalf("safe dial failure changed session state: %#v %v", meta, err)
	}
}

func TestRevisionWatermarkSurvivesForgetAndRestart(t *testing.T) {
	m, v, dir := managerFor(t, providerFor("http://127.0.0.1:9999"))
	first, err := m.Import("alice", Import{Provider: "test", RefreshToken: "r0"})
	if err != nil { t.Fatal(err) }
	delayed := first.Revision
	if err := m.Forget("alice"); err != nil { t.Fatal(err) }
	ahead := uint64(time.Now().Add(time.Hour).UnixMilli())
	if err := v.recordRevision(ahead); err != nil { t.Fatal(err) }
	if err := v.Close(); err != nil { t.Fatal(err) }
	reopened, err := OpenVault(dir)
	if err != nil { t.Fatal(err) }
	defer reopened.Close()
	m2, err := NewManager(reopened, Config{Providers: []Provider{providerFor("http://127.0.0.1:9999")}})
	if err != nil { t.Fatal(err) }
	fresh, err := m2.Import("alice", Import{Provider: "test", RefreshToken: "fresh"})
	if err != nil { t.Fatal(err) }
	if fresh.Revision <= ahead || fresh.Revision > maxRevision {
		t.Fatalf("revision %d did not advance durable watermark %d", fresh.Revision, ahead)
	}
	_, err = m2.Import("alice", Import{
		Provider: "test", RefreshToken: "delayed", Replace: true, ExpectedRevision: &delayed,
	})
	wantCode(t, err, "revision_conflict")
	e, _ := m2.get("alice")
	if e.state.RefreshToken != "fresh" { t.Fatal("delayed replacement overwrote reimport") }
}
