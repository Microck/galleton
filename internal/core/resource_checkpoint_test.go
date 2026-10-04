package core

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestResourceCheckpointBlocksReplayAfterRestart(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "rotated", Path: "/"})
	}))
	defer server.Close()
	m, v, dir := managerFor(t, providerFor(server.URL))
	if _, err := m.Import("alice", Import{Provider: "test", AccessToken: "a0", RefreshToken: "r0"}); err != nil {
		t.Fatal(err)
	}
	e, _ := m.get("alice")
	e.state.NextRefresh = time.Now().Add(time.Hour)
	done := make(chan error, 1)
	go func() { _, err := m.Request("alice", RequestInput{URL: server.URL}); done <- err }()
	defer func() {
		close(release)
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	<-entered
	// Snapshot the durable files while the provider has consumed the request
	// but has not returned its rotated cookie, then recover that snapshot.
	snapshot := t.TempDir()
	for _, name := range []string{"master.key", revisionWatermarkFile, sessionFilename("alice")} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(snapshot, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	recovered, err := OpenVault(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	m2, err := NewManager(recovered, Config{Providers: []Provider{providerFor(server.URL)}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = m2.Headers("alice", server.URL)
	wantCode(t, err, "renewal_uncertain")
	_, err = m2.Request("alice", RequestInput{URL: server.URL})
	wantCode(t, err, "renewal_uncertain")
	states, err := v.LoadAll()
	if err != nil || len(states) != 1 || !states[0].PendingRequest {
		t.Fatalf("missing durable checkpoint: %v", err)
	}
}

func TestResourceCheckpointWriteFailureSendsNoCredentials(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer server.Close()
	m, v, _ := managerFor(t, providerFor(server.URL))
	if _, err := m.Import("alice", Import{Provider: "test", AccessToken: "a0", RefreshToken: "r0"}); err != nil {
		t.Fatal(err)
	}
	e, _ := m.get("alice")
	e.state.NextRefresh = time.Now().Add(time.Hour)
	v.saveHook = func(s *State) error {
		if s.PendingRequest {
			return errors.New("disk unavailable")
		}
		return nil
	}
	_, err := m.Request("alice", RequestInput{URL: server.URL})
	wantCode(t, err, "storage_failure")
	if calls.Load() != 0 {
		t.Fatal("request reached provider without a durable checkpoint")
	}
	v.saveHook = nil
	if _, err := m.Request("alice", RequestInput{URL: server.URL}); err != nil {
		t.Fatal(err)
	}
	states, err := v.LoadAll()
	if err != nil || len(states) != 1 || states[0].PendingRequest {
		t.Fatalf("successful response left checkpoint: %v", err)
	}
}
