package core

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestOversizedCapturedStatePersistsBoundedUncertainty(t *testing.T) {
	rawURL := "http://127.0.0.1:9999"
	m, v, _ := managerFor(t, providerFor(rawURL))
	if _, err := m.Import("alice", Import{Provider: "test", AccessToken: "a0", RefreshToken: "r0"}); err != nil {
		t.Fatal(err)
	}
	e, _ := m.get("alice")
	e.state.NextRefresh = time.Now().Add(time.Hour)
	lines := make([]string, 256)
	for i := range lines {
		lines[i] = fmt.Sprintf("c%03d=%s; Path=/", i, strings.Repeat("x", 5000))
	}
	_, err := m.Capture("alice", rawURL, lines)
	wantCode(t, err, "renewal_uncertain")
	_, err = m.Headers("alice", rawURL)
	wantCode(t, err, "renewal_uncertain")
	states, err := v.LoadAll()
	if err != nil || len(states) != 1 || states[0].Status != "uncertain" {
		t.Fatalf("bounded uncertain state was not persisted: %v", err)
	}
	raw, err := json.Marshal(states[0])
	if err != nil { t.Fatal(err) }
	if len(raw) > 1<<20 {
		t.Fatalf("persisted state exceeds vault limit: %d", len(raw))
	}
}

func TestStateSizeCheckReservesCommitTimestampGrowth(t *testing.T) {
	state := &State{
		ID: "alice", Provider: "test", Status: "ready", Revision: 1,
		CreatedAt: time.Unix(0, 0).UTC(), UpdatedAt: time.Unix(0, 0).UTC(),
		Secrets: map[string]string{"padding": ""},
	}
	base, err := json.Marshal(state)
	if err != nil { t.Fatal(err) }
	state.Secrets["padding"] = strings.Repeat("x", (1<<20)-len(base))
	raw, err := json.Marshal(state)
	if err != nil { t.Fatal(err) }
	if len(raw) != 1<<20 { t.Fatalf("boundary setup produced %d bytes", len(raw)) }
	if stateFitsVault(state) {
		t.Fatal("size check did not reserve maximum UpdatedAt growth")
	}
}
