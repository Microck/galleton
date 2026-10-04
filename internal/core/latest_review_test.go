package core

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

func TestSystemdInstallerRestoresPriorUnitOnFailedRestart(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires a POSIX shell")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	binDir := filepath.Join(root, "bin")
	state := filepath.Join(root, "state")
	for _, dir := range []string{home, binDir, state} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(root, "galleton")
	config := filepath.Join(root, "adapters.json")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "api.token"), []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	unitDir := filepath.Join(home, ".config", "systemd", "user")
	if err := os.MkdirAll(unitDir, 0o700); err != nil {
		t.Fatal(err)
	}
	unitPath := filepath.Join(unitDir, "galleton.service")
	const oldUnit = "old working unit\n"
	if err := os.WriteFile(unitPath, []byte(oldUnit), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(root, "systemctl.log")
	markerPath := filepath.Join(root, "restart.failed")
	fake := `#!/bin/sh
echo "$*" >> "$GALLETON_TEST_LOG"
case "$*" in
  *"is-enabled"*) exit 0 ;;
  *"is-active"*) exit 0 ;;
  *"restart galleton.service"*)
    if [ ! -e "$GALLETON_TEST_MARKER" ]; then
      : > "$GALLETON_TEST_MARKER"
      exit 1
    fi
    ;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(binDir, "systemctl"), []byte(fake), 0o700); err != nil {
		t.Fatal(err)
	}
	installer := filepath.Join("..", "..", "deploy", "install-systemd.sh")
	cmd := exec.Command("sh", installer, binary, state, config)
	cmd.Env = append(os.Environ(),
		"HOME="+home,
		"XDG_CONFIG_HOME="+filepath.Join(home, ".config"),
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GALLETON_TEST_LOG="+logPath,
		"GALLETON_TEST_MARKER="+markerPath,
	)
	if err := cmd.Run(); err == nil {
		t.Fatal("installer succeeded despite synthetic restart failure")
	}
	got, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != oldUnit {
		t.Fatalf("failed reinstall left unit %q, want restored %q", got, oldUnit)
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(logData)
	if strings.Count(log, "--user daemon-reload") < 2 ||
		strings.Count(log, "--user restart galleton.service") < 2 {
		t.Fatalf("rollback did not reload and restart the prior unit:\n%s", log)
	}
}

func TestLaunchdInstallerRestoresPriorPlist(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "install-launchd.py"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	for _, required := range []string{
		"previous = destination.read_bytes()",
		"was_loaded = subprocess.run(",
		"except Exception:",
		"write_plist(previous)",
		"destination.unlink(missing_ok=True)",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("launchd rollback missing %q", required)
		}
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
	if !got.ExpiresAt.IsZero() {
		t.Fatalf("cookie-only headers expose expired bearer deadline %s", got.ExpiresAt)
	}
}

func TestAuthenticatedShutdownEndpoint(t *testing.T) {
	m, _, _ := managerFor(t, providerFor("http://127.0.0.1:11111"))
	stopped := make(chan struct{})
	h := HandlerWithShutdown(m, "local-token", func() { close(stopped) })
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/v1/shutdown", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer local-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusAccepted || !strings.Contains(w.Body.String(), `"stopping":true`) {
		t.Fatalf("shutdown response = %d %s", w.Code, w.Body.String())
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("authenticated shutdown callback was not invoked")
	}
}

func TestWindowsInstallerGracefullyReplacesRunningTask(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "install-windows.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	disable := strings.Index(script, "Disable-ScheduledTask")
	shutdown := strings.Index(script, "& $Binary shutdown --dir $ExistingStateDir")
	wait := strings.Index(script, "Test-GalletonTaskRunning) -and")
	register := strings.Index(script, `Register-ScheduledTask -TaskName "Galleton" -Action $Action`)
	start := strings.Index(script, `Start-ScheduledTask -TaskName "Galleton"`)
	rollback := strings.Index(script, `Register-ScheduledTask -TaskName "Galleton" -Xml $ExistingTaskXML -Force`)
	if disable < 0 || shutdown < disable || wait < shutdown || register < wait || start < register || rollback < start {
		t.Fatalf("installer does not disable, gracefully drain, replace, then start the task inside rollback coverage")
	}
	for _, required := range []string{
		"GetRunningTasks(1)", ".AddSeconds(330)", "Export-ScheduledTask",
		"$ExistingTaskWasEnabled", "$ExistingTaskWasRunning", "Unregister-ScheduledTask",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("Windows handoff missing %q", required)
		}
	}
}

func TestRefreshHeaderDefaultsPreserveAdapterValues(t *testing.T) {
	tests := []struct {
		name       string
		configured map[string]string
		wantAccept string
		wantAgent  string
	}{
		{"defaults", nil, "application/json", "Galleton/" + Version},
		{"configured", map[string]string{
			"Accept": "application/vnd.example+json",
			"User-Agent": "Example-Renewer/1.0",
		}, "application/vnd.example+json", "Example-Renewer/1.0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var gotAccept, gotAgent string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotAccept = r.Header.Get("Accept")
				gotAgent = r.Header.Get("User-Agent")
				_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
			}))
			defer server.Close()

			p := providerFor(server.URL)
			p.Kind = "http"
			p.RefreshURL = server.URL + "/token"
			p.RefreshMethod = "POST"
			p.RefreshHeaders = tc.configured
			p.Response = ResponseMapping{Success: "/ok"}
			m, _, _ := managerFor(t, p)
			if _, err := m.Import("alice", Import{Provider: "test", RefreshToken: "r0"}); err != nil {
				t.Fatal(err)
			}
			if _, err := m.Refresh("alice"); err != nil {
				t.Fatal(err)
			}
			if gotAccept != tc.wantAccept || gotAgent != tc.wantAgent {
				t.Fatalf("refresh headers = Accept %q, User-Agent %q; want %q, %q", gotAccept, gotAgent, tc.wantAccept, tc.wantAgent)
			}
		})
	}
}
