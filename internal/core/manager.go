package core

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type entry struct {
	mu        sync.Mutex
	state     *State
	dirty     bool // A rotated credential is in memory but not durably acknowledged.
	deleted   bool
	completed time.Time
}
type Manager struct {
	mu        sync.RWMutex
	entries   map[string]*entry
	providers map[string]*Provider
	vault     *Vault
	upstream  *http.Client
	stopping  atomic.Bool
}

func NewManager(v *Vault, c Config) (*Manager, error) {
	providers, err := compileProviders(c)
	if err != nil {
		return nil, err
	}
	states, err := v.LoadAll()
	if err != nil {
		return nil, err
	}
	m := &Manager{entries: map[string]*entry{}, providers: providers, vault: v, upstream: newUpstreamClient()}
	for _, s := range states {
		changed := false
		if s.PendingRefresh || s.PendingRequest {
			s.PendingRefresh = false
			s.PendingRequest = false
			s.Status = "uncertain"
			s.LastError = problem(409, "renewal_uncertain", "The process stopped during a credential-bearing operation; automatic replay is paused.")
			changed = true
		}
		if p, ok := providers[s.Provider]; !ok || s.ConfigHash != p.hash {
			s.Status = "configuration_error"
			s.LastError = problem(409, "configuration_error", "Provider configuration changed; reconnect explicitly before using it.")
			changed = true
		}
		if changed {
			boundTerminalState(s)
			if err = v.Save(s); err != nil {
				return nil, err
			}
		}
		m.entries[s.ID] = &entry{state: s}
	}
	return m, nil
}
func cloneState(s *State) *State {
	n := *s
	n.Cookies = append([]StoredCookie(nil), s.Cookies...)
	n.Secrets = map[string]string{}
	for k, v := range s.Secrets {
		n.Secrets[k] = v
	}
	return &n
}
func stateFitsVault(s *State) bool {
	probe := cloneState(s)
	// commit replaces UpdatedAt. Measure with the longest UTC RFC3339Nano form
	// so a candidate accepted here cannot grow past the vault limit afterward.
	probe.UpdatedAt = time.Date(2000, 1, 1, 0, 0, 0, 999999999, time.UTC)
	// Reserve room for the pre-send checkpoints written by ensure and Request.
	probe.PendingRefresh = true
	probe.PendingRequest = true
	if len(probe.Status) < len("refreshing") {
		probe.Status = "refreshing"
	}
	raw, err := json.Marshal(probe)
	return err == nil && len(raw) <= 1<<20
}
func boundTerminalState(s *State) {
	if stateFitsVault(s) {
		return
	}
	s.AccessToken = ""
	s.RefreshToken = ""
	s.AccessExpiresAt = time.Time{}
	s.Secrets = map[string]string{}
	s.Cookies = nil
	s.NextRefresh = time.Time{}
}
func (m *Manager) get(id string) (*entry, error) {
	if err := checkID(id); err != nil {
		return nil, err
	}
	m.mu.RLock()
	e := m.entries[id]
	m.mu.RUnlock()
	if e == nil {
		return nil, problem(404, "not_found", "Session not found.")
	}
	return e, nil
}
func (m *Manager) commit(e *entry, next *State) error {
	next.UpdatedAt = time.Now().UTC()
	e.state = next
	e.dirty = true
	if err := m.vault.Save(next); err != nil {
		return storageProblem()
	}
	e.dirty = false
	return nil
}
func (m *Manager) flush(e *entry) error {
	if e.deleted {
		return problem(404, "not_found", "Session not found.")
	}
	if !e.dirty {
		return nil
	}
	if err := m.vault.Save(e.state); err != nil {
		return storageProblem()
	}
	e.dirty = false
	return nil
}
func metadataOf(e *entry) Metadata {
	meta := e.state.metadata()
	if e.dirty {
		meta.Status = "storage_error"
		meta.Error = storageProblem()
	}
	return meta
}

func (m *Manager) Import(id string, in Import) (Metadata, error) {
	if m.stopping.Load() {
		return Metadata{}, problem(503, "shutting_down", "The daemon is shutting down.")
	}
	if err := checkID(id); err != nil {
		return Metadata{}, err
	}
	p, ok := m.providers[in.Provider]
	if !ok {
		return Metadata{}, invalid("Unknown provider.")
	}
	if len(in.AccessToken) > 64<<10 || len(in.RefreshToken) > 64<<10 || len(in.CookieHeader) > 128<<10 || len(in.Secrets) > 32 {
		return Metadata{}, invalid("Credentials exceed size limits.")
	}
	if !validHeader("Authorization", in.AccessToken) || !validHeader("Authorization", in.RefreshToken) {
		return Metadata{}, invalid("Token contains invalid header characters.")
	}
	if p.Kind == "oauth2" && in.RefreshToken == "" {
		return Metadata{}, invalid("An OAuth refresh_token is required; an access token alone is not renewable.")
	}
	now := time.Now().UTC()
	s := &State{ID: id, Provider: p.Name, ConfigHash: p.hash, Status: "ready", CreatedAt: now, UpdatedAt: now, NextRefresh: now, AccessToken: in.AccessToken, RefreshToken: in.RefreshToken, AccessExpiresAt: in.AccessExpiresAt, Secrets: map[string]string{}}
	for k, v := range in.Secrets {
		if checkID(k) != nil || len(v) > 64<<10 {
			return Metadata{}, invalid("Invalid secret name or size.")
		}
		s.Secrets[k] = v
	}
	if in.CookieHeader != "" || len(in.SetCookies) > 0 {
		u, err := p.allowed(in.CookieOrigin)
		if err != nil {
			return Metadata{}, err
		}
		var cookies []*http.Cookie
		if in.CookieHeader != "" {
			parsed, err := http.ParseCookie(in.CookieHeader)
			if err != nil {
				return Metadata{}, invalid("Invalid Cookie header.")
			}
			for _, c := range parsed {
				c.Path = "/"
				c.Secure = u.Scheme == "https"
			}
			cookies = append(cookies, parsed...)
		}
		parsed, err := parseSetCookies(in.SetCookies)
		if err != nil {
			return Metadata{}, err
		}
		cookies = append(cookies, parsed...)
		var accepted int
		s.Cookies, accepted, _, err = updateCookies(nil, u, cookies, now)
		if err != nil {
			return Metadata{}, err
		}
		if accepted < len(cookies) {
			return Metadata{}, invalid("One or more cookies are not valid for cookie_origin.")
		}
	}
	if s.AccessToken == "" && s.RefreshToken == "" && len(s.Cookies) == 0 && len(s.Secrets) == 0 {
		return Metadata{}, invalid("No usable credentials were supplied.")
	}
	m.mu.Lock()
	if old := m.entries[id]; old != nil {
		m.mu.Unlock()
		if !in.Replace {
			return Metadata{}, problem(409, "already_exists", "Session exists; reconnect with replace=true and expected_revision.")
		}
		old.mu.Lock()
		defer old.mu.Unlock()
		m.mu.RLock()
		current := m.entries[id] == old && !old.deleted
		m.mu.RUnlock()
		if !current || in.ExpectedRevision == nil || *in.ExpectedRevision != old.state.Revision {
			return Metadata{}, problem(409, "revision_conflict", "Reconnect requires the current expected_revision; inspect status before retrying.")
		}
		if m.stopping.Load() {
			return Metadata{}, problem(503, "shutting_down", "The daemon is shutting down.")
		}
		revision, err := m.vault.nextRevision(old.state.Revision)
		if err != nil {
			return Metadata{}, storageProblem()
		}
		s.Revision = revision
		if !stateFitsVault(s) {
			return Metadata{}, invalid("Combined imported credentials exceed the 1 MiB state limit.")
		}
		if err := m.commit(old, s); err != nil {
			return Metadata{}, err
		}
		return metadataOf(old), nil
	}
	if in.Replace || in.ExpectedRevision != nil {
		m.mu.Unlock()
		return Metadata{}, problem(409, "revision_conflict", "The session to reconnect no longer exists.")
	}
	if m.stopping.Load() {
		m.mu.Unlock()
		return Metadata{}, problem(503, "shutting_down", "The daemon is shutting down.")
	}
	if len(m.entries) >= 1024 {
		m.mu.Unlock()
		return Metadata{}, invalid("The local session limit was reached.")
	}
	revision, err := m.vault.nextRevision(0)
	if err != nil {
		m.mu.Unlock()
		return Metadata{}, storageProblem()
	}
	s.Revision = revision
	if !stateFitsVault(s) {
		m.mu.Unlock()
		return Metadata{}, invalid("Combined imported credentials exceed the 1 MiB state limit.")
	}
	e := &entry{state: s}
	e.mu.Lock()
	defer e.mu.Unlock()
	m.entries[id] = e
	m.mu.Unlock()
	if err := m.commit(e, s); err != nil {
		return Metadata{}, err
	}
	return metadataOf(e), nil
}
func (m *Manager) Status(id string) (Metadata, error) {
	e, err := m.get(id)
	if err != nil {
		return Metadata{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.deleted {
		return Metadata{}, problem(404, "not_found", "Session not found.")
	}
	return metadataOf(e), nil
}
func (m *Manager) List() []Metadata {
	m.mu.RLock()
	entries := make([]*entry, 0, len(m.entries))
	for _, e := range m.entries {
		entries = append(entries, e)
	}
	m.mu.RUnlock()
	out := []Metadata{}
	for _, e := range entries {
		e.mu.Lock()
		if !e.deleted {
			out = append(out, metadataOf(e))
		}
		e.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
func (m *Manager) Forget(id string) error {
	e, err := m.get(id)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	m.mu.RLock()
	current := m.entries[id] == e && !e.deleted
	m.mu.RUnlock()
	if !current {
		return problem(404, "not_found", "Session not found.")
	}
	if err := m.vault.Delete(id); err != nil {
		return storageProblem()
	}
	e.deleted = true
	m.mu.Lock()
	delete(m.entries, id)
	m.mu.Unlock()
	return nil
}

func nextRefresh(s *State, p *Provider, now time.Time) time.Time {
	next := now.Add(time.Duration(p.RefreshIntervalSeconds) * time.Second)
	consider := func(exp time.Time) {
		if exp.IsZero() || !exp.After(now) {
			return
		}
		margin := time.Duration(p.RefreshBeforeSeconds) * time.Second
		if limit := exp.Sub(now) / 5; margin > limit {
			margin = limit
		}
		target := exp.Add(-margin)
		if target.Before(next) {
			next = target
		}
	}
	consider(s.AccessExpiresAt)
	for _, c := range s.Cookies {
		consider(c.Cookie.Expires)
	}
	if next.Before(now.Add(100 * time.Millisecond)) {
		next = now.Add(100 * time.Millisecond)
	}
	return next
}
func backoff(failures int) time.Duration {
	if failures > 9 {
		failures = 9
	}
	if failures < 1 {
		failures = 1
	}
	base := time.Second * time.Duration(1<<failures)
	var b [8]byte
	_, _ = rand.Read(b[:])
	jitter := time.Duration(binary.LittleEndian.Uint64(b[:]) % uint64(base/2+1))
	return base + jitter
}
func (m *Manager) ensure(e *entry, force bool) error {
	if m.stopping.Load() {
		return problem(503, "shutting_down", "The daemon is shutting down; no new renewal was started.")
	}
	if err := m.flush(e); err != nil {
		return err
	}
	if err := terminal(e.state); err != nil {
		return err
	}
	now := time.Now().UTC()
	s := e.state
	stillValid := s.AccessExpiresAt.IsZero() || now.Before(s.AccessExpiresAt)
	if s.Status == "retry_wait" && now.Before(s.NextRefresh) {
		usable := s.AccessToken != "" && stillValid
		for _, cookie := range s.Cookies {
			if cookie.Cookie.Expires.IsZero() || now.Before(cookie.Cookie.Expires) {
				usable = true
				break
			}
		}
		if !force && usable {
			return nil
		}
		p := problem(503, "retry_later", "Renewal is waiting for its retry deadline.")
		p.RetryAt = s.NextRefresh
		return p
	}
	if !force && s.Status == "ready" && now.Before(s.NextRefresh) && stillValid {
		return nil
	}
	p := m.providers[s.Provider]
	if p == nil || s.ConfigHash != p.hash {
		return problem(409, "configuration_error", "Provider configuration does not match the imported session.")
	}
	// Build before journaling so missing credentials or bad templates don't create
	// an ambiguous network outcome. Client disconnects cannot interrupt persistence.
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(p.TimeoutSeconds)*time.Second)
	defer cancel()
	req, err := makeRefreshRequest(ctx, s, p)
	if err != nil {
		n := cloneState(s)
		n.Status = "configuration_error"
		n.LastError = problem(409, "configuration_error", "Missing refresh credentials or invalid adapter template.")
		if err := m.commit(e, n); err != nil {
			return err
		}
		return n.LastError
	}
	pending := cloneState(s)
	pending.PendingRefresh = true
	pending.Status = "refreshing"
	if err = m.vault.Save(pending); err != nil {
		return storageProblem()
	} // No request was sent.
	e.state = pending
	result := performRefresh(pending, p, m.upstream, req)
	pending.PendingRefresh = false
	pending.Revision++
	e.completed = time.Now().UTC()
	if result == nil {
		pending.Status = "ready"
		pending.Failures = 0
		pending.LastError = nil
		pending.LastRefresh = e.completed
		pending.NextRefresh = nextRefresh(pending, p, e.completed)
	} else {
		pending.LastError = result
		pending.Failures++
		switch result.Code {
		case "retry_later":
			pending.Status = "retry_wait"
			pending.NextRefresh = e.completed.Add(backoff(pending.Failures))
			if result.RetryAt.After(pending.NextRefresh) {
				pending.NextRefresh = result.RetryAt
			}
			result.RetryAt = pending.NextRefresh
		case "reauth_required":
			pending.Status = "reauth_required"
		case "renewal_uncertain":
			pending.Status = "uncertain"
		case "configuration_error":
			pending.Status = "configuration_error"
		default:
			pending.Status = "protocol_error"
		}
	}
	if !stateFitsVault(pending) {
		return m.boundedUncertain(e, "Renewal produced credentials too large to persist; automatic credential reuse is paused.")
	}
	if err := m.commit(e, pending); err != nil {
		return err
	}
	if result != nil {
		return result
	}
	return nil
}
func (m *Manager) Refresh(id string) (Metadata, error) {
	started := time.Now()
	e, err := m.get(id)
	if err != nil {
		return Metadata{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err = m.ensure(e, !e.completed.After(started)); err != nil {
		return Metadata{}, err
	}
	return metadataOf(e), nil
}

type HeadersResult struct {
	Headers   map[string]string `json:"headers"`
	Revision  uint64            `json:"revision"`
	ExpiresAt time.Time         `json:"expires_at,omitempty"`
}

func headersFor(s *State, uRaw string) (HeadersResult, error) {
	u, _, err := canonicalURL(uRaw)
	if err != nil {
		return HeadersResult{}, err
	}
	headers := map[string]string{}
	if s.AccessToken != "" {
		headers["Authorization"] = "Bearer " + s.AccessToken
	}
	if c := cookieHeaders(s.Cookies, u, time.Now()); c != "" {
		headers["Cookie"] = c
	}
	if len(headers) == 0 {
		return HeadersResult{}, problem(409, "no_credentials_for_origin", "This session has no usable headers for the requested origin.")
	}
	return HeadersResult{headers, s.Revision, s.AccessExpiresAt}, nil
}
func (m *Manager) Headers(id, rawURL string) (HeadersResult, error) {
	e, err := m.get(id)
	if err != nil {
		return HeadersResult{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	p := m.providers[e.state.Provider]
	if p == nil {
		return HeadersResult{}, problem(409, "configuration_error", "Provider is unavailable.")
	}
	if _, err = p.allowed(rawURL); err != nil {
		return HeadersResult{}, err
	} // Check scope before any renewal.
	if err = m.ensure(e, false); err != nil {
		return HeadersResult{}, err
	}
	return headersFor(e.state, rawURL)
}
func (m *Manager) Capture(id, rawURL string, lines []string) (Metadata, error) {
	e, err := m.get(id)
	if err != nil {
		return Metadata{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err = m.flush(e); err != nil {
		return Metadata{}, err
	}
	if err := terminal(e.state); err != nil {
		return Metadata{}, err
	}
	p := m.providers[e.state.Provider]
	u, err := p.allowed(rawURL)
	if err != nil {
		return Metadata{}, err
	}
	cookies, rejected := parseSetCookiesPartial(lines)
	n := cloneState(e.state)
	accepted := 0
	if len(cookies) > 0 {
		n.Cookies, accepted, _, err = updateCookies(n.Cookies, u, cookies, time.Now().UTC())
	}
	if err != nil {
		return Metadata{}, m.cookieCaptureFailure(e)
	}
	if rejected || accepted < len(cookies) {
		return Metadata{}, m.cookieCaptureFailureFrom(e, n)
	}
	n.Revision++
	if candidate := nextRefresh(n, p, time.Now().UTC()); candidate.Before(n.NextRefresh) {
		n.NextRefresh = candidate
	}
	if !stateFitsVault(n) {
		return Metadata{}, m.cookieCaptureFailure(e)
	}
	if err = m.commit(e, n); err != nil {
		return Metadata{}, err
	}
	return metadataOf(e), nil
}

type RequestInput struct {
	URL        string            `json:"url"`
	Method     string            `json:"method,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	BodyBase64 string            `json:"body_base64,omitempty"`
}
type RequestResult struct {
	Status     int         `json:"status"`
	Headers    http.Header `json:"headers"`
	BodyBase64 string      `json:"body_base64"`
	Revision   uint64      `json:"revision"`
}

func (m *Manager) Request(id string, in RequestInput) (RequestResult, error) {
	e, err := m.get(id)
	if err != nil {
		return RequestResult{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	p := m.providers[e.state.Provider]
	if p == nil {
		return RequestResult{}, problem(409, "configuration_error", "Provider is unavailable.")
	}
	u, err := p.allowed(in.URL)
	if err != nil {
		return RequestResult{}, err
	}
	method := strings.ToUpper(in.Method)
	if method == "" {
		method = "GET"
	}
	switch method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
	default:
		return RequestResult{}, invalid("Unsupported request method.")
	}
	body, err := base64.StdEncoding.DecodeString(in.BodyBase64)
	if err != nil || len(body) > 1<<20 {
		return RequestResult{}, invalid("Invalid base64 request body, or body exceeds 1 MiB.")
	}
	headers := http.Header{}
	if len(in.Headers) > 64 {
		return RequestResult{}, invalid("Too many request headers.")
	}
	for k, v := range in.Headers {
		if forbiddenHeader(k) || strings.EqualFold(k, "Authorization") || strings.EqualFold(k, "Cookie") || !validHeader(k, v) {
			return RequestResult{}, invalid("Reserved or invalid request header.")
		}
		headers.Set(k, v)
	}
	if err = m.ensure(e, false); err != nil {
		return RequestResult{}, err
	}
	auth, err := headersFor(e.state, u.String())
	if err != nil {
		return RequestResult{}, err
	}
	for k, v := range auth.Headers {
		headers.Set(k, v)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(p.TimeoutSeconds)*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), strings.NewReader(string(body)))
	if err != nil {
		return RequestResult{}, invalid("Invalid upstream request.")
	}
	req.GetBody = nil
	req.Header = headers
	var connected atomic.Bool
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) { connected.Store(true) },
	}))
	// Persist before any credential can reach the upstream. A restart must
	// treat an unfinished request as ambiguous, just like an unfinished renewal.
	pending := cloneState(e.state)
	pending.PendingRequest = true
	if err := m.vault.Save(pending); err != nil {
		return RequestResult{}, storageProblem()
	}
	e.state = pending
	resp, err := m.upstream.Do(req)
	if err != nil {
		if connected.Load() {
			return RequestResult{}, m.resourceRequestFailure(e)
		}
		n := cloneState(e.state)
		n.PendingRequest = false
		if err := m.commit(e, n); err != nil {
			return RequestResult{}, err
		}
		return RequestResult{}, problem(502, "upstream_request_failed", "The upstream response was not received. The resource request was not retried; its side effects may be unknown.")
	}
	defer resp.Body.Close()
	// Capture credentials and clear the checkpoint in the same durable write
	// before reading/returning an application response body.
	n := cloneState(e.state)
	n.PendingRequest = false
	if lines := resp.Header.Values("Set-Cookie"); len(lines) > 0 {
		cookies, rejected := parseSetCookiesPartial(lines)
		accepted := 0
		if len(cookies) > 0 {
			n.Cookies, accepted, _, err = updateCookies(n.Cookies, u, cookies, time.Now().UTC())
		}
		if err != nil {
			return RequestResult{}, m.cookieCaptureFailure(e)
		}
		if rejected || accepted < len(cookies) {
			return RequestResult{}, m.cookieCaptureFailureFrom(e, n)
		}
		n.Revision++
		if candidate := nextRefresh(n, p, time.Now().UTC()); candidate.Before(n.NextRefresh) {
			n.NextRefresh = candidate
		}
		if !stateFitsVault(n) {
			return RequestResult{}, m.cookieCaptureFailure(e)
		}
	}
	if err = m.commit(e, n); err != nil {
		return RequestResult{}, err
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (4<<20)+1))
	if err != nil {
		return RequestResult{}, problem(502, "upstream_request_failed", "Could not read the complete upstream response; request was not retried.")
	}
	if len(raw) > 4<<20 {
		return RequestResult{}, problem(502, "response_too_large", "Upstream response exceeds the 4 MiB buffered response limit.")
	}
	outHeaders := http.Header{}
	for k, v := range resp.Header {
		if !forbiddenHeader(k) && !strings.EqualFold(k, "Set-Cookie") {
			outHeaders[k] = v
		}
	}
	return RequestResult{resp.StatusCode, outHeaders, base64.StdEncoding.EncodeToString(raw), e.state.Revision}, nil
}

// RunScheduler blocks until cancellation and until in-flight renewal writes are
// finished. Call it in a goroutine, and wait for it before closing the vault.
func (m *Manager) RunScheduler(ctx context.Context) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	defer wg.Wait()
	scan := func() {
		m.mu.RLock()
		entries := make([]*entry, 0, len(m.entries))
		for _, e := range m.entries {
			entries = append(entries, e)
		}
		m.mu.RUnlock()
		for _, e := range entries {
			if !e.mu.TryLock() {
				continue
			}
			due := !e.deleted && (e.dirty || ((e.state.Status == "ready" || e.state.Status == "retry_wait") && !time.Now().Before(e.state.NextRefresh)))
			if !due {
				e.mu.Unlock()
				continue
			}
			select {
			case sem <- struct{}{}:
				wg.Add(1)
				go func(e *entry) { defer wg.Done(); defer func() { <-sem; e.mu.Unlock() }(); _ = m.ensure(e, false) }(e)
			default:
				e.mu.Unlock()
			}
		}
	}
	scan()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			scan()
		}
	}
}
func AsProblem(err error) *Problem {
	var p *Problem
	if errors.As(err, &p) && p != nil {
		copy := *p
		if copy.HTTPStatus == 0 {
			copy.HTTPStatus = 500
		}
		return &copy
	}
	return problem(500, "internal_error", "An internal error occurred.")
}

// BeginShutdown rejects queued/new renewals while in-flight requests finish.
func (m *Manager) BeginShutdown() { m.stopping.Store(true) }

// FlushAll saves in-memory rotations after requests and scheduler work drain.
// It never starts a new network operation, including during shutdown.
func (m *Manager) FlushAll() error {
	m.mu.RLock()
	entries := make([]*entry, 0, len(m.entries))
	for _, e := range m.entries {
		entries = append(entries, e)
	}
	m.mu.RUnlock()
	var result error
	for _, e := range entries {
		e.mu.Lock()
		if !e.deleted {
			result = errors.Join(result, m.flush(e))
		}
		e.mu.Unlock()
	}
	return result
}

func (m *Manager) cookieCaptureFailure(e *entry) error {
	return m.cookieCaptureFailureFrom(e, nil)
}

func (m *Manager) cookieCaptureFailureFrom(e *entry, candidate *State) error {
	if candidate == nil {
		candidate = e.state
	}
	return m.boundedUncertainFrom(e, candidate, "Cookie capture failed after a resource response; automatic credential reuse is paused.")
}

func (m *Manager) boundedUncertain(e *entry, message string) error {
	return m.boundedUncertainFrom(e, e.state, message)
}

func (m *Manager) boundedUncertainFrom(e *entry, candidate *State, message string) error {
	n := cloneState(candidate)
	n.PendingRequest = false
	n.PendingRefresh = false
	n.Status = "uncertain"
	n.LastError = problem(409, "renewal_uncertain", message)
	n.Revision++
	if !stateFitsVault(n) {
		// The previous state was durable, but adding terminal metadata can cross
		// the limit. Drop credentials rather than leave a reusable disk copy.
		boundTerminalState(n)
	}
	if err := m.commit(e, n); err != nil {
		return err
	}
	return n.LastError
}

func (m *Manager) resourceRequestFailure(e *entry) error {
	return m.boundedUncertain(e, "The upstream connection closed before a resource response was received; automatic credential reuse is paused.")
}
