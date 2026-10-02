// Package core implements Galleton's local, single-owner session manager.
package core

import (
	"fmt"
	"net/http"
	"time"
)

const Version = "0.1.0"

// Provider is trusted operator configuration, never supplied by an API caller.
// URLs are explicitly allowlisted. Templates are substitutions, not executable code.
type Provider struct {
	Name                   string            `json:"name"`
	Kind                   string            `json:"kind"` // oauth2 or http
	Origins                []string          `json:"origins"`
	RefreshURL             string            `json:"refresh_url"`
	RefreshMethod          string            `json:"refresh_method,omitempty"`
	RefreshHeaders         map[string]string `json:"refresh_headers,omitempty"`
	BodyFormat             string            `json:"body_format,omitempty"` // none, form, json
	Body                   map[string]string `json:"body,omitempty"`
	Response               ResponseMapping   `json:"response,omitempty"`
	ClientID               string            `json:"client_id,omitempty"`
	ClientSecretEnv        string            `json:"client_secret_env,omitempty"`
	ClientAuth             string            `json:"client_auth,omitempty"` // none, basic, body
	RefreshIntervalSeconds int               `json:"refresh_interval_seconds"`
	RefreshBeforeSeconds   int               `json:"refresh_before_seconds,omitempty"`
	TimeoutSeconds         int               `json:"timeout_seconds,omitempty"`
	RetrySafe              bool              `json:"retry_safe,omitempty"`
	AllowHTTPLoopback      bool              `json:"allow_http_loopback,omitempty"`
	secret                 string
	hash                   string
}

type ResponseMapping struct {
	AccessToken      string `json:"access_token_pointer,omitempty"`
	RefreshToken     string `json:"refresh_token_pointer,omitempty"`
	ExpiresIn        string `json:"expires_in_pointer,omitempty"`
	ExpiresAt        string `json:"expires_at_pointer,omitempty"`
	Success          string `json:"success_pointer,omitempty"` // must be JSON true
	RequireSetCookie bool   `json:"require_set_cookie,omitempty"`
}

type Config struct {
	Providers []Provider `json:"providers"`
}

type Import struct {
	Provider         string            `json:"provider"`
	CookieOrigin     string            `json:"cookie_origin,omitempty"`
	CookieHeader     string            `json:"cookie_header,omitempty"`
	SetCookies       []string          `json:"set_cookies,omitempty"`
	AccessToken      string            `json:"access_token,omitempty"`
	RefreshToken     string            `json:"refresh_token,omitempty"`
	AccessExpiresAt  time.Time         `json:"access_expires_at,omitempty"`
	Secrets          map[string]string `json:"secrets,omitempty"`
	Replace          bool              `json:"replace,omitempty"`
	ExpectedRevision *uint64           `json:"expected_revision,omitempty"`
}

// StoredCookie is deliberately pinned to the exact issuing origin, including port.
// Parent-domain cookies are narrowed, not widened, during import/capture.
type StoredCookie struct {
	Origin    string      `json:"origin"`
	Cookie    http.Cookie `json:"cookie"`
	CreatedAt time.Time   `json:"created_at"`
}

type State struct {
	ID              string            `json:"id"`
	Provider        string            `json:"provider"`
	ConfigHash      string            `json:"config_hash"`
	Status          string            `json:"status"`
	Revision        uint64            `json:"revision"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
	LastRefresh     time.Time         `json:"last_refresh,omitempty"`
	NextRefresh     time.Time         `json:"next_refresh,omitempty"`
	AccessExpiresAt time.Time         `json:"access_expires_at,omitempty"`
	AccessToken     string            `json:"access_token,omitempty"`
	RefreshToken    string            `json:"refresh_token,omitempty"`
	Secrets         map[string]string `json:"secrets,omitempty"`
	Cookies         []StoredCookie    `json:"cookies,omitempty"`
	PendingRequest  bool              `json:"pending_request,omitempty"`
	PendingRefresh  bool              `json:"pending_refresh,omitempty"`
	Failures        int               `json:"failures,omitempty"`
	LastError       *Problem          `json:"last_error,omitempty"`
}

type Metadata struct {
	ID              string    `json:"id"`
	Provider        string    `json:"provider"`
	Status          string    `json:"status"`
	Revision        uint64    `json:"revision"`
	CreatedAt       time.Time `json:"created_at"`
	LastRefresh     time.Time `json:"last_refresh,omitempty"`
	NextRefresh     time.Time `json:"next_refresh,omitempty"`
	AccessExpiresAt time.Time `json:"access_expires_at,omitempty"`
	CookieCount     int       `json:"cookie_count"`
	Error           *Problem  `json:"error,omitempty"`
}

func (s *State) metadata() Metadata {
	return Metadata{s.ID, s.Provider, s.Status, s.Revision, s.CreatedAt, s.LastRefresh, s.NextRefresh, s.AccessExpiresAt, len(s.Cookies), s.LastError}
}

// Problem messages must never contain provider response bodies or credentials.
type Problem struct {
	Code       string    `json:"code"`
	Message    string    `json:"message"`
	RetryAt    time.Time `json:"retry_at,omitempty"`
	HTTPStatus int       `json:"-"`
}

func (p *Problem) Error() string { return p.Code + ": " + p.Message }
func problem(status int, code, message string) *Problem {
	return &Problem{Code: code, Message: message, HTTPStatus: status}
}
func invalid(message string) *Problem { return problem(400, "invalid_request", message) }
func storageProblem() *Problem {
	return problem(503, "storage_failure", "Credential persistence failed; no further renewal will run until the pending state is saved.")
}
func terminal(s *State) *Problem {
	switch s.Status {
	case "reauth_required":
		return problem(401, "reauth_required", "The provider rejected renewal. Reconnect this session.")
	case "uncertain":
		return problem(409, "renewal_uncertain", "A renewal may have consumed a rotating credential. Automatic replay is paused; reconnect or resolve with the provider.")
	case "configuration_error":
		return problem(409, "configuration_error", "The provider configuration or OAuth client is incompatible with this session.")
	case "protocol_error":
		return problem(502, "protocol_error", "The renewal response did not match the adapter. Inspect the adapter and reconnect.")
	}
	return nil
}
func checkID(id string) error {
	if len(id) < 1 || len(id) > 64 {
		return invalid("Session IDs must contain 1–64 ASCII letters, digits, underscores or hyphens.")
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return invalid("Invalid session ID.")
		}
	}
	return nil
}
func contextError(err error) error { return fmt.Errorf("galleton: %w", err) }
