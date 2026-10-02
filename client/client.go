// Package client is Galleton's dependency-free Go client. It talks to a local
// daemon; it does not retain or return the provider's refresh credentials.
package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Client struct {
	base  string
	token string
	http  *http.Client
}
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	RetryAt string `json:"retry_at,omitempty"`
	Status  int    `json:"-"`
}

func (e *Error) Error() string { return "galleton: " + e.Code + ": " + e.Message }

type Metadata struct {
	ID              string    `json:"id"`
	Provider        string    `json:"provider"`
	Status          string    `json:"status"`
	Revision        uint64    `json:"revision"`
	CreatedAt       time.Time `json:"created_at"`
	LastRefresh     time.Time `json:"last_refresh"`
	NextRefresh     time.Time `json:"next_refresh"`
	AccessExpiresAt time.Time `json:"access_expires_at"`
	CookieCount     int       `json:"cookie_count"`
	Error           *Error    `json:"error,omitempty"`
}
type Credentials struct {
	Provider        string            `json:"provider"`
	CookieOrigin    string            `json:"cookie_origin,omitempty"`
	CookieHeader    string            `json:"cookie_header,omitempty"`
	SetCookies      []string          `json:"set_cookies,omitempty"`
	AccessToken     string            `json:"access_token,omitempty"`
	RefreshToken    string            `json:"refresh_token,omitempty"`
	AccessExpiresAt *time.Time        `json:"access_expires_at,omitempty"`
	Secrets         map[string]string `json:"secrets,omitempty"`
	Replace         bool              `json:"replace,omitempty"`
	ExpectedRevision *uint64          `json:"expected_revision,omitempty"`
}
type Headers struct {
	Headers   map[string]string `json:"headers"`
	Revision  uint64            `json:"revision"`
	ExpiresAt time.Time         `json:"expires_at"`
}
type Response struct {
	Status   int
	Headers  http.Header
	Body     []byte
	Revision uint64
}

func (r Response) JSON(out any) error { return json.Unmarshal(r.Body, out) }
func New(baseURL, token string) (*Client, error) {
	if baseURL == "" {
		baseURL = "http://127.0.0.1:8766"
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return nil, errors.New("Galleton URL must be a plain loopback HTTP origin")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return nil, errors.New("Galleton client only supports literal loopback addresses")
	}
	token = strings.TrimSpace(token)
	if token == "" || strings.ContainsAny(token, "\r\n") {
		return nil, errors.New("a local API token is required")
	}
	return &Client{base: strings.TrimRight(baseURL, "/"), token: token, http: &http.Client{Timeout: 5 * time.Minute, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func FromDir(baseURL, dir string) (*Client, error) {
	b, err := os.ReadFile(filepath.Join(dir, "api.token"))
	if err != nil {
		return nil, err
	}
	return New(baseURL, string(b))
}
func idPath(id string) (string, error) {
	if len(id) < 1 || len(id) > 64 {
		return "", errors.New("invalid session ID")
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return "", errors.New("invalid session ID")
		}
	}
	return "/v1/sessions/" + id, nil
}
func (c *Client) call(ctx context.Context, method, path string, in, out any) error {
	var body []byte
	var err error
	if in != nil {
		body, err = json.Marshal(in)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return errors.New("galleton daemon is unavailable or the local request timed out")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (8<<20)+1))
	if err != nil || len(raw) > 8<<20 {
		return errors.New("invalid or oversized Galleton response")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var envelope struct {
			Error Error `json:"error"`
		}
		if json.Unmarshal(raw, &envelope) != nil || envelope.Error.Code == "" {
			return fmt.Errorf("galleton returned HTTP %d", resp.StatusCode)
		}
		envelope.Error.Status = resp.StatusCode
		return &envelope.Error
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}
func (c *Client) Connect(ctx context.Context, id string, in Credentials) (Metadata, error) {
	var out Metadata
	p, err := idPath(id)
	if err == nil {
		err = c.call(ctx, "PUT", p, in, &out)
	}
	return out, err
}
func (c *Client) Status(ctx context.Context, id string) (Metadata, error) {
	var out Metadata
	p, err := idPath(id)
	if err == nil {
		err = c.call(ctx, "GET", p, nil, &out)
	}
	return out, err
}
func (c *Client) List(ctx context.Context) ([]Metadata, error) {
	var out struct {
		Sessions []Metadata `json:"sessions"`
	}
	err := c.call(ctx, "GET", "/v1/sessions", nil, &out)
	return out.Sessions, err
}
func (c *Client) Refresh(ctx context.Context, id string) (Metadata, error) {
	var out Metadata
	p, err := idPath(id)
	if err == nil {
		err = c.call(ctx, "POST", p+"/refresh", struct{}{}, &out)
	}
	return out, err
}
func (c *Client) Headers(ctx context.Context, id, rawURL string) (Headers, error) {
	var out Headers
	p, err := idPath(id)
	if err == nil {
		err = c.call(ctx, "POST", p+"/headers", map[string]string{"url": rawURL}, &out)
	}
	return out, err
}
func (c *Client) Capture(ctx context.Context, id, rawURL string, setCookie []string) (Metadata, error) {
	var out Metadata
	p, err := idPath(id)
	if err == nil {
		err = c.call(ctx, "POST", p+"/cookies", map[string]any{"url": rawURL, "set_cookie": setCookie}, &out)
	}
	return out, err
}
func (c *Client) Forget(ctx context.Context, id string) error {
	p, err := idPath(id)
	if err != nil {
		return err
	}
	return c.call(ctx, "DELETE", p, nil, nil)
}
func (c *Client) Request(ctx context.Context, id, method, rawURL string, headers map[string]string, body []byte) (Response, error) {
	var wire struct {
		Status     int         `json:"status"`
		Headers    http.Header `json:"headers"`
		BodyBase64 string      `json:"body_base64"`
		Revision   uint64      `json:"revision"`
	}
	p, err := idPath(id)
	if err != nil {
		return Response{}, err
	}
	err = c.call(ctx, "POST", p+"/request", map[string]any{"url": rawURL, "method": method, "headers": headers, "body_base64": base64.StdEncoding.EncodeToString(body)}, &wire)
	if err != nil {
		return Response{}, err
	}
	data, err := base64.StdEncoding.DecodeString(wire.BodyBase64)
	return Response{wire.Status, wire.Headers, data, wire.Revision}, err
}
