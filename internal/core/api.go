package core

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Handler is intentionally a localhost, single-trust-domain API. The token has
// full control of every session in this daemon. Do not expose it to tenants or a
// browser. Use separate daemon instances/state directories for separate users.
func Handler(m *Manager, apiToken string) http.Handler {
	expected := sha256.Sum256([]byte("Bearer " + apiToken))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Type", "application/json")
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		if !loopbackHost(host) || r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") != "" {
			writeError(w, problem(403, "local_clients_only", "Only non-browser clients using a literal loopback host are accepted."))
			return
		}
		actual := sha256.Sum256([]byte(r.Header.Get("Authorization")))
		if subtle.ConstantTimeCompare(expected[:], actual[:]) != 1 {
			writeError(w, problem(401, "unauthorized", "A valid local API bearer token is required."))
			return
		}
		if r.URL.RawQuery != "" {
			writeError(w, invalid("Query parameters are not accepted."))
			return
		}
		if r.Method == "OPTIONS" {
			writeError(w, problem(405, "method_not_allowed", "Browser CORS access is not supported."))
			return
		}
		path := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(path) < 2 || path[0] != "v1" {
			writeError(w, problem(404, "not_found", "Endpoint not found."))
			return
		}
		switch path[1] {
		case "health":
			if len(path) == 2 && r.Method == "GET" {
				writeJSON(w, 200, map[string]any{"ok": true, "version": Version})
				return
			}
		case "providers":
			if len(path) == 2 && r.Method == "GET" {
				providers := []map[string]any{}
				for _, p := range m.providers {
					providers = append(providers, map[string]any{"name": p.Name, "kind": p.Kind, "origins": p.Origins})
				}
				writeJSON(w, 200, map[string]any{"providers": providers})
				return
			}
		case "sessions":
			if len(path) == 2 && r.Method == "GET" {
				writeJSON(w, 200, map[string]any{"sessions": m.List()})
				return
			}
			if len(path) < 3 || len(path) > 4 {
				break
			}
			id := path[2]
			if err := checkID(id); err != nil {
				writeError(w, err)
				return
			}
			var result any
			var err error
			code := 200
			if len(path) == 3 {
				switch r.Method {
				case "GET":
					result, err = m.Status(id)
				case "PUT":
					var in Import
					if !decodeBody(w, r, &in) {
						return
					}
					result, err = m.Import(id, in)
					code = 201
				case "DELETE":
					err = m.Forget(id)
					result = map[string]bool{"deleted": err == nil}
				default:
					err = problem(405, "method_not_allowed", "Unsupported method.")
				}
			} else if r.Method != "POST" {
				err = problem(405, "method_not_allowed", "This endpoint requires POST.")
			} else {
				switch path[3] {
				case "headers":
					var in struct {
						URL string `json:"url"`
					}
					if !decodeBody(w, r, &in) {
						return
					}
					result, err = m.Headers(id, in.URL)
				case "refresh":
					var in struct{}
					if !decodeBody(w, r, &in) {
						return
					}
					result, err = m.Refresh(id)
				case "cookies":
					var in struct {
						URL       string   `json:"url"`
						SetCookie []string `json:"set_cookie"`
					}
					if !decodeBody(w, r, &in) {
						return
					}
					result, err = m.Capture(id, in.URL, in.SetCookie)
				case "request":
					var in RequestInput
					if !decodeBody(w, r, &in) {
						return
					}
					result, err = m.Request(id, in)
				default:
					err = problem(404, "not_found", "Endpoint not found.")
				}
			}
			if err != nil {
				writeError(w, err)
			} else {
				writeJSON(w, code, result)
			}
			return
		}
		writeError(w, problem(404, "not_found", "Endpoint not found."))
	})
}
func decodeBody(w http.ResponseWriter, r *http.Request, out any) bool {
	media := strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])
	if media != "application/json" {
		writeError(w, problem(415, "unsupported_media_type", "Use application/json."))
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		var limit *http.MaxBytesError
		if errors.As(err, &limit) {
			writeError(w, problem(413, "body_too_large", "Request exceeds 2 MiB."))
		} else {
			writeError(w, invalid("Invalid JSON body or unknown fields."))
		}
		return false
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		writeError(w, invalid("The request must contain one JSON object."))
		return false
	}
	return true
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, err error) {
	p := AsProblem(err)
	if !p.RetryAt.IsZero() {
		w.Header().Set("Retry-After", p.RetryAt.UTC().Format(http.TimeFormat))
	}
	writeJSON(w, p.HTTPStatus, map[string]any{"error": p})
}
func NewServer(addr string, handler http.Handler) (*http.Server, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || !loopbackHost(host) {
		return nil, errors.New("listen address must use a literal loopback IP and port")
	}
	return &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 5 * time.Minute, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10}, nil
}
