// A disposable, loopback-only fake provider for integration tests. Never use it
// as a real identity provider. Its initial credentials are deliberately public.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:9909", "loopback address")
	ttl := flag.Duration("ttl", 10*time.Second, "access-token lifetime; refresh/cookie lifetime is three times this")
	flag.Parse()
	host, _, err := net.SplitHostPort(*listen)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || !ip.IsLoopback() || *ttl < time.Second {
		fmt.Fprintln(os.Stderr, "Use a literal loopback IP and ttl >= 1s")
		os.Exit(1)
	}
	var mu sync.Mutex
	oauthN, cookieN := 0, 0
	refresh := "demo-refresh-0"
	cookie := "demo-cookie-0"
	refreshExpiry := time.Now().Add(3 * *ttl)
	cookieExpiry := refreshExpiry
	access := map[string]time.Time{}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"ok":true}`) })
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != refresh || time.Now().After(refreshExpiry) {
			w.WriteHeader(400)
			fmt.Fprint(w, `{"error":"invalid_grant"}`)
			return
		}
		oauthN++
		refresh = "demo-refresh-" + strconv.Itoa(oauthN)
		token := "demo-access-" + strconv.Itoa(oauthN)
		access[token] = time.Now().Add(*ttl)
		refreshExpiry = time.Now().Add(3 * *ttl)
		for old, expiry := range access {
			if time.Now().After(expiry) {
				delete(access, old)
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": token, "refresh_token": refresh, "token_type": "Bearer", "expires_in": int(ttl.Seconds())})
	})
	mux.HandleFunc("/cookie/session", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		received, err := r.Cookie("sid")
		if err != nil || received.Value != cookie || time.Now().After(cookieExpiry) {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":"expired_session"}`)
			return
		}
		cookieN++
		cookie = "demo-cookie-" + strconv.Itoa(cookieN)
		cookieExpiry = time.Now().Add(3 * *ttl)
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: cookie, Path: "/", MaxAge: int(3 * ttl.Seconds()), HttpOnly: true, SameSite: http.SameSiteLaxMode})
		fmt.Fprint(w, `{"ok":true}`)
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		kind := ""
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if expiry, ok := access[token]; ok && time.Now().Before(expiry) {
			kind = "oauth2"
		}
		if c, err := r.Cookie("sid"); err == nil && c.Value == cookie && time.Now().Before(cookieExpiry) {
			kind = "cookie"
		}
		if kind == "" {
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":"unauthorized"}`)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "auth": kind, "oauth_renewals": oauthN, "cookie_renewals": cookieN})
	})
	fmt.Fprintln(os.Stderr, "Disposable demo provider listening on", *listen)
	srv := http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
