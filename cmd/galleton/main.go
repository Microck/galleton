package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/Microck/galleton/client"
	"github.com/Microck/galleton/cookiefile"
	"github.com/Microck/galleton/internal/core"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "galleton:", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		fmt.Println("Galleton " + core.Version + "\n\nCommands: init, serve, shutdown, connect, status, list, refresh, forget, headers, request, providers, pause, resume, version\n\nFlags follow the command, BEFORE positional IDs.\n  galleton init --dir ./state\n  galleton serve --dir ./state --config ./adapters.json\n  galleton connect --dir ./state account < credentials.json\n  galleton connect --dir ./state --provider vinted --cookies cookies.txt account\n  galleton status --dir ./state account\n  galleton pause --dir ./state --seconds 900 vinted\n\nconnect --cookies reads a cookie export: Netscape cookies.txt, Cookie-Editor\nor EditThisCookie JSON, or a Cookie header. The format is detected; override\nit with --format.\n\nThe daemon listens on 127.0.0.1:8766. See README.md for adapters and SDKs.")
		return nil
	}
	if args[0] == "version" {
		fmt.Println(core.Version)
		return nil
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(os.Stderr)
	dir := f.String("dir", core.DefaultDir(), "private state directory")
	addr := f.String("listen", "127.0.0.1:8766", "daemon loopback listen address")
	base := f.String("api", "http://127.0.0.1:8766", "daemon URL")
	config := f.String("config", "", "provider configuration JSON (serve)")
	rawURL := f.String("url", "", "upstream URL (headers or request)")
	method := f.String("method", "GET", "upstream method (request)")
	provider := f.String("provider", "", "provider name (connect --cookies)")
	cookies := f.String("cookies", "", "cookie export file, or - for stdin (connect)")
	format := f.String("format", "auto", "cookie export format: auto, netscape, json or header (connect)")
	cookieOrigin := f.String("cookie-origin", "", "origin for cookies without a domain (connect)")
	credentials := f.String("credentials", "", "credentials JSON file instead of stdin (connect)")
	replace := f.Bool("replace", false, "reconnect an existing session; needs --expected-revision (connect --cookies)")
	expectedRevision := f.Uint64("expected-revision", 0, "current session revision when replacing (connect --cookies)")
	seconds := f.Int("seconds", 0, "pause length in seconds, 1-86400 (pause)")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "init":
		if err := core.Init(*dir); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Initialized private state directory:", *dir)
		return nil
	case "serve":
		if *config == "" {
			*config = filepath.Join(*dir, "adapters.json")
		}
		cfg, err := core.LoadConfig(*config)
		if err != nil {
			return err
		}
		token, err := core.ReadAPIToken(*dir)
		if err != nil {
			return err
		}
		vault, err := core.OpenVault(*dir)
		if err != nil {
			return err
		}
		defer vault.Close()
		manager, err := core.NewManager(vault, cfg)
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		srv, err := core.NewServer(*addr, core.HandlerWithShutdown(manager, token, stop))
		if err != nil {
			return err
		}
		listener, err := net.Listen("tcp", *addr)
		if err != nil {
			return err
		}
		// Handle platform termination signals as well as Ctrl-C.
		registerTerminate(stop)
		schedulerCtx, cancelScheduler := context.WithCancel(context.Background())
		schedulerDone := make(chan struct{})
		go func() { manager.RunScheduler(schedulerCtx); close(schedulerDone) }()
		serveDone := make(chan error, 1)
		go func() { serveDone <- srv.Serve(listener) }()
		fmt.Fprintln(os.Stderr, "Galleton listening on", listener.Addr(), "(authenticated loopback API)")
		select {
		case err = <-serveDone:
		case <-ctx.Done():
		}
		manager.BeginShutdown()
		cancelScheduler()
		// No new requests; wait for complete renewal/persistence before closing the vault.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		shutdownErr := srv.Shutdown(shutdownCtx)
		<-schedulerDone
		flushErr := manager.FlushAll()
		if flushErr != nil {
			return errors.Join(shutdownErr, flushErr)
		}
		if shutdownErr != nil {
			return shutdownErr
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
	c, err := client.FromDir(*base, *dir)
	if err != nil {
		return err
	}
	ctx := context.Background()
	var out any
	if args[0] == "list" {
		out, err = c.List(ctx)
	} else if args[0] == "shutdown" {
		err = c.Shutdown(ctx)
		out = map[string]bool{"stopping": err == nil}
	} else if args[0] == "providers" {
		out, err = c.Providers(ctx)
	} else {
		if f.NArg() != 1 {
			return errors.New("provide one session ID (or provider name) after all flags")
		}
		id := f.Arg(0)
		switch args[0] {
		case "pause":
			out, err = c.Pause(ctx, id, *seconds)
		case "resume":
			out, err = c.Resume(ctx, id)
		case "connect":
			var input client.Credentials
			if *cookies == "" || *credentials != "" {
				input, err = readCredentials(*credentials)
				if err != nil {
					return err
				}
			}
			if *provider != "" {
				input.Provider = *provider
			}
			if *cookieOrigin != "" {
				input.CookieOrigin = *cookieOrigin
			}
			if *replace {
				if *expectedRevision == 0 {
					return errors.New("--replace needs --expected-revision; read it with galleton status")
				}
				input.Replace = true
				input.ExpectedRevision = expectedRevision
			}
			if input.Provider == "" {
				return errors.New("connect needs a provider: use --provider or a credentials JSON object")
			}
			if *cookies != "" {
				hosts, err := providerHosts(ctx, c, input.Provider)
				if err != nil {
					return err
				}
				parsed, used, err := readCookies(*cookies, *format, hosts)
				if err != nil {
					return err
				}
				input.Cookies = append(input.Cookies, parsed...)
				fmt.Fprintf(os.Stderr, "Kept %d cookies (%s) for %s.\n", len(parsed), used, strings.Join(hosts, ", "))
			}
			out, err = c.Connect(ctx, id, input)
		case "status":
			out, err = c.Status(ctx, id)
		case "refresh":
			out, err = c.Refresh(ctx, id)
		case "forget":
			err = c.Forget(ctx, id)
			out = map[string]bool{"deleted": err == nil}
		case "headers":
			out, err = c.Headers(ctx, id, *rawURL)
		case "request":
			response, requestErr := c.Request(ctx, id, *method, *rawURL, nil, nil)
			err = requestErr
			out = map[string]any{"status": response.Status, "headers": response.Headers, "body": string(response.Body), "revision": response.Revision}
		default:
			return errors.New("unknown command; run galleton help")
		}
	}
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// readCredentials decodes one credentials JSON object from path, or stdin.
func readCredentials(path string) (client.Credentials, error) {
	var input client.Credentials
	var source io.Reader = os.Stdin
	if path != "" {
		file, err := os.Open(path)
		if err != nil {
			return input, err
		}
		defer file.Close()
		source = file
	}
	d := json.NewDecoder(io.LimitReader(source, 2<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(&input); err != nil {
		return input, errors.New("connect reads one credentials JSON object from stdin or --credentials")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return input, errors.New("only one credentials JSON object is accepted")
	}
	return input, nil
}

// providerHosts returns the host names of a provider's origins, so a
// whole-browser export is narrowed before it is sent to the daemon.
func providerHosts(ctx context.Context, c *client.Client, name string) ([]string, error) {
	providers, err := c.Providers(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range providers {
		if p.Name != name {
			continue
		}
		var hosts []string
		for _, origin := range p.Origins {
			u, err := url.Parse(origin)
			if err != nil || u.Hostname() == "" {
				return nil, fmt.Errorf("provider %s lists an invalid origin", name)
			}
			hosts = append(hosts, strings.ToLower(u.Hostname()))
		}
		return hosts, nil
	}
	return nil, fmt.Errorf("unknown provider %q; see galleton providers", name)
}

// readCookies parses a cookie export locally and keeps only cookies for the
// given hosts; only those are sent to the daemon, which filters again.
func readCookies(path, format string, hosts []string) ([]cookiefile.Cookie, string, error) {
	var source io.Reader = os.Stdin
	if path != "-" {
		file, err := os.Open(path)
		if err != nil {
			return nil, "", err
		}
		defer file.Close()
		source = file
	}
	cookies, used, err := cookiefile.Read(source, format, hosts...)
	if err != nil {
		return nil, used, fmt.Errorf("cookie export: %w", err)
	}
	return cookies, used, nil
}
