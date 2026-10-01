package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/Microck/galleton/client"
	"github.com/Microck/galleton/internal/core"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
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
		fmt.Println("Galleton " + core.Version + "\n\nCommands: init, serve, connect, status, list, refresh, forget, headers, request, version\n\nFlags follow the command, BEFORE positional IDs.\n  galleton init --dir ./state\n  galleton serve --dir ./state --config ./adapters.json\n  galleton connect --dir ./state account < credentials.json\n  galleton status --dir ./state account\n\nThe daemon listens on 127.0.0.1:8766. See README.md for adapters and SDKs.")
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
		srv, err := core.NewServer(*addr, core.Handler(manager, token))
		if err != nil {
			return err
		}
		listener, err := net.Listen("tcp", *addr)
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		// Include SIGTERM on Unix without referring to an unavailable Windows symbol.
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
	} else {
		if f.NArg() != 1 {
			return errors.New("provide one session ID after all flags")
		}
		id := f.Arg(0)
		switch args[0] {
		case "connect":
			var input client.Credentials
			d := json.NewDecoder(io.LimitReader(os.Stdin, 2<<20))
			d.DisallowUnknownFields()
			if err = d.Decode(&input); err != nil {
				return errors.New("connect reads one credentials JSON object from stdin")
			}
			var extra any
			if d.Decode(&extra) != io.EOF {
				return errors.New("only one credentials JSON object is accepted")
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
