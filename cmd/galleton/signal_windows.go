//go:build windows

package main

import (
	"os"
	"os/signal"
	"syscall"
)

func registerTerminate(stop func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM)
	go func() { <-ch; stop() }()
}
