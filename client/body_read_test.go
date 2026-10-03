package client_test

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/Microck/galleton/client"
)

func TestInterruptedDaemonResponsePreservesAmbiguousStatus(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		request := make([]byte, 4096)
		_, _ = conn.Read(request)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{}")
	}()

	c, err := client.New("http://"+listener.Addr().String(), "local")
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Status(context.Background(), "alice")
	var apiErr *client.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected typed ambiguous error, got %T: %v", err, err)
	}
	if apiErr.Status != 200 || apiErr.Code != "daemon_unavailable" ||
		!strings.Contains(apiErr.Message, "may already have completed") {
		t.Fatalf("lost interrupted-response context: %#v", apiErr)
	}
	<-done
}
