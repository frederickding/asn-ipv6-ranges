package radb

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeWHOIS starts a local listener speaking the WHOIS protocol, points the
// package at it, and returns the query line the client sent.
func fakeWHOIS(t *testing.T, response string) <-chan string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	orig := addr
	addr = ln.Addr().String()
	t.Cleanup(func() { addr = orig })

	got := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		line, _ := bufio.NewReader(conn).ReadString('\n')
		got <- line
		// The client reads to EOF, so the close is what ends the response.
		conn.Write([]byte(response))
	}()
	return got
}

func TestQuery(t *testing.T) {
	const response = "route6:         2a00:86c0::/32\norigin:         AS2906\n"
	queries := fakeWHOIS(t, response)

	body, err := Query(context.Background(), "2906")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if body != response {
		t.Errorf("got body %q, want %q", body, response)
	}

	// The inverse-origin query must be CRLF-terminated, with the AS prefix
	// added by this package (callers pass a bare decimal ASN).
	if got := <-queries; got != "-i origin AS2906\r\n" {
		t.Errorf("sent %q", got)
	}
}

// TestQueryRejectsOversizedResponse: an over-limit response must be an error,
// never a silently shortened prefix list. Measured real responses run to
// 2.43 MB (AS4134), so the limit has to be both generous and enforced.
func TestQueryOversizedResponse(t *testing.T) {
	t.Run("at the limit is accepted", func(t *testing.T) {
		fakeWHOIS(t, strings.Repeat("x", maxBody))
		body, err := Query(context.Background(), "2906")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(body) != maxBody {
			t.Errorf("got %d bytes, want %d", len(body), maxBody)
		}
	})

	t.Run("one byte over is rejected", func(t *testing.T) {
		fakeWHOIS(t, strings.Repeat("x", maxBody+1))
		body, err := Query(context.Background(), "2906")
		if err == nil {
			t.Fatalf("oversized response accepted, returning %d bytes", len(body))
		}
		if !strings.Contains(err.Error(), "exceeds") {
			t.Errorf("unhelpful error: %v", err)
		}
		// Callers key off this sentinel to keep answering the parts of a
		// request that do not depend on the prefix list.
		if !errors.Is(err, ErrTooLarge) {
			t.Errorf("got %v, want ErrTooLarge", err)
		}
		if body != "" {
			t.Errorf("returned %d bytes alongside the error", len(body))
		}
	})
}

func TestQueryDialFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closed := ln.Addr().String()
	ln.Close() // nothing is listening now

	orig := addr
	addr = closed
	t.Cleanup(func() { addr = orig })

	if _, err := Query(context.Background(), "2906"); err == nil {
		t.Fatal("expected a dial error")
	}
}

func TestHost(t *testing.T) {
	// Host is printed in service output, so keep it hostname-only (no port).
	if strings.Contains(Host, ":") {
		t.Errorf("Host must not include a port: %q", Host)
	}
}

// TestQueryHonoursCancellation: RADB limits concurrent connections per source
// IP, so a query nobody is waiting on still costs us one of them. Cancelling
// the context must drop the connection rather than wait out the deadline.
func TestQueryHonoursCancellation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	// Accepts, reads the query, and then never answers.
	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		bufio.NewReader(conn).ReadString('\n')
		accepted <- struct{}{}
		select {}
	}()

	origAddr := addr
	addr = ln.Addr().String()
	t.Cleanup(func() { addr = origAddr })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := Query(ctx, "2906")
		done <- err
	}()

	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("server never saw the query")
	}
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("got %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("query outlived its cancelled context; it would hold a RADB connection slot")
	}
}
