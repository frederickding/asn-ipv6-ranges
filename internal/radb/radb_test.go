package radb

import (
	"bufio"
	"net"
	"strings"
	"testing"
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

	body, err := Query("2906")
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

	if _, err := Query("2906"); err == nil {
		t.Fatal("expected a dial error")
	}
}

func TestHost(t *testing.T) {
	// Host is printed in service output, so keep it hostname-only (no port).
	if strings.Contains(Host, ":") {
		t.Errorf("Host must not include a port: %q", Host)
	}
}
