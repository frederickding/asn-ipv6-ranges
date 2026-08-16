// Command asn-ipv6-ranges serves the IPv6 prefixes announced by an ASN as
// text/plain, one prefix per line.
//
// Source data comes from two upstreams, each isolated in its own package:
// internal/radb (raw WHOIS over TCP) and internal/whoisfreaks (the optional
// HTTPS organization-name lookup). This package holds the HTTP surface,
// caching, and ASN/prefix logic.
package main

//go:generate go run gen_asn_ranges.go

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// listenAddr resolves the bind address: LISTEN_ADDR wins, else PORT (the
// serverless container convention), else :8080.
func listenAddr() string {
	if addr := os.Getenv("LISTEN_ADDR"); addr != "" {
		return addr
	}
	if port := os.Getenv("PORT"); port != "" {
		return ":" + port
	}
	return ":8080"
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/as/", asHandler)
	// Exact path, no trailing slash: only /-/status matches.
	mux.HandleFunc(statusPath, statusHandler)

	srv := &http.Server{
		Addr:              listenAddr(),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("listening on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
}
