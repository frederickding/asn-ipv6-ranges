// Command asn-ipv6-ranges serves the IPv6 prefixes announced by an ASN as
// text/plain, one prefix per line.
//
// Source data comes from several upstreams, each isolated in its own
// package: internal/radb (raw WHOIS over TCP) for prefixes, and
// internal/cymrudns (DNS), internal/peeringdb (HTTPS), internal/rirwhois
// (raw WHOIS), and internal/rdap (HTTPS) for organization-name lookups. This
// package holds the HTTP surface, caching, and ASN/prefix logic.
package main

//go:generate go run gen_asn_ranges.go

import (
	"context"
	"errors"
	"flag"
	"fmt"
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
	// The only flag this command takes. Because the image ENTRYPOINT is the
	// binary itself, this makes `docker run <image> -version` report what an
	// image contains without starting a server. Note that introducing flag
	// parsing at all means unrecognized arguments are now rejected rather than
	// ignored.
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(build.Version)
		return
	}

	initAccessLog()
	initLimits()
	logDataSources()

	mux := http.NewServeMux()
	mux.HandleFunc("/as/", asHandler)
	// Exact paths, no trailing slash: only /-/status and /-/version match.
	mux.HandleFunc(statusPath, statusHandler)
	mux.HandleFunc(versionPath, versionHandler)

	// The concurrency cap sits inside the access log so shed requests are still
	// logged — a burst of 503s is exactly what an operator needs to see.
	srv := &http.Server{
		Addr:    listenAddr(),
		Handler: withAccessLog(withInflightLimit(mux)),

		// Every one of these is load-bearing, and Go defaults them all to no
		// limit at all. Without ReadTimeout and WriteTimeout a client that
		// dribbles a request or refuses to read a response holds a goroutine
		// and its buffers indefinitely, which is the cheapest way to exhaust
		// this process's memory. Without IdleTimeout, keep-alive connections
		// are never reaped.
		//
		// WriteTimeout must stay above the handler's requestTimeout, or a slow
		// upstream would drop the connection before the handler could render
		// the error explaining why.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,

		// The request line and headers are attacker-controlled and reach a
		// builder in the access log. Nothing here needs Go's 1 MB default.
		MaxHeaderBytes: 16 << 10,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Reclaims cached entries once they pass their cache's max age, even while
	// the service is idle and no insert is prompting a prune.
	startCacheReaper(ctx)
	startStatsLogger(ctx)
	startPeeringDBBatcher(ctx)
	// Non-blocking: a key PeeringDB will not accept must be reported and
	// dropped, but never delay the listener or keep the service from starting.
	startPeeringDBKeyCheck(ctx)

	go func() {
		log.Printf("asn-ipv6-ranges %s listening on %s", build.Version, srv.Addr)
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
