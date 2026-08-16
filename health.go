package main

import (
	"fmt"
	"net/http"
	"time"
)

// statusPath is the health endpoint. The /-/ prefix is a common convention for
// operational endpoints and cannot collide with /as/{asn}.
const statusPath = "/-/status"

// startTime is when the process began serving, reported as uptime.
var startTime = time.Now()

// statusHandler answers Kubernetes liveness and readiness probes.
//
// It deliberately performs no upstream I/O. Probing RADB, a RIR, or the
// WhoisFreaks API here would tie the pod's health to third parties: an outage
// at any of them would fail the probe and make Kubernetes restart or
// depool otherwise-healthy pods, turning a degraded feature into an outage.
// The service can still serve cached prefixes and return useful errors while
// an upstream is down, so it is healthy in the sense a probe should measure —
// the process is up and its listener is accepting requests.
//
// The same endpoint suits both probe types: this service holds no startup
// state that would make it live but not yet ready.
func statusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, http.StatusMethodNotAllowed, "method %s not allowed, use GET", r.Method)
		return
	}

	cacheMu.RLock()
	prefixEntries := len(cache)
	cacheMu.RUnlock()

	orgCacheMu.RLock()
	orgEntries := len(orgCache)
	orgCacheMu.RUnlock()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// Probes must never be answered from an intermediary's cache.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	// The first line is the machine-readable verdict; the rest is detail for a
	// human reading the endpoint directly, in the same # comment style as the
	// prefix output.
	fmt.Fprintln(w, "ok")
	fmt.Fprintf(w, "# uptime: %s\n", nowFunc().Sub(startTime).Round(time.Second))
	// Reported against capacity: a cache sitting at its limit means entries are
	// being evicted, which is the signal that cacheMaxEntries is too low for
	// the traffic this pod sees.
	fmt.Fprintf(w, "# prefix cache: %d/%d ASNs\n", prefixEntries, cacheMaxEntries)
	fmt.Fprintf(w, "# org cache: %d/%d entries\n", orgEntries, cacheMaxEntries)
}
