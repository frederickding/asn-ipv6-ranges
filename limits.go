package main

import (
	"log"
	"net/http"
	"strconv"
)

// Server-side limits on how much work one process will hold at once.
const (
	// defaultMaxInflight bounds concurrent requests, and through them memory.
	//
	// Go's default is one goroutine per connection with no ceiling, so without
	// this a burst of requests for large ASNs walks straight past GOMEMLIMIT
	// and the container's memory limit, and the pod is OOM-killed. Trading a
	// 503 for a restart is the right side of that bargain: a shed request is
	// one client's error, a restart drops every in-flight request and empties
	// the cache.
	//
	// 32 was never a real ceiling, though — it was sized against memory alone,
	// ignoring that every uncached request also has to clear a per-upstream
	// budget in upstream.go before it does any real work. RADB's is the tight
	// one, radbBudget.concurrency = 3, and it is hit by every request this
	// service serves, cached org lookups aside. A live measurement makes the
	// gap concrete: 12 concurrent requests for 12 distinct, uncached real ASNs
	// produced exactly 3 successes (0.17s, 1.24s, 3.35s) and 9 immediate
	// sub-5ms 503s — the other 29 slots a limit of 32 would have reserved were
	// never reachable, since a spent budget fails fast rather than queuing.
	//
	// 12 is the sum of every upstream's own concurrency ceiling — radb(3) +
	// lacnic(2) + ripe(2) + registry(2) + api(2) = 11, rounded up by one — so a
	// burst that legitimately maxes out every registry at once (a mixed batch
	// of org=1 requests, say) still finds a free slot, with the remainder
	// available for cache hits, which never touch a budget at all and are the
	// traffic this number should actually flex for. Raise it and the memory
	// limit together, never alone.
	defaultMaxInflight = 12

	// inflightRetryAfter is advertised on a shed request. Requests are shed
	// because the process is momentarily saturated, which is a condition that
	// clears in well under a second.
	inflightRetryAfter = 1
)

// maxInflight is resolved once at startup from MAX_INFLIGHT.
var maxInflight = defaultMaxInflight

// initLimits reads the concurrency cap from the environment.
//
// An unusable value warns and keeps the default rather than refusing to start,
// matching initAccessLog: a bad tuning knob should not take the service down.
// Zero and negative values are rejected rather than treated as "unlimited" —
// unlimited is the behaviour this exists to remove.
func initLimits() {
	raw := getenv("MAX_INFLIGHT")
	if raw == "" {
		return
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 1 {
		log.Printf("invalid MAX_INFLIGHT value %q, using %d", raw, defaultMaxInflight)
		return
	}
	maxInflight = v
}

// withInflightLimit caps concurrent requests, answering 503 once the cap is
// reached rather than queueing.
//
// Failing fast is deliberate. Queueing would hold the connection, the goroutine
// and its buffers — the very resources the cap is protecting — and hand back an
// answer the client has probably stopped waiting for. A 503 with Retry-After
// tells a well-behaved client to back off and tells a misconfigured one nothing
// it can use to consume more.
//
// The health endpoint is exempt: shedding a readiness probe under load would
// depool a pod that is working exactly as designed, converting overload into an
// outage. Only that one path — versionPath shares the /-/ prefix but nothing
// polls it on an interval, so it is ordinary traffic and stays under the cap
// rather than becoming an unauthenticated way past it.
func withInflightLimit(next http.Handler) http.Handler {
	slots := make(chan struct{}, maxInflight)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == statusPath {
			next.ServeHTTP(w, r)
			return
		}

		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
			next.ServeHTTP(w, r)
		default:
			w.Header().Set("Retry-After", strconv.Itoa(inflightRetryAfter))
			writeError(w, http.StatusServiceUnavailable,
				"server is at its concurrent request limit, retry shortly")
		}
	})
}
