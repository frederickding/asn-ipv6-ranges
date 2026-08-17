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
	// The binding cost is the upstream response: internal/radb caps a body at
	// 8 MiB, and a request holds that plus the prefixes parsed out of it. Go's
	// default is one goroutine per connection with no ceiling, so without this
	// a burst of requests for large ASNs walks straight past GOMEMLIMIT and the
	// container's memory limit, and the pod is OOM-killed. Trading a 503 for a
	// restart is the right side of that bargain: a shed request is one client's
	// error, a restart drops every in-flight request and empties the cache.
	//
	// 32 is sized against the 80 MiB GOMEMLIMIT in the manifest, assuming the
	// common case of responses far below the 8 MiB cap. Raise it and the memory
	// limit together, never alone.
	defaultMaxInflight = 32

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
// outage.
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
