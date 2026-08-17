package main

import (
	"log"
	"strings"
	"sync"
	"time"

	"asn-ipv6-ranges/internal/ratelimit"
)

// Outbound query budgets, one per upstream host.
//
// These are what keeps the service inside the registries' limits regardless of
// how much traffic arrives. Only LACNIC publishes usable numbers, and they are
// the tightest of the five, so its budget is set from its documented limit and
// everything else gets a conservative default. The sources for each number, and
// what is documented versus community-reported, are in doc/networking.md.
//
// Two caveats worth keeping in mind before tuning these upward:
//
//   - They are per process. The Kubernetes manifest runs replicas: 2, so the
//     rate a registry actually sees is these values times the replica count.
//     Halve them, or run a single replica, if a registry objects.
//   - They are a floor, not the only control. Coalescing (getPrefixes and
//     getOrgName) and the response cache mean the steady-state upstream rate is
//     far below these ceilings; the budget only binds during a burst of misses.
//
// Declared as vars rather than consts so tests can substitute tighter values.
var (
	// radbBudget covers the one upstream every uncached request reaches. RADB
	// does not publish a limit; the reported behaviour is 4 concurrent
	// connections per IP, with the fifth reset, so concurrency stays at 3.
	radbBudget = budget{rate: 2, burst: 5, concurrency: 3}

	// lacnicBudget is the strictest. LACNIC documents ~100 queries per 5
	// minutes and refuses aggressively, so 8/min leaves substantial headroom
	// even doubled across replicas.
	lacnicBudget = budget{rate: 8.0 / 60.0, burst: 4, concurrency: 2}

	// ripeBudget respects the AUP's cap of 3 simultaneous connections to the
	// database server, shared between its whois and RDAP front ends.
	ripeBudget = budget{rate: 2, burst: 5, concurrency: 2}

	// registryBudget is the default for ARIN, APNIC, and AFRINIC, none of which
	// publish a number. Chosen low enough that it should never be noticed.
	registryBudget = budget{rate: 2, burst: 5, concurrency: 2}

	// apiBudget covers the metered commercial API, where every call has a cost
	// and the limit is contractual rather than technical.
	apiBudget = budget{rate: 1, burst: 3, concurrency: 2}
)

type budget struct {
	rate        float64 // queries per second
	burst       int     // bucket depth
	concurrency int     // simultaneous queries
}

// budgetFor maps an upstream host to its budget. Matching is by registry rather
// than exact hostname so a registry's whois and RDAP front ends share one
// budget: they are the same service behind two protocols, and a limit measured
// per registry is what the registries themselves enforce.
//
// A var so tests can widen the budgets they are not exercising. The limiter
// keeps its own real clock, which a test's frozen clock cannot advance, so a
// test that made hundreds of lookups would otherwise exhaust a budget that real
// traffic — spread over real seconds — never would.
var budgetFor = func(host string) budget {
	switch {
	case host == "whois.radb.net":
		return radbBudget
	case strings.Contains(host, "lacnic"):
		return lacnicBudget
	case strings.Contains(host, "ripe"):
		return ripeBudget
	case strings.Contains(host, "whoisfreaks"):
		return apiBudget
	default:
		return registryBudget
	}
}

// unlimitedBudget is wide enough that no test hits it by accident. Tests that
// are about the budgets set their own.
var unlimitedBudget = budget{rate: 1e6, burst: 1e6, concurrency: 1024}

var (
	limitersMu sync.Mutex
	limiters   = make(map[string]*ratelimit.Limiter)
)

// limiterFor returns the limiter for an upstream host, creating it on first
// use. The set of hosts is closed — five registries times two protocols, plus
// RADB and the API — so this map cannot grow with traffic.
func limiterFor(host string) *ratelimit.Limiter {
	limitersMu.Lock()
	defer limitersMu.Unlock()
	l, ok := limiters[host]
	if !ok {
		b := budgetFor(host)
		l = ratelimit.New(b.rate, b.burst, b.concurrency)
		limiters[host] = l
	}
	return l
}

// withUpstreamBudget runs fn only if host's budget allows another query, and
// holds a concurrency slot for its duration.
//
// Every outbound call goes through here. Adding an upstream without one is the
// way this service would start exceeding a registry's limits again, so new
// callers belong in the lookup wrappers in cache.go rather than elsewhere.
func withUpstreamBudget[T any](host string, fn func() (T, error)) (T, error) {
	var zero T
	release, err := limiterFor(host).Acquire()
	if err != nil {
		return zero, &budgetError{host: host}
	}
	defer release()
	return fn()
}

// defaultUpstreamPause is how long an upstream is left alone after it
// rate-limits us without saying for how long. Long enough that we are visibly
// not the problem, short enough that one bad minute does not disable a source
// for the rest of the day.
const defaultUpstreamPause = 5 * time.Minute

// pauseUpstream parks a host's budget until t, in response to that host telling
// us we are querying too fast.
func pauseUpstream(host string, t time.Time) {
	log.Printf("upstream %s rate-limited us, pausing queries until %s", host, t.UTC().Format(time.RFC3339))
	limiterFor(host).PauseUntil(t)
}

// retryAfterFor is the Retry-After value to advertise when host's budget is
// spent, in whole seconds.
func retryAfterFor(host string) int {
	return int(limiterFor(host).RetryAfter() / time.Second)
}

// resetLimiters drops all limiter state, so a test starts with full budgets.
func resetLimiters() {
	limitersMu.Lock()
	defer limitersMu.Unlock()
	limiters = make(map[string]*ratelimit.Limiter)
}
