package main

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"asn-ipv6-ranges/internal/asnreg"
)

const sampleWhois = `route:          23.246.0.0/18
descr:          SS-144
origin:         AS2906
source:         RADB

route6:         2a00:86c0::/32
origin:         AS2906
source:         RADB

route6:         2607:fb10::/32
origin:         AS2906
source:         RADB

route6:         2a00:86c0::/32
descr:          RPKI ROA for 2a00:86c0::/32 / AS2906
origin:         AS2906
source:         RPKI  # Trust Anchor: ripe

route:          23.246.15.0/24
origin:         AS2906
source:         NTTCOM
`

const nestedWhois = "route6: 2001:db8::/32\nroute6: 2001:db8:1::/48\nroute6: 2001:db9::/32\n"

func prefixStrings(ps []netip.Prefix) []string {
	if len(ps) == 0 {
		return nil
	}
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

func extractStrings(input string) []string {
	return prefixStrings(extractIPv6Prefixes(input))
}

func aggregateStrings(input string) []string {
	return prefixStrings(aggregatePrefixes(extractIPv6Prefixes(input)))
}

// swapTestHooks isolates cache/clock/upstream state for a single test. Both org
// sources and the env reader default to failing loudly, so any test that
// reaches them without opting in is caught rather than hitting the live paid
// API or a real RIR whois server.
//
// query takes no context: almost every test cares only about what the upstream
// returns, and threading a context through each stub would add noise to all of
// them for the benefit of the two that exercise cancellation. Those two assign
// whoisQuery directly.
func swapTestHooks(t *testing.T, clock *time.Time, query func(string) (string, error)) {
	t.Helper()
	origQuery := whoisQuery
	origCymru, origPeeringDB, origPeeringDBBatch := orgCymruLookup, orgPeeringDBLookup, orgPeeringDBBatchLookup
	origRIR, origRDAP := orgRIRLookup, orgRDAPLookup
	origNow, origGetenv := nowFunc, getenv

	whoisQuery = func(_ context.Context, asn string) (string, error) { return query(asn) }
	nowFunc = func() time.Time { return *clock }
	orgCymruLookup = func(context.Context, string, string) (string, error) {
		t.Error("Cymru DNS called without an explicit test hook")
		return "", errors.New("unexpected Cymru lookup")
	}
	orgPeeringDBLookup = func(context.Context, string, string) (string, error) {
		t.Error("PeeringDB called without an explicit test hook")
		return "", errors.New("unexpected PeeringDB lookup")
	}
	orgPeeringDBBatchLookup = func(context.Context, []string, string) (map[string]string, error) {
		t.Error("PeeringDB batch called without an explicit test hook")
		return nil, errors.New("unexpected PeeringDB batch lookup")
	}
	orgRIRLookup = func(context.Context, asnreg.Registry, string) (string, error) {
		t.Error("RIR whois called without an explicit test hook")
		return "", errors.New("unexpected RIR lookup")
	}
	orgRDAPLookup = func(context.Context, asnreg.Registry, string) (string, error) {
		t.Error("RIR RDAP called without an explicit test hook")
		return "", errors.New("unexpected RDAP lookup")
	}
	getenv = func(string) string { return "" }

	resetCaches := func() {
		cacheMu.Lock()
		cache = make(map[string]cacheEntry)
		cacheMu.Unlock()
		orgCacheMu.Lock()
		orgCache = make(map[orgCacheKey]orgCacheEntry)
		orgCacheMu.Unlock()
	}
	resetCaches()

	// Budgets are process-wide and keep a real clock, so a test's frozen clock
	// cannot refill them. Tests that are not about rate limiting get an
	// effectively unlimited budget; swapUpstreamBudget sets a real one.
	origBudgetFor := budgetFor
	budgetFor = func(string) budget { return unlimitedBudget }
	resetLimiters()

	// The PeeringDB batcher's pending queue is process-wide too; a
	// queued-but-never-drained request from one test could leak into the next.
	peeringdbBatchMu.Lock()
	peeringdbPending = nil
	peeringdbBusy = false
	peeringdbBatchMu.Unlock()

	t.Cleanup(func() {
		whoisQuery = origQuery
		orgCymruLookup, orgPeeringDBLookup, orgPeeringDBBatchLookup = origCymru, origPeeringDB, origPeeringDBBatch
		orgRIRLookup, orgRDAPLookup = origRIR, origRDAP
		nowFunc, getenv = origNow, origGetenv
		budgetFor = origBudgetFor
		resetCaches()
		resetLimiters()
	})
}

// swapUpstreamBudget gives every upstream the same budget for one test, so a
// test can exercise what happens when one is spent.
func swapUpstreamBudget(t *testing.T, b budget) {
	t.Helper()
	orig := budgetFor
	budgetFor = func(string) budget { return b }
	resetLimiters()
	t.Cleanup(func() {
		budgetFor = orig
		resetLimiters()
	})
}

// bodyComments returns only the "#" comment lines of a response.
func bodyComments(body string) []string {
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		if strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

func hasComment(body, want string) bool {
	return slices.Contains(bodyComments(body), want)
}
