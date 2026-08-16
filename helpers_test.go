package main

import (
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
func swapTestHooks(t *testing.T, clock *time.Time, query func(string) (string, error)) {
	t.Helper()
	origQuery, origAPI, origRIR := whoisQuery, orgAPILookup, orgRIRLookup
	origNow, origGetenv := nowFunc, getenv

	whoisQuery = query
	nowFunc = func() time.Time { return *clock }
	orgAPILookup = func(string, string) (string, error) {
		t.Error("WhoisFreaks API called without an explicit test hook")
		return "", errors.New("unexpected API lookup")
	}
	orgRIRLookup = func(asnreg.Registry, string) (string, error) {
		t.Error("RIR whois called without an explicit test hook")
		return "", errors.New("unexpected RIR lookup")
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

	t.Cleanup(func() {
		whoisQuery, orgAPILookup, orgRIRLookup = origQuery, origAPI, origRIR
		nowFunc, getenv = origNow, origGetenv
		resetCaches()
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
