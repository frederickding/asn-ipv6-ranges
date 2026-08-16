package main

import (
	"net/netip"
	"os"
	"sync"
	"time"

	"asn-ipv6-ranges/internal/radb"
	"asn-ipv6-ranges/internal/whoisfreaks"
)

const cacheTTL = 5 * time.Minute

// Seams overridden in tests to avoid real network calls and real waiting.
var (
	whoisQuery = radb.Query
	orgLookup  = whoisfreaks.LookupOrgName
	nowFunc    = time.Now
	getenv     = os.Getenv
)

type cacheEntry struct {
	prefixes  []netip.Prefix
	queriedAt time.Time
}

type orgCacheEntry struct {
	name      string
	fetchedAt time.Time
}

var (
	cacheMu sync.RWMutex
	cache   = make(map[string]cacheEntry)

	// Separate from the prefix cache: the org API is metered, so results are
	// reused for the same TTL to avoid repeat billing on refreshes.
	orgCacheMu sync.RWMutex
	orgCache   = make(map[string]orgCacheEntry)
)

// getPrefixes returns an ASN's prefixes plus the time of the upstream query
// that produced them. Failures are not cached, so a transient outage does not
// lock out retries for the whole TTL.
func getPrefixes(asn string) ([]netip.Prefix, time.Time, error) {
	cacheMu.RLock()
	entry, ok := cache[asn]
	cacheMu.RUnlock()
	if ok && nowFunc().Sub(entry.queriedAt) < cacheTTL {
		return entry.prefixes, entry.queriedAt, nil
	}

	output, err := whoisQuery(asn)
	if err != nil {
		return nil, time.Time{}, err
	}

	// Cached un-aggregated, so both agg=1 and agg=0 share one upstream query.
	prefixes := extractIPv6Prefixes(output)
	queriedAt := nowFunc()
	cacheMu.Lock()
	cache[asn] = cacheEntry{prefixes: prefixes, queriedAt: queriedAt}
	cacheMu.Unlock()
	return prefixes, queriedAt, nil
}

func getOrgName(asn, apiKey string) (string, error) {
	orgCacheMu.RLock()
	entry, ok := orgCache[asn]
	orgCacheMu.RUnlock()
	if ok && nowFunc().Sub(entry.fetchedAt) < cacheTTL {
		return entry.name, nil
	}

	name, err := orgLookup(asn, apiKey)
	if err != nil {
		return "", err
	}

	orgCacheMu.Lock()
	orgCache[asn] = orgCacheEntry{name: name, fetchedAt: nowFunc()}
	orgCacheMu.Unlock()
	return name, nil
}
