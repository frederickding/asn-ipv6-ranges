package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"asn-ipv6-ranges/internal/asnreg"
	"asn-ipv6-ranges/internal/radb"
	"asn-ipv6-ranges/internal/rdap"
	"asn-ipv6-ranges/internal/rirwhois"
	"asn-ipv6-ranges/internal/whoisfreaks"
)

// Cache bounds. These are three separate limits, and it is worth keeping them
// distinct:
//
//   - cacheTTL is freshness: past it, an entry is re-queried upstream rather
//     than served.
//   - cacheMaxAge is retention: past it, an entry is deleted outright. Only
//     entries nobody has successfully refreshed reach this age, so it is what
//     reclaims ASNs that were queried once and never again.
//   - cacheMaxEntries is capacity, the hard bound on memory. Without it the
//     maps grew with the number of distinct ASNs ever queried, so a scan of the
//     ASN space was an unbounded allocation.
const (
	cacheTTL        = 5 * time.Minute
	cacheMaxAge     = time.Hour
	cacheMaxEntries = 256
)

// Org sources, as selected by the src request parameter.
const (
	srcAuto  = "auto"
	srcAPI   = "api"
	srcWHOIS = "whois"
	srcRDAP  = "rdap"
)

// orgSources lists the valid src values, for validation and error messages.
var orgSources = []string{srcAuto, srcAPI, srcWHOIS, srcRDAP}

// Seams overridden in tests to avoid real network calls and real waiting.
var (
	whoisQuery    = radb.Query
	orgAPILookup  = whoisfreaks.LookupOrgName
	orgRIRLookup  = rirwhois.LookupOrgName
	orgRDAPLookup = rdap.LookupOrgName
	nowFunc       = time.Now
	getenv        = os.Getenv
)

type cacheEntry struct {
	prefixes  []netip.Prefix
	queriedAt time.Time
}

// orgResult is an organization name plus the host that supplied it, so the
// response can say where the answer came from.
type orgResult struct {
	name   string
	source string
}

// orgCacheKey separates answers by requested source: the same ASN can resolve
// to different names from different sources, and serving one for another would
// misreport the source.
type orgCacheKey struct {
	asn string
	src string
}

type orgCacheEntry struct {
	result    orgResult
	fetchedAt time.Time
}

var (
	cacheMu sync.RWMutex
	cache   = make(map[string]cacheEntry)

	// Separate from the prefix cache: the org API is metered and registry
	// servers rate-limit, so results are reused for the same TTL.
	orgCacheMu sync.RWMutex
	orgCache   = make(map[orgCacheKey]orgCacheEntry)
)

// pruneLocked enforces cacheMaxAge and cacheMaxEntries on a cache map. It runs
// after an insert, and the caller must hold the write lock.
//
// keep names the entry just written, which is exempt: having just paid for an
// upstream query, discarding its result immediately would be pointless work.
//
// Sweeping on write rather than from a background goroutine keeps the cache
// free of a lifecycle to start, stop, and synchronize in tests. The cost is
// bounded by cacheMaxEntries, so it is a scan of at most a few hundred entries
// on a path that has just done network I/O.
func pruneLocked[K comparable, V any](m map[K]V, keep K, timestamp func(V) time.Time, now time.Time) {
	for k, v := range m {
		if k != keep && now.Sub(timestamp(v)) >= cacheMaxAge {
			delete(m, k)
		}
	}

	// Still over capacity: drop the least recently refreshed. Entries are
	// rewritten whenever a request refreshes them past cacheTTL, so the oldest
	// timestamp identifies the coldest ASN.
	for len(m) > cacheMaxEntries {
		var oldestKey K
		var oldestAt time.Time
		found := false
		for k, v := range m {
			if k == keep {
				continue
			}
			if t := timestamp(v); !found || t.Before(oldestAt) {
				oldestKey, oldestAt, found = k, t, true
			}
		}
		if !found {
			return
		}
		delete(m, oldestKey)
	}
}

// sweepInterval is how often idle caches are reaped.
const sweepInterval = time.Minute

// sweepCaches deletes entries past cacheMaxAge from both caches and reports how
// many went.
//
// Inserts prune as they go, which covers a pod that is serving traffic. This
// exists for the idle case: with no requests arriving there is no insert to
// trigger a prune, so a pod that goes quiet would hold its last 256 entries
// indefinitely. Retention should not depend on someone making a request.
func sweepCaches(now time.Time) int {
	before := 0
	// The zero key is passed as keep because no real entry uses it: an ASN key
	// is always a canonicalized decimal string, never empty.
	cacheMu.Lock()
	before += len(cache)
	pruneLocked(cache, "", func(e cacheEntry) time.Time { return e.queriedAt }, now)
	after := len(cache)
	cacheMu.Unlock()

	orgCacheMu.Lock()
	before += len(orgCache)
	pruneLocked(orgCache, orgCacheKey{}, func(e orgCacheEntry) time.Time { return e.fetchedAt }, now)
	after += len(orgCache)
	orgCacheMu.Unlock()

	return before - after
}

// startCacheReaper sweeps both caches on a ticker until ctx is cancelled.
func startCacheReaper(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(sweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n := sweepCaches(nowFunc()); n > 0 {
					log.Printf("cache sweep removed %d expired entries", n)
				}
			}
		}
	}()
}

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
	pruneLocked(cache, asn, func(e cacheEntry) time.Time { return e.queriedAt }, queriedAt)
	cacheMu.Unlock()
	return prefixes, queriedAt, nil
}

func getOrgName(asn string, v uint64, src string) (orgResult, error) {
	key := orgCacheKey{asn: asn, src: src}

	orgCacheMu.RLock()
	entry, ok := orgCache[key]
	orgCacheMu.RUnlock()
	if ok && nowFunc().Sub(entry.fetchedAt) < cacheTTL {
		return entry.result, nil
	}

	result, err := resolveOrgName(asn, v, src)
	if err != nil {
		return orgResult{}, err
	}

	fetchedAt := nowFunc()
	orgCacheMu.Lock()
	orgCache[key] = orgCacheEntry{result: result, fetchedAt: fetchedAt}
	// Bounded on the same terms. Entries here are far smaller than a prefix
	// list, but an unbounded map is an unbounded map, and this one is keyed by
	// {asn, src} so a single ASN can occupy up to four slots.
	pruneLocked(orgCache, key, func(e orgCacheEntry) time.Time { return e.fetchedAt }, fetchedAt)
	orgCacheMu.Unlock()
	return result, nil
}

// preferRDAP reports whether a registry's RDAP endpoint should be tried before
// its whois server in the automatic chain.
//
// RIPE is the only registry where whois is the expensive option. Its aut-num
// objects carry the operator's full routing policy — AS24940 answers with
// 60,151 bytes, of which 58,926 are 1,306 import:/export: lines — and its org
// name needs a second whois query to resolve the org: handle. RDAP returns the
// same name in 14,925 bytes and one request. Port 43 offers no way to exclude
// attributes, so the saving has to come from switching protocol.
//
// Elsewhere whois is smaller and single-query (ARIN: 1,683 bytes vs 5,432).
func preferRDAP(reg asnreg.Registry) bool {
	return reg.Name == "RIPE NCC"
}

// resolveOrgName picks a source for the organization name.
//
// With src auto, the WhoisFreaks API is tried first when a key is configured,
// then the two registry sources in the order preferRDAP chooses. An explicit
// src uses only that source and never falls back, so the parameter can be
// trusted to exercise one path.
func resolveOrgName(asn string, v uint64, src string) (orgResult, error) {
	reg, haveRegistry := asnreg.Lookup(v)

	switch src {
	case srcAPI:
		apiKey := getenv(whoisfreaks.KeyEnv)
		if apiKey == "" {
			return orgResult{}, fmt.Errorf("api selected but %s is not set", whoisfreaks.KeyEnv)
		}
		return lookupAPI(asn, apiKey)

	case srcWHOIS:
		if !haveRegistry {
			return orgResult{}, fmt.Errorf("no registry known for AS%s", asn)
		}
		return lookupWHOIS(reg, asn)

	case srcRDAP:
		if !haveRegistry {
			return orgResult{}, fmt.Errorf("no registry known for AS%s", asn)
		}
		return lookupRDAP(reg, asn)
	}

	// src auto: try each available source in turn, reporting every failure if
	// none succeeds.
	var errs []error
	if apiKey := getenv(whoisfreaks.KeyEnv); apiKey != "" {
		res, err := lookupAPI(asn, apiKey)
		if err == nil {
			return res, nil
		}
		errs = append(errs, err)
	}

	if !haveRegistry {
		if len(errs) == 0 {
			errs = append(errs, fmt.Errorf("no registry known for AS%s", asn))
		}
		return orgResult{}, errors.Join(errs...)
	}

	registryLookups := []func(asnreg.Registry, string) (orgResult, error){lookupWHOIS, lookupRDAP}
	if preferRDAP(reg) {
		registryLookups = []func(asnreg.Registry, string) (orgResult, error){lookupRDAP, lookupWHOIS}
	}
	for _, lookup := range registryLookups {
		res, err := lookup(reg, asn)
		if err == nil {
			return res, nil
		}
		errs = append(errs, err)
	}
	return orgResult{}, errors.Join(errs...)
}

func lookupAPI(asn, apiKey string) (orgResult, error) {
	name, err := orgAPILookup(asn, apiKey)
	if err != nil {
		return orgResult{}, fmt.Errorf("%s: %w", whoisfreaks.Host, err)
	}
	return orgResult{name: name, source: whoisfreaks.Host}, nil
}

func lookupWHOIS(reg asnreg.Registry, asn string) (orgResult, error) {
	name, err := orgRIRLookup(reg, asn)
	if err != nil {
		return orgResult{}, fmt.Errorf("%s: %w", reg.WHOISHost, err)
	}
	return orgResult{name: name, source: reg.WHOISHost}, nil
}

func lookupRDAP(reg asnreg.Registry, asn string) (orgResult, error) {
	if reg.RDAPBase == "" {
		return orgResult{}, fmt.Errorf("%s: no RDAP endpoint", reg.Name)
	}
	name, err := orgRDAPLookup(reg, asn)
	if err != nil {
		return orgResult{}, fmt.Errorf("%s: %w", rdapHost(reg), err)
	}
	return orgResult{name: name, source: rdapHost(reg)}, nil
}

// rdapHost is the RDAP base reduced to a hostname, for the source annotation.
func rdapHost(reg asnreg.Registry) string {
	host := strings.TrimPrefix(reg.RDAPBase, "https://")
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	return host
}
