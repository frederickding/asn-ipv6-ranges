package main

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"time"

	"asn-ipv6-ranges/internal/asnreg"
	"asn-ipv6-ranges/internal/radb"
	"asn-ipv6-ranges/internal/rirwhois"
	"asn-ipv6-ranges/internal/whoisfreaks"
)

const cacheTTL = 5 * time.Minute

// Seams overridden in tests to avoid real network calls and real waiting.
var (
	whoisQuery   = radb.Query
	orgAPILookup = whoisfreaks.LookupOrgName
	orgRIRLookup = rirwhois.LookupOrgName
	nowFunc      = time.Now
	getenv       = os.Getenv
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

// orgCacheKey separates forced-RIR answers from default ones: the two can
// differ, and serving one for the other would misreport the source.
type orgCacheKey struct {
	asn      string
	forceRIR bool
}

type orgCacheEntry struct {
	result    orgResult
	fetchedAt time.Time
}

var (
	cacheMu sync.RWMutex
	cache   = make(map[string]cacheEntry)

	// Separate from the prefix cache: the org API is metered and RIR whois
	// servers rate-limit, so results are reused for the same TTL.
	orgCacheMu sync.RWMutex
	orgCache   = make(map[orgCacheKey]orgCacheEntry)
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

func getOrgName(asn string, v uint64, forceRIR bool) (orgResult, error) {
	key := orgCacheKey{asn: asn, forceRIR: forceRIR}

	orgCacheMu.RLock()
	entry, ok := orgCache[key]
	orgCacheMu.RUnlock()
	if ok && nowFunc().Sub(entry.fetchedAt) < cacheTTL {
		return entry.result, nil
	}

	result, err := resolveOrgName(asn, v, forceRIR)
	if err != nil {
		return orgResult{}, err
	}

	orgCacheMu.Lock()
	orgCache[key] = orgCacheEntry{result: result, fetchedAt: nowFunc()}
	orgCacheMu.Unlock()
	return result, nil
}

// resolveOrgName picks a source for the organization name.
//
// By default the WhoisFreaks API is tried first when a key is configured, with
// the authoritative RIR as fallback. With forceRIR the API is skipped entirely
// and no fallback occurs — a forced lookup that fails must report the failure,
// otherwise the parameter could not be used to exercise the RIR path.
func resolveOrgName(asn string, v uint64, forceRIR bool) (orgResult, error) {
	reg, haveRegistry := asnreg.Lookup(v)

	if forceRIR {
		if !haveRegistry {
			return orgResult{}, fmt.Errorf("no registry known for AS%s", asn)
		}
		name, err := orgRIRLookup(reg, asn)
		if err != nil {
			return orgResult{}, fmt.Errorf("%s: %w", reg.WHOISHost, err)
		}
		return orgResult{name: name, source: reg.WHOISHost}, nil
	}

	var apiErr error
	if apiKey := getenv(whoisfreaks.KeyEnv); apiKey != "" {
		name, err := orgAPILookup(asn, apiKey)
		if err == nil {
			return orgResult{name: name, source: whoisfreaks.Host}, nil
		}
		apiErr = fmt.Errorf("%s: %w", whoisfreaks.Host, err)
	}

	if !haveRegistry {
		if apiErr != nil {
			return orgResult{}, apiErr
		}
		return orgResult{}, fmt.Errorf("no registry known for AS%s", asn)
	}

	name, err := orgRIRLookup(reg, asn)
	if err != nil {
		rirErr := fmt.Errorf("%s: %w", reg.WHOISHost, err)
		if apiErr != nil {
			return orgResult{}, errors.Join(apiErr, rirErr)
		}
		return orgResult{}, rirErr
	}
	return orgResult{name: name, source: reg.WHOISHost}, nil
}
