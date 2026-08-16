package main

import (
	"errors"
	"fmt"
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

const cacheTTL = 5 * time.Minute

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

	orgCacheMu.Lock()
	orgCache[key] = orgCacheEntry{result: result, fetchedAt: nowFunc()}
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
