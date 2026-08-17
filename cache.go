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
	"asn-ipv6-ranges/internal/cymrudns"
	"asn-ipv6-ranges/internal/peeringdb"
	"asn-ipv6-ranges/internal/radb"
	"asn-ipv6-ranges/internal/ratelimit"
	"asn-ipv6-ranges/internal/rdap"
	"asn-ipv6-ranges/internal/rirwhois"
)

// Cache bounds. For each cache these are three separate limits, and it is
// worth keeping them distinct:
//
//   - TTL is freshness: past it, an entry is re-queried upstream rather than
//     served.
//   - MaxAge is retention: past it, an entry is deleted outright. Only
//     entries nobody has successfully refreshed reach this age, so it is what
//     reclaims ASNs that were queried once and never again. It must stay
//     above TTL — retention below freshness would delete an entry before it
//     ever goes stale, forcing a needless re-query.
//   - MaxEntries is capacity, the hard bound on memory. Without it the maps
//     grew with the number of distinct ASNs ever queried, so a scan of the
//     ASN space was an unbounded allocation.
//
// The prefix and org caches use different values for all three: an ASN's
// announced prefixes can change at any time, but its registered organization
// changes on the timescale of ASN reassignment — years, not minutes — so the
// org cache can hold answers far longer, which is also fewer queries against
// the tightly-budgeted registries in doc/networking.md. See doc/caching.md.
//
// failureTTL is how long a failed lookup is remembered, shared by both
// caches. Without it, an ASN whose upstream answer is broken — or an ASN
// chosen precisely because it fails — is re-queried on every single request,
// so inbound rate becomes upstream rate with the cache contributing nothing.
const (
	prefixCacheTTL        = 5 * time.Minute
	prefixCacheMaxAge     = time.Hour
	prefixCacheMaxEntries = 256

	orgCacheTTL        = 6 * time.Hour
	orgCacheMaxAge     = 72 * time.Hour
	orgCacheMaxEntries = 512

	failureTTL = 30 * time.Second
)

// Org sources, as selected by the src request parameter.
const (
	srcAuto      = "auto"
	srcCymru     = "cymru"
	srcPeeringDB = "peeringdb"
	srcWHOIS     = "whois"
	srcRDAP      = "rdap"
)

// orgSources lists the valid src values, for validation and error messages.
var orgSources = []string{srcAuto, srcCymru, srcPeeringDB, srcWHOIS, srcRDAP}

// Seams overridden in tests to avoid real network calls and real waiting.
var (
	whoisQuery              = radb.Query
	orgCymruLookup          = cymrudns.LookupOrgName
	orgPeeringDBLookup      = peeringdb.LookupOrgName
	orgPeeringDBBatchLookup = peeringdb.LookupOrgNames
	orgRIRLookup            = rirwhois.LookupOrgName
	orgRDAPLookup           = rdap.LookupOrgName
	nowFunc                 = time.Now
	getenv                  = os.Getenv
)

// budgetError reports that an upstream's query budget is spent. It carries the
// host so the handler can advertise a Retry-After specific to that budget, and
// unwraps to ratelimit.ErrLimited so callers can test for the condition without
// knowing about this type.
type budgetError struct{ host string }

// The host is deliberately absent from the message: callers that report an
// upstream failure already prefix it with the host they were querying.
func (e *budgetError) Error() string {
	return "query budget for this upstream is exhausted, not querying it"
}

func (e *budgetError) Unwrap() error { return ratelimit.ErrLimited }

// call is one in-flight upstream lookup. Every request that asks for the same
// thing while it runs waits on it instead of starting its own.
type call[T any] struct {
	done chan struct{}
	val  T
	err  error
}

// group coalesces concurrent lookups for the same key into one.
//
// This is what makes the upstream budgets hold. Without it, the cache only
// helps requests that arrive after an answer is stored, so a burst of K
// concurrent requests for one uncached ASN is K identical upstream queries —
// and pointing a bot at one ASN was enough to generate unbounded upstream load.
// With it, that burst costs exactly one query and the other K-1 requests wait
// for its result.
type group[K comparable, T any] struct {
	mu sync.Mutex
	m  map[K]*call[T]
}

// do runs fn for key, or waits for the in-flight call that is already doing so.
//
// A waiter that gives up (its own context is cancelled) leaves the leader
// running: the leader has its own deadline, and abandoning a query mid-flight
// would waste the upstream request that everyone else is still waiting for.
//
// The converse costs a little accuracy: if the leader's own request is
// cancelled, its waiters see that cancellation rather than an answer. They are
// no worse off than if they had queried alone and been refused, and nothing is
// cached, so the next request gets a real lookup.
func (g *group[K, T]) do(ctx context.Context, key K, fn func() (T, error)) (T, error) {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[K]*call[T])
	}
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		select {
		case <-c.done:
			return c.val, c.err
		case <-ctx.Done():
			var zero T
			return zero, ctx.Err()
		}
	}
	c := &call[T]{done: make(chan struct{})}
	g.m[key] = c
	g.mu.Unlock()

	// Deleted before the waiters are released so a request arriving after this
	// call finishes starts a fresh one rather than joining a completed call.
	c.val, c.err = fn()
	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()
	close(c.done)

	return c.val, c.err
}

var (
	prefixGroup group[string, cacheEntry]
	orgGroup    group[orgCacheKey, orgCacheEntry]
)

// cacheable reports whether a failure is worth remembering.
//
// Only the upstream's own answers are. A cancelled request says nothing about
// the ASN, and a refusal from our own rate limiter is already backed off by the
// limiter itself — caching either would deny a later, legitimate request an
// answer it could have had.
func cacheable(ctx context.Context, err error) bool {
	if err == nil {
		return true
	}
	if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return !errors.Is(err, ratelimit.ErrLimited)
}

// cacheEntry holds either a result or the failure that replaced it. Failures
// are cached too, for the shorter failureTTL — see getPrefixes.
type cacheEntry struct {
	prefixes  []netip.Prefix
	err       error
	queriedAt time.Time
}

// fresh reports whether an entry may still be served. Failures expire sooner
// than results: they are cached to stop repeat upstream queries, not because
// they are worth keeping.
func (e cacheEntry) fresh(now time.Time) bool {
	return isFresh(e.queriedAt, e.err, prefixCacheTTL, now)
}

// isFresh reports whether an entry queried at at is still servable without a
// re-query. A failed lookup uses the shared, much shorter failureTTL instead
// of the cache's own ttl, regardless of which cache is asking.
func isFresh(at time.Time, err error, ttl time.Duration, now time.Time) bool {
	if err != nil {
		ttl = failureTTL
	}
	return now.Sub(at) < ttl
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
	err       error
	fetchedAt time.Time
}

func (e orgCacheEntry) fresh(now time.Time) bool {
	return isFresh(e.fetchedAt, e.err, orgCacheTTL, now)
}

var (
	cacheMu sync.RWMutex
	cache   = make(map[string]cacheEntry)

	// Separate from the prefix cache: the org API is metered and registry
	// servers rate-limit, so results are reused for the same TTL.
	orgCacheMu sync.RWMutex
	orgCache   = make(map[orgCacheKey]orgCacheEntry)
)

// pruneLocked enforces maxAge and maxEntries on a cache map. It runs after an
// insert, and the caller must hold the write lock.
//
// keep names the entry just written, which is exempt: having just paid for an
// upstream query, discarding its result immediately would be pointless work.
//
// Sweeping on write rather than from a background goroutine keeps the cache
// free of a lifecycle to start, stop, and synchronize in tests. The cost is
// bounded by maxEntries, so it is a scan of at most a few hundred entries on a
// path that has just done network I/O.
func pruneLocked[K comparable, V any](m map[K]V, keep K, timestamp func(V) time.Time, now time.Time, maxAge time.Duration, maxEntries int) {
	for k, v := range m {
		if k != keep && now.Sub(timestamp(v)) >= maxAge {
			delete(m, k)
		}
	}

	// Still over capacity: drop the least recently refreshed. Entries are
	// rewritten whenever a request refreshes them past their TTL, so the
	// oldest timestamp identifies the coldest ASN.
	for len(m) > maxEntries {
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

// sweepCaches deletes entries past their cache's max age from both caches and
// reports how many went.
//
// Inserts prune as they go, which covers a pod that is serving traffic. This
// exists for the idle case: with no requests arriving there is no insert to
// trigger a prune, so a pod that goes quiet would hold its last entries —
// up to prefixCacheMaxEntries and orgCacheMaxEntries respectively —
// indefinitely. Retention should not depend on someone making a request.
func sweepCaches(now time.Time) int {
	before := 0
	// The zero key is passed as keep because no real entry uses it: an ASN key
	// is always a canonicalized decimal string, never empty.
	cacheMu.Lock()
	before += len(cache)
	pruneLocked(cache, "", func(e cacheEntry) time.Time { return e.queriedAt }, now, prefixCacheMaxAge, prefixCacheMaxEntries)
	after := len(cache)
	cacheMu.Unlock()

	orgCacheMu.Lock()
	before += len(orgCache)
	pruneLocked(orgCache, orgCacheKey{}, func(e orgCacheEntry) time.Time { return e.fetchedAt }, now, orgCacheMaxAge, orgCacheMaxEntries)
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

// lookupPrefixCache returns a cached entry if one is still fresh.
func lookupPrefixCache(asn string) (cacheEntry, bool) {
	cacheMu.RLock()
	entry, ok := cache[asn]
	cacheMu.RUnlock()
	return entry, ok && entry.fresh(nowFunc())
}

// getPrefixes returns an ASN's prefixes plus the time of the upstream query
// that produced them.
//
// Three things bound the upstream load this can generate, and all three are
// needed: the cache serves repeats, the group coalesces concurrent misses into
// one query, and the budget refuses the query outright when RADB's allowance is
// spent. A failure is cached for failureTTL rather than not at all — the old
// behaviour let one unanswerable ASN be replayed into unlimited upstream
// traffic — but only when it came from RADB itself, per cacheable.
func getPrefixes(ctx context.Context, asn string) ([]netip.Prefix, time.Time, error) {
	if entry, ok := lookupPrefixCache(asn); ok {
		return entry.prefixes, entry.queriedAt, entry.err
	}

	entry, err := prefixGroup.do(ctx, asn, func() (cacheEntry, error) {
		// Re-checked inside the group: this call may have been queued behind
		// one that has just stored an answer.
		if entry, ok := lookupPrefixCache(asn); ok {
			return entry, entry.err
		}

		output, err := withUpstreamBudget(radb.Host, func() (string, error) {
			return whoisQuery(ctx, asn)
		})
		if err != nil && !cacheable(ctx, err) {
			return cacheEntry{}, err
		}

		// Cached un-aggregated, so both agg=1 and agg=0 share one upstream query.
		entry := cacheEntry{queriedAt: nowFunc(), err: err}
		if err == nil {
			entry.prefixes = extractIPv6Prefixes(output)
		}

		cacheMu.Lock()
		cache[asn] = entry
		pruneLocked(cache, asn, func(e cacheEntry) time.Time { return e.queriedAt }, entry.queriedAt, prefixCacheMaxAge, prefixCacheMaxEntries)
		cacheMu.Unlock()
		return entry, err
	})
	if err != nil {
		return nil, time.Time{}, err
	}
	return entry.prefixes, entry.queriedAt, nil
}

func lookupOrgCache(key orgCacheKey) (orgCacheEntry, bool) {
	orgCacheMu.RLock()
	entry, ok := orgCache[key]
	orgCacheMu.RUnlock()
	return entry, ok && entry.fresh(nowFunc())
}

// getOrgName resolves an ASN's organization name, on the same three terms as
// getPrefixes. It matters more here: an org lookup can reach a registry whose
// published limit is as low as a hundred queries per five minutes.
func getOrgName(ctx context.Context, asn string, v uint64, src string) (orgResult, error) {
	key := orgCacheKey{asn: asn, src: src}

	if entry, ok := lookupOrgCache(key); ok {
		return entry.result, entry.err
	}

	entry, err := orgGroup.do(ctx, key, func() (orgCacheEntry, error) {
		if entry, ok := lookupOrgCache(key); ok {
			return entry, entry.err
		}

		result, err := resolveOrgName(ctx, asn, v, src)
		if err != nil && !cacheable(ctx, err) {
			return orgCacheEntry{}, err
		}

		entry := orgCacheEntry{result: result, err: err, fetchedAt: nowFunc()}
		orgCacheMu.Lock()
		orgCache[key] = entry
		// Bounded on the same terms as the prefix cache, but with its own
		// longer-lived TTL/max-age and larger capacity — see the constants
		// above. Entries here are far smaller than a prefix list, but an
		// unbounded map is an unbounded map, and this one is keyed by
		// {asn, src} so a single ASN can occupy up to four slots.
		pruneLocked(orgCache, key, func(e orgCacheEntry) time.Time { return e.fetchedAt }, entry.fetchedAt, orgCacheMaxAge, orgCacheMaxEntries)
		orgCacheMu.Unlock()
		return entry, err
	})
	if err != nil {
		return orgResult{}, err
	}
	return entry.result, nil
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
// With src auto, Cymru's DNS zone is tried first, then PeeringDB, then the
// two registry sources in the order preferRDAP chooses. Cymru and PeeringDB
// both treat an empty org name as an error internally, so this loop's normal
// "try the next source on any error" behavior already produces the
// empty-name fallback for free. An explicit src uses only that source and
// never falls back, so the parameter can be trusted to exercise one path.
//
// If Cymru and PeeringDB both come back with a *confirmed* empty result —
// cymrudns.ErrNotFound / peeringdb.ErrNotFound, not just any failure — the
// registry sources are skipped entirely rather than queried and (almost
// certainly) also come back empty. Any other failure from either one
// (a budget refusal, an upstream's own rate-limit response, a timeout, a
// malformed record) leaves that flag false, so the registry fallback still
// runs exactly as before: the two cheap sources have to actually agree the
// ASN has no data, not merely fail to answer.
func resolveOrgName(ctx context.Context, asn string, v uint64, src string) (orgResult, error) {
	reg, haveRegistry := asnreg.Lookup(v)

	switch src {
	case srcCymru:
		return lookupCymru(ctx, asn)

	case srcPeeringDB:
		return lookupPeeringDBBatched(ctx, asn)

	case srcWHOIS:
		if !haveRegistry {
			return orgResult{}, fmt.Errorf("no registry known for AS%s", asn)
		}
		return lookupWHOIS(ctx, reg, asn)

	case srcRDAP:
		if !haveRegistry {
			return orgResult{}, fmt.Errorf("no registry known for AS%s", asn)
		}
		return lookupRDAP(ctx, reg, asn)
	}

	// src auto: try each available source in turn, reporting every failure if
	// none succeeds. Cymru/PeeringDB are the cheap sources positioned to
	// protect the registries, so — unlike the registry loop below — a budget
	// refusal from either one is not a reason to stop early; falling through
	// to the next source (even eventually a registry) is exactly the point.
	var errs []error
	var cymruNotFound, peeringdbNotFound bool
	if res, err := lookupCymru(ctx, asn); err == nil {
		return res, nil
	} else {
		errs = append(errs, err)
		cymruNotFound = errors.Is(err, cymrudns.ErrNotFound)
	}
	if res, err := lookupPeeringDB(ctx, asn); err == nil {
		return res, nil
	} else {
		errs = append(errs, err)
		peeringdbNotFound = errors.Is(err, peeringdb.ErrNotFound)
	}

	if cymruNotFound && peeringdbNotFound {
		errs = append(errs, errors.New(
			"skipping RIR whois/RDAP: Cymru DNS and PeeringDB both confirm no organization record for this ASN"))
		return orgResult{}, errors.Join(errs...)
	}

	if !haveRegistry {
		if len(errs) == 0 {
			errs = append(errs, fmt.Errorf("no registry known for AS%s", asn))
		}
		return orgResult{}, errors.Join(errs...)
	}

	registryLookups := []func(context.Context, asnreg.Registry, string) (orgResult, error){lookupWHOIS, lookupRDAP}
	if preferRDAP(reg) {
		registryLookups = []func(context.Context, asnreg.Registry, string) (orgResult, error){lookupRDAP, lookupWHOIS}
	}
	for _, lookup := range registryLookups {
		res, err := lookup(ctx, reg, asn)
		if err == nil {
			return res, nil
		}
		errs = append(errs, err)
		// A budget refusal is not a reason to try the next source: the fallback
		// would spend another registry's budget answering a request the first
		// one already declined, turning one shed query into two.
		if errors.Is(err, ratelimit.ErrLimited) {
			break
		}
	}
	return orgResult{}, errors.Join(errs...)
}

func lookupCymru(ctx context.Context, asn string) (orgResult, error) {
	resolver := getenv(cymrudns.ResolverEnv)
	name, err := withUpstreamBudget(cymrudns.Host, func() (string, error) {
		return orgCymruLookup(ctx, asn, resolver)
	})
	if err != nil {
		return orgResult{}, fmt.Errorf("%s: %w", cymrudns.Host, err)
	}
	return orgResult{name: name, source: cymrudns.Host}, nil
}

func lookupPeeringDB(ctx context.Context, asn string) (orgResult, error) {
	apiKey := getenv(peeringdb.KeyEnv)
	name, err := withUpstreamBudget(peeringdb.Host, func() (string, error) {
		return orgPeeringDBLookup(ctx, asn, apiKey)
	})
	if err != nil {
		return orgResult{}, fmt.Errorf("%s: %w", peeringdb.Host, err)
	}
	return orgResult{name: name, source: peeringdb.Host}, nil
}

// lookupWHOIS spends one token per lookup even though rirwhois may issue a
// follow-up query to resolve an org: handle. The budgets are sized with that
// second query in mind, and the concurrency slot — which is what RIPE's AUP
// actually limits — is held across both.
func lookupWHOIS(ctx context.Context, reg asnreg.Registry, asn string) (orgResult, error) {
	name, err := withUpstreamBudget(reg.WHOISHost, func() (string, error) {
		return orgRIRLookup(ctx, reg, asn)
	})
	if err != nil {
		return orgResult{}, fmt.Errorf("%s: %w", reg.WHOISHost, err)
	}
	return orgResult{name: name, source: reg.WHOISHost}, nil
}

func lookupRDAP(ctx context.Context, reg asnreg.Registry, asn string) (orgResult, error) {
	if reg.RDAPBase == "" {
		return orgResult{}, fmt.Errorf("%s: no RDAP endpoint", reg.Name)
	}
	host := rdapHost(reg)
	name, err := withUpstreamBudget(host, func() (string, error) {
		return orgRDAPLookup(ctx, reg, asn)
	})
	if err != nil {
		// The registry's own verdict on our rate outranks the budget we guessed
		// for it: park the host until it says we may resume.
		var limited *rdap.RateLimitedError
		if errors.As(err, &limited) {
			retryAfter := limited.RetryAfter
			if retryAfter <= 0 {
				retryAfter = defaultUpstreamPause
			}
			pauseUpstream(host, nowFunc().Add(retryAfter))
		}
		return orgResult{}, fmt.Errorf("%s: %w", host, err)
	}
	return orgResult{name: name, source: host}, nil
}

// rdapHost is the RDAP base reduced to a hostname, for the source annotation.
func rdapHost(reg asnreg.Registry) string {
	host := strings.TrimPrefix(reg.RDAPBase, "https://")
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	return host
}
