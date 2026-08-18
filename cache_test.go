package main

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"asn-ipv6-ranges/internal/asnreg"
	"asn-ipv6-ranges/internal/ratelimit"
)

// Cache accessors used by the eviction tests, taking the same locks the
// production code does so the race detector stays quiet.
func cacheLen() int {
	cacheMu.RLock()
	defer cacheMu.RUnlock()
	return len(cache)
}

func cacheHas(asn string) bool {
	cacheMu.RLock()
	defer cacheMu.RUnlock()
	_, ok := cache[asn]
	return ok
}

func orgCacheLen() int {
	orgCacheMu.RLock()
	defer orgCacheMu.RUnlock()
	return len(orgCache)
}

func TestGetPrefixesCaching(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	calls := 0
	swapTestHooks(t, &clock, func(string) (string, error) {
		calls++
		return sampleWhois, nil
	})

	rest0, err := getPrefixes(context.Background(), "2906", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 upstream call, got %d", calls)
	}

	clock = clock.Add(time.Minute)
	rest1, err := getPrefixes(context.Background(), "2906", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Errorf("cache hit should not query upstream, got %d calls", calls)
	}
	if t0, t1 := rest0.queriedAt, rest1.queriedAt; !t1.Equal(t0) {
		t.Errorf("cached timestamp changed: %v -> %v", t0, t1)
	}

	clock = clock.Add(prefixCacheTTL)
	rest2, err := getPrefixes(context.Background(), "2906", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 2 {
		t.Errorf("expected refresh after TTL, got %d calls", calls)
	}
	if t0, t2 := rest0.queriedAt, rest2.queriedAt; !t2.After(t0) {
		t.Errorf("refreshed timestamp should advance: %v -> %v", t0, t2)
	}
}

// TestCacheEvictsPastMaxAge covers the retention rule: an entry that nobody has
// refreshed within prefixCacheMaxAge is deleted, not merely ignored.
func TestCacheEvictsPastMaxAge(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	swapTestHooks(t, &clock, func(string) (string, error) { return sampleWhois, nil })

	if _, err := getPrefixes(context.Background(), "2906", true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cacheHas("2906") {
		t.Fatal("entry should be cached")
	}

	// Just short of the limit, the cold entry is still retained.
	clock = clock.Add(prefixCacheMaxAge - time.Minute)
	if _, err := getPrefixes(context.Background(), "24940", true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cacheHas("2906") {
		t.Error("entry younger than prefixCacheMaxAge was evicted")
	}

	// Past it, the next insert reaps it.
	clock = clock.Add(2 * time.Minute)
	if _, err := getPrefixes(context.Background(), "13335", true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cacheHas("2906") {
		t.Error("entry older than prefixCacheMaxAge should have been deleted")
	}
	if !cacheHas("24940") {
		t.Error("younger entry should have survived")
	}
}

// TestCacheRespectsMaxEntries is the memory bound: the map must never exceed
// prefixCacheMaxEntries no matter how many distinct ASNs are queried.
func TestCacheRespectsMaxEntries(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	swapTestHooks(t, &clock, func(string) (string, error) { return sampleWhois, nil })

	for i := range prefixCacheMaxEntries * 2 {
		// Advance the clock so recency is well defined, but stay inside
		// prefixCacheMaxAge so this exercises capacity eviction rather than age.
		clock = clock.Add(time.Second)
		if _, err := getPrefixes(context.Background(), strconv.Itoa(1000+i), true); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n := cacheLen(); n > prefixCacheMaxEntries {
			t.Fatalf("after %d inserts the cache holds %d entries, over the %d cap", i+1, n, prefixCacheMaxEntries)
		}
	}

	if n := cacheLen(); n != prefixCacheMaxEntries {
		t.Errorf("cache holds %d entries, want it filled to %d", n, prefixCacheMaxEntries)
	}

	// The oldest go first, so the most recent inserts must all be present.
	for i := prefixCacheMaxEntries; i < prefixCacheMaxEntries*2; i++ {
		if !cacheHas(strconv.Itoa(1000 + i)) {
			t.Errorf("recent entry AS%d was evicted before older ones", 1000+i)
		}
	}
	// ...and the earliest must be gone.
	if cacheHas("1000") {
		t.Error("the oldest entry survived eviction")
	}
}

// TestCacheKeepsTheEntryJustWritten guards the pruneLocked keep parameter: a
// full cache must not discard the result of the upstream query that just ran.
func TestCacheKeepsTheEntryJustWritten(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	swapTestHooks(t, &clock, func(string) (string, error) { return sampleWhois, nil })

	// Fill to capacity with entries that all share a timestamp, so the new
	// entry cannot win eviction on recency alone.
	cacheMu.Lock()
	for i := range prefixCacheMaxEntries {
		cache[strconv.Itoa(5000+i)] = cacheEntry{queriedAt: clock}
	}
	cacheMu.Unlock()

	if _, err := getPrefixes(context.Background(), "2906", true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cacheHas("2906") {
		t.Error("the entry just fetched was evicted immediately")
	}
	if n := cacheLen(); n != prefixCacheMaxEntries {
		t.Errorf("cache holds %d entries, want %d", n, prefixCacheMaxEntries)
	}
}

// TestSweepCachesReapsWhenIdle covers the case inserts cannot: a pod with no
// traffic must still release entries past their cache's max age. The two
// caches' max ages differ, so the clock advances past the longer of the two
// (the org cache's) to confirm both get reaped in the same sweep.
func TestSweepCachesReapsWhenIdle(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	swapTestHooks(t, &clock, func(string) (string, error) { return sampleWhois, nil })

	getenv = func(string) string { return "" }
	orgRIRLookup = func(context.Context, asnreg.Registry, string) (string, error) { return "Netflix", nil }

	if _, err := getPrefixes(context.Background(), "2906", true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := getOrgName(context.Background(), "2906", 2906, srcWHOIS); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// No further requests arrive; only the sweep runs.
	clock = clock.Add(orgCacheMaxAge + time.Minute)
	if n := sweepCaches(clock); n != 2 {
		t.Errorf("sweep removed %d entries, want 2", n)
	}
	if cacheLen() != 0 {
		t.Errorf("prefix cache still holds %d entries", cacheLen())
	}
	if orgCacheLen() != 0 {
		t.Errorf("org cache still holds %d entries", orgCacheLen())
	}

	// A sweep with nothing to do must not remove live entries.
	if _, err := getPrefixes(context.Background(), "2906", true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n := sweepCaches(clock); n != 0 {
		t.Errorf("sweep removed %d fresh entries, want 0", n)
	}
	if cacheLen() != 1 {
		t.Errorf("fresh entry was swept: %d entries", cacheLen())
	}
}

// TestOrgCacheRespectsMaxEntries: the org cache is keyed by {asn, src}, so it
// grows up to four times faster per ASN and needs the same bound.
func TestOrgCacheRespectsMaxEntries(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	swapTestHooks(t, &clock, func(string) (string, error) { return sampleWhois, nil })
	orgRIRLookup = func(_ context.Context, _ asnreg.Registry, asn string) (string, error) { return "Org " + asn, nil }

	for i := range orgCacheMaxEntries * 2 {
		clock = clock.Add(time.Second)
		asn := strconv.Itoa(1000 + i)
		if _, err := getOrgName(context.Background(), asn, uint64(1000+i), srcWHOIS); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n := orgCacheLen(); n > orgCacheMaxEntries {
			t.Fatalf("org cache holds %d entries, over the %d cap", n, orgCacheMaxEntries)
		}
	}
	if n := orgCacheLen(); n != orgCacheMaxEntries {
		t.Errorf("org cache holds %d entries, want %d", n, orgCacheMaxEntries)
	}
}

// TestGetPrefixesCachesErrorsBriefly is the bound on failure traffic: an ASN
// that cannot be resolved must not be replayable into one upstream query per
// request. The failure is remembered, but only for failureTTL, so a transient
// outage does not lock out retries for the full prefixCacheTTL.
func TestGetPrefixesCachesErrorsBriefly(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	calls := 0
	swapTestHooks(t, &clock, func(string) (string, error) {
		calls++
		return "", errors.New("dial failed")
	})

	for range 5 {
		if _, err := getPrefixes(context.Background(), "2906", true); err == nil {
			t.Fatal("expected error")
		}
	}
	if calls != 1 {
		t.Errorf("repeat failures must be served from cache, got %d upstream calls", calls)
	}

	// Past failureTTL the ASN is retried...
	clock = clock.Add(failureTTL + time.Second)
	if _, err := getPrefixes(context.Background(), "2906", true); err == nil {
		t.Fatal("expected error")
	}
	if calls != 2 {
		t.Errorf("a failure older than failureTTL must be retried, got %d upstream calls", calls)
	}

	// ...but not for the whole prefixCacheTTL, which is what a successful
	// answer gets.
	if failureTTL >= prefixCacheTTL {
		t.Errorf("failureTTL %s must be shorter than prefixCacheTTL %s", failureTTL, prefixCacheTTL)
	}
}

// TestGetPrefixesDoesNotCacheCancellations separates the two kinds of failure:
// a cancelled request says nothing about the ASN, so caching it would deny the
// next caller an answer it could have had.
func TestGetPrefixesDoesNotCacheCancellations(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	calls := 0
	swapTestHooks(t, &clock, func(string) (string, error) { return sampleWhois, nil })

	whoisQuery = func(ctx context.Context, _ string) (string, error) {
		calls++
		if calls == 1 {
			return "", ctx.Err()
		}
		return sampleWhois, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := getPrefixes(ctx, "2906", true); err == nil {
		t.Fatal("expected error")
	}

	if _, err := getPrefixes(context.Background(), "2906", true); err != nil {
		t.Fatalf("a cancelled lookup must not poison the cache: %v", err)
	}
	if calls != 2 {
		t.Errorf("got %d upstream calls, want 2", calls)
	}
}

// TestOrgCacheOutlivesPrefixCacheTTL is the point of splitting the two caches'
// bounds apart: an org name must still be served from cache well past the
// point where a prefix list for the same ASN would have gone stale.
func TestOrgCacheOutlivesPrefixCacheTTL(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	swapTestHooks(t, &clock, func(string) (string, error) { return sampleWhois, nil })
	orgCalls := 0
	orgRIRLookup = func(context.Context, asnreg.Registry, string) (string, error) {
		orgCalls++
		return "Netflix", nil
	}

	if _, err := getPrefixes(context.Background(), "2906", true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := getOrgName(context.Background(), "2906", 2906, srcWHOIS); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if orgCalls != 1 {
		t.Fatalf("expected 1 org lookup, got %d", orgCalls)
	}

	// Past the prefix TTL, short of the org TTL.
	clock = clock.Add(prefixCacheTTL + time.Second)
	if prefixCacheTTL >= orgCacheTTL {
		t.Fatalf("prefixCacheTTL %s must be shorter than orgCacheTTL %s for this test to mean anything", prefixCacheTTL, orgCacheTTL)
	}

	if entry, ok := lookupPrefixEntry("2906"); ok && entry.servable(clock) {
		t.Errorf("prefix entry is still considered fresh after prefixCacheTTL: %+v", entry)
	}
	if _, ok := lookupOrgCache(orgCacheKey{asn: "2906", src: srcWHOIS}); !ok {
		t.Error("org entry went stale before orgCacheTTL elapsed")
	}

	if _, err := getOrgName(context.Background(), "2906", 2906, srcWHOIS); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if orgCalls != 1 {
		t.Errorf("org name was re-queried before orgCacheTTL elapsed, got %d calls", orgCalls)
	}
}

// TestUpstreamBudgetRefusesQuery is the guarantee the registries care about:
// once the budget for an upstream is spent, no request reaches it, however many
// arrive.
func TestUpstreamBudgetRefusesQuery(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	calls := 0
	swapTestHooks(t, &clock, func(string) (string, error) {
		calls++
		return sampleWhois, nil
	})
	// One query, then nothing until the bucket refills a second later.
	swapUpstreamBudget(t, budget{rate: 1, burst: 1, concurrency: 1})

	if _, err := getPrefixes(context.Background(), "2906", true); err != nil {
		t.Fatalf("first query should be allowed: %v", err)
	}

	// Distinct ASNs, so neither the cache nor coalescing can absorb them.
	for i := range 20 {
		_, err := getPrefixes(context.Background(), strconv.Itoa(4000+i), true)
		if !errors.Is(err, ratelimit.ErrLimited) {
			t.Fatalf("query %d: got %v, want a budget refusal", i, err)
		}
	}
	if calls != 1 {
		t.Errorf("upstream saw %d queries, want 1", calls)
	}

	// A refusal is not an answer about the ASN, so it must not be cached.
	if cacheHas("4000") {
		t.Error("a budget refusal was cached")
	}
}

// TestGetPrefixesCoalescesConcurrentMisses is what makes the budgets hold: a
// burst of requests for one uncached ASN must cost exactly one upstream query,
// not one per request.
func TestGetPrefixesCoalescesConcurrentMisses(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)

	var mu sync.Mutex
	calls := 0
	release := make(chan struct{})
	swapTestHooks(t, &clock, func(string) (string, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		// Held open so every goroutine is waiting before the answer lands.
		<-release
		return sampleWhois, nil
	})

	const concurrent = 50
	var wg sync.WaitGroup
	errs := make([]error, concurrent)
	for i := range concurrent {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = getPrefixes(context.Background(), "2906", true)
		}()
	}

	// Let the goroutines pile up on the single in-flight call before it answers.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Errorf("%d concurrent requests produced %d upstream queries, want 1", concurrent, calls)
	}
}

// TestStalePrefixesServedWhenBudgetSpent is the headline case: RADB is the
// narrowest upstream here, and once its budget is spent the expired-but-held
// entry is a free answer. Refusing to use it would cost the client an answer
// and invite the retry that costs RADB another query.
func TestStalePrefixesServedWhenBudgetSpent(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	calls := 0
	swapTestHooks(t, &clock, func(asn string) (string, error) {
		if asn == "2906" {
			calls++
		}
		return sampleWhois, nil
	})

	res, err := getPrefixes(context.Background(), "2906", true)
	if err != nil {
		t.Fatalf("warming the cache: %v", err)
	}
	warm := res.queriedAt
	if res.stale {
		t.Error("a freshly queried answer must not be reported stale")
	}

	// Past the TTL, well short of retention. The bucket never refills at rate
	// 0, and New floors burst at 1, so spend that one token on another ASN to
	// leave the budget genuinely exhausted.
	clock = clock.Add(prefixCacheTTL + 18*time.Minute)
	swapUpstreamBudget(t, budget{rate: 0, burst: 1, concurrency: 1})
	if _, err := getPrefixes(context.Background(), "3999", true); err != nil {
		t.Fatalf("spending the last token: %v", err)
	}

	res, err = getPrefixes(context.Background(), "2906", true)
	if err != nil {
		t.Fatalf("expected the stale entry, got error: %v", err)
	}
	if !res.stale {
		t.Error("a past-TTL answer was not reported as stale")
	}
	if !res.queriedAt.Equal(warm) {
		t.Errorf("queriedAt moved: %v -> %v; it must keep naming when the data was obtained", warm, res.queriedAt)
	}
	if len(res.prefixes) == 0 {
		t.Error("stale answer carried no prefixes")
	}
	if calls != 1 {
		t.Errorf("serving stale cost %d upstream queries, want 0 beyond the first", calls-1)
	}
}

// TestStalePrefixesSurviveACachedFailure is the case that shaped cacheEntry: a
// failure that gets cached used to overwrite the entry outright, destroying the
// data the fallback needs. The entry has to hold both.
func TestStalePrefixesSurviveACachedFailure(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	calls := 0
	fail := false
	swapTestHooks(t, &clock, func(string) (string, error) {
		calls++
		if fail {
			return "", errors.New("dial tcp: connection refused")
		}
		return sampleWhois, nil
	})

	res, err := getPrefixes(context.Background(), "2906", true)
	if err != nil {
		t.Fatalf("warming the cache: %v", err)
	}
	warm := res.queriedAt

	clock = clock.Add(prefixCacheTTL + time.Minute)
	fail = true

	res, err = getPrefixes(context.Background(), "2906", true)
	if err != nil {
		t.Fatalf("a transport failure with usable data cached must not error: %v", err)
	}
	if !res.stale || !res.queriedAt.Equal(warm) {
		t.Errorf("got %+v, want the original data marked stale", res)
	}
	if calls != 2 {
		t.Fatalf("got %d upstream calls, want 2", calls)
	}

	// Within failureTTL the failure is still remembered, so the next request
	// serves the same stale data without asking RADB again.
	res, err = getPrefixes(context.Background(), "2906", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.stale || calls != 2 {
		t.Errorf("negative caching stopped working: stale=%v, %d upstream calls", res.stale, calls)
	}
}

// TestStaleOptOutReturnsTheError: stale=0 gets the failure it asked for, and —
// just as important — does not generate an extra upstream query to get it.
func TestStaleOptOutReturnsTheError(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	calls := 0
	fail := false
	swapTestHooks(t, &clock, func(string) (string, error) {
		calls++
		if fail {
			return "", errors.New("dial tcp: connection refused")
		}
		return sampleWhois, nil
	})

	if _, err := getPrefixes(context.Background(), "2906", true); err != nil {
		t.Fatalf("warming the cache: %v", err)
	}
	clock = clock.Add(prefixCacheTTL + time.Minute)
	fail = true

	if _, err := getPrefixes(context.Background(), "2906", false); err == nil {
		t.Fatal("stale=0 must surface the failure, not the expired entry")
	}
	if calls != 2 {
		t.Fatalf("got %d upstream calls, want 2", calls)
	}

	// The cached failure path must honour it too, and still not re-query.
	if _, err := getPrefixes(context.Background(), "2906", false); err == nil {
		t.Error("stale=0 served an expired entry from the cached-failure path")
	}
	if calls != 2 {
		t.Errorf("stale=0 cost an extra upstream query: %d calls", calls)
	}

	// The opt-out is per-request: it must not have changed what is stored.
	if _, err := getPrefixes(context.Background(), "2906", true); err != nil {
		t.Errorf("one client's stale=0 changed what another is served: %v", err)
	}
}

// TestStalePrefixesRespectRetention: past prefixCacheMaxAge an entry is
// promised to be gone. Retention is swept lazily, so it can still be sitting in
// the map — serving it anyway would make the documented bound meaningless.
func TestStalePrefixesRespectRetention(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	fail := false
	swapTestHooks(t, &clock, func(string) (string, error) {
		if fail {
			return "", errors.New("dial tcp: connection refused")
		}
		return sampleWhois, nil
	})

	if _, err := getPrefixes(context.Background(), "2906", true); err != nil {
		t.Fatalf("warming the cache: %v", err)
	}
	clock = clock.Add(prefixCacheMaxAge + time.Second)
	fail = true

	if !cacheHas("2906") {
		t.Fatal("precondition: the entry should still be in the map, unswept")
	}
	if _, err := getPrefixes(context.Background(), "2906", true); err == nil {
		t.Error("an entry past prefixCacheMaxAge was served as stale")
	}
}

// TestFailureWithoutPriorDataStillErrors: the fallback only softens failures
// for ASNs we have answered before. A first-ever query that fails has nothing
// to fall back to and must say so.
func TestFailureWithoutPriorDataStillErrors(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	swapTestHooks(t, &clock, func(string) (string, error) {
		return "", errors.New("dial tcp: connection refused")
	})

	if _, err := getPrefixes(context.Background(), "2906", true); err == nil {
		t.Error("a cold failure was somehow answered")
	}
}

// TestFailureOnlyEntryIsNotSweptEarly: a failure with no prior data has no
// queriedAt to age from. Aging it from the zero time would make it look older
// than any retention bound, so the next insert would sweep it away and take
// the negative caching with it — the ASN would be re-queried on every request.
func TestFailureOnlyEntryIsNotSweptEarly(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	calls := 0
	swapTestHooks(t, &clock, func(asn string) (string, error) {
		calls++
		if asn == "2906" {
			return "", errors.New("dial tcp: connection refused")
		}
		return sampleWhois, nil
	})

	if _, err := getPrefixes(context.Background(), "2906", true); err == nil {
		t.Fatal("expected an error")
	}
	// An unrelated insert prunes, and the reaper does too.
	if _, err := getPrefixes(context.Background(), "24940", true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sweepCaches(clock)

	if !cacheHas("2906") {
		t.Fatal("the failure entry was swept before failureTTL elapsed")
	}
	if _, err := getPrefixes(context.Background(), "2906", true); err == nil {
		t.Fatal("expected an error")
	}
	if calls != 2 {
		t.Errorf("upstream saw %d queries, want 2: the failure must still suppress a re-query", calls)
	}

	// It still ages out on the ordinary schedule, measured from the failure.
	clock = clock.Add(prefixCacheMaxAge + time.Second)
	sweepCaches(clock)
	if cacheHas("2906") {
		t.Error("a failure entry outlived prefixCacheMaxAge")
	}
}
