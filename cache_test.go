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

	_, t0, err := getPrefixes(context.Background(), "2906")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 upstream call, got %d", calls)
	}

	clock = clock.Add(time.Minute)
	_, t1, err := getPrefixes(context.Background(), "2906")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Errorf("cache hit should not query upstream, got %d calls", calls)
	}
	if !t1.Equal(t0) {
		t.Errorf("cached timestamp changed: %v -> %v", t0, t1)
	}

	clock = clock.Add(cacheTTL)
	_, t2, err := getPrefixes(context.Background(), "2906")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 2 {
		t.Errorf("expected refresh after TTL, got %d calls", calls)
	}
	if !t2.After(t0) {
		t.Errorf("refreshed timestamp should advance: %v -> %v", t0, t2)
	}
}

// TestCacheEvictsPastMaxAge covers the retention rule: an entry that nobody has
// refreshed within cacheMaxAge is deleted, not merely ignored.
func TestCacheEvictsPastMaxAge(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	swapTestHooks(t, &clock, func(string) (string, error) { return sampleWhois, nil })

	if _, _, err := getPrefixes(context.Background(), "2906"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cacheHas("2906") {
		t.Fatal("entry should be cached")
	}

	// Just short of the limit, the cold entry is still retained.
	clock = clock.Add(cacheMaxAge - time.Minute)
	if _, _, err := getPrefixes(context.Background(), "24940"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cacheHas("2906") {
		t.Error("entry younger than cacheMaxAge was evicted")
	}

	// Past it, the next insert reaps it.
	clock = clock.Add(2 * time.Minute)
	if _, _, err := getPrefixes(context.Background(), "13335"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cacheHas("2906") {
		t.Error("entry older than cacheMaxAge should have been deleted")
	}
	if !cacheHas("24940") {
		t.Error("younger entry should have survived")
	}
}

// TestCacheRespectsMaxEntries is the memory bound: the map must never exceed
// cacheMaxEntries no matter how many distinct ASNs are queried.
func TestCacheRespectsMaxEntries(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	swapTestHooks(t, &clock, func(string) (string, error) { return sampleWhois, nil })

	for i := range cacheMaxEntries * 2 {
		// Advance the clock so recency is well defined, but stay inside
		// cacheMaxAge so this exercises capacity eviction rather than age.
		clock = clock.Add(time.Second)
		if _, _, err := getPrefixes(context.Background(), strconv.Itoa(1000+i)); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n := cacheLen(); n > cacheMaxEntries {
			t.Fatalf("after %d inserts the cache holds %d entries, over the %d cap", i+1, n, cacheMaxEntries)
		}
	}

	if n := cacheLen(); n != cacheMaxEntries {
		t.Errorf("cache holds %d entries, want it filled to %d", n, cacheMaxEntries)
	}

	// The oldest go first, so the most recent inserts must all be present.
	for i := cacheMaxEntries; i < cacheMaxEntries*2; i++ {
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
	for i := range cacheMaxEntries {
		cache[strconv.Itoa(5000+i)] = cacheEntry{queriedAt: clock}
	}
	cacheMu.Unlock()

	if _, _, err := getPrefixes(context.Background(), "2906"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cacheHas("2906") {
		t.Error("the entry just fetched was evicted immediately")
	}
	if n := cacheLen(); n != cacheMaxEntries {
		t.Errorf("cache holds %d entries, want %d", n, cacheMaxEntries)
	}
}

// TestSweepCachesReapsWhenIdle covers the case inserts cannot: a pod with no
// traffic must still release entries past cacheMaxAge.
func TestSweepCachesReapsWhenIdle(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	swapTestHooks(t, &clock, func(string) (string, error) { return sampleWhois, nil })

	getenv = func(string) string { return "" }
	orgRIRLookup = func(context.Context, asnreg.Registry, string) (string, error) { return "Netflix", nil }

	if _, _, err := getPrefixes(context.Background(), "2906"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := getOrgName(context.Background(), "2906", 2906, srcWHOIS); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// No further requests arrive; only the sweep runs.
	clock = clock.Add(cacheMaxAge + time.Minute)
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
	if _, _, err := getPrefixes(context.Background(), "2906"); err != nil {
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

	for i := range cacheMaxEntries * 2 {
		clock = clock.Add(time.Second)
		asn := strconv.Itoa(1000 + i)
		if _, err := getOrgName(context.Background(), asn, uint64(1000+i), srcWHOIS); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if n := orgCacheLen(); n > cacheMaxEntries {
			t.Fatalf("org cache holds %d entries, over the %d cap", n, cacheMaxEntries)
		}
	}
	if n := orgCacheLen(); n != cacheMaxEntries {
		t.Errorf("org cache holds %d entries, want %d", n, cacheMaxEntries)
	}
}

// TestGetPrefixesCachesErrorsBriefly is the bound on failure traffic: an ASN
// that cannot be resolved must not be replayable into one upstream query per
// request. The failure is remembered, but only for failureTTL, so a transient
// outage does not lock out retries for the full cacheTTL.
func TestGetPrefixesCachesErrorsBriefly(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	calls := 0
	swapTestHooks(t, &clock, func(string) (string, error) {
		calls++
		return "", errors.New("dial failed")
	})

	for range 5 {
		if _, _, err := getPrefixes(context.Background(), "2906"); err == nil {
			t.Fatal("expected error")
		}
	}
	if calls != 1 {
		t.Errorf("repeat failures must be served from cache, got %d upstream calls", calls)
	}

	// Past failureTTL the ASN is retried...
	clock = clock.Add(failureTTL + time.Second)
	if _, _, err := getPrefixes(context.Background(), "2906"); err == nil {
		t.Fatal("expected error")
	}
	if calls != 2 {
		t.Errorf("a failure older than failureTTL must be retried, got %d upstream calls", calls)
	}

	// ...but not for the whole cacheTTL, which is what a successful answer gets.
	if failureTTL >= cacheTTL {
		t.Errorf("failureTTL %s must be shorter than cacheTTL %s", failureTTL, cacheTTL)
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
	if _, _, err := getPrefixes(ctx, "2906"); err == nil {
		t.Fatal("expected error")
	}

	if _, _, err := getPrefixes(context.Background(), "2906"); err != nil {
		t.Fatalf("a cancelled lookup must not poison the cache: %v", err)
	}
	if calls != 2 {
		t.Errorf("got %d upstream calls, want 2", calls)
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

	if _, _, err := getPrefixes(context.Background(), "2906"); err != nil {
		t.Fatalf("first query should be allowed: %v", err)
	}

	// Distinct ASNs, so neither the cache nor coalescing can absorb them.
	for i := range 20 {
		_, _, err := getPrefixes(context.Background(), strconv.Itoa(4000+i))
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
			_, _, errs[i] = getPrefixes(context.Background(), "2906")
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
