package main

import (
	"errors"
	"strconv"
	"testing"
	"time"

	"asn-ipv6-ranges/internal/asnreg"
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

	_, t0, err := getPrefixes("2906")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 upstream call, got %d", calls)
	}

	clock = clock.Add(time.Minute)
	_, t1, err := getPrefixes("2906")
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
	_, t2, err := getPrefixes("2906")
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

	if _, _, err := getPrefixes("2906"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cacheHas("2906") {
		t.Fatal("entry should be cached")
	}

	// Just short of the limit, the cold entry is still retained.
	clock = clock.Add(cacheMaxAge - time.Minute)
	if _, _, err := getPrefixes("24940"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cacheHas("2906") {
		t.Error("entry younger than cacheMaxAge was evicted")
	}

	// Past it, the next insert reaps it.
	clock = clock.Add(2 * time.Minute)
	if _, _, err := getPrefixes("13335"); err != nil {
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
		if _, _, err := getPrefixes(strconv.Itoa(1000 + i)); err != nil {
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

	if _, _, err := getPrefixes("2906"); err != nil {
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
	orgRIRLookup = func(asnreg.Registry, string) (string, error) { return "Netflix", nil }

	if _, _, err := getPrefixes("2906"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := getOrgName("2906", 2906, srcWHOIS); err != nil {
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
	if _, _, err := getPrefixes("2906"); err != nil {
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
	orgRIRLookup = func(_ asnreg.Registry, asn string) (string, error) { return "Org " + asn, nil }

	for i := range cacheMaxEntries * 2 {
		clock = clock.Add(time.Second)
		asn := strconv.Itoa(1000 + i)
		if _, err := getOrgName(asn, uint64(1000+i), srcWHOIS); err != nil {
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

func TestGetPrefixesDoesNotCacheErrors(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	calls := 0
	swapTestHooks(t, &clock, func(string) (string, error) {
		calls++
		return "", errors.New("dial failed")
	})

	if _, _, err := getPrefixes("2906"); err == nil {
		t.Fatal("expected error")
	}
	if _, _, err := getPrefixes("2906"); err == nil {
		t.Fatal("expected error")
	}
	if calls != 2 {
		t.Errorf("errors must not be cached, got %d calls", calls)
	}
}
