package main

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// waitForPendingLen polls the batcher's pending queue until it reaches n, or
// fails the test after a generous timeout. Used to synchronize a test with
// goroutines racing to enqueue against the batcher's own goroutine.
func waitForPendingLen(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		peeringdbBatchMu.Lock()
		got := len(peeringdbPending)
		peeringdbBatchMu.Unlock()
		if got == n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d pending requests, have %d", n, got)
		}
		time.Sleep(time.Millisecond)
	}
}

func failWhois(t *testing.T) func(string) (string, error) {
	return func(string) (string, error) {
		t.Error("whois queried unexpectedly")
		return "", nil
	}
}

// TestLookupPeeringDBBatchedUncontended: with nothing else in flight, a
// request must take the plain single-ASN path immediately rather than being
// routed through the batch machinery at all — this is what "never hold the
// front-runner" guarantees in practice.
func TestLookupPeeringDBBatchedUncontended(t *testing.T) {
	clock := time.Now()
	swapTestHooks(t, &clock, failWhois(t))

	var singleCalls, batchCalls int32
	orgPeeringDBLookup = func(context.Context, string, string) (string, error) {
		atomic.AddInt32(&singleCalls, 1)
		return "Org 2906", nil
	}
	orgPeeringDBBatchLookup = func(context.Context, []string, string) (map[string]string, error) {
		atomic.AddInt32(&batchCalls, 1)
		return nil, errors.New("batch path should not be reached")
	}

	res, err := lookupPeeringDBBatched(context.Background(), "2906")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.name != "Org 2906" {
		t.Errorf("got %q", res.name)
	}
	if singleCalls != 1 {
		t.Errorf("got %d single-ASN calls, want 1", singleCalls)
	}
	if batchCalls != 0 {
		t.Errorf("got %d batch calls, want 0", batchCalls)
	}
}

// TestLookupPeeringDBBatchedMergesConcurrentRequests: two requests for
// different ASNs that are genuinely concurrent (forced here by marking a
// round "in flight" before either starts) must be answered by one shared
// orgPeeringDBBatchLookup call, not one each.
func TestLookupPeeringDBBatchedMergesConcurrentRequests(t *testing.T) {
	clock := time.Now()
	swapTestHooks(t, &clock, failWhois(t))

	orgPeeringDBLookup = func(context.Context, string, string) (string, error) {
		t.Error("single-ASN PeeringDB lookup called; expected both requests to share the batch path")
		return "", errors.New("unexpected")
	}
	var batchCalls int32
	var mu sync.Mutex
	var gotBatches [][]string
	orgPeeringDBBatchLookup = func(ctx context.Context, asns []string, key string) (map[string]string, error) {
		atomic.AddInt32(&batchCalls, 1)
		mu.Lock()
		gotBatches = append(gotBatches, append([]string(nil), asns...))
		mu.Unlock()
		result := make(map[string]string, len(asns))
		for _, asn := range asns {
			result[asn] = "Org " + asn
		}
		return result, nil
	}

	// Force both callers below to find a round already "in flight" so both
	// queue instead of one winning an uncontended fast path. The dispatcher
	// is deliberately not started yet: it drains the queue as soon as
	// anything is in it, with no regard for this flag, so starting it early
	// could let it grab just the first entry before the second one enqueues
	// — exactly the merge this test exists to prove happens.
	peeringdbBatchMu.Lock()
	peeringdbBusy = true
	peeringdbBatchMu.Unlock()

	var wg sync.WaitGroup
	results := make(chan orgResult, 2)
	for _, asn := range []string{"2906", "3356"} {
		wg.Add(1)
		go func(asn string) {
			defer wg.Done()
			res, err := lookupPeeringDBBatched(context.Background(), asn)
			if err != nil {
				t.Errorf("asn %s: unexpected error: %v", asn, err)
				return
			}
			results <- res
		}(asn)
	}

	waitForPendingLen(t, 2)

	// Now release the round and start the dispatcher: both entries are
	// already queued together, so it drains them in one round.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	peeringdbBatchMu.Lock()
	peeringdbBusy = false
	peeringdbBatchMu.Unlock()
	startPeeringDBBatcher(ctx)
	select {
	case peeringdbKick <- struct{}{}:
	default:
	}

	wg.Wait()
	close(results)

	got := map[string]bool{}
	for res := range results {
		got[res.name] = true
	}
	if !got["Org 2906"] || !got["Org 3356"] {
		t.Errorf("missing results: %v", got)
	}
	if batchCalls != 1 {
		t.Errorf("got %d batch calls, want 1 (both ASNs should have shared one)", batchCalls)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(gotBatches) != 1 || len(gotBatches[0]) != 2 {
		t.Errorf("got batches %v, want exactly one call with both ASNs", gotBatches)
	}
}

// TestLookupPeeringDBBatchedDoesNotRaceFastPath is a regression test for a
// real bug found via manual smoke-testing: the dispatcher, on waking from a
// kick, used to fire a round without checking whether a fast-path call (or
// another round) was already in flight. Under real concurrent load this
// meant a burst of different-ASN requests fragmented into many small/solo
// rounds that all fought over the same tight PeeringDB concurrency budget
// instead of merging into one — most of them failing with a budget-exhausted
// error rather than being answered. The dispatcher must now leave a kick
// that finds a round already busy as a no-op, and let whoever clears busy
// re-kick once they're done.
func TestLookupPeeringDBBatchedDoesNotRaceFastPath(t *testing.T) {
	clock := time.Now()
	swapTestHooks(t, &clock, failWhois(t))

	release := make(chan struct{})
	orgPeeringDBLookup = func(ctx context.Context, asn, key string) (string, error) {
		<-release
		return "Org " + asn, nil
	}
	var batchCalls int32
	var batchStartedAfterRelease int32
	orgPeeringDBBatchLookup = func(ctx context.Context, asns []string, key string) (map[string]string, error) {
		atomic.AddInt32(&batchCalls, 1)
		select {
		case <-release:
			atomic.AddInt32(&batchStartedAfterRelease, 1)
		default:
			t.Error("batch round fired while the fast-path leader was still in flight")
		}
		result := make(map[string]string, len(asns))
		for _, asn := range asns {
			result[asn] = "Org " + asn
		}
		return result, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startPeeringDBBatcher(ctx)

	// G1 takes the fast path and blocks until release.
	leaderDone := make(chan struct{})
	go func() {
		defer close(leaderDone)
		if _, err := lookupPeeringDBBatched(context.Background(), "2906"); err != nil {
			t.Errorf("leader: unexpected error: %v", err)
		}
	}()

	// G2 and G3 arrive while the leader is still in flight; both must queue.
	var wg sync.WaitGroup
	results := make(chan orgResult, 2)
	for _, asn := range []string{"3356", "15169"} {
		wg.Add(1)
		go func(asn string) {
			defer wg.Done()
			res, err := lookupPeeringDBBatched(context.Background(), asn)
			if err != nil {
				t.Errorf("asn %s: unexpected error: %v", asn, err)
				return
			}
			results <- res
		}(asn)
	}
	waitForPendingLen(t, 2)

	// Give the dispatcher real wall-clock time to (wrongly) fire a premature
	// round before the leader releases — this is what the buggy version did.
	time.Sleep(50 * time.Millisecond)
	if atomic.LoadInt32(&batchCalls) != 0 {
		t.Fatalf("batch fired %d time(s) before the leader finished, want 0", batchCalls)
	}

	close(release)

	select {
	case <-leaderDone:
	case <-time.After(2 * time.Second):
		t.Fatal("leader never finished")
	}
	wg.Wait()
	close(results)

	got := map[string]bool{}
	for res := range results {
		got[res.name] = true
	}
	if !got["Org 3356"] || !got["Org 15169"] {
		t.Errorf("missing results: %v", got)
	}
	if batchCalls != 1 {
		t.Errorf("got %d batch calls, want exactly 1 (both followers merged into one round)", batchCalls)
	}
	if batchStartedAfterRelease != 1 {
		t.Errorf("the one batch call did not correctly start after release")
	}
}

// TestLookupPeeringDBBatchedCancellation: a request whose ctx is cancelled
// while it's queued must return promptly with the cancellation error, and
// must not stop the round from still answering everyone else.
func TestLookupPeeringDBBatchedCancellation(t *testing.T) {
	clock := time.Now()
	swapTestHooks(t, &clock, failWhois(t))

	release := make(chan struct{})
	orgPeeringDBLookup = func(ctx context.Context, asn, key string) (string, error) {
		<-release
		return "Org " + asn, nil
	}
	orgPeeringDBBatchLookup = func(ctx context.Context, asns []string, key string) (map[string]string, error) {
		result := make(map[string]string, len(asns))
		for _, asn := range asns {
			result[asn] = "Org " + asn
		}
		return result, nil
	}

	// No dispatcher is started for this test: the follower's entry must stay
	// put in the queue, undrained, so cancelling it races against nothing —
	// a live dispatcher could otherwise answer it before bcancel() below
	// ever runs, turning this into a test of the success path instead.

	// A takes the fast path and blocks inside orgPeeringDBLookup until release.
	leaderDone := make(chan struct{})
	go func() {
		defer close(leaderDone)
		if _, err := lookupPeeringDBBatched(context.Background(), "2906"); err != nil {
			t.Errorf("leader: unexpected error: %v", err)
		}
	}()

	// Wait until the leader is actually busy before starting the follower,
	// so the follower is guaranteed to queue rather than race for the fast
	// path itself.
	deadline := time.Now().Add(2 * time.Second)
	for {
		peeringdbBatchMu.Lock()
		busy := peeringdbBusy
		peeringdbBatchMu.Unlock()
		if busy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("leader never marked the round busy")
		}
		time.Sleep(time.Millisecond)
	}

	bctx, bcancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := lookupPeeringDBBatched(bctx, "3356")
		done <- err
	}()

	waitForPendingLen(t, 1)
	bcancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("got %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled request did not return promptly")
	}

	// The abandoned round must still complete for whoever else is waiting;
	// releasing the leader here also lets its own fast-path call finish.
	close(release)
	select {
	case <-leaderDone:
	case <-time.After(2 * time.Second):
		t.Fatal("leader never finished")
	}
}

// TestLookupPeeringDBBatchedOverflowSplitsRounds: a queue larger than
// peeringdbMaxBatch must split into multiple rounds, each within the cap,
// and every request must still resolve correctly.
func TestLookupPeeringDBBatchedOverflowSplitsRounds(t *testing.T) {
	clock := time.Now()
	swapTestHooks(t, &clock, failWhois(t))

	orgPeeringDBLookup = func(context.Context, string, string) (string, error) {
		t.Error("single-ASN PeeringDB lookup called; expected the batch path")
		return "", errors.New("unexpected")
	}
	var mu sync.Mutex
	var callSizes []int
	orgPeeringDBBatchLookup = func(ctx context.Context, asns []string, key string) (map[string]string, error) {
		mu.Lock()
		callSizes = append(callSizes, len(asns))
		mu.Unlock()
		result := make(map[string]string, len(asns))
		for _, asn := range asns {
			result[asn] = "Org " + asn
		}
		return result, nil
	}

	// Dispatcher deliberately not started yet — see the comment in
	// TestLookupPeeringDBBatchedMergesConcurrentRequests.
	peeringdbBatchMu.Lock()
	peeringdbBusy = true
	peeringdbBatchMu.Unlock()

	const n = peeringdbMaxBatch + 50
	var wg sync.WaitGroup
	var okCount int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			asn := strconv.Itoa(i)
			res, err := lookupPeeringDBBatched(context.Background(), asn)
			if err == nil && res.name == "Org "+asn {
				atomic.AddInt32(&okCount, 1)
			} else if err != nil {
				t.Errorf("asn %s: unexpected error: %v", asn, err)
			}
		}(i)
	}

	waitForPendingLen(t, n)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	peeringdbBatchMu.Lock()
	peeringdbBusy = false
	peeringdbBatchMu.Unlock()
	startPeeringDBBatcher(ctx)
	select {
	case peeringdbKick <- struct{}{}:
	default:
	}

	wg.Wait()

	if okCount != n {
		t.Errorf("got %d successful results, want %d", okCount, n)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(callSizes) < 2 {
		t.Fatalf("got %d batch calls, want at least 2 to cover a %d-request overflow", len(callSizes), n)
	}
	total := 0
	for _, sz := range callSizes {
		if sz > peeringdbMaxBatch {
			t.Errorf("a single call had %d ASNs, want at most %d", sz, peeringdbMaxBatch)
		}
		total += sz
	}
	if total != n {
		t.Errorf("calls covered %d ASNs total, want %d", total, n)
	}
}

// TestResolveOrgNameSrcPeeringDBUsesFastPathWhenAlone confirms
// resolveOrgName's srcPeeringDB case really does go through
// lookupPeeringDBBatched end-to-end (not some other path), and that an
// uncontended call still takes the cheap single-ASN lookup rather than the
// batch endpoint.
func TestResolveOrgNameSrcPeeringDBUsesFastPathWhenAlone(t *testing.T) {
	clock := time.Now()
	swapTestHooks(t, &clock, failWhois(t))

	var singleCalls int32
	orgPeeringDBLookup = func(context.Context, string, string) (string, error) {
		atomic.AddInt32(&singleCalls, 1)
		return "Org", nil
	}
	orgPeeringDBBatchLookup = func(ctx context.Context, asns []string, key string) (map[string]string, error) {
		t.Error("batch path called for an uncontended request")
		return nil, errors.New("unexpected")
	}

	if _, err := resolveOrgName(context.Background(), "2906", 0, srcPeeringDB); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if singleCalls != 1 {
		t.Errorf("got %d single-ASN calls, want 1", singleCalls)
	}
}

// TestResolveOrgNameSrcPeeringDBMergesConcurrentRequests confirms
// resolveOrgName's srcPeeringDB case, called concurrently for different
// ASNs, produces the same merging lookupPeeringDBBatched itself already
// proves — end to end, through the actual public entry point requests reach.
func TestResolveOrgNameSrcPeeringDBMergesConcurrentRequests(t *testing.T) {
	clock := time.Now()
	swapTestHooks(t, &clock, failWhois(t))

	orgPeeringDBLookup = func(context.Context, string, string) (string, error) {
		t.Error("single-ASN PeeringDB lookup called; expected both requests to share the batch path")
		return "", errors.New("unexpected")
	}
	var batchCalls int32
	orgPeeringDBBatchLookup = func(ctx context.Context, asns []string, key string) (map[string]string, error) {
		atomic.AddInt32(&batchCalls, 1)
		result := make(map[string]string, len(asns))
		for _, asn := range asns {
			result[asn] = "Org " + asn
		}
		return result, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startPeeringDBBatcher(ctx)

	peeringdbBatchMu.Lock()
	peeringdbBusy = true
	peeringdbBatchMu.Unlock()

	var wg sync.WaitGroup
	for _, asn := range []string{"2906", "3356"} {
		wg.Add(1)
		go func(asn string) {
			defer wg.Done()
			res, err := resolveOrgName(context.Background(), asn, 0, srcPeeringDB)
			if err != nil {
				t.Errorf("asn %s: unexpected error: %v", asn, err)
				return
			}
			if res.name != "Org "+asn {
				t.Errorf("asn %s: got name %q", asn, res.name)
			}
		}(asn)
	}

	waitForPendingLen(t, 2)

	peeringdbBatchMu.Lock()
	peeringdbBusy = false
	peeringdbBatchMu.Unlock()
	select {
	case peeringdbKick <- struct{}{}:
	default:
	}

	wg.Wait()
	if batchCalls != 1 {
		t.Errorf("got %d batch calls, want 1 (both ASNs should have shared one)", batchCalls)
	}
}
