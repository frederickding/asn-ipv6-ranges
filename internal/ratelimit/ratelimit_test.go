package ratelimit

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// withClock freezes the limiter's clock so budgets can be exercised without
// waiting for real time.
func withClock(t *testing.T, at *time.Time) {
	t.Helper()
	orig := now
	now = func() time.Time { return *at }
	t.Cleanup(func() { now = orig })
}

func TestBurstThenRefusal(t *testing.T) {
	clock := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	withClock(t, &clock)

	l := New(1, 3, 10)
	for i := range 3 {
		release, err := l.Acquire()
		if err != nil {
			t.Fatalf("query %d should be inside the burst: %v", i, err)
		}
		release()
	}

	if _, err := l.Acquire(); !errors.Is(err, ErrLimited) {
		t.Fatalf("got %v, want ErrLimited once the burst is spent", err)
	}
}

func TestTokensRefillOverTime(t *testing.T) {
	clock := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	withClock(t, &clock)

	l := New(2, 1, 10)
	release, err := l.Acquire()
	if err != nil {
		t.Fatalf("first query: %v", err)
	}
	release()

	if _, err := l.Acquire(); !errors.Is(err, ErrLimited) {
		t.Fatal("bucket should be empty immediately after its only token was taken")
	}

	// At 2/s, half a second buys exactly one token.
	clock = clock.Add(500 * time.Millisecond)
	release, err = l.Acquire()
	if err != nil {
		t.Fatalf("after refill: %v", err)
	}
	release()
}

// TestBurstIsCapped guards the difference between a bucket and a counter: idle
// time must not accumulate into an unbounded allowance to spend at once.
func TestBurstIsCapped(t *testing.T) {
	clock := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	withClock(t, &clock)

	l := New(1, 2, 10)
	clock = clock.Add(time.Hour)

	for i := range 2 {
		release, err := l.Acquire()
		if err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
		release()
	}
	if _, err := l.Acquire(); !errors.Is(err, ErrLimited) {
		t.Fatal("an hour idle must not buy more than the bucket depth")
	}
}

// TestConcurrencyCeiling covers the limit registries enforce separately from
// rate: RIPE's AUP caps simultaneous connections, not queries per second.
func TestConcurrencyCeiling(t *testing.T) {
	clock := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	withClock(t, &clock)

	l := New(1000, 1000, 2)
	first, err := l.Acquire()
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := l.Acquire()
	if err != nil {
		t.Fatalf("second: %v", err)
	}

	if _, err := l.Acquire(); !errors.Is(err, ErrLimited) {
		t.Fatal("a third simultaneous query should be refused")
	}

	first()
	third, err := l.Acquire()
	if err != nil {
		t.Fatalf("a slot freed by release should be usable: %v", err)
	}
	third()
	second()
}

// TestRefusalDoesNotSpendAToken: a query refused for concurrency must leave the
// bucket alone, or a saturated host would also drain its rate budget.
func TestRefusalDoesNotSpendAToken(t *testing.T) {
	clock := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	withClock(t, &clock)

	l := New(1, 5, 1)
	held, err := l.Acquire()
	if err != nil {
		t.Fatalf("first: %v", err)
	}

	for range 10 {
		if _, err := l.Acquire(); !errors.Is(err, ErrLimited) {
			t.Fatalf("got %v, want a concurrency refusal", err)
		}
	}
	held()

	// Four of the five tokens must still be there.
	for i := range 4 {
		release, err := l.Acquire()
		if err != nil {
			t.Fatalf("token %d was consumed by a refused query: %v", i, err)
		}
		release()
	}
}

// TestDoubleReleaseFreesOneSlot: a caller that releases twice must not free a
// slot another query is holding.
func TestDoubleReleaseFreesOneSlot(t *testing.T) {
	clock := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	withClock(t, &clock)

	l := New(1000, 1000, 1)
	release, err := l.Acquire()
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	release()
	release()

	held, err := l.Acquire()
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	if _, err := l.Acquire(); !errors.Is(err, ErrLimited) {
		t.Fatal("double release inflated the concurrency ceiling")
	}
	held()
}

func TestPauseUntilBlocksEvenWithTokens(t *testing.T) {
	clock := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	withClock(t, &clock)

	l := New(100, 100, 10)
	l.PauseUntil(clock.Add(time.Minute))

	if _, err := l.Acquire(); !errors.Is(err, ErrLimited) {
		t.Fatal("a paused limiter must refuse regardless of its bucket")
	}
	if got := l.RetryAfter(); got != time.Minute {
		t.Errorf("RetryAfter = %s, want %s", got, time.Minute)
	}

	clock = clock.Add(time.Minute + time.Second)
	release, err := l.Acquire()
	if err != nil {
		t.Fatalf("after the pause elapsed: %v", err)
	}
	release()
}

// TestPauseUntilNeverShortens: a second, nearer pause must not undo a longer
// one an upstream already asked for.
func TestPauseUntilNeverShortens(t *testing.T) {
	clock := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	withClock(t, &clock)

	l := New(100, 100, 10)
	l.PauseUntil(clock.Add(time.Hour))
	l.PauseUntil(clock.Add(time.Second))

	if got := l.RetryAfter(); got != time.Hour {
		t.Errorf("RetryAfter = %s, want the longer pause of %s", got, time.Hour)
	}
}

// TestRetryAfterRoundsUp: advertising a shorter wait than the budget needs
// invites a retry that is refused again.
func TestRetryAfterRoundsUp(t *testing.T) {
	clock := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	withClock(t, &clock)

	l := New(100, 100, 10)
	l.PauseUntil(clock.Add(1500 * time.Millisecond))

	if got := l.RetryAfter(); got != 2*time.Second {
		t.Errorf("RetryAfter = %s, want it rounded up to 2s", got)
	}
}

// TestRetryAfterIsAtLeastOneSecond: Retry-After has one-second granularity, and
// zero would invite an immediate retry.
func TestRetryAfterIsAtLeastOneSecond(t *testing.T) {
	clock := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	withClock(t, &clock)

	l := New(1000, 1, 10)
	if got := l.RetryAfter(); got < time.Second {
		t.Errorf("RetryAfter = %s, want at least 1s", got)
	}
}

// TestConcurrentAcquireStaysUnderTheCeiling exercises the limiter the way the
// service uses it — from many goroutines at once — and asserts the ceiling
// holds under the race detector.
func TestConcurrentAcquireStaysUnderTheCeiling(t *testing.T) {
	l := New(1e6, 1e6, 4)

	var mu sync.Mutex
	inFlight, peak := 0, 0

	var wg sync.WaitGroup
	for range 200 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := l.Acquire()
			if err != nil {
				return
			}
			mu.Lock()
			inFlight++
			if inFlight > peak {
				peak = inFlight
			}
			mu.Unlock()

			time.Sleep(time.Millisecond)

			mu.Lock()
			inFlight--
			mu.Unlock()
			release()
		}()
	}
	wg.Wait()

	if peak > 4 {
		t.Errorf("peak concurrency %d exceeded the ceiling of 4", peak)
	}
}
