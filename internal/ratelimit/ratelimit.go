// Package ratelimit bounds how fast and how concurrently this service queries a
// single upstream host.
//
// It exists to keep the service inside the registries' published query limits
// no matter how much traffic arrives. Inbound load is not a reliable proxy for
// outbound load — one incoming request can fan out to several upstreams — so
// the budget is enforced where the outbound call is made, per host.
//
// A Limiter is a token bucket paired with a concurrency ceiling. Both are
// non-blocking: Acquire either succeeds immediately or reports ErrLimited, so a
// spent budget sheds the request rather than parking a goroutine against it.
// See doc/networking.md for the budget each upstream is given and why.
package ratelimit

import (
	"errors"
	"math"
	"sync"
	"time"
)

// ErrLimited reports that the caller's budget for an upstream is spent. Callers
// should surface this as a 503 with Retry-After rather than retrying.
var ErrLimited = errors.New("upstream query budget exhausted")

// now is the clock, replaced in tests so budgets can be exercised without
// waiting for real time to pass.
var now = time.Now

// Limiter bounds the query rate and in-flight concurrency for one upstream
// host. The zero value is not usable; construct with New.
type Limiter struct {
	mu sync.Mutex
	// rate is tokens accrued per second and burst is the bucket depth, so a
	// host can absorb a short burst but not a sustained overrate.
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
	// pausedUntil parks the bucket entirely, set from an upstream's own
	// Retry-After when it tells us we are going too fast.
	pausedUntil time.Time

	// slots is the concurrency ceiling. Separate from the token bucket because
	// registries limit both: RIPE's AUP caps simultaneous connections, while
	// LACNIC caps queries per interval.
	slots chan struct{}
}

// New returns a Limiter allowing rate queries per second with the given bucket
// depth, and at most concurrency queries in flight at once. The bucket starts
// full, so a cold process can serve an initial burst.
func New(rate float64, burst, concurrency int) *Limiter {
	if burst < 1 {
		burst = 1
	}
	if concurrency < 1 {
		concurrency = 1
	}
	return &Limiter{
		rate:   rate,
		burst:  float64(burst),
		tokens: float64(burst),
		last:   now(),
		slots:  make(chan struct{}, concurrency),
	}
}

// Acquire reserves one query against the budget. On success it returns a
// release function the caller must invoke when the query finishes; on failure
// it returns ErrLimited and the caller must not contact the upstream.
//
// The concurrency slot is taken before the token so a refusal never has to
// return a token to the bucket, which would let a rejected caller inflate the
// rate seen by the next one.
func (l *Limiter) Acquire() (release func(), err error) {
	select {
	case l.slots <- struct{}{}:
	default:
		return nil, ErrLimited
	}

	if !l.takeToken() {
		<-l.slots
		return nil, ErrLimited
	}

	// Guarded so a caller that releases twice cannot free another query's slot.
	var once sync.Once
	return func() { once.Do(func() { <-l.slots }) }, nil
}

func (l *Limiter) takeToken() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	t := now()
	if t.Before(l.pausedUntil) {
		return false
	}
	if elapsed := t.Sub(l.last); elapsed > 0 {
		l.tokens = math.Min(l.burst, l.tokens+elapsed.Seconds()*l.rate)
		l.last = t
	}
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}

// PauseUntil stops the limiter handing out tokens until t. It is called when an
// upstream answers 429: the registry's own view of our rate outranks the budget
// configured here, which is only ever an estimate of an unpublished limit.
func (l *Limiter) PauseUntil(t time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if t.After(l.pausedUntil) {
		l.pausedUntil = t
	}
}

// RetryAfter estimates how long until Acquire could succeed, for the
// Retry-After header. It is a hint, not a promise: another caller may take the
// token first. The result is always at least one second, because Retry-After
// has one-second granularity and zero would invite an immediate retry.
func (l *Limiter) RetryAfter() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	t := now()
	wait := l.pausedUntil.Sub(t)

	if l.rate > 0 {
		available := l.tokens
		if elapsed := t.Sub(l.last); elapsed > 0 {
			available = math.Min(l.burst, available+elapsed.Seconds()*l.rate)
		}
		if deficit := 1 - available; deficit > 0 {
			if d := time.Duration(deficit / l.rate * float64(time.Second)); d > wait {
				wait = d
			}
		}
	}

	if wait < time.Second {
		return time.Second
	}
	// Rounded up: advertising a shorter wait than the budget actually needs
	// would invite a retry that is refused again.
	if rem := wait % time.Second; rem > 0 {
		wait += time.Second - rem
	}
	return wait
}
