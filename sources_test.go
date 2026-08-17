package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"testing"
	"time"

	"asn-ipv6-ranges/internal/cymrudns"
	"asn-ipv6-ranges/internal/peeringdb"
	"asn-ipv6-ranges/internal/radb"
)

// logSink captures log output a line at a time. A channel rather than a buffer
// because the key check logs from a goroutine: the test needs to wait for the
// line, not poll for it.
type logSink struct{ lines chan string }

func (s *logSink) Write(p []byte) (int, error) {
	select {
	case s.lines <- string(p):
	default: // never block the code under test on a test's channel
	}
	return len(p), nil
}

// captureLog redirects the standard logger for one test.
func captureLog(t *testing.T) *logSink {
	t.Helper()
	sink := &logSink{lines: make(chan string, 8)}
	origOut, origFlags := log.Writer(), log.Flags()
	log.SetOutput(sink)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(origOut); log.SetFlags(origFlags) })
	return sink
}

// awaitLine returns the next logged line, failing the test if none arrives.
func (s *logSink) awaitLine(t *testing.T) string {
	t.Helper()
	select {
	case line := <-s.lines:
		return line
	case <-time.After(5 * time.Second):
		t.Fatal("nothing was logged")
		return ""
	}
}

// swapEnv points getenv at a fixed map for one test.
func swapEnv(t *testing.T, env map[string]string) {
	t.Helper()
	orig := getenv
	getenv = func(k string) string { return env[k] }
	t.Cleanup(func() { getenv = orig })
}

func TestLogDataSources(t *testing.T) {
	t.Run("names every source and reports the defaults", func(t *testing.T) {
		swapEnv(t, nil)
		sink := captureLog(t)

		logDataSources()
		line := sink.awaitLine(t)

		// An operator reading a fresh pod's log should be able to see every
		// upstream this process will talk to, without reading the source.
		for _, want := range []string{radb.Host, cymrudns.Host, peeringdb.Host, "whois", "RDAP"} {
			if !strings.Contains(line, want) {
				t.Errorf("source %q missing from %q", want, line)
			}
		}
		if !strings.Contains(line, cymrudns.DefaultResolver) || !strings.Contains(line, "default") {
			t.Errorf("resolver not reported as the default: %q", line)
		}
		if !strings.Contains(line, "no api key") {
			t.Errorf("missing key state: %q", line)
		}
	})

	t.Run("reports the configured resolver and a set key", func(t *testing.T) {
		swapEnv(t, map[string]string{
			cymrudns.ResolverEnv: "9.9.9.9:53",
			peeringdb.KeyEnv:     "some-key",
		})
		sink := captureLog(t)

		logDataSources()
		line := sink.awaitLine(t)

		if !strings.Contains(line, "9.9.9.9:53") || strings.Contains(line, cymrudns.DefaultResolver) {
			t.Errorf("configured resolver not reported: %q", line)
		}
		if !strings.Contains(line, "api key set") {
			t.Errorf("key presence not reported: %q", line)
		}
		// The point of the line is to catch a misconfigured key, so it must
		// never be the thing that discloses one.
		if strings.Contains(line, "some-key") {
			t.Errorf("API key leaked into the startup log: %q", line)
		}
	})
}

func TestStartPeeringDBKeyCheck(t *testing.T) {
	// verifyStub swaps in a verification result and reports the key it was
	// handed, so a test can prove both the outcome and that the key travelled.
	verifyStub := func(t *testing.T, err error) chan string {
		t.Helper()
		seen := make(chan string, 1)
		orig := orgPeeringDBVerify
		orgPeeringDBVerify = func(_ context.Context, key string) error {
			seen <- key
			return err
		}
		t.Cleanup(func() { orgPeeringDBVerify = orig })
		return seen
	}

	setup := func(t *testing.T, key string) {
		t.Helper()
		env := map[string]string{}
		if key != "" {
			env[peeringdb.KeyEnv] = key
		}
		swapEnv(t, env)
		peeringdbKeyRejected.Store(false)
		resetLimiters()
		t.Cleanup(func() { peeringdbKeyRejected.Store(false); resetLimiters() })
	}

	t.Run("accepted key stays in use", func(t *testing.T) {
		setup(t, "good-key")
		seen := verifyStub(t, nil)
		sink := captureLog(t)

		startPeeringDBKeyCheck(context.Background())

		if got := <-seen; got != "good-key" {
			t.Errorf("verified with %q", got)
		}
		if line := sink.awaitLine(t); !strings.Contains(line, "verified") {
			t.Errorf("unclear log line: %q", line)
		}
		if peeringdbKeyRejected.Load() {
			t.Error("a key PeeringDB accepted was marked rejected")
		}
		if peeringDBAPIKey() != "good-key" {
			t.Errorf("key no longer in use: %q", peeringDBAPIKey())
		}
	})

	// The whole point of the check: a key PeeringDB refuses must stop being
	// sent, and the budget must drop back to the anonymous rate rather than
	// keep querying at the authenticated one with no credential.
	t.Run("rejected key is dropped and falls back to the anonymous budget", func(t *testing.T) {
		setup(t, "wrong-key")
		verifyStub(t, fmt.Errorf("%w: api returned 401: Invalid API key", peeringdb.ErrInvalidKey))
		sink := captureLog(t)

		if got := budgetFor(peeringdb.Host); got != peeringdbAuthBudget {
			t.Fatalf("precondition: got %+v, want the authenticated budget", got)
		}
		// Build the limiter from the authenticated budget first, so the test
		// covers the cached-limiter problem forgetLimiter exists to solve.
		limiterFor(peeringdb.Host)

		startPeeringDBKeyCheck(context.Background())

		line := sink.awaitLine(t)
		if !strings.Contains(line, "rejected") {
			t.Errorf("unclear log line: %q", line)
		}
		if !peeringdbKeyRejected.Load() {
			t.Fatal("rejected key was not recorded")
		}
		if peeringDBAPIKey() != "" {
			t.Errorf("rejected key still in use: %q", peeringDBAPIKey())
		}
		if got := budgetFor(peeringdb.Host); got != peeringdbBudget {
			t.Errorf("got %+v, want the anonymous budget", got)
		}
		// A limiter built before the rejection would still hold the higher
		// rate; forgetLimiter is what makes the new budget take effect.
		limitersMu.Lock()
		_, cached := limiters[peeringdb.Host]
		limitersMu.Unlock()
		if cached {
			t.Error("stale limiter kept the authenticated rate in force")
		}
	})

	// An inconclusive failure says nothing about the key. Disabling it here
	// would throw away a working credential over one bad minute upstream, and
	// nothing retries.
	t.Run("inconclusive failure keeps the key", func(t *testing.T) {
		setup(t, "good-key")
		verifyStub(t, errors.New("dial tcp: i/o timeout"))
		sink := captureLog(t)

		startPeeringDBKeyCheck(context.Background())

		line := sink.awaitLine(t)
		if !strings.Contains(line, "could not verify") || !strings.Contains(line, "keeping it") {
			t.Errorf("unclear log line: %q", line)
		}
		if peeringdbKeyRejected.Load() {
			t.Fatal("a key was disabled by a failure that says nothing about it")
		}
		if peeringDBAPIKey() != "good-key" {
			t.Errorf("key no longer in use: %q", peeringDBAPIKey())
		}
	})

	t.Run("no key means no request", func(t *testing.T) {
		setup(t, "")
		seen := verifyStub(t, nil)

		startPeeringDBKeyCheck(context.Background())

		// Nothing to verify, so nothing may be spent on verifying it.
		select {
		case key := <-seen:
			t.Fatalf("verified an unset key (%q)", key)
		case <-time.After(200 * time.Millisecond):
		}
	})
}

func TestPeeringDBAPIKey(t *testing.T) {
	swapEnv(t, map[string]string{peeringdb.KeyEnv: "a-key"})
	peeringdbKeyRejected.Store(false)
	t.Cleanup(func() { peeringdbKeyRejected.Store(false) })

	if got := peeringDBAPIKey(); got != "a-key" {
		t.Errorf("got %q, want the configured key", got)
	}
	peeringdbKeyRejected.Store(true)
	// Rejection has to survive re-reading the environment, which is the whole
	// reason call sites go through this accessor.
	if got := peeringDBAPIKey(); got != "" {
		t.Errorf("rejected key came back as %q", got)
	}
}
