package main

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These are the end-to-end tests for the two properties the service has to hold
// under load it does not control: it must not fall over, and it must not exceed
// what the upstream registries allow. They drive the real server stack —
// access log, concurrency cap, handler, cache, coalescing, budgets — rather
// than any one layer of it.

// testServer starts the full handler stack on a local listener.
func testServer(t *testing.T) *httptest.Server {
	t.Helper()
	setAccessLogOutput(io.Discard)
	t.Cleanup(func() { setAccessLogOutput(io.Discard) })

	mux := http.NewServeMux()
	mux.HandleFunc("/as/", asHandler)
	mux.HandleFunc(statusPath, statusHandler)

	srv := httptest.NewServer(withAccessLog(withInflightLimit(mux)))
	t.Cleanup(srv.Close)
	return srv
}

// TestOverloadDoesNotExceedTheUpstreamBudget is the registry-facing guarantee:
// however many requests arrive, and however they are distributed, the upstream
// sees no more than its budget allows.
func TestOverloadDoesNotExceedTheUpstreamBudget(t *testing.T) {
	clock := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)

	var upstreamCalls atomic.Int64
	swapTestHooks(t, &clock, func(string) (string, error) {
		upstreamCalls.Add(1)
		// Slow enough that requests genuinely overlap.
		time.Sleep(5 * time.Millisecond)
		return sampleWhois, nil
	})
	// The real RADB budget, not the wide-open test one.
	swapUpstreamBudget(t, radbBudget)
	swapMaxInflight(t, 32)

	srv := testServer(t)
	start := time.Now()

	// 400 requests over 400 distinct ASNs: nothing the cache or coalescing can
	// absorb, so every one of them wants its own upstream query.
	const requests = 400
	var wg sync.WaitGroup
	statuses := make([]int, requests)
	for i := range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Get(srv.URL + "/as/" + strconv.Itoa(3000+i))
			if err != nil {
				statuses[i] = -1
				return
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)
			statuses[i] = resp.StatusCode
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	for i, status := range statuses {
		switch status {
		case http.StatusOK, http.StatusServiceUnavailable:
		case -1:
			t.Fatalf("request %d failed at the transport level: the server dropped it", i)
		default:
			t.Fatalf("request %d got %d, want 200 or 503", i, status)
		}
	}

	// The budget is a rate, so the ceiling is the burst plus whatever the
	// bucket refilled while the test ran, times the concurrency headroom.
	calls := upstreamCalls.Load()
	allowed := int64(float64(radbBudget.burst) + radbBudget.rate*elapsed.Seconds() + 1)
	if calls > allowed {
		t.Errorf("upstream saw %d queries in %s, over the %d its budget allows", calls, elapsed, allowed)
	}
	if calls == 0 {
		t.Error("no query reached the upstream at all; the test is not exercising the path")
	}
}

// TestOverloadShedsRatherThanGrowing checks the process-facing guarantee: past
// the concurrency cap, requests are refused rather than accumulating goroutines
// and 8 MiB buffers until the pod is OOM-killed.
func TestOverloadShedsRatherThanGrowing(t *testing.T) {
	clock := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)

	var inFlight, peak atomic.Int64
	swapTestHooks(t, &clock, func(string) (string, error) {
		n := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		return sampleWhois, nil
	})
	swapMaxInflight(t, 4)

	srv := testServer(t)

	const requests = 100
	var wg sync.WaitGroup
	var shed atomic.Int64
	for i := range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Get(srv.URL + "/as/" + strconv.Itoa(5000+i))
			if err != nil {
				return
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)
			if resp.StatusCode == http.StatusServiceUnavailable {
				shed.Add(1)
				if resp.Header.Get("Retry-After") == "" {
					t.Error("a shed request must carry Retry-After")
				}
			}
		}()
	}
	wg.Wait()

	if p := peak.Load(); p > 4 {
		t.Errorf("%d requests were in the handler at once, over the cap of 4", p)
	}
	if shed.Load() == 0 {
		t.Error("100 concurrent requests against a cap of 4 shed none; the cap is not engaging")
	}
}

// TestOverloadOnOneASNCostsOneQuery is the case a misconfigured bot actually
// produces: the same URL, as fast as it can. Without coalescing this was one
// upstream query per request.
func TestOverloadOnOneASNCostsOneQuery(t *testing.T) {
	clock := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)

	var upstreamCalls atomic.Int64
	swapTestHooks(t, &clock, func(string) (string, error) {
		upstreamCalls.Add(1)
		time.Sleep(50 * time.Millisecond)
		return sampleWhois, nil
	})
	swapUpstreamBudget(t, radbBudget)
	swapMaxInflight(t, 64)

	srv := testServer(t)

	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Get(srv.URL + "/as/2906")
			if err != nil {
				return
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)
		}()
	}
	wg.Wait()

	if n := upstreamCalls.Load(); n != 1 {
		t.Errorf("100 concurrent requests for one ASN produced %d upstream queries, want 1", n)
	}
}

// TestRepeatedFailuresDoNotReachUpstream: an ASN that cannot be resolved is the
// cheapest thing for a bot to hammer, since a failure used never to be cached.
func TestRepeatedFailuresDoNotReachUpstream(t *testing.T) {
	clock := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)

	var upstreamCalls atomic.Int64
	swapTestHooks(t, &clock, func(string) (string, error) {
		upstreamCalls.Add(1)
		// An upstream failure, not a cancellation: cancellations are
		// deliberately not cached, and this test is about the ones that are.
		return "", errors.New("dial tcp: connection refused")
	})
	swapMaxInflight(t, 32)

	srv := testServer(t)

	for range 50 {
		resp, err := http.Get(srv.URL + "/as/2906")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("status = %d, want 502", resp.StatusCode)
		}
	}

	if n := upstreamCalls.Load(); n != 1 {
		t.Errorf("50 requests for a failing ASN produced %d upstream queries, want 1", n)
	}
}
