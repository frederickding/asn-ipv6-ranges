package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"asn-ipv6-ranges/internal/peeringdb"
)

// swapMaxInflight sets the concurrency cap for one test.
func swapMaxInflight(t *testing.T, n int) {
	t.Helper()
	orig := maxInflight
	maxInflight = n
	t.Cleanup(func() { maxInflight = orig })
}

// TestInflightLimitShedsExcessRequests is the memory bound at the front door:
// past the cap, requests must be refused rather than queued, because a queued
// request still holds the goroutine and buffers the cap exists to limit.
func TestInflightLimitShedsExcessRequests(t *testing.T) {
	swapMaxInflight(t, 2)

	release := make(chan struct{})
	entered := make(chan struct{}, 8)
	h := withInflightLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	}))

	var wg sync.WaitGroup
	codes := make([]int, 2)
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/as/2906", nil))
			codes[i] = rec.Code
		}()
	}

	// Both slots are taken and held before the third request arrives.
	for range 2 {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("handler did not start")
		}
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/as/2906", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d once the cap is reached", rec.Code, http.StatusServiceUnavailable)
	}
	if got := rec.Header().Get("Retry-After"); got != strconv.Itoa(inflightRetryAfter) {
		t.Errorf("Retry-After = %q, want %q", got, strconv.Itoa(inflightRetryAfter))
	}
	if body := rec.Body.String(); !strings.HasPrefix(body, "# error:") {
		t.Errorf("shed response should use the service's error format, got %q", body)
	}

	close(release)
	wg.Wait()
	for i, code := range codes {
		if code != http.StatusOK {
			t.Errorf("request %d inside the cap got %d, want 200", i, code)
		}
	}
}

// TestInflightLimitReleasesSlots: a completed request must give its slot back,
// or the service would shed everything after the first burst.
func TestInflightLimitReleasesSlots(t *testing.T) {
	swapMaxInflight(t, 1)

	h := withInflightLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := range 10 {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/as/2906", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("sequential request %d got %d, want 200", i, rec.Code)
		}
	}
}

// TestInflightLimitExemptsProbes: shedding a readiness probe under load would
// depool a pod that is behaving exactly as designed.
func TestInflightLimitExemptsProbes(t *testing.T) {
	swapMaxInflight(t, 1)

	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	h := withInflightLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == statusPath {
			w.WriteHeader(http.StatusOK)
			return
		}
		entered <- struct{}{}
		<-release
	}))

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/as/2906", nil))
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not start")
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, statusPath, nil))
	if rec.Code != http.StatusOK {
		t.Errorf("probe got %d while the cap was full, want 200", rec.Code)
	}

	close(release)
	wg.Wait()
}

func TestInitLimits(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want int
	}{
		{"unset keeps the default", "", defaultMaxInflight},
		{"a valid value is used", "8", 8},
		{"zero is rejected, not treated as unlimited", "0", defaultMaxInflight},
		{"negative is rejected", "-1", defaultMaxInflight},
		{"unparseable is rejected", "lots", defaultMaxInflight},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			swapMaxInflight(t, defaultMaxInflight)
			origGetenv := getenv
			getenv = func(name string) string {
				if name == "MAX_INFLIGHT" {
					return tc.env
				}
				return ""
			}
			t.Cleanup(func() { getenv = origGetenv })

			initLimits()
			if maxInflight != tc.want {
				t.Errorf("maxInflight = %d, want %d", maxInflight, tc.want)
			}
		})
	}
}

// TestBudgetForMapsRegistriesToTheirLimits pins the mapping the doc describes:
// a registry's whois and RDAP front ends share one budget, and LACNIC — the
// only registry that publishes a number, and the tightest — gets its own.
func TestBudgetForMapsRegistriesToTheirLimits(t *testing.T) {
	t.Setenv(peeringdb.KeyEnv, "") // deterministic: this table expects the anonymous tier

	tests := []struct {
		host string
		want budget
	}{
		{"whois.radb.net", radbBudget},
		{"whois.lacnic.net", lacnicBudget},
		{"rdap.lacnic.net", lacnicBudget},
		{"whois.ripe.net", ripeBudget},
		{"rdap.db.ripe.net", ripeBudget},
		{"asn.cymru.com", cymruBudget},
		{"www.peeringdb.com", peeringdbBudget},
		{"whois.arin.net", registryBudget},
		{"rdap.arin.net", registryBudget},
		{"rdap.apnic.net", registryBudget},
		{"rdap.afrinic.net", registryBudget},
	}
	for _, tc := range tests {
		if got := budgetFor(tc.host); got != tc.want {
			t.Errorf("budgetFor(%q) = %+v, want %+v", tc.host, got, tc.want)
		}
	}
}

// TestBudgetForPeeringDBAuthTier: an API key raises PeeringDB's rate-limit
// tier, so budgetFor must switch budgets based on whether one is configured.
func TestBudgetForPeeringDBAuthTier(t *testing.T) {
	t.Setenv(peeringdb.KeyEnv, "a-key")
	if got := budgetFor("www.peeringdb.com"); got != peeringdbAuthBudget {
		t.Errorf("budgetFor with a key set = %+v, want peeringdbAuthBudget %+v", got, peeringdbAuthBudget)
	}
}

// TestLacnicBudgetStaysUnderItsPublishedLimit is the one registry limit that is
// documented rather than guessed: ~100 queries per 5 minutes. The budget must
// leave room for the second replica the manifest runs.
func TestLacnicBudgetStaysUnderItsPublishedLimit(t *testing.T) {
	const (
		lacnicPublished = 100.0 // queries per 5 minutes
		window          = 5 * time.Minute
		replicas        = 2
	)

	perWindow := lacnicBudget.rate * window.Seconds() * replicas
	if perWindow >= lacnicPublished {
		t.Errorf("across %d replicas the budget allows %.0f queries per 5 minutes, at or over LACNIC's published %.0f",
			replicas, perWindow, lacnicPublished)
	}
}

// TestUpstreamBudgetErrorCarriesItsHost: the handler needs the host to pick a
// Retry-After, and callers need errors.Is to recognise the condition.
func TestUpstreamBudgetErrorCarriesItsHost(t *testing.T) {
	swapUpstreamBudget(t, budget{rate: 1, burst: 1, concurrency: 1})

	if _, err := withUpstreamBudget("whois.example.net", func() (int, error) { return 1, nil }); err != nil {
		t.Fatalf("first call: %v", err)
	}

	_, err := withUpstreamBudget("whois.example.net", func() (int, error) {
		t.Error("upstream was called despite a spent budget")
		return 0, nil
	})

	var be *budgetError
	if !errors.As(err, &be) {
		t.Fatalf("got %T, want *budgetError", err)
	}
	if be.host != "whois.example.net" {
		t.Errorf("host = %q, want whois.example.net", be.host)
	}
	if retryAfterFor(be.host) < 1 {
		t.Error("Retry-After must be at least one second")
	}
}

// TestPauseUpstreamStopsQueries covers the response to a registry telling us we
// are querying too fast: its verdict outranks the budget we guessed for it.
func TestPauseUpstreamStopsQueries(t *testing.T) {
	swapUpstreamBudget(t, budget{rate: 1000, burst: 1000, concurrency: 10})

	pauseUpstream("rdap.example.net", time.Now().Add(time.Minute))

	_, err := withUpstreamBudget("rdap.example.net", func() (int, error) {
		t.Error("a paused upstream was queried")
		return 0, nil
	})
	if !errors.As(err, new(*budgetError)) {
		t.Fatalf("got %v, want a budget refusal", err)
	}
}

// TestHandlerReportsSpentBudgetAs503 checks the client-facing contract: a spent
// budget is not an upstream failure, and the client is told when to come back.
func TestHandlerReportsSpentBudgetAs503(t *testing.T) {
	clock := time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)
	swapTestHooks(t, &clock, func(string) (string, error) { return sampleWhois, nil })
	swapUpstreamBudget(t, budget{rate: 1, burst: 1, concurrency: 1})

	// Spend the budget on a different ASN so the cache cannot answer the next.
	if _, err := getPrefixes(context.Background(), "2906", true); err != nil {
		t.Fatalf("priming query: %v", err)
	}

	rec := httptest.NewRecorder()
	asHandler(rec, httptest.NewRequest(http.MethodGet, "/as/24940", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("a 503 from a spent budget must advertise Retry-After")
	}
}
