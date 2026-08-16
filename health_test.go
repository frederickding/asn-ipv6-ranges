package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestStatusHandler(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	swapTestHooks(t, &clock, func(string) (string, error) {
		t.Error("health check queried an upstream")
		return "", errors.New("unexpected upstream query")
	})

	origStart := startTime
	startTime = clock.Add(-90 * time.Second)
	t.Cleanup(func() { startTime = origStart })

	rec := httptest.NewRecorder()
	statusHandler(rec, httptest.NewRequest(http.MethodGet, statusPath, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("got content-type %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("got cache-control %q, want no-store", cc)
	}

	body := rec.Body.String()
	// Probes read the status code, but the first line is the verdict for
	// anything that reads the body.
	if first, _, _ := strings.Cut(body, "\n"); first != "ok" {
		t.Errorf("first line = %q, want %q", first, "ok")
	}
	if !strings.Contains(body, "# uptime: 1m30s") {
		t.Errorf("missing or wrong uptime in:\n%s", body)
	}
	for _, want := range []string{"# prefix cache: 0 ASNs", "# org cache: 0 entries"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
}

// TestStatusHandlerIndependentOfUpstreams is the point of the endpoint: a
// failing upstream must not fail the probe, or Kubernetes would restart healthy
// pods during a third-party outage.
func TestStatusHandlerIndependentOfUpstreams(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	swapTestHooks(t, &clock, func(string) (string, error) {
		return "", errors.New("radb is down")
	})
	getenv = func(string) string { return "secret-key" }
	orgAPILookup = func(string, string) (string, error) { return "", errors.New("api is down") }

	// Confirm the service really is degraded right now.
	asRec := httptest.NewRecorder()
	asHandler(asRec, httptest.NewRequest(http.MethodGet, "/as/2906", nil))
	if asRec.Code != http.StatusBadGateway {
		t.Fatalf("expected the ASN endpoint to be failing, got %d", asRec.Code)
	}

	rec := httptest.NewRecorder()
	statusHandler(rec, httptest.NewRequest(http.MethodGet, statusPath, nil))
	if rec.Code != http.StatusOK {
		t.Errorf("probe returned %d while an upstream was down; it must stay 200", rec.Code)
	}
}

func TestStatusHandlerMethods(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	swapTestHooks(t, &clock, func(string) (string, error) { return sampleWhois, nil })

	t.Run("HEAD is allowed", func(t *testing.T) {
		rec := httptest.NewRecorder()
		statusHandler(rec, httptest.NewRequest(http.MethodHead, statusPath, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("got status %d, want 200", rec.Code)
		}
	})

	t.Run("POST is rejected", func(t *testing.T) {
		rec := httptest.NewRecorder()
		statusHandler(rec, httptest.NewRequest(http.MethodPost, statusPath, nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("got status %d, want 405", rec.Code)
		}
		if allow := rec.Header().Get("Allow"); allow != "GET, HEAD" {
			t.Errorf("got Allow %q", allow)
		}
	})
}

// TestStatusHandlerReportsCacheSizes proves the counters are live, so the
// endpoint is useful for spotting a pod that is serving but never caching.
func TestStatusHandlerReportsCacheSizes(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	swapTestHooks(t, &clock, func(string) (string, error) { return sampleWhois, nil })

	for _, asn := range []string{"2906", "24940"} {
		rec := httptest.NewRecorder()
		asHandler(rec, httptest.NewRequest(http.MethodGet, "/as/"+asn, nil))
	}

	rec := httptest.NewRecorder()
	statusHandler(rec, httptest.NewRequest(http.MethodGet, statusPath, nil))
	if !strings.Contains(rec.Body.String(), "# prefix cache: 2 ASNs") {
		t.Errorf("expected 2 cached ASNs in:\n%s", rec.Body.String())
	}
}

// TestStatusRouting checks the mux wiring: the path is exact, so it must not
// swallow neighbouring paths.
func TestStatusRouting(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	swapTestHooks(t, &clock, func(string) (string, error) { return sampleWhois, nil })

	mux := http.NewServeMux()
	mux.HandleFunc("/as/", asHandler)
	mux.HandleFunc(statusPath, statusHandler)

	tests := []struct {
		path       string
		wantStatus int
		wantBody   string
	}{
		{statusPath, http.StatusOK, "ok"},
		{"/-/status/extra", http.StatusNotFound, ""},
		{"/-/", http.StatusNotFound, ""},
		{"/as/2906", http.StatusOK, "# IPv6 prefixes"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))
			if rec.Code != tt.wantStatus {
				t.Errorf("got status %d, want %d", rec.Code, tt.wantStatus)
			}
			if tt.wantBody != "" && !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Errorf("body %q missing %q", rec.Body.String(), tt.wantBody)
			}
		})
	}
}
