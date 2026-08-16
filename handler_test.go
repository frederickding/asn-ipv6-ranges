package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"asn-ipv6-ranges/internal/whoisfreaks"
)

func TestASHandlerValidation(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		wantStatus int
	}{
		{"non-numeric", "/as/abc", http.StatusBadRequest},
		{"empty", "/as/", http.StatusBadRequest},
		{"overflow", "/as/4294967296", http.StatusBadRequest},
		{"private use", "/as/4200000001", http.StatusBadRequest},
		{"documentation reserved", "/as/65540", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			asHandler(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))

			if rec.Code != tt.wantStatus {
				t.Errorf("got status %d, want %d", rec.Code, tt.wantStatus)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
				t.Errorf("got content-type %q", ct)
			}
			if body := rec.Body.String(); len(body) == 0 || body[0] != '#' {
				t.Errorf("error body must be a # comment, got %q", body)
			}
		})
	}
}

func TestASHandlerSuccess(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	swapTestHooks(t, &clock, func(string) (string, error) { return sampleWhois, nil })

	rec := httptest.NewRecorder()
	asHandler(rec, httptest.NewRequest(http.MethodGet, "/as/2906", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d", rec.Code)
	}
	want := "# IPv6 prefixes for AS2906 (source: whois.radb.net)\n" +
		"# aggregate: on (more-specifics covered by a broader prefix removed)\n" +
		"# count: 2\n" +
		"2607:fb10::/32\n" +
		"2a00:86c0::/32\n" +
		"# queried: 2026-08-16T12:00:00Z\n"
	if got := rec.Body.String(); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestASHandlerNoPrefixes(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	swapTestHooks(t, &clock, func(string) (string, error) {
		return "%  No entries found for the selected source(s).\n", nil
	})

	rec := httptest.NewRecorder()
	asHandler(rec, httptest.NewRequest(http.MethodGet, "/as/2906", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200", rec.Code)
	}
	want := "# IPv6 prefixes for AS2906 (source: whois.radb.net)\n" +
		"# aggregate: on (more-specifics covered by a broader prefix removed)\n" +
		"# no IPv6 prefixes found\n" +
		"# queried: 2026-08-16T12:00:00Z\n"
	if got := rec.Body.String(); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestASHandlerUpstreamFailure(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	swapTestHooks(t, &clock, func(string) (string, error) {
		return "", errors.New("dial tcp: timeout")
	})

	rec := httptest.NewRecorder()
	asHandler(rec, httptest.NewRequest(http.MethodGet, "/as/2906", nil))

	if rec.Code != http.StatusBadGateway {
		t.Errorf("got status %d, want 502", rec.Code)
	}
}

func TestASHandlerAggParam(t *testing.T) {
	tests := []struct {
		name  string
		query string
		want  []string
	}{
		{"default aggregates", "", []string{"2001:db8::/32", "2001:db9::/32"}},
		{"empty value falls back to default", "?agg=", []string{"2001:db8::/32", "2001:db9::/32"}},
		{"agg=1", "?agg=1", []string{"2001:db8::/32", "2001:db9::/32"}},
		{"agg=true", "?agg=true", []string{"2001:db8::/32", "2001:db9::/32"}},
		{"agg=0 keeps more-specifics", "?agg=0", []string{"2001:db8::/32", "2001:db8:1::/48", "2001:db9::/32"}},
		{"agg=false keeps more-specifics", "?agg=false", []string{"2001:db8::/32", "2001:db8:1::/48", "2001:db9::/32"}},
		{"agg=FALSE is case-insensitive", "?agg=FALSE", []string{"2001:db8::/32", "2001:db8:1::/48", "2001:db9::/32"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
			swapTestHooks(t, &clock, func(string) (string, error) { return nestedWhois, nil })

			rec := httptest.NewRecorder()
			asHandler(rec, httptest.NewRequest(http.MethodGet, "/as/2906"+tt.query, nil))

			if rec.Code != http.StatusOK {
				t.Fatalf("got status %d", rec.Code)
			}
			var got []string
			for _, line := range strings.Split(strings.TrimSpace(rec.Body.String()), "\n") {
				if !strings.HasPrefix(line, "#") {
					got = append(got, line)
				}
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestASHandlerAggParamInvalid(t *testing.T) {
	// Hooks swapped so a regression that accepts a bad value fails the
	// assertion rather than silently reaching the real whois server.
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	swapTestHooks(t, &clock, func(string) (string, error) {
		t.Error("upstream queried despite invalid agg value")
		return "", nil
	})

	for _, v := range []string{"yes", "no", "2", "on", "off"} {
		t.Run(v, func(t *testing.T) {
			rec := httptest.NewRecorder()
			asHandler(rec, httptest.NewRequest(http.MethodGet, "/as/2906?agg="+v, nil))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("agg=%q: got status %d, want 400", v, rec.Code)
			}
		})
	}
}

func TestASHandlerOrgParam(t *testing.T) {
	t.Run("not requested by default", func(t *testing.T) {
		clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
		swapTestHooks(t, &clock, func(string) (string, error) { return nestedWhois, nil })
		getenv = func(string) string { return "secret-key" }
		orgLookup = func(string, string) (string, error) {
			t.Error("org lookup ran without ?org=1")
			return "", nil
		}

		rec := httptest.NewRecorder()
		asHandler(rec, httptest.NewRequest(http.MethodGet, "/as/2906", nil))

		for _, c := range bodyComments(rec.Body.String()) {
			if strings.HasPrefix(c, "# org:") {
				t.Errorf("unexpected org comment: %q", c)
			}
		}
	})

	t.Run("requested with key configured", func(t *testing.T) {
		clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
		swapTestHooks(t, &clock, func(string) (string, error) { return nestedWhois, nil })
		getenv = func(name string) string {
			if name != whoisfreaks.KeyEnv {
				t.Errorf("read unexpected env var %q", name)
			}
			return "secret-key"
		}
		gotKey := ""
		orgLookup = func(asn, key string) (string, error) {
			gotKey = key
			return "Netflix Streaming Services Inc.", nil
		}

		rec := httptest.NewRecorder()
		asHandler(rec, httptest.NewRequest(http.MethodGet, "/as/2906?org=1", nil))

		if rec.Code != http.StatusOK {
			t.Fatalf("got status %d", rec.Code)
		}
		if gotKey != "secret-key" {
			t.Errorf("lookup got key %q", gotKey)
		}
		if !hasComment(rec.Body.String(), "# org: Netflix Streaming Services Inc.") {
			t.Errorf("missing org comment in:\n%s", rec.Body.String())
		}
	})

	// The documented behavior: with no key configured, org has zero effect but
	// the response says so.
	t.Run("requested with no key configured", func(t *testing.T) {
		clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
		swapTestHooks(t, &clock, func(string) (string, error) { return nestedWhois, nil })
		getenv = func(string) string { return "" }

		rec := httptest.NewRecorder()
		asHandler(rec, httptest.NewRequest(http.MethodGet, "/as/2906?org=true", nil))

		if rec.Code != http.StatusOK {
			t.Fatalf("got status %d", rec.Code)
		}
		want := "# org: not looked up (WHOISFREAKS_API_KEY is not set, org parameter has no effect)"
		if !hasComment(rec.Body.String(), want) {
			t.Errorf("missing no-key notice in:\n%s", rec.Body.String())
		}
		// Prefixes must still be served normally.
		if !hasComment(rec.Body.String(), "# count: 2") {
			t.Errorf("prefix output changed when org had no effect:\n%s", rec.Body.String())
		}
	})

	t.Run("lookup failure degrades gracefully", func(t *testing.T) {
		clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
		swapTestHooks(t, &clock, func(string) (string, error) { return nestedWhois, nil })
		getenv = func(string) string { return "secret-key" }
		orgLookup = func(string, string) (string, error) {
			return "", errors.New("api returned 401: Provided API key is invalid.")
		}

		rec := httptest.NewRecorder()
		asHandler(rec, httptest.NewRequest(http.MethodGet, "/as/2906?org=1", nil))

		if rec.Code != http.StatusOK {
			t.Errorf("org failure must not fail the request, got %d", rec.Code)
		}
		if !hasComment(rec.Body.String(), "# count: 2") {
			t.Errorf("prefixes missing after org failure:\n%s", rec.Body.String())
		}
		if !hasComment(rec.Body.String(), "# org: lookup failed: api returned 401: Provided API key is invalid.") {
			t.Errorf("missing failure comment:\n%s", rec.Body.String())
		}
	})

	// A newline in third-party data must not escape its comment line and forge
	// something that parses as a prefix.
	t.Run("multiline org name cannot inject output lines", func(t *testing.T) {
		clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
		swapTestHooks(t, &clock, func(string) (string, error) { return nestedWhois, nil })
		getenv = func(string) string { return "secret-key" }
		orgLookup = func(string, string) (string, error) {
			return "Evil Corp\n2001:dead::/32", nil
		}

		rec := httptest.NewRecorder()
		asHandler(rec, httptest.NewRequest(http.MethodGet, "/as/2906?org=1", nil))

		for _, line := range strings.Split(strings.TrimSpace(rec.Body.String()), "\n") {
			if line == "2001:dead::/32" {
				t.Fatalf("injected prefix line in output:\n%s", rec.Body.String())
			}
		}
		if !hasComment(rec.Body.String(), "# org: Evil Corp 2001:dead::/32") {
			t.Errorf("unexpected flattening:\n%s", rec.Body.String())
		}
	})

	t.Run("org result is cached", func(t *testing.T) {
		clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
		swapTestHooks(t, &clock, func(string) (string, error) { return nestedWhois, nil })
		getenv = func(string) string { return "secret-key" }
		calls := 0
		orgLookup = func(string, string) (string, error) {
			calls++
			return "Example Org", nil
		}

		for i := 0; i < 3; i++ {
			rec := httptest.NewRecorder()
			asHandler(rec, httptest.NewRequest(http.MethodGet, "/as/2906?org=1", nil))
		}
		if calls != 1 {
			t.Errorf("metered API called %d times, want 1", calls)
		}

		clock = clock.Add(cacheTTL + time.Second)
		rec := httptest.NewRecorder()
		asHandler(rec, httptest.NewRequest(http.MethodGet, "/as/2906?org=1", nil))
		if calls != 2 {
			t.Errorf("expected refresh after TTL, got %d calls", calls)
		}
	})

	t.Run("invalid org value", func(t *testing.T) {
		clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
		swapTestHooks(t, &clock, func(string) (string, error) { return nestedWhois, nil })

		rec := httptest.NewRecorder()
		asHandler(rec, httptest.NewRequest(http.MethodGet, "/as/2906?org=yes", nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("got status %d, want 400", rec.Code)
		}
	})
}

// The toggle must be a GET parameter: a POST body must never supply it.
func TestASHandlerRejectsNonGET(t *testing.T) {
	clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	swapTestHooks(t, &clock, func(string) (string, error) { return nestedWhois, nil })

	req := httptest.NewRequest(http.MethodPost, "/as/2906", strings.NewReader("agg=0"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	asHandler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("got status %d, want 405", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); allow != "GET, HEAD" {
		t.Errorf("got Allow %q", allow)
	}
}

// A POSTed body value must not leak in even if the method guard were relaxed.
func TestAggParamIgnoresRequestBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/as/2906", strings.NewReader("agg=0"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	got, err := parseBoolParam(req, "agg", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Error("body value overrode the default; agg must come from the URL query only")
	}
}
