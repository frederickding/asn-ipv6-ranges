package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"asn-ipv6-ranges/internal/asnreg"
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

// arinASN is 2906, which the generated table maps to ARIN — used so the RIR
// path has a real registry to resolve.
const arinASN = "2906"

// ripeASN is 24940 (Hetzner), which the generated table maps to RIPE NCC — the
// one registry whose automatic order puts RDAP first.
const ripeASN = "24940"

func TestASHandlerOrgSources(t *testing.T) {
	t.Run("not requested by default", func(t *testing.T) {
		clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
		swapTestHooks(t, &clock, func(string) (string, error) { return nestedWhois, nil })
		getenv = func(string) string { return "secret-key" }
		orgAPILookup = func(context.Context, string, string) (string, error) {
			t.Error("org lookup ran without ?org=1")
			return "", nil
		}

		rec := httptest.NewRecorder()
		asHandler(rec, httptest.NewRequest(http.MethodGet, "/as/"+arinASN, nil))

		for _, c := range bodyComments(rec.Body.String()) {
			if strings.HasPrefix(c, "# org:") {
				t.Errorf("unexpected org comment: %q", c)
			}
		}
	})

	t.Run("auto prefers the API when a key is set", func(t *testing.T) {
		clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
		swapTestHooks(t, &clock, func(string) (string, error) { return nestedWhois, nil })
		getenv = func(name string) string {
			if name != whoisfreaks.KeyEnv {
				t.Errorf("read unexpected env var %q", name)
			}
			return "secret-key"
		}
		orgAPILookup = func(context.Context, string, string) (string, error) { return "From API", nil }
		orgRIRLookup = func(context.Context, asnreg.Registry, string) (string, error) {
			t.Error("whois queried even though the API succeeded")
			return "", nil
		}

		rec := httptest.NewRecorder()
		asHandler(rec, httptest.NewRequest(http.MethodGet, "/as/"+arinASN+"?org=1", nil))

		if !hasComment(rec.Body.String(), "# org: From API (source: "+whoisfreaks.Host+")") {
			t.Errorf("missing API-sourced org comment in:\n%s", rec.Body.String())
		}
	})

	t.Run("auto uses the registry when no key is configured", func(t *testing.T) {
		clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
		swapTestHooks(t, &clock, func(string) (string, error) { return nestedWhois, nil })
		getenv = func(string) string { return "" }
		orgRIRLookup = func(_ context.Context, reg asnreg.Registry, asn string) (string, error) {
			if reg.Name != "ARIN" {
				t.Errorf("resolved against %q, want ARIN", reg.Name)
			}
			return "From whois", nil
		}

		rec := httptest.NewRecorder()
		asHandler(rec, httptest.NewRequest(http.MethodGet, "/as/"+arinASN+"?org=1", nil))

		if !hasComment(rec.Body.String(), "# org: From whois (source: whois.arin.net)") {
			t.Errorf("missing whois-sourced comment in:\n%s", rec.Body.String())
		}
	})

	t.Run("src=api forces the API", func(t *testing.T) {
		clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
		swapTestHooks(t, &clock, func(string) (string, error) { return nestedWhois, nil })
		getenv = func(string) string { return "secret-key" }
		orgAPILookup = func(context.Context, string, string) (string, error) { return "From API", nil }

		rec := httptest.NewRecorder()
		asHandler(rec, httptest.NewRequest(http.MethodGet, "/as/"+arinASN+"?org=1&src=api", nil))

		if !hasComment(rec.Body.String(), "# org: From API (source: "+whoisfreaks.Host+")") {
			t.Errorf("got:\n%s", rec.Body.String())
		}
	})

	t.Run("src=api without a key reports why", func(t *testing.T) {
		clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
		swapTestHooks(t, &clock, func(string) (string, error) { return nestedWhois, nil })
		getenv = func(string) string { return "" }

		rec := httptest.NewRecorder()
		asHandler(rec, httptest.NewRequest(http.MethodGet, "/as/"+arinASN+"?org=1&src=api", nil))

		if rec.Code != http.StatusOK {
			t.Errorf("org failure must not fail the request, got %d", rec.Code)
		}
		want := "# org: lookup failed: api selected but WHOISFREAKS_API_KEY is not set"
		if !hasComment(rec.Body.String(), want) {
			t.Errorf("got:\n%s", rec.Body.String())
		}
	})

	t.Run("src=whois forces whois even with a key", func(t *testing.T) {
		clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
		swapTestHooks(t, &clock, func(string) (string, error) { return nestedWhois, nil })
		getenv = func(string) string { return "secret-key" }
		orgAPILookup = func(context.Context, string, string) (string, error) {
			t.Error("API called despite src=whois")
			return "", nil
		}
		orgRIRLookup = func(context.Context, asnreg.Registry, string) (string, error) { return "From whois", nil }

		rec := httptest.NewRecorder()
		asHandler(rec, httptest.NewRequest(http.MethodGet, "/as/"+arinASN+"?org=1&src=whois", nil))

		if !hasComment(rec.Body.String(), "# org: From whois (source: whois.arin.net)") {
			t.Errorf("got:\n%s", rec.Body.String())
		}
	})

	t.Run("src=rdap forces RDAP even with a key", func(t *testing.T) {
		clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
		swapTestHooks(t, &clock, func(string) (string, error) { return nestedWhois, nil })
		getenv = func(string) string { return "secret-key" }
		orgAPILookup = func(context.Context, string, string) (string, error) {
			t.Error("API called despite src=rdap")
			return "", nil
		}
		orgRIRLookup = func(context.Context, asnreg.Registry, string) (string, error) {
			t.Error("whois called despite src=rdap")
			return "", nil
		}
		orgRDAPLookup = func(context.Context, asnreg.Registry, string) (string, error) { return "From RDAP", nil }

		rec := httptest.NewRecorder()
		asHandler(rec, httptest.NewRequest(http.MethodGet, "/as/"+arinASN+"?org=1&src=rdap", nil))

		if !hasComment(rec.Body.String(), "# org: From RDAP (source: rdap.arin.net)") {
			t.Errorf("got:\n%s", rec.Body.String())
		}
	})

	// Forcing means forcing: an explicit source must not silently fall back, or
	// the parameter could not be trusted to exercise one path.
	t.Run("explicit source does not fall back", func(t *testing.T) {
		clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
		swapTestHooks(t, &clock, func(string) (string, error) { return nestedWhois, nil })
		getenv = func(string) string { return "secret-key" }
		orgAPILookup = func(context.Context, string, string) (string, error) {
			t.Error("API used as a fallback despite src=whois")
			return "Should Not Appear", nil
		}
		orgRDAPLookup = func(context.Context, asnreg.Registry, string) (string, error) {
			t.Error("RDAP used as a fallback despite src=whois")
			return "Should Not Appear", nil
		}
		orgRIRLookup = func(context.Context, asnreg.Registry, string) (string, error) {
			return "", errors.New("dial tcp: timeout")
		}

		rec := httptest.NewRecorder()
		asHandler(rec, httptest.NewRequest(http.MethodGet, "/as/"+arinASN+"?org=1&src=whois", nil))

		if strings.Contains(rec.Body.String(), "Should Not Appear") {
			t.Error("fell back to another source")
		}
		if !hasComment(rec.Body.String(), "# count: 2") {
			t.Errorf("prefixes missing after org failure:\n%s", rec.Body.String())
		}
	})

	t.Run("src without org is reported as ignored", func(t *testing.T) {
		clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
		swapTestHooks(t, &clock, func(string) (string, error) { return nestedWhois, nil })

		rec := httptest.NewRecorder()
		asHandler(rec, httptest.NewRequest(http.MethodGet, "/as/"+arinASN+"?src=rdap", nil))

		if !hasComment(rec.Body.String(), "# src: ignored (org lookup not requested)") {
			t.Errorf("missing ignored notice in:\n%s", rec.Body.String())
		}
	})

	t.Run("invalid values", func(t *testing.T) {
		clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
		swapTestHooks(t, &clock, func(string) (string, error) { return nestedWhois, nil })

		for _, q := range []string{"?org=yes", "?org=1&src=bogus", "?src=rir"} {
			rec := httptest.NewRecorder()
			asHandler(rec, httptest.NewRequest(http.MethodGet, "/as/"+arinASN+q, nil))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s: got status %d, want 400", q, rec.Code)
			}
		}
	})

	// A newline in third-party data must not escape its comment line and forge
	// something that parses as a prefix.
	t.Run("multiline org name cannot inject output lines", func(t *testing.T) {
		clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
		swapTestHooks(t, &clock, func(string) (string, error) { return nestedWhois, nil })
		getenv = func(string) string { return "" }
		orgRIRLookup = func(context.Context, asnreg.Registry, string) (string, error) {
			return "Evil Corp\n2001:dead::/32", nil
		}

		rec := httptest.NewRecorder()
		asHandler(rec, httptest.NewRequest(http.MethodGet, "/as/"+arinASN+"?org=1", nil))

		for _, line := range strings.Split(strings.TrimSpace(rec.Body.String()), "\n") {
			if line == "2001:dead::/32" {
				t.Fatalf("injected prefix line in output:\n%s", rec.Body.String())
			}
		}
	})

	t.Run("results are cached per source", func(t *testing.T) {
		clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
		swapTestHooks(t, &clock, func(string) (string, error) { return nestedWhois, nil })
		getenv = func(string) string { return "secret-key" }
		apiCalls, rdapCalls := 0, 0
		orgAPILookup = func(context.Context, string, string) (string, error) {
			apiCalls++
			return "From API", nil
		}
		orgRDAPLookup = func(context.Context, asnreg.Registry, string) (string, error) {
			rdapCalls++
			return "From RDAP", nil
		}

		get := func(query string) string {
			rec := httptest.NewRecorder()
			asHandler(rec, httptest.NewRequest(http.MethodGet, "/as/"+arinASN+query, nil))
			return rec.Body.String()
		}

		for i := 0; i < 3; i++ {
			get("?org=1")
		}
		if apiCalls != 1 {
			t.Errorf("metered API called %d times, want 1", apiCalls)
		}

		// A different source must not be served the cached auto answer.
		if body := get("?org=1&src=rdap"); !hasComment(body, "# org: From RDAP (source: rdap.arin.net)") {
			t.Errorf("forced request replayed the cached auto answer:\n%s", body)
		}
		if rdapCalls != 1 {
			t.Errorf("RDAP called %d times, want 1", rdapCalls)
		}
		if body := get("?org=1"); !hasComment(body, "# org: From API (source: "+whoisfreaks.Host+")") {
			t.Errorf("auto request served the forced answer:\n%s", body)
		}

		clock = clock.Add(orgCacheTTL + time.Second)
		get("?org=1")
		if apiCalls != 2 {
			t.Errorf("expected refresh after TTL, got %d API calls", apiCalls)
		}
	})
}

// TestOrgAutoOrdering pins the per-registry ordering: RIPE pays 60 KB across
// two whois queries versus 15 KB of RDAP, so RDAP goes first there and whois
// first everywhere else.
func TestOrgAutoOrdering(t *testing.T) {
	tests := []struct {
		name      string
		asn       string
		wantFirst string
	}{
		{"RIPE prefers RDAP", ripeASN, "rdap"},
		{"ARIN prefers whois", arinASN, "whois"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
			swapTestHooks(t, &clock, func(string) (string, error) { return nestedWhois, nil })
			getenv = func(string) string { return "" } // no key: registry sources only

			var order []string
			orgRIRLookup = func(context.Context, asnreg.Registry, string) (string, error) {
				order = append(order, "whois")
				return "name", nil
			}
			orgRDAPLookup = func(context.Context, asnreg.Registry, string) (string, error) {
				order = append(order, "rdap")
				return "name", nil
			}

			rec := httptest.NewRecorder()
			asHandler(rec, httptest.NewRequest(http.MethodGet, "/as/"+tt.asn+"?org=1", nil))

			if len(order) != 1 {
				t.Fatalf("expected exactly one lookup, got %v", order)
			}
			if order[0] != tt.wantFirst {
				t.Errorf("tried %q first, want %q", order[0], tt.wantFirst)
			}
		})
	}
}

func TestOrgAutoFallsThrough(t *testing.T) {
	tests := []struct {
		name      string
		asn       string
		wantOrder []string
	}{
		{"RIPE falls back to whois", ripeASN, []string{"rdap", "whois"}},
		{"ARIN falls back to RDAP", arinASN, []string{"whois", "rdap"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
			swapTestHooks(t, &clock, func(string) (string, error) { return nestedWhois, nil })
			getenv = func(string) string { return "" }

			var order []string
			// The preferred source fails; the other must still answer.
			orgRIRLookup = func(context.Context, asnreg.Registry, string) (string, error) {
				order = append(order, "whois")
				if tt.wantOrder[0] == "whois" {
					return "", errors.New("whois down")
				}
				return "Fallback Name", nil
			}
			orgRDAPLookup = func(context.Context, asnreg.Registry, string) (string, error) {
				order = append(order, "rdap")
				if tt.wantOrder[0] == "rdap" {
					return "", errors.New("rdap down")
				}
				return "Fallback Name", nil
			}

			rec := httptest.NewRecorder()
			asHandler(rec, httptest.NewRequest(http.MethodGet, "/as/"+tt.asn+"?org=1", nil))

			if !slices.Equal(order, tt.wantOrder) {
				t.Errorf("order %v, want %v", order, tt.wantOrder)
			}
			if !strings.Contains(rec.Body.String(), "Fallback Name") {
				t.Errorf("fallback answer missing:\n%s", rec.Body.String())
			}
		})
	}
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
