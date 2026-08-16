package main

import (
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

const sampleWhois = `route:          23.246.0.0/18
descr:          SS-144
origin:         AS2906
source:         RADB

route6:         2a00:86c0::/32
origin:         AS2906
source:         RADB

route6:         2607:fb10::/32
origin:         AS2906
source:         RADB

route6:         2a00:86c0::/32
descr:          RPKI ROA for 2a00:86c0::/32 / AS2906
origin:         AS2906
source:         RPKI  # Trust Anchor: ripe

route:          23.246.15.0/24
origin:         AS2906
source:         NTTCOM
`

func prefixStrings(ps []netip.Prefix) []string {
	if len(ps) == 0 {
		return nil
	}
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

func extractStrings(input string) []string {
	return prefixStrings(extractIPv6Prefixes(input))
}

func aggregateStrings(input string) []string {
	return prefixStrings(aggregatePrefixes(extractIPv6Prefixes(input)))
}

func TestExtractIPv6Prefixes(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "dedups and sorts, ignores ipv4 route lines",
			input: sampleWhois,
			want:  []string{"2607:fb10::/32", "2a00:86c0::/32"},
		},
		{
			name:  "no entries found",
			input: "%  No entries found for the selected source(s).\n",
			want:  nil,
		},
		{
			name:  "ipv4 only",
			input: "route:          23.246.0.0/18\norigin:         AS2906\n",
			want:  nil,
		},
		{
			name: "more-specifics are retained without aggregation",
			input: "route6:  2607:fb10:2033::/48\n" +
				"route6:  2607:fb10::/32\n" +
				"route6:  2607:fb10::/48\n",
			want: []string{"2607:fb10::/32", "2607:fb10::/48", "2607:fb10:2033::/48"},
		},
		{
			name:  "exact duplicates are collapsed",
			input: "route6:  2a00:86c0::/32\nroute6:  2a00:86c0::/32\n",
			want:  []string{"2a00:86c0::/32"},
		},
		{
			name:  "malformed and non-ipv6 values are skipped",
			input: "route6:  not-a-prefix\nroute6:  192.0.2.0/24\nroute6:  2a00:86c0::/32\n",
			want:  []string{"2a00:86c0::/32"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractStrings(tt.input)
			if !slices.Equal(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAggregatePrefixes(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "more-specifics covered by a broader prefix are dropped",
			input: "route6:  2607:fb10:2033::/48\n" +
				"route6:  2607:fb10::/32\n" +
				"route6:  2607:fb10::/48\n",
			want: []string{"2607:fb10::/32"},
		},
		{
			name: "covering prefix listed last still wins",
			input: "route6:  2a00:86c0:4::/48\n" +
				"route6:  2a00:86c0:5::/48\n" +
				"route6:  2a00:86c0::/32\n",
			want: []string{"2a00:86c0::/32"},
		},
		{
			name: "sibling prefixes without a common cover are all kept",
			input: "route6:  2a00:86c0:4::/48\n" +
				"route6:  2a00:86c0:5::/48\n" +
				"route6:  2620:0:ef0::/48\n",
			want: []string{"2620:0:ef0::/48", "2a00:86c0:4::/48", "2a00:86c0:5::/48"},
		},
		{
			name: "adjacent but non-covering prefixes are kept",
			input: "route6:  2001:db8::/33\n" +
				"route6:  2001:db8:8000::/33\n",
			want: []string{"2001:db8::/33", "2001:db8:8000::/33"},
		},
		{
			name: "nested three levels deep collapses to the broadest",
			input: "route6:  2001:db8:1:2::/64\n" +
				"route6:  2001:db8:1::/48\n" +
				"route6:  2001:db8::/32\n",
			want: []string{"2001:db8::/32"},
		},
		{
			name: "cover does not swallow a later unrelated prefix",
			input: "route6:  2001:db8::/32\n" +
				"route6:  2001:db8:1::/48\n" +
				"route6:  2001:db9::/32\n",
			want: []string{"2001:db8::/32", "2001:db9::/32"},
		},
		{
			name:  "unmasked prefix is normalized before comparison",
			input: "route6:  2001:db8:1:2::/32\nroute6:  2001:db8:aaaa::/48\n",
			want:  []string{"2001:db8::/32"},
		},
		{
			name:  "empty input",
			input: "%  No entries found for the selected source(s).\n",
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := aggregateStrings(tt.input)
			if !slices.Equal(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// TestAggregatePrefixesDoesNotMutateInput guards the cache: entries are shared
// across requests, so aggregation must not write through its input slice.
func TestAggregatePrefixesDoesNotMutateInput(t *testing.T) {
	in := extractIPv6Prefixes("route6: 2001:db8::/32\nroute6: 2001:db8:1::/48\nroute6: 2001:db9::/32\n")
	before := prefixStrings(in)

	got := prefixStrings(aggregatePrefixes(in))
	if want := []string{"2001:db8::/32", "2001:db9::/32"}; !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if after := prefixStrings(in); !slices.Equal(before, after) {
		t.Errorf("input mutated: %v -> %v", before, after)
	}
}

// TestAggregatePrefixesInvariants cross-checks the linear covering-prefix sweep
// against brute force on randomized input: no survivor may cover another, and
// every input must still be covered by some survivor.
func TestAggregatePrefixesInvariants(t *testing.T) {
	rng := rand.New(rand.NewSource(1))

	for iter := 0; iter < 500; iter++ {
		var input strings.Builder
		var in []netip.Prefix
		for n := 0; n < 12; n++ {
			var b [16]byte
			// Few distinct high bytes, so covers and nesting occur often.
			b[0], b[1] = 0x20, byte(rng.Intn(3))
			b[2] = byte(rng.Intn(4))
			b[3] = byte(rng.Intn(4))
			bits := 16 + 8*rng.Intn(6)
			p := netip.PrefixFrom(netip.AddrFrom16(b), bits).Masked()
			in = append(in, p)
			fmt.Fprintf(&input, "route6: %s\n", p)
		}

		out := aggregatePrefixes(extractIPv6Prefixes(input.String()))

		for i, a := range out {
			for j, b := range out {
				if i != j && a.Contains(b.Addr()) && a.Bits() <= b.Bits() {
					t.Fatalf("iter %d: %s is covered by %s but survived", iter, b, a)
				}
			}
		}

		for _, p := range in {
			covered := false
			for _, q := range out {
				if q.Contains(p.Addr()) && q.Bits() <= p.Bits() {
					covered = true
					break
				}
			}
			if !covered {
				t.Fatalf("iter %d: input %s lost, not covered by any survivor", iter, p)
			}
		}
	}
}

func TestParseASN(t *testing.T) {
	tests := []struct {
		in        string
		wantValue uint64
		wantCanon string
		wantErr   bool
	}{
		{in: "2906", wantValue: 2906, wantCanon: "2906"},
		{in: "0", wantValue: 0, wantCanon: "0"},
		{in: "65535", wantValue: 65535, wantCanon: "65535"},
		{in: "4294967295", wantValue: 4294967295, wantCanon: "4294967295"},
		{in: "007", wantValue: 7, wantCanon: "7"},
		{in: "", wantErr: true},
		{in: "abc", wantErr: true},
		{in: "29a6", wantErr: true},
		{in: "-5", wantErr: true},
		{in: "4294967296", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			v, canon, err := parseASN(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got %d/%q", tt.in, v, canon)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if v != tt.wantValue || canon != tt.wantCanon {
				t.Errorf("got %d/%q, want %d/%q", v, canon, tt.wantValue, tt.wantCanon)
			}
		})
	}
}

func TestIsPermittedASN(t *testing.T) {
	tests := []struct {
		name string
		asn  uint64
		want bool
	}{
		{"zero", 0, true},
		{"typical 16-bit", 2906, true},
		{"16-bit max", 65535, true},
		{"documentation reserved", 65540, false},
		{"reserved block", 100000, false},
		{"first APNIC block start", 131072, true},
		{"first APNIC block end", 132095, true},
		{"unallocated after APNIC", 155962, false},
		{"first RIPE block", 196608, true},
		{"reserved for private use", 4200000001, false},
		{"final reserved value", 4294967295, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPermittedASN(tt.asn); got != tt.want {
				t.Errorf("isPermittedASN(%d) = %v, want %v", tt.asn, got, tt.want)
			}
		})
	}
}

func TestIsPermittedASNRangeBoundaries(t *testing.T) {
	for _, r := range allocatedASNRanges {
		if !isPermittedASN(uint64(r.start)) || !isPermittedASN(uint64(r.end)) {
			t.Errorf("range %d-%d: boundaries should be permitted", r.start, r.end)
		}
	}
}

// swapTestHooks isolates cache/clock/upstream state for a single test. The org
// lookup and env reader default to failing loudly, so any test that reaches
// them without opting in is caught rather than hitting the live paid API.
func swapTestHooks(t *testing.T, clock *time.Time, query func(string) (string, error)) {
	t.Helper()
	origQuery, origOrg, origNow, origGetenv := whoisQuery, orgLookup, nowFunc, getenv
	whoisQuery = query
	nowFunc = func() time.Time { return *clock }
	orgLookup = func(string, string) (string, error) {
		t.Error("org API called without an explicit test hook")
		return "", errors.New("unexpected org lookup")
	}
	getenv = func(string) string { return "" }

	resetCaches := func() {
		cacheMu.Lock()
		cache = make(map[string]cacheEntry)
		cacheMu.Unlock()
		orgCacheMu.Lock()
		orgCache = make(map[string]orgCacheEntry)
		orgCacheMu.Unlock()
	}
	resetCaches()

	t.Cleanup(func() {
		whoisQuery, orgLookup, nowFunc, getenv = origQuery, origOrg, origNow, origGetenv
		resetCaches()
	})
}

// bodyComments returns only the "#" comment lines of a response.
func bodyComments(body string) []string {
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		if strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

func hasComment(body, want string) bool {
	return slices.Contains(bodyComments(body), want)
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

const nestedWhois = "route6: 2001:db8::/32\nroute6: 2001:db8:1::/48\nroute6: 2001:db9::/32\n"

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
			if name != orgAPIKeyEnv {
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

// swapOrgAPIURL points the org lookup at a stub server; the returned func restores it.
func swapOrgAPIURL(t *testing.T, u string) func() {
	t.Helper()
	orig := orgAPIURL
	orgAPIURL = u
	return func() { orgAPIURL = orig }
}

func TestRedactKey(t *testing.T) {
	const key = "0123456789abcdef0123456789abcdef" // dummy, shaped like a real key
	in := `Get "https://api.whoisfreaks.com/v2.0/asn-whois?apiKey=` + key + `&asn=AS2906": dial tcp: timeout`

	got := redactKey(in, key)
	if strings.Contains(got, key) {
		t.Errorf("API key leaked: %q", got)
	}
	if !strings.Contains(got, "REDACTED") {
		t.Errorf("expected redaction marker, got %q", got)
	}
	if redactKey("no key here", "") != "no key here" {
		t.Error("empty key must be a no-op")
	}
}

func TestLookupOrgName(t *testing.T) {
	const key = "test-key-123"

	t.Run("parses orgName", func(t *testing.T) {
		var gotQuery url.Values
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotQuery = r.URL.Query()
			io.WriteString(w, `{"asNumber":"2906","asName":"AS-SSI","orgName":"Netflix Streaming Services Inc."}`)
		}))
		defer srv.Close()
		defer swapOrgAPIURL(t, srv.URL)()

		got, err := lookupOrgName("2906", key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "Netflix Streaming Services Inc." {
			t.Errorf("got %q", got)
		}
		if gotQuery.Get("apiKey") != key || gotQuery.Get("asn") != "AS2906" {
			t.Errorf("unexpected query: %v", gotQuery)
		}
	})

	t.Run("falls back to asName", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `{"orgName":"","asName":"IETF-MEETING"}`)
		}))
		defer srv.Close()
		defer swapOrgAPIURL(t, srv.URL)()

		got, err := lookupOrgName("56554", key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "IETF-MEETING" {
			t.Errorf("got %q", got)
		}
	})

	t.Run("surfaces api error message without the key", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"status":401,"error":"Api Access Exception","message":"Provided API key is invalid."}`)
		}))
		defer srv.Close()
		defer swapOrgAPIURL(t, srv.URL)()

		_, err := lookupOrgName("2906", key)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "Provided API key is invalid.") {
			t.Errorf("unhelpful error: %v", err)
		}
		if strings.Contains(err.Error(), key) {
			t.Errorf("API key leaked in error: %v", err)
		}
	})

	t.Run("transport error does not leak the key", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		srv.Close() // refuse connections
		defer swapOrgAPIURL(t, srv.URL)()

		_, err := lookupOrgName("2906", key)
		if err == nil {
			t.Fatal("expected error")
		}
		if strings.Contains(err.Error(), key) {
			t.Errorf("API key leaked in transport error: %v", err)
		}
	})

	t.Run("empty name is an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `{"orgName":"","asName":""}`)
		}))
		defer srv.Close()
		defer swapOrgAPIURL(t, srv.URL)()

		if _, err := lookupOrgName("2906", key); err == nil {
			t.Error("expected error for missing name")
		}
	})
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
