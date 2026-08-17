package rdap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"asn-ipv6-ranges/internal/asnreg"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return b
}

// serveFixture starts a stub RDAP server returning one canned response and
// points the package at it. It returns the paths requested.
func serveFixture(t *testing.T, body []byte, status int) *[]string {
	t.Helper()
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if accept := r.Header.Get("Accept"); accept != "application/rdap+json" {
			t.Errorf("Accept header = %q", accept)
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		w.WriteHeader(status)
		w.Write(body)
	}))
	t.Cleanup(srv.Close)

	orig := baseOverride
	baseOverride = srv.URL
	t.Cleanup(func() { baseOverride = orig })
	return &paths
}

func TestLookupOrgName(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		reg     asnreg.Registry
		asn     string
		want    string
	}{
		{
			name: "ARIN registrant org", fixture: "arin_as2906.json",
			reg: asnreg.Registry{Name: "ARIN"}, asn: "2906",
			want: "Netflix Streaming Services Inc.",
		},
		{
			name: "RIPE registrant org", fixture: "ripe_as24940.json",
			reg: asnreg.Registry{Name: "RIPE NCC"}, asn: "24940",
			want: "Hetzner Online GmbH",
		},
		{
			// APNIC with a registrant org entity: rule 1 answers.
			name: "APNIC with registrant org", fixture: "apnic_as7575.json",
			reg: asnreg.Registry{Name: "APNIC"}, asn: "7575",
			want: "Australian Academic and Research Network",
		},
		{
			// APNIC without one: only the remark carries the operator.
			name: "APNIC via remarks", fixture: "apnic_as9605.json",
			reg: asnreg.Registry{Name: "APNIC"}, asn: "9605",
			want: "NTT DOCOMO, INC.",
		},
		{
			name: "LACNIC registrant org", fixture: "lacnic_as27947.json",
			reg: asnreg.Registry{Name: "LACNIC"}, asn: "27947",
			want: "Telconet S.A",
		},
		{
			name: "AFRINIC registrant org", fixture: "afrinic_as37100.json",
			reg: asnreg.Registry{Name: "AFRINIC"}, asn: "37100",
			want: "SEACOM Limited",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := serveFixture(t, fixture(t, tt.fixture), http.StatusOK)

			got, err := LookupOrgName(context.Background(), tt.reg, tt.asn)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
			if want := "/autnum/" + tt.asn; len(*paths) != 1 || (*paths)[0] != want {
				t.Errorf("requested %v, want [%s]", *paths, want)
			}
		})
	}
}

// TestLookupOrgNameRejectsWrongEntities pins the specific wrong answers that
// simpler selection rules would return. Each of these is a real value present
// in the fixture.
func TestLookupOrgNameRejectsWrongEntities(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		reg     asnreg.Registry
		asn     string
		reject  []string
	}{
		{
			name: "RIPE maintainer handles and contact role", fixture: "ripe_as24940.json",
			reg: asnreg.Registry{Name: "RIPE NCC"}, asn: "24940",
			// HOS-GUN is what "first entity with role registrant" returns.
			reject: []string{"HOS-GUN", "RIPE-NCC-END-MNT", "Hetzner Online GmbH - Contact Role"},
		},
		{
			name: "APNIC delegating registry", fixture: "apnic_as9605.json",
			reg: asnreg.Registry{Name: "APNIC"}, asn: "9605",
			// The only entity with a name is JPNIC, which delegated the block.
			reject: []string{"Japan Network Information Center", "docomo"},
		},
		{
			name: "APNIC address lines and NOC", fixture: "apnic_as7575.json",
			reg: asnreg.Registry{Name: "APNIC"}, asn: "7575",
			// description[] continues into a postal address; joining it or
			// taking a later line would surface these.
			reject: []string{"GPO Box 1559", "Canberra, ACT 2601", "AARNet Network Operations Centre"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := fixture(t, tt.fixture)
			for _, r := range tt.reject {
				if !strings.Contains(string(body), r) {
					t.Fatalf("fixture no longer contains %q; this regression is untested", r)
				}
			}
			serveFixture(t, body, http.StatusOK)

			got, err := LookupOrgName(context.Background(), tt.reg, tt.asn)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for _, r := range tt.reject {
				if got == r {
					t.Errorf("returned %q, which is not the operator name", got)
				}
			}
		})
	}
}

func TestLookupOrgNameErrors(t *testing.T) {
	t.Run("no RDAP base", func(t *testing.T) {
		orig := baseOverride
		baseOverride = ""
		t.Cleanup(func() { baseOverride = orig })

		if _, err := LookupOrgName(context.Background(), asnreg.Registry{Name: "NOWHERE"}, "1"); err == nil {
			t.Error("expected an error when the registry has no RDAP base")
		}
	})

	t.Run("http error status", func(t *testing.T) {
		serveFixture(t, []byte(`{"errorCode":404}`), http.StatusNotFound)
		if _, err := LookupOrgName(context.Background(), asnreg.Registry{Name: "ARIN"}, "99999"); err == nil {
			t.Error("expected an error for a 404 response")
		}
	})

	t.Run("malformed json", func(t *testing.T) {
		serveFixture(t, []byte(`{not json`), http.StatusOK)
		if _, err := LookupOrgName(context.Background(), asnreg.Registry{Name: "ARIN"}, "2906"); err == nil {
			t.Error("expected an error for a malformed body")
		}
	})

	t.Run("no usable name", func(t *testing.T) {
		serveFixture(t, []byte(`{"objectClassName":"autnum","entities":[]}`), http.StatusOK)
		if _, err := LookupOrgName(context.Background(), asnreg.Registry{Name: "ARIN"}, "2906"); err == nil {
			t.Error("expected an error when no name is present")
		}
	})
}

// TestOrgNameFallsBackToName covers rule 3 in isolation; no captured response
// currently needs it.
func TestOrgNameFallsBackToName(t *testing.T) {
	var r autnumResponse
	if err := json.Unmarshal([]byte(`{"name":"EXAMPLE-AS"}`), &r); err != nil {
		t.Fatal(err)
	}
	if got := orgName(&r); got != "EXAMPLE-AS" {
		t.Errorf("got %q, want EXAMPLE-AS", got)
	}
}

// TestVCardSkipsStructuredValues guards the jCard scanner against the "adr"
// property, whose value is an array rather than a string.
func TestVCardSkipsStructuredValues(t *testing.T) {
	var e entity
	raw := `{"handle":"X","vcardArray":["vcard",[["version",{},"text","4.0"],
	         ["adr",{},"text",["","","Somewhere","","","",""]],
	         ["fn",{},"text","Example Org"],["kind",{},"text","org"]]]}`
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		t.Fatal(err)
	}
	props := vcard(e)
	if props["fn"] != "Example Org" || props["kind"] != "org" {
		t.Errorf("got %v", props)
	}
	if _, ok := props["adr"]; ok {
		t.Error("structured adr value should be skipped, not stringified")
	}
}

// TestFixturesCarryNoPersonalData keeps contact details out of the repository.
// RDAP vCards embed named individuals, emails, and phone numbers that the
// extraction rules never read.
func TestFixturesCarryNoPersonalData(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures found: %v", err)
	}
	// Matches an address shape rather than a bare "@": RIPE embeds JSONPath
	// expressions such as $.entities[?(@.handle=='X')] that contain @ but no
	// address.
	email := regexp.MustCompile(`[\w.+-]+@[\w-]+\.[\w.-]+`)

	for _, f := range files {
		body := string(fixture(t, filepath.Base(f)))
		for _, m := range email.FindAllString(body, -1) {
			if !strings.HasSuffix(m, "example.invalid") {
				t.Errorf("%s: unredacted address: %q", f, m)
			}
		}
		// Names of real people that were present in the captured responses.
		for _, name := range []string{"Carlos Montero", "Patricio Samaniego", "Noah Maina", "Kyalo Mutisya"} {
			if strings.Contains(body, name) {
				t.Errorf("%s: unredacted personal name %q", f, name)
			}
		}
	}
}

// serveStatus starts a stub RDAP server with control over the response headers,
// for the rate-limiting cases.
func serveStatus(t *testing.T, status int, body string, headers map[string]string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	orig := baseOverride
	baseOverride = srv.URL
	t.Cleanup(func() { baseOverride = orig })
}

// TestLookupOrgNameReportsRateLimiting covers the one signal the registries give
// us about limits none of them publish. A 429 has to be distinguishable from an
// ordinary failure, or the caller keeps querying at exactly the rate that
// provoked it.
func TestLookupOrgNameReportsRateLimiting(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		headers    map[string]string
		retryAfter time.Duration
	}{
		{
			name: "429 with delay-seconds", status: http.StatusTooManyRequests,
			headers: map[string]string{"Retry-After": "120"}, retryAfter: 2 * time.Minute,
		},
		{
			name: "429 without Retry-After", status: http.StatusTooManyRequests,
		},
		{
			name: "503 is treated the same", status: http.StatusServiceUnavailable,
			headers: map[string]string{"Retry-After": "30"}, retryAfter: 30 * time.Second,
		},
		{
			// LACNIC signals refusal this way rather than with a 429.
			name: "403 naming a rate limit", status: http.StatusForbidden,
			body: `{"errorCode":403,"title":"rate limit exceeded for IP: 192.0.2.1"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			serveStatus(t, tc.status, tc.body, tc.headers)

			_, err := LookupOrgName(context.Background(), asnreg.Registry{Name: "ARIN"}, "2906")
			var limited *RateLimitedError
			if !errors.As(err, &limited) {
				t.Fatalf("got %v (%T), want a *RateLimitedError", err, err)
			}
			if limited.Status != tc.status {
				t.Errorf("Status = %d, want %d", limited.Status, tc.status)
			}
			if limited.RetryAfter != tc.retryAfter {
				t.Errorf("RetryAfter = %s, want %s", limited.RetryAfter, tc.retryAfter)
			}
		})
	}
}

// TestLookupOrgNameKeepsOrdinaryDenialsOrdinary: a 403 that is not about rate
// limiting must not park the registry.
func TestLookupOrgNameKeepsOrdinaryDenialsOrdinary(t *testing.T) {
	serveStatus(t, http.StatusForbidden, `{"errorCode":403,"title":"access denied"}`, nil)

	_, err := LookupOrgName(context.Background(), asnreg.Registry{Name: "ARIN"}, "2906")
	if err == nil {
		t.Fatal("expected an error")
	}
	if errors.As(err, new(*RateLimitedError)) {
		t.Errorf("a plain 403 was misread as rate limiting: %v", err)
	}
}

func TestParseRetryAfter(t *testing.T) {
	base := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		header string
		want   time.Duration
	}{
		{"absent", "", 0},
		{"delay seconds", "45", 45 * time.Second},
		{"zero means no useful hint", "0", 0},
		{"negative is ignored", "-5", 0},
		{"http date in the future", base.Add(90 * time.Second).Format(http.TimeFormat), 90 * time.Second},
		{"http date in the past", base.Add(-time.Hour).Format(http.TimeFormat), 0},
		{"unparseable", "soon", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseRetryAfter(tc.header, base); got != tc.want {
				t.Errorf("parseRetryAfter(%q) = %s, want %s", tc.header, got, tc.want)
			}
		})
	}
}

// TestLookupOrgNameHonoursCancellation: an abandoned request must not leave a
// query running against a registry that counts it.
func TestLookupOrgNameHonoursCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)

	orig := baseOverride
	baseOverride = srv.URL
	t.Cleanup(func() { baseOverride = orig })

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	done := make(chan error, 1)
	go func() {
		_, err := LookupOrgName(ctx, asnreg.Registry{Name: "ARIN"}, "2906")
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("got %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lookup outlived its cancelled context")
	}
}
