package rirwhois

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"asn-ipv6-ranges/internal/asnreg"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return string(b)
}

// fakeRIR serves canned responses over TCP, keyed by the query it receives, and
// records the queries in order. Responses are real (sanitized) RIR output.
type fakeRIR struct {
	mu      sync.Mutex
	queries []string
}

func startFakeRIR(t *testing.T, responses map[string]string) *fakeRIR {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	f := &fakeRIR{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				line, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					return
				}
				q := strings.TrimSpace(line)
				f.mu.Lock()
				f.queries = append(f.queries, q)
				f.mu.Unlock()
				if resp, ok := responses[q]; ok {
					conn.Write([]byte(resp))
				}
			}()
		}
	}()

	orig := dialAddr
	dialAddr = func(string) string { return ln.Addr().String() }
	t.Cleanup(func() { dialAddr = orig })
	return f
}

func (f *fakeRIR) sent() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...)
}

func TestLookupOrgName(t *testing.T) {
	tests := []struct {
		name        string
		reg         asnreg.Registry
		asn         string
		responses   map[string]string
		want        string
		wantQueries []string
	}{
		{
			name: "ARIN flat format",
			reg:  asnreg.Registry{Name: "ARIN", WHOISHost: "whois.arin.net"},
			asn:  "2906",
			responses: map[string]string{
				"AS2906": fixture(t, "arin_as2906.txt"),
			},
			want:        "Netflix Streaming Services Inc.",
			wantQueries: []string{"AS2906"},
		},
		{
			name: "RIPE resolves the org handle in a second query",
			reg:  asnreg.Registry{Name: "RIPE NCC", WHOISHost: "whois.ripe.net"},
			asn:  "56554",
			responses: map[string]string{
				"-r AS56554":        fixture(t, "ripe_as56554.txt"),
				"-r ORG-IS136-RIPE": fixture(t, "ripe_org_is136.txt"),
			},
			want:        "Internet Society",
			wantQueries: []string{"-r AS56554", "-r ORG-IS136-RIPE"},
		},
		{
			name: "APNIC falls back to descr on the aut-num",
			reg:  asnreg.Registry{Name: "APNIC", WHOISHost: "whois.apnic.net"},
			asn:  "4608",
			responses: map[string]string{
				"-r AS4608": fixture(t, "apnic_as4608.txt"),
			},
			want: "Asia Pacific Network Information Centre",
		},
		{
			name: "LACNIC uses owner",
			reg:  asnreg.Registry{Name: "LACNIC", WHOISHost: "whois.lacnic.net"},
			asn:  "27947",
			responses: map[string]string{
				"AS27947": fixture(t, "lacnic_as27947.txt"),
			},
			want:        "Telconet S.A",
			wantQueries: []string{"AS27947"}, // no -r flag: LACNIC rejects it
		},
		{
			name: "AFRINIC uses descr",
			reg:  asnreg.Registry{Name: "AFRINIC", WHOISHost: "whois.afrinic.net"},
			asn:  "37100",
			responses: map[string]string{
				"-r AS37100": fixture(t, "afrinic_as37100.txt"),
			},
			want: "SEACOM Limited",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := startFakeRIR(t, tt.responses)

			got, err := LookupOrgName(tt.reg, tt.asn)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
			if tt.wantQueries != nil {
				if q := f.sent(); !equal(q, tt.wantQueries) {
					t.Errorf("queries = %v, want %v", q, tt.wantQueries)
				}
			}
			if n := len(f.sent()); n > 2 {
				t.Errorf("issued %d queries, want at most 2", n)
			}
		})
	}
}

// TestLookupOrgNameIgnoresASBlock is the regression guard for the trap that
// shaped the parser: RIPE and APNIC responses open with the parent as-block,
// whose descr names the block rather than the operator.
func TestLookupOrgNameIgnoresASBlock(t *testing.T) {
	for _, tc := range []struct {
		name, file, query, reject string
		reg                       asnreg.Registry
		asn                       string
	}{
		{
			name: "RIPE", file: "ripe_as56554.txt", query: "-r AS56554",
			reject: "RIPE NCC ASN block",
			reg:    asnreg.Registry{Name: "RIPE NCC", WHOISHost: "whois.ripe.net"}, asn: "56554",
		},
		{
			name: "APNIC", file: "apnic_as4608.txt", query: "-r AS4608",
			reject: "APNIC ASN block",
			reg:    asnreg.Registry{Name: "APNIC", WHOISHost: "whois.apnic.net"}, asn: "4608",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := fixture(t, tc.file)
			if !strings.Contains(body, tc.reject) {
				t.Fatalf("fixture no longer contains the as-block %q; the trap is untested", tc.reject)
			}
			// Only the aut-num query is answered, so no handle resolution occurs.
			startFakeRIR(t, map[string]string{tc.query: body})

			got, err := LookupOrgName(tc.reg, tc.asn)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got == tc.reject {
				t.Fatalf("returned the as-block description %q instead of the operator", got)
			}
		})
	}
}

func TestLookupOrgNameErrors(t *testing.T) {
	t.Run("no whois host", func(t *testing.T) {
		if _, err := LookupOrgName(asnreg.Registry{Name: "NOWHERE"}, "1"); err == nil {
			t.Error("expected an error when the registry has no host")
		}
	})

	t.Run("no matching aut-num", func(t *testing.T) {
		startFakeRIR(t, map[string]string{
			"-r AS99999": "% No entries found\n",
		})
		reg := asnreg.Registry{Name: "RIPE NCC", WHOISHost: "whois.ripe.net"}
		if _, err := LookupOrgName(reg, "99999"); err == nil {
			t.Error("expected an error when no aut-num object is returned")
		}
	})

	t.Run("dial failure", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		dead := ln.Addr().String()
		ln.Close()

		orig := dialAddr
		dialAddr = func(string) string { return dead }
		t.Cleanup(func() { dialAddr = orig })

		reg := asnreg.Registry{Name: "ARIN", WHOISHost: "whois.arin.net"}
		if _, err := LookupOrgName(reg, "2906"); err == nil {
			t.Error("expected a dial error")
		}
	})
}

// TestFixturesCarryNoPersonalData keeps contact details out of the repository:
// the parser never needs them, so they must not be committed.
func TestFixturesCarryNoPersonalData(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "*.txt"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures found: %v", err)
	}
	for _, f := range files {
		body := fixture(t, filepath.Base(f))
		for _, line := range strings.Split(body, "\n") {
			lower := strings.ToLower(strings.TrimSpace(line))
			for _, field := range []string{"person:", "e-mail:", "email:", "phone:", "fax-no:"} {
				if strings.HasPrefix(lower, field) && !strings.Contains(lower, "redacted") {
					t.Errorf("%s: unredacted %s line: %q", f, field, line)
				}
			}
			if strings.Contains(line, "@") && !strings.Contains(line, "example.invalid") {
				t.Errorf("%s: unredacted address: %q", f, line)
			}
		}
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
