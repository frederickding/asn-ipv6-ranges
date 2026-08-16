package asnreg

import (
	"net/url"
	"strings"
	"testing"
)

func TestLookup(t *testing.T) {
	tests := []struct {
		name     string
		asn      uint64
		wantOK   bool
		wantName string
		wantHost string
	}{
		// One live-verified ASN per registry.
		{"ARIN 16-bit", 2906, true, "ARIN", "whois.arin.net"},
		{"RIPE 16-bit", 56554, true, "RIPE NCC", "whois.ripe.net"},
		{"APNIC 16-bit", 4608, true, "APNIC", "whois.apnic.net"},
		{"LACNIC 16-bit", 27947, true, "LACNIC", "whois.lacnic.net"},
		{"AFRINIC 16-bit", 37100, true, "AFRINIC", "whois.afrinic.net"},
		{"APNIC 32-bit", 131072, true, "APNIC", "whois.apnic.net"},
		{"RIPE 32-bit", 196608, true, "RIPE NCC", "whois.ripe.net"},

		// Reserved and unallocated, both spaces.
		{"AS0 reserved", 0, false, "", ""},
		{"AS_TRANS", 23456, false, "", ""},
		{"documentation", 64500, false, "", ""},
		{"private use start", 64512, false, "", ""},
		{"private use end", 65534, false, "", ""},
		{"AS65535 reserved", 65535, false, "", ""},
		{"unallocated 32-bit", 155962, false, "", ""},
		{"private use 32-bit", 4200000001, false, "", ""},
		{"final reserved", 4294967295, false, "", ""},
		{"beyond 32-bit", 4294967296, false, "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg, ok := Lookup(tt.asn)
			if ok != tt.wantOK {
				t.Fatalf("Lookup(%d) ok = %v, want %v (got %+v)", tt.asn, ok, tt.wantOK, reg)
			}
			if !tt.wantOK {
				if reg != (Registry{}) {
					t.Errorf("expected zero Registry for unallocated %d, got %+v", tt.asn, reg)
				}
				return
			}
			if reg.Name != tt.wantName || reg.WHOISHost != tt.wantHost {
				t.Errorf("Lookup(%d) = %+v, want {%s %s}", tt.asn, reg, tt.wantName, tt.wantHost)
			}
		})
	}
}

func TestIsAllocated(t *testing.T) {
	if !IsAllocated(2906) {
		t.Error("2906 should be allocated")
	}
	if IsAllocated(64512) {
		t.Error("64512 (private use) should not be allocated")
	}
}

// TestRangesShape checks the generated table's invariants. Lookup's binary
// search is only correct while these hold.
func TestRangesShape(t *testing.T) {
	if len(ranges) == 0 {
		t.Fatal("generated table is empty")
	}
	if len(registries) == 0 {
		t.Fatal("no registries generated")
	}

	for i, r := range ranges {
		if r.end < r.start {
			t.Errorf("entry %d: end %d before start %d", i, r.end, r.start)
		}
		if int(r.reg) >= len(registries) {
			t.Errorf("entry %d: registry index %d out of bounds (%d registries)", i, r.reg, len(registries))
		}
		if i == 0 {
			continue
		}
		prev := ranges[i-1]
		if r.start <= prev.end {
			t.Errorf("entry %d: %d-%d overlaps previous %d-%d", i, r.start, r.end, prev.start, prev.end)
		}
		// Touching ranges are merged only within a registry, so a neighbouring
		// pair may touch — but only if they differ in registry.
		if r.start == prev.end+1 && r.reg == prev.reg {
			t.Errorf("entry %d: %d-%d touches previous %d-%d with the same registry and should have merged",
				i, r.start, r.end, prev.start, prev.end)
		}
	}
}

func TestRegistriesWellFormed(t *testing.T) {
	seen := make(map[string]bool)
	for i, r := range registries {
		if r.Name == "" || r.WHOISHost == "" || r.RDAPBase == "" {
			t.Errorf("registry %d is incomplete: %+v", i, r)
		}
		// IANA publishes two URLs concatenated for some registries, e.g.
		// "https://rdap.arin.net/registryhttp://rdap.arin.net/registry". The
		// generator must split them; a surviving second scheme means it did not.
		u, err := url.Parse(r.RDAPBase)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			t.Errorf("registry %q has an unusable RDAPBase %q", r.Name, r.RDAPBase)
		}
		if strings.Contains(strings.TrimPrefix(r.RDAPBase, "https://"), "http") {
			t.Errorf("registry %q RDAPBase still contains a second URL: %q", r.Name, r.RDAPBase)
		}
		if seen[r.Name] {
			t.Errorf("duplicate registry name %q", r.Name)
		}
		seen[r.Name] = true
	}
	// The five RIRs; a missing one means a parsing regression in the generator.
	for _, want := range []string{"AFRINIC", "APNIC", "ARIN", "LACNIC", "RIPE NCC"} {
		if !seen[want] {
			t.Errorf("registry %q missing from generated table", want)
		}
	}
}

// TestLookupBoundaries walks every range edge, catching off-by-one errors in
// the binary search that spot checks would miss.
func TestLookupBoundaries(t *testing.T) {
	for i, r := range ranges {
		if _, ok := Lookup(uint64(r.start)); !ok {
			t.Errorf("entry %d: start %d should resolve", i, r.start)
		}
		if _, ok := Lookup(uint64(r.end)); !ok {
			t.Errorf("entry %d: end %d should resolve", i, r.end)
		}
		// The value below start belongs to the previous range or to no range,
		// but never to this one.
		if r.start > 0 {
			below := uint64(r.start) - 1
			reg, ok := Lookup(below)
			if ok && reg == registries[r.reg] && (i == 0 || ranges[i-1].reg != r.reg) {
				t.Errorf("entry %d: %d resolved to this entry's registry", i, below)
			}
		}
	}
}
