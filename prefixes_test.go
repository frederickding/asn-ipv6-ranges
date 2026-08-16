package main

import (
	"fmt"
	"math/rand"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

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
