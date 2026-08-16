package main

import (
	"net/netip"
	"regexp"
	"slices"
)

var route6Pattern = regexp.MustCompile(`(?im)^route6:\s*(\S+)`)

// extractIPv6Prefixes returns every distinct route6 prefix in an RPSL response,
// in numeric order. More-specifics are retained here; see aggregatePrefixes.
func extractIPv6Prefixes(whoisOutput string) []netip.Prefix {
	seen := make(map[string]bool)
	var parsed []netip.Prefix
	for _, m := range route6Pattern.FindAllStringSubmatch(whoisOutput, -1) {
		p, err := netip.ParsePrefix(m[1])
		if err != nil || !p.Addr().Is6() {
			continue
		}
		p = p.Masked()
		if key := p.String(); !seen[key] {
			seen[key] = true
			parsed = append(parsed, p)
		}
	}

	// Numeric order, so a covering prefix always precedes its more-specifics.
	slices.SortFunc(parsed, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	return parsed
}

// aggregatePrefixes drops prefixes already covered by a broader one. Given the
// sort order from extractIPv6Prefixes, the most recently kept prefix is the
// only possible cover: anything sorting between a cover and the prefixes it
// covers must itself start inside that cover, and would have been dropped here
// already.
//
// The result is a fresh slice; prefixes may be a shared cache entry, so it must
// never be mutated in place.
func aggregatePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	kept := make([]netip.Prefix, 0, len(prefixes))
	for _, p := range prefixes {
		if n := len(kept); n > 0 && kept[n-1].Contains(p.Addr()) {
			continue
		}
		kept = append(kept, p)
	}
	return kept
}
