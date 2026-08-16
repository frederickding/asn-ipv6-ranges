package main

import (
	"fmt"
	"strconv"
)

const max16BitASN = 65535

// parseASN validates an ASN string and returns its numeric value plus the
// canonical decimal form (leading zeros stripped) used as the cache key.
func parseASN(s string) (uint64, string, error) {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, "", fmt.Errorf("invalid ASN %q, expected a numeric AS number: 0-65535 (16-bit) or 0-4294967295 (32-bit)", s)
	}
	return v, strconv.FormatUint(v, 10), nil
}

// isPermittedASN reports whether an ASN may be looked up. The whole 16-bit
// space is allowed; above that, the value must fall inside a range IANA has
// delegated to an RIR (see asn_ranges_gen.go), which excludes unallocated,
// reserved, documentation, and private-use ranges.
func isPermittedASN(v uint64) bool {
	if v <= max16BitASN {
		return true
	}
	for _, r := range allocatedASNRanges {
		if v >= uint64(r.start) && v <= uint64(r.end) {
			return true
		}
	}
	return false
}
