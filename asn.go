package main

import (
	"fmt"
	"strconv"

	"asn-ipv6-ranges/internal/asnreg"
)

// parseASN validates an ASN string and returns its numeric value plus the
// canonical decimal form (leading zeros stripped) used as the cache key.
func parseASN(s string) (uint64, string, error) {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, "", fmt.Errorf("invalid ASN %q, expected a numeric AS number: 0-65535 (16-bit) or 0-4294967295 (32-bit)", s)
	}
	return v, strconv.FormatUint(v, 10), nil
}

// isPermittedASN reports whether an ASN may be looked up: it must be delegated
// to an RIR per the IANA registries. This covers both AS number sub-registries,
// so reserved, documentation, and private-use numbers are rejected in the
// 16-bit space too — AS0, AS23456 (AS_TRANS), 64496-64511, 64512-65534, and
// AS65535 included.
func isPermittedASN(v uint64) bool {
	return asnreg.IsAllocated(v)
}
