// Package asnreg maps an AS number to the regional internet registry that
// administers it, using a table generated at build time from the two IANA AS
// number sub-registries. Nothing here touches the network.
package asnreg

import "sort"

// Registry identifies an RIR and the two ways to query it.
type Registry struct {
	Name      string // e.g. "ARIN", "RIPE NCC"
	WHOISHost string // e.g. "whois.arin.net"
	RDAPBase  string // e.g. "https://rdap.arin.net/registry"
}

// asnRange is a half-open-free, fully inclusive range [start, end] delegated to
// registries[reg].
type asnRange struct {
	start, end uint32
	reg        uint8
}

// Lookup returns the registry responsible for an AS number. The second result
// is false when the number falls outside every delegated range — reserved,
// unallocated, documentation, and private-use numbers all report false, in both
// the 16-bit and 32-bit spaces.
func Lookup(asn uint64) (Registry, bool) {
	if asn > uint64(^uint32(0)) {
		return Registry{}, false
	}
	v := uint32(asn)

	// ranges is sorted and non-overlapping: find the last entry starting at or
	// before v, then check whether v falls inside it.
	i := sort.Search(len(ranges), func(i int) bool { return ranges[i].start > v })
	if i == 0 {
		return Registry{}, false
	}
	r := ranges[i-1]
	if v > r.end {
		return Registry{}, false
	}
	return registries[r.reg], true
}

// IsAllocated reports whether an AS number is delegated to an RIR, and so may
// be looked up.
func IsAllocated(asn uint64) bool {
	_, ok := Lookup(asn)
	return ok
}
