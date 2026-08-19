//go:build ignore

package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The two IANA AS number sub-registries. Both are fetched exactly once, at
// build time only: the running service never contacts IANA.
var registryURLs = []string{
	"https://www.iana.org/assignments/as-numbers/as-numbers-1.csv", // 16-bit
	"https://www.iana.org/assignments/as-numbers/as-numbers-2.csv", // 32-bit
}

const (
	outputFile = "internal/asnreg/ranges_gen.go"
	// Only rows delegated to an RIR are kept. Everything else is Reserved,
	// Unallocated, Reserved for Private Use, AS_TRANS, or the 32-bit
	// registry's pointer at the 16-bit sub-registry.
	assignedPrefix = "Assigned by "
)

type registry struct{ name, whois, rdap string }

// rdapBase extracts a usable RDAP base URL from the registry's RDAP column.
//
// IANA publishes two URLs concatenated with no separator for some registries,
// e.g. ARIN's "https://rdap.arin.net/registryhttp://rdap.arin.net/registry".
// Split on the embedded scheme and keep the https entry.
func rdapBase(field string) (string, error) {
	field = strings.TrimSpace(field)
	if field == "" {
		return "", fmt.Errorf("empty RDAP column")
	}

	// Cut at any scheme that starts after position 0, then keep the https one.
	var candidates []string
	rest := field
	for {
		next := -1
		for _, scheme := range []string{"https://", "http://"} {
			if i := strings.Index(rest[1:], scheme); i >= 0 && (next < 0 || i+1 < next) {
				next = i + 1
			}
		}
		if next < 0 {
			candidates = append(candidates, rest)
			break
		}
		candidates = append(candidates, rest[:next])
		rest = rest[next:]
	}

	for _, c := range candidates {
		u, err := url.Parse(c)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			continue
		}
		return c, nil
	}
	return "", fmt.Errorf("no absolute https URL in %q", field)
}

type asnRange struct {
	start, end uint32
	reg        registry
}

func main() {
	var ranges []asnRange
	for _, u := range registryURLs {
		rows, err := fetchRegistry(u)
		if err != nil {
			log.Fatalf("fetch %s: %v", u, err)
		}
		parsed, err := parseAssignedRanges(rows)
		if err != nil {
			log.Fatalf("parse %s: %v", u, err)
		}
		if len(parsed) == 0 {
			log.Fatalf("no assigned ranges in %s; refusing to write a partial table", u)
		}
		log.Printf("fetched %s: %d assigned ranges", u, len(parsed))
		ranges = append(ranges, parsed...)
	}

	merged := mergeRanges(ranges)
	if err := validate(merged); err != nil {
		log.Fatalf("generated table is invalid: %v", err)
	}

	regs, index := internRegistries(merged)
	if err := writeTable(merged, regs, index); err != nil {
		log.Fatalf("write %s: %v", outputFile, err)
	}
	log.Printf("wrote %s: %d ranges across %d registries (from %d rows)",
		outputFile, len(merged), len(regs), len(ranges))
}

func fetchRegistry(url string) ([][]string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}
	return csv.NewReader(resp.Body).ReadAll()
}

// parseAssignedRanges keeps rows delegated to an RIR, taking the registry name
// from the Description column and the authoritative server from the WHOIS
// column, so no RIR-to-host mapping is hardcoded here.
func parseAssignedRanges(rows [][]string) ([]asnRange, error) {
	var ranges []asnRange
	for i, row := range rows {
		if i == 0 || len(row) < 4 {
			continue
		}
		if !strings.HasPrefix(row[1], assignedPrefix) {
			continue
		}
		name := strings.TrimSpace(strings.TrimPrefix(row[1], assignedPrefix))
		whois := strings.TrimSpace(row[2])
		if name == "" || whois == "" {
			return nil, fmt.Errorf("row %d: assigned range %q has no registry name or whois host", i+1, row[0])
		}
		rdap, err := rdapBase(row[3])
		if err != nil {
			return nil, fmt.Errorf("row %d: assigned range %q: %w", i+1, row[0], err)
		}
		r, err := parseRange(row[0])
		if err != nil {
			return nil, fmt.Errorf("row %d: %w", i+1, err)
		}
		r.reg = registry{name: name, whois: whois, rdap: rdap}
		ranges = append(ranges, r)
	}
	return ranges, nil
}

// parseRange handles both "131072-132095" and bare "4294967295" forms.
func parseRange(field string) (asnRange, error) {
	field = strings.TrimSpace(field)
	startStr, endStr, isRange := strings.Cut(field, "-")
	if !isRange {
		endStr = startStr
	}
	start, err := strconv.ParseUint(strings.TrimSpace(startStr), 10, 32)
	if err != nil {
		return asnRange{}, fmt.Errorf("bad start in %q: %w", field, err)
	}
	end, err := strconv.ParseUint(strings.TrimSpace(endStr), 10, 32)
	if err != nil {
		return asnRange{}, fmt.Errorf("bad end in %q: %w", field, err)
	}
	if end < start {
		return asnRange{}, fmt.Errorf("end before start in %q", field)
	}
	return asnRange{start: uint32(start), end: uint32(end)}, nil
}

// mergeRanges sorts and coalesces touching ranges, but only when they belong to
// the same registry — merging across registries would erase the RIR identity
// this table exists to record.
func mergeRanges(ranges []asnRange) []asnRange {
	if len(ranges) == 0 {
		return nil
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })

	merged := []asnRange{ranges[0]}
	for _, r := range ranges[1:] {
		last := &merged[len(merged)-1]
		sameRegistry := r.reg == last.reg
		// uint32 care: compare against end+1 without overflowing at 2^32-1.
		touching := r.start <= last.end || (last.end < ^uint32(0) && r.start == last.end+1)
		if sameRegistry && touching {
			if r.end > last.end {
				last.end = r.end
			}
			continue
		}
		merged = append(merged, r)
	}
	return merged
}

func validate(ranges []asnRange) error {
	if len(ranges) == 0 {
		return fmt.Errorf("no ranges")
	}
	for i, r := range ranges {
		if r.end < r.start {
			return fmt.Errorf("entry %d: end %d before start %d", i, r.end, r.start)
		}
		if i > 0 && r.start <= ranges[i-1].end {
			return fmt.Errorf("entry %d (%d-%d) overlaps previous (%d-%d)",
				i, r.start, r.end, ranges[i-1].start, ranges[i-1].end)
		}
	}
	return nil
}

// internRegistries returns the distinct registries sorted by name, plus a
// lookup from registry to its index, so the table stores a small integer
// instead of repeating host strings on every row.
func internRegistries(ranges []asnRange) ([]registry, map[registry]int) {
	seen := make(map[registry]bool)
	for _, r := range ranges {
		seen[r.reg] = true
	}
	regs := make([]registry, 0, len(seen))
	for r := range seen {
		regs = append(regs, r)
	}
	sort.Slice(regs, func(i, j int) bool { return regs[i].name < regs[j].name })

	index := make(map[registry]int, len(regs))
	for i, r := range regs {
		index[r] = i
	}
	return regs, index
}

func writeTable(ranges []asnRange, regs []registry, index map[registry]int) error {
	var b strings.Builder
	b.WriteString("// Code generated by gen_asn_ranges.go; DO NOT EDIT.\n")
	b.WriteString(fmt.Sprintf("// Last updated: %s\n\n", time.Now().Format(time.DateTime)))
	b.WriteString("//\n")
	b.WriteString("// Source: the IANA AS number registries as-numbers-1.csv (16-bit) and\n")
	b.WriteString("// as-numbers-2.csv (32-bit), keeping only ranges delegated to an RIR.\n")
	b.WriteString("// Touching ranges are merged when they share a registry, so entries do\n")
	b.WriteString("// not map 1:1 to registry rows.\n\n")
	b.WriteString("package asnreg\n\n")

	b.WriteString("var registries = []Registry{\n")
	for _, r := range regs {
		fmt.Fprintf(&b, "\t{Name: %q, WHOISHost: %q, RDAPBase: %q},\n", r.name, r.whois, r.rdap)
	}
	b.WriteString("}\n\n")

	b.WriteString("// ranges is sorted by start and non-overlapping, which Lookup relies on\n")
	b.WriteString("// for its binary search.\n")
	b.WriteString("var ranges = []asnRange{\n")
	for _, r := range ranges {
		fmt.Fprintf(&b, "\t{%d, %d, %d}, // %s\n", r.start, r.end, index[r.reg], r.reg.name)
	}
	b.WriteString("}\n")

	if err := os.MkdirAll("internal/asnreg", 0o755); err != nil {
		return err
	}
	return os.WriteFile(outputFile, []byte(b.String()), 0o644)
}
