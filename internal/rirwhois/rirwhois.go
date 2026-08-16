// Package rirwhois resolves an ASN's organization name from the authoritative
// regional internet registry, over the raw WHOIS protocol (TCP port 43).
//
// The five RIRs do not agree on a format. ARIN serves flat "Key: value" lines;
// the others serve RPSL objects separated by blank lines, and disagree on which
// attribute carries the organization. Both shapes are handled here so callers
// get one string back.
package rirwhois

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"asn-ipv6-ranges/internal/asnreg"
)

const (
	timeout = 15 * time.Second
	// maxBody bounds the read: this is third-party input.
	maxBody = 1 << 20
)

// dialAddr builds the dial target; overridden in tests to reach a local listener.
var dialAddr = func(host string) string { return host + ":43" }

// LookupOrgName returns the organization name an RIR publishes for an ASN
// (decimal, no "AS" prefix).
//
// RIPE-style registries answer with an org: handle rather than a name, so one
// follow-up query may be issued to resolve it — at most two queries per lookup.
func LookupOrgName(reg asnreg.Registry, asn string) (string, error) {
	if reg.WHOISHost == "" {
		return "", fmt.Errorf("no whois host for registry %q", reg.Name)
	}

	body, err := query(reg.WHOISHost, autNumQuery(reg, asn))
	if err != nil {
		return "", err
	}

	// ARIN is not RPSL; it answers with flat key/value lines.
	if isARIN(reg) {
		if name := firstValue(body, "OrgName"); name != "" {
			return name, nil
		}
		if name := firstValue(body, "ASName"); name != "" {
			return name, nil
		}
		return "", fmt.Errorf("no organization name in %s response", reg.Name)
	}

	obj := autNumObject(body, asn)
	if obj == nil {
		return "", fmt.Errorf("no aut-num object for AS%s in %s response", asn, reg.Name)
	}

	// A direct name, when the registry inlines one.
	if name := obj.value("org-name"); name != "" {
		return name, nil
	}
	// LACNIC's equivalent.
	if name := obj.value("owner"); name != "" {
		return name, nil
	}

	// Otherwise resolve the org: handle, which is where RIPE keeps the name.
	if handle := obj.value("org"); handle != "" {
		if name, err := resolveOrgHandle(reg, handle); err == nil && name != "" {
			return name, nil
		}
		// Fall through to the descriptive attributes below.
	}

	// descr is free text; its first line is conventionally the operator name.
	if name := obj.value("descr"); name != "" {
		return name, nil
	}
	if name := obj.value("as-name"); name != "" {
		return name, nil
	}
	return "", fmt.Errorf("no organization name in %s response", reg.Name)
}

func resolveOrgHandle(reg asnreg.Registry, handle string) (string, error) {
	body, err := query(reg.WHOISHost, flagPrefix(reg)+handle)
	if err != nil {
		return "", err
	}
	for _, obj := range objects(body) {
		if obj.value("organisation") != "" || obj.value("organization") != "" {
			if name := obj.value("org-name"); name != "" {
				return name, nil
			}
		}
	}
	return "", fmt.Errorf("handle %s did not resolve to an org-name", handle)
}

func isARIN(reg asnreg.Registry) bool {
	return strings.EqualFold(reg.Name, "ARIN")
}

// flagPrefix asks RPSL registries to omit referenced contact objects. Besides
// keeping personal data out of the response, this is what RIPE rate-limits on.
// ARIN and LACNIC do not accept the flag.
func flagPrefix(reg asnreg.Registry) string {
	if isARIN(reg) || strings.EqualFold(reg.Name, "LACNIC") {
		return ""
	}
	return "-r "
}

func autNumQuery(reg asnreg.Registry, asn string) string {
	return flagPrefix(reg) + "AS" + asn
}

func query(host, q string) (string, error) {
	conn, err := net.DialTimeout("tcp", dialAddr(host), timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}
	if _, err := fmt.Fprintf(conn, "%s\r\n", q); err != nil {
		return "", err
	}
	body, err := io.ReadAll(io.LimitReader(conn, maxBody))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// object is one RPSL object: attribute name to values, in order.
type object struct {
	attrs []attr
}

type attr struct{ name, value string }

// value returns the first value for an attribute, case-insensitively. "First"
// matters: descr repeats, and only the opening line names the operator.
func (o *object) value(name string) string {
	for _, a := range o.attrs {
		if strings.EqualFold(a.name, name) {
			return a.value
		}
	}
	return ""
}

// objects splits an RPSL response on blank lines, dropping server comments.
func objects(body string) []*object {
	var out []*object
	cur := &object{}
	flush := func() {
		if len(cur.attrs) > 0 {
			out = append(out, cur)
			cur = &object{}
		}
	}

	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			flush()
			continue
		}
		if strings.HasPrefix(trimmed, "%") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Continuation lines start with whitespace and extend the previous value.
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		cur.attrs = append(cur.attrs, attr{
			name:  strings.TrimSpace(name),
			value: strings.TrimSpace(value),
		})
	}
	flush()
	return out
}

// autNumObject picks the object describing this ASN. Responses also contain the
// parent as-block, whose descr ("RIPE NCC ASN block") would otherwise be
// mistaken for the operator name.
func autNumObject(body, asn string) *object {
	want := "AS" + asn
	for _, obj := range objects(body) {
		if strings.EqualFold(obj.value("aut-num"), want) {
			return obj
		}
	}
	return nil
}

// firstValue reads a flat "Key: value" response (ARIN).
func firstValue(body, key string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimRight(line, "\r")
		name, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), key) {
			if v := strings.TrimSpace(value); v != "" {
				return v
			}
		}
	}
	return ""
}
