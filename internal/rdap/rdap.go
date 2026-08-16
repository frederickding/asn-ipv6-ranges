// Package rdap resolves an ASN's organization name from a regional internet
// registry over RDAP (RFC 7483), the structured JSON successor to port-43
// whois.
//
// RDAP is uniform in transport but not in where registries put the operator
// name, so the extraction rules here are deliberately explicit — see
// LookupOrgName.
package rdap

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"asn-ipv6-ranges/internal/asnreg"
)

const (
	timeout = 15 * time.Second
	// maxBody bounds the read: this is third-party input.
	maxBody = 1 << 20
)

// baseOverride, when set, replaces the registry's RDAP base in tests.
var baseOverride string

// autnumResponse is the subset of RFC 7483 this package needs. Everything else
// in the response is ignored rather than modelled.
type autnumResponse struct {
	Name     string   `json:"name"`
	Entities []entity `json:"entities"`
	Remarks  []remark `json:"remarks"`
}

type entity struct {
	Handle string   `json:"handle"`
	Roles  []string `json:"roles"`
	// vCard is jCard (RFC 7095): ["vcard", [[name, params, type, value], ...]].
	// The inner entries are heterogeneous arrays, so they stay as raw JSON
	// until scanned.
	VCardArray []json.RawMessage `json:"vcardArray"`
}

type remark struct {
	Title       string   `json:"title"`
	Description []string `json:"description"`
}

// LookupOrgName returns the organization name a registry publishes for an ASN
// (decimal, no "AS" prefix).
//
// Registries disagree on where the name lives, so three rules are tried in
// order:
//
//  1. the entity with role "registrant" whose vCard kind is "org" — correct for
//     ARIN, RIPE, LACNIC, AFRINIC, and most APNIC objects;
//  2. the remark titled "description" — APNIC omits the registrant entity on
//     some objects (AS9605) and only records the operator there;
//  3. the top-level name, as a last resort.
//
// Administrative and technical entities are never consulted: they carry named
// individuals, and on APNIC they name the delegating registry rather than the
// operator.
func LookupOrgName(reg asnreg.Registry, asn string) (string, error) {
	base := reg.RDAPBase
	if baseOverride != "" {
		base = baseOverride
	}
	if base == "" {
		return "", fmt.Errorf("no RDAP base URL for registry %q", reg.Name)
	}

	url := strings.TrimSuffix(base, "/") + "/autnum/" + asn
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/rdap+json")

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("rdap returned %d", resp.StatusCode)
	}

	var payload autnumResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", err
	}
	name := orgName(&payload)
	if name == "" {
		return "", fmt.Errorf("no organization name in %s RDAP response", reg.Name)
	}
	return name, nil
}

// orgName applies the three selection rules. Exported behavior is tested
// through this function against real captured responses.
func orgName(r *autnumResponse) string {
	// Rule 1: the registrant that is an organization.
	//
	// Both halves matter. RIPE returns several registrant entities — maintainer
	// handles such as HOS-GUN and RIPE-NCC-END-MNT alongside the real
	// ORG-... object — so role alone picks a maintainer, and "not an
	// individual" picks a contact-role group.
	for _, e := range r.Entities {
		if !hasRole(e, "registrant") {
			continue
		}
		props := vcard(e)
		if props["kind"] == "org" && props["fn"] != "" {
			return props["fn"]
		}
	}

	// Rule 2: the remark titled "description".
	//
	// Matched by title rather than position: APNIC objects can carry a second
	// remark titled "remarks" (an unrelated RADB pointer), and RIPE emits a
	// remark with no title and no content.
	for _, rem := range r.Remarks {
		if !strings.EqualFold(rem.Title, "description") {
			continue
		}
		// First non-empty line only. The array continues into postal address,
		// so joining it would report a street address as the organization.
		for _, line := range rem.Description {
			if line = strings.TrimSpace(line); line != "" {
				return line
			}
		}
	}

	return strings.TrimSpace(r.Name)
}

func hasRole(e entity, role string) bool {
	for _, r := range e.Roles {
		if strings.EqualFold(r, role) {
			return true
		}
	}
	return false
}

// vcard flattens a jCard into property name to first value. jCard entries are
// positional arrays — [name, params, type, value] — and the value may be a
// string or an array (structured "adr"), so non-string values are skipped.
func vcard(e entity) map[string]string {
	props := make(map[string]string)
	if len(e.VCardArray) < 2 {
		return props
	}

	var entries [][]json.RawMessage
	if err := json.Unmarshal(e.VCardArray[1], &entries); err != nil {
		return props
	}
	for _, entry := range entries {
		if len(entry) < 4 {
			continue
		}
		var name, value string
		if json.Unmarshal(entry[0], &name) != nil {
			continue
		}
		if json.Unmarshal(entry[3], &value) != nil {
			continue // structured value, e.g. adr
		}
		if _, seen := props[name]; !seen {
			props[name] = strings.TrimSpace(value)
		}
	}
	return props
}
