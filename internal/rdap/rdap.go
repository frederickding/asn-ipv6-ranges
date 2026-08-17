// Package rdap resolves an ASN's organization name from a regional internet
// registry over RDAP (RFC 7483), the structured JSON successor to port-43
// whois.
//
// RDAP is uniform in transport but not in where registries put the operator
// name, so the extraction rules here are deliberately explicit — see
// LookupOrgName.
package rdap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
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

// client is shared across lookups rather than built per call.
//
// A fresh http.Client per request falls back to http.DefaultTransport, whose
// MaxIdleConnsPerHost is 2 — so under concurrency most queries pay a full TLS
// handshake to a registry that is already rate-limiting us on connection count.
// Reusing one transport keeps connections warm, and MaxConnsPerHost is a
// transport-level backstop underneath the per-host budget the caller enforces.
var client = &http.Client{
	Timeout: timeout,
	Transport: &http.Transport{
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 4,
		MaxConnsPerHost:     4,
		IdleConnTimeout:     90 * time.Second,
	},
}

// RateLimitedError reports that a registry refused the query because we are
// querying too fast. It is distinguished from other failures because the
// response is actionable: the caller should stop querying this registry, not
// retry or fall back to another source.
type RateLimitedError struct {
	Status int
	// RetryAfter is the registry's own Retry-After, or zero when it sent none.
	RetryAfter time.Duration
}

func (e *RateLimitedError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("rdap returned %d, retry after %s", e.Status, e.RetryAfter)
	}
	return fmt.Sprintf("rdap returned %d (rate limited)", e.Status)
}

// parseRetryAfter reads RFC 9110's two Retry-After forms, delay-seconds and
// HTTP-date. An absent, unparseable, or past value reports zero, leaving the
// caller to fall back to its own backoff.
func parseRetryAfter(h string, now time.Time) time.Duration {
	h = strings.TrimSpace(h)
	if h == "" {
		return 0
	}
	if secs, err := strconv.Atoi(h); err == nil {
		if secs <= 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(h); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

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
func LookupOrgName(ctx context.Context, reg asnreg.Registry, asn string) (string, error) {
	base := reg.RDAPBase
	if baseOverride != "" {
		base = baseOverride
	}
	if base == "" {
		return "", fmt.Errorf("no RDAP base URL for registry %q", reg.Name)
	}

	url := strings.TrimSuffix(base, "/") + "/autnum/" + asn
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/rdap+json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Status is checked before the body is read. Every RIR rate-limits RDAP and
	// none of them publish the threshold, so a 429 is the one signal we get
	// that we are over it — reading a megabyte of error page first would be
	// paying for a response that is already known to be useless.
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
		return "", &RateLimitedError{
			Status:     resp.StatusCode,
			RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()),
		}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return "", err
	}

	// LACNIC — the strictest of the five and the only one to publish its
	// limits — signals refusal with 403 and a message in the body rather than
	// the 429 the other registries use. Treating it as an ordinary denial would
	// keep us querying at exactly the rate it just objected to.
	if resp.StatusCode == http.StatusForbidden && strings.Contains(strings.ToLower(string(body)), "rate limit") {
		return "", &RateLimitedError{
			Status:     resp.StatusCode,
			RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()),
		}
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
