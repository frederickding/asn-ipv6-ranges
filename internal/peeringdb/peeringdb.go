// Package peeringdb resolves an ASN's organization name via the PeeringDB
// API (https://www.peeringdb.com/apidocs/), a free, self-reported registry of
// network operator data. An API key is optional — it only raises PeeringDB's
// documented per-minute rate limit, it is never required for a lookup to
// succeed — and is sent as a request header, so unlike WhoisFreaks it never
// appears in a URL or an *http.Client transport error.
package peeringdb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// KeyEnv names the environment variable holding an optional PeeringDB API
// key. Unlike whoisfreaks.KeyEnv, an unset key does not disable this source —
// it just runs at PeeringDB's lower, anonymous rate limit.
const KeyEnv = "PEERINGDB_API_KEY"

// Host identifies this source in service output.
const Host = "www.peeringdb.com"

const (
	timeout = 10 * time.Second
	// maxBody bounds every response read in this package. A single net
	// object's free-text "notes" field alone can run to several KB (Netflix's
	// does), and a batch response holds up to maxBatch of them, so this is
	// sized well above any single-ASN response's real footprint.
	maxBody = 8 << 20

	// maxBatch is PeeringDB's documented cap on values in an __in filter.
	maxBatch = 150
)

// Overridden in tests to point at a stub server.
var apiBase = "https://www.peeringdb.com/api"

// ErrNotFound reports that PeeringDB has no record for the requested ASN (an
// empty org name counts as not found too — there is nothing usable to
// return). Wrapped so callers can distinguish "nothing there" from a
// transport failure with errors.Is.
var ErrNotFound = errors.New("no organization found")

// client is shared across lookups, built once for the same reason as the
// other HTTP-based adapters in this repo: a per-call client falls back to
// http.DefaultTransport's two idle connections per host and pays a TLS
// handshake per query.
var client = &http.Client{
	Timeout: timeout,
	Transport: &http.Transport{
		MaxIdleConns:        8,
		MaxIdleConnsPerHost: 4,
		MaxConnsPerHost:     4,
		IdleConnTimeout:     90 * time.Second,
	},
}

type orgPayload struct {
	Data []struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	} `json:"data"`
	Meta struct {
		Error string `json:"error"`
	} `json:"meta"`
}

type netPayload struct {
	Data []struct {
		ASN   int `json:"asn"`
		OrgID int `json:"org_id"`
	} `json:"data"`
	Meta struct {
		Error string `json:"error"`
	} `json:"meta"`
}

// get issues a GET to path with query params, decoding a JSON body shaped
// like orgPayload/netPayload into dst. It applies apiKey, timeout, and
// maxBody uniformly, and turns a non-200 status into an error carrying the
// upstream's own message when it has one.
func get(ctx context.Context, path string, query url.Values, apiKey string, dst interface{ metaError() string }) error {
	endpoint, err := url.Parse(apiBase + path)
	if err != nil {
		return err
	}
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return err
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Api-Key "+apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return err
	}

	// A non-JSON body is not fatal by itself; the status check below reports it.
	jsonErr := json.Unmarshal(body, dst)

	if resp.StatusCode != http.StatusOK {
		if msg := dst.metaError(); msg != "" {
			return fmt.Errorf("api returned %d: %s", resp.StatusCode, msg)
		}
		return fmt.Errorf("api returned %d", resp.StatusCode)
	}
	return jsonErr
}

func (p *orgPayload) metaError() string { return p.Meta.Error }
func (p *netPayload) metaError() string { return p.Meta.Error }

// LookupOrgName resolves the organization name for a single ASN (decimal, no
// "AS" prefix). apiKey may be empty, in which case the request is anonymous.
func LookupOrgName(ctx context.Context, asn, apiKey string) (string, error) {
	var payload orgPayload
	if err := get(ctx, "/org", url.Values{"asn": {asn}}, apiKey, &payload); err != nil {
		return "", err
	}
	if len(payload.Data) == 0 {
		return "", fmt.Errorf("%w for AS%s", ErrNotFound, asn)
	}
	name := strings.TrimSpace(payload.Data[0].Name)
	if name == "" {
		return "", fmt.Errorf("%w for AS%s: empty name", ErrNotFound, asn)
	}
	return name, nil
}

// LookupOrgNames resolves organization names for up to maxBatch ASNs
// (decimal, no "AS" prefix) in as few requests as PeeringDB's data model
// allows.
//
// PeeringDB's /api/org has no real "asn" field — asn=<n> is a special
// single-value convenience filter, and asn__in silently ignores the list and
// returns the entire org table instead of filtering (confirmed against the
// live API) — so this is a two-step join instead of one request: /api/net
// (which does have a real, properly __in-filterable asn field) maps each ASN
// to an org_id, then /api/org?id__in=<org_ids> (id is a real field) resolves
// the distinct org_ids to names.
//
// The returned map is keyed by the requested ASN string and holds only the
// ASNs PeeringDB actually has a name for — an ASN with no net object, or
// whose net resolved but had no name, is simply absent, not an error. A
// transport-level failure of either underlying request fails the whole
// batch and returns a nil map.
func LookupOrgNames(ctx context.Context, asns []string, apiKey string) (map[string]string, error) {
	if len(asns) == 0 {
		return map[string]string{}, nil
	}
	if len(asns) > maxBatch {
		asns = asns[:maxBatch]
	}
	if len(asns) == 1 {
		name, err := LookupOrgName(ctx, asns[0], apiKey)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return map[string]string{}, nil
			}
			return nil, err
		}
		return map[string]string{asns[0]: name}, nil
	}

	var netResp netPayload
	if err := get(ctx, "/net", url.Values{"asn__in": {strings.Join(asns, ",")}}, apiKey, &netResp); err != nil {
		return nil, err
	}

	asnToOrgID := make(map[string]int, len(netResp.Data))
	orgIDSet := make(map[int]struct{}, len(netResp.Data))
	for _, n := range netResp.Data {
		asn := strconv.Itoa(n.ASN)
		asnToOrgID[asn] = n.OrgID
		orgIDSet[n.OrgID] = struct{}{}
	}
	if len(orgIDSet) == 0 {
		return map[string]string{}, nil
	}

	orgIDs := make([]string, 0, len(orgIDSet))
	for id := range orgIDSet {
		orgIDs = append(orgIDs, strconv.Itoa(id))
	}

	var orgResp orgPayload
	if err := get(ctx, "/org", url.Values{"id__in": {strings.Join(orgIDs, ",")}}, apiKey, &orgResp); err != nil {
		return nil, err
	}

	orgIDToName := make(map[int]string, len(orgResp.Data))
	for _, o := range orgResp.Data {
		if name := strings.TrimSpace(o.Name); name != "" {
			orgIDToName[o.ID] = name
		}
	}

	result := make(map[string]string, len(asnToOrgID))
	for asn, orgID := range asnToOrgID {
		if name, ok := orgIDToName[orgID]; ok {
			result[asn] = name
		}
	}
	return result, nil
}
