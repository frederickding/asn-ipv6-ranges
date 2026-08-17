// Package cymrudns resolves an ASN's organization name via Team Cymru's IP-to-
// ASN mapping DNS zone (https://asn.cymru.com/), querying AS<n>.asn.cymru.com
// for a TXT record over a configurable DNS resolver — one UDP round trip, no
// HTTP, no key, and (unlike Cymru's own rate-limited whois-over-port-43
// service) built specifically to take high query volume.
package cymrudns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// ResolverEnv names the environment variable holding the resolver address
// ("host:port") to query. Unset or empty falls back to DefaultResolver —
// unlike an API key, this is never required for the lookup to run.
const ResolverEnv = "CYMRU_DNS_RESOLVER"

// DefaultResolver is used whenever ResolverEnv is unset or empty: Cloudflare's
// public resolver, fast and reachable with no configuration required.
const DefaultResolver = "1.1.1.1:53"

// Host identifies this source in service output. It names the DNS zone being
// queried, not the resolver relaying the query — the resolver is transport.
const Host = "asn.cymru.com"

// timeout bounds the whole lookup (dial plus response wait): DNS is a single
// round trip, so this can be far tighter than the HTTP adapters' timeouts.
const timeout = 5 * time.Second

// LookupOrgName resolves the organization name for an ASN (decimal, no "AS"
// prefix) via Team Cymru's DNS zone. resolverAddr is a "host:port" resolver
// to query; an empty string uses DefaultResolver.
//
// The TXT record is pipe-delimited: "ASN | CC | Registry | Allocated | AS
// Name" (see https://asn.cymru.com/). The AS Name field — Cymru's own
// mnemonic-plus-name-plus-country format, e.g. "DEEPLY2 - Deeply II LLC,
// US" — is returned as-is; every other Cymru-based tool shows the same raw
// field, so no attempt is made to reformat it.
func LookupOrgName(ctx context.Context, asn, resolverAddr string) (string, error) {
	if resolverAddr == "" {
		resolverAddr = DefaultResolver
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, resolverAddr)
		},
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	name := fmt.Sprintf("AS%s.asn.cymru.com", asn)
	txts, err := resolver.LookupTXT(ctx, name)
	if err != nil {
		return "", err
	}
	if len(txts) == 0 {
		return "", fmt.Errorf("no TXT record for AS%s", asn)
	}

	fields := strings.Split(txts[0], "|")
	if len(fields) < 5 {
		return "", fmt.Errorf("unexpected record format: %q", txts[0])
	}

	orgName := strings.TrimSpace(fields[4])
	if orgName == "" {
		return "", errors.New("no organization name in response")
	}
	return orgName, nil
}
