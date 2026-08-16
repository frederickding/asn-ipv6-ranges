# asn-ipv6-ranges

A minimal HTTP service that returns the IPv6 prefixes announced by an ASN as
`text/plain`, one prefix per line, with comments prefixed by `#`.

> Generated with [Claude Code](https://claude.com/claude-code). See
> [Provenance](#provenance).

Prefix data comes from the [RADB](https://www.radb.net/) Internet Routing
Registry, queried over the raw WHOIS protocol (TCP port 43) using native Go
networking — the service never shells out to a `whois` binary.

## Endpoint

```
GET /as/{asn}
```

`{asn}` is the AS number in decimal, with no `AS` prefix — `2906`, not `AS2906`.
Leading zeros are accepted and normalized (`/as/007` is treated as `/as/7`).

Only `GET` and `HEAD` are accepted; anything else returns `405` with an
`Allow: GET, HEAD` header. All parameters below are URL query parameters and are
read from the query string only — values in a request body are never consulted.

```bash
curl http://localhost:8080/as/2906
```

```
# IPv6 prefixes for AS2906 (source: whois.radb.net)
# aggregate: on (more-specifics covered by a broader prefix removed)
# count: 5
2607:fb10::/32
2620:0:ef0::/48
2620:10c:7000::/44
2a00:86c0::/32
2a03:5640::/32
# queried: 2026-08-16T18:39:24Z
```

The `# queried:` footer is the timestamp of the actual upstream WHOIS query. It
stays fixed while a cached answer is served and only advances when a fresh
lookup runs — so a saved file records when its data was really fetched.

## Parameters

All parameters accept `1`/`0` and `true`/`false` (case-insensitive; `t`/`f`
also work). An empty value (`?agg=`) falls back to the default. Any other value
returns `400`.

| Parameter | Default | Effect |
| --- | --- | --- |
| `agg` | `1` (on) | Remove prefixes already covered by a broader prefix in the list. |
| `org` | `0` (off) | Look up the ASN's organization name and report it in a comment. |
| `rir` | `0` (off) | Force the org lookup to use the authoritative RIR, bypassing the WhoisFreaks API. |

### `agg` — prefix aggregation

Registries commonly list both a covering prefix and many more-specifics beneath
it. With `agg=1` (the default), a prefix is dropped when a broader prefix in the
same response already covers it, so `2607:fb10:2033::/48` is omitted when
`2607:fb10::/32` is present.

Use `agg=0` to get every registered prefix. This matters if you need the exact
registered route objects — for example when building prefix filters that must
match specific more-specifics.

```bash
curl 'http://localhost:8080/as/2906?agg=0'
```

For AS2906 this is the difference between 5 lines and 42.

Prefixes are always deduplicated (the same prefix is often registered in several
mirrored sources), normalized to their masked form, and sorted numerically so a
covering prefix precedes anything beneath it.

### `org` — organization name lookup

`org=1` performs an additional lookup for the ASN's organization name and adds
an `# org:` comment naming the source that answered:

```bash
curl 'http://localhost:8080/as/2906?org=1'
```

```
# IPv6 prefixes for AS2906 (source: whois.radb.net)
# org: Netflix Streaming Services Inc. (source: whois.arin.net)
...
```

There are two sources, and **no configuration is required** — the authoritative
RIR is always available:

| Source | Requires | Notes |
| --- | --- | --- |
| The ASN's RIR whois server | nothing | Chosen from the IANA-derived table, e.g. `whois.arin.net` for AS2906 |
| [WhoisFreaks ASN WHOIS API](https://whoisfreaks.com/documentation/asn-whois-api) | `WHOISFREAKS_API_KEY` | Normalized single-field answer |

By default the API is tried first **when a key is set**, falling back to the RIR
if it fails; with no key, the RIR is used directly. Use [`rir`](#rir--force-the-authoritative-rir)
to force the registry path. The `(source: …)` annotation always reports which
one actually answered.

The lookup is never performed unless `org` is explicitly enabled, so the service
contacts neither source by default.

A failed lookup does not fail the request — the prefix list is the primary
output, so the response is still `200` with the reason in a comment:

```
# org: lookup failed: whois.arin.net: dial tcp: i/o timeout
```

The API key is stripped from any error text before it reaches the response, and
names from either source are flattened to a single line so they cannot escape
their comment and forge a prefix entry.

### `rir` — force the authoritative RIR

`rir=1` skips the WhoisFreaks API entirely, even when a key is configured, and
resolves the name from the registry that administers the ASN:

```bash
curl 'http://localhost:8080/as/2906?org=1&rir=1'
```

```
# org: Netflix Streaming Services Inc. (source: whois.arin.net)
```

Forcing means forcing: if the RIR lookup fails there is **no** fallback to the
API, since a parameter that silently reverted could not be used to exercise the
registry path.

`rir` only modifies an org lookup. Supplied without `org=1` it does nothing, and
the response says so rather than passing silently:

```
# rir: ignored (org lookup not requested)
```

The five registries answer in four different formats — ARIN serves flat
`Key: value` lines, LACNIC uses `owner:`, APNIC and AFRINIC use `descr:` on the
`aut-num` object, and RIPE returns an `org:` handle that costs one extra query
to resolve into `org-name:`. Responses also contain the parent *as-block*, so
the parser selects the object matching the queried ASN rather than reading the
first description it sees. Queries to RPSL registries use the `-r` flag, which
suppresses personal contact objects — the data RIPE rate-limits on.

## Upstream data sources

| Source | URL | When it is contacted |
| --- | --- | --- |
| RADB WHOIS | `whois.radb.net:43` (raw WHOIS over TCP) | Every uncached request. |
| RIR whois servers | `whois.{arin,ripe,apnic,lacnic,afrinic}.net:43` | Only for `org` lookups: when no API key is set, when the API fails, or when `rir=1`. |
| WhoisFreaks ASN WHOIS API | `https://api.whoisfreaks.com/v2.0/asn-whois` | Only when `org` is enabled, an API key is set, and `rir=1` was not given. |
| IANA AS number registries | `https://www.iana.org/assignments/as-numbers/as-numbers-1.csv` (16-bit)<br>`https://www.iana.org/assignments/as-numbers/as-numbers-2.csv` (32-bit) | Build time only, via `go generate` — two fetches total. Never at runtime. |

### RADB WHOIS

Queried on TCP port 43 with an inverse lookup on origin, terminated by CRLF:

```
-i origin AS2906
```

The response is scanned for `route6:` attributes. Defined in
`internal/radb/radb.go`.

### RIR whois servers

Which server is authoritative for an ASN comes from the generated IANA table,
so no RIR-to-host mapping is hardcoded. The query is the ASN with an `AS`
prefix, sent with `-r` to RPSL registries:

```
-r AS56554
```

Implemented in `internal/rirwhois/rirwhois.go`; the per-registry response
formats are described under [`rir`](#rir--force-the-authoritative-rir).

### WhoisFreaks ASN WHOIS API

Documentation: <https://whoisfreaks.com/documentation/asn-whois-api>

The request is a `GET` to the endpoint above with three query parameters —
`apiKey`, `asn` (sent with an `AS` prefix), and `format`:

```
https://api.whoisfreaks.com/v2.0/asn-whois?apiKey=YOUR_API_KEY&asn=AS2906&format=JSON
```

The organization name is read from the top-level `orgName` field, falling back
to `asName` when `orgName` is empty. Implemented in
`internal/whoisfreaks/whoisfreaks.go`.

### IANA AS number registries

Registry page: <https://www.iana.org/assignments/as-numbers/as-numbers.xhtml>

`gen_asn_ranges.go` fetches both sub-registries — 16-bit and 32-bit — exactly
once each at build time and keeps only rows whose description begins with
`Assigned by ` (the five RIRs). Each kept row contributes its range, the
registry name, and the authoritative whois server from the CSV's own `WHOIS`
column. Rows marked `Unallocated`, `Reserved`, `Reserved for Private Use`,
`Reserved for use in documentation and sample code`, or `AS_TRANS` are excluded,
which is what makes those ASNs return `400`.

The result is written to `internal/asnreg/ranges_gen.go`, which is committed.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `8080` | Port to listen on. The convention used by most serverless container platforms. |
| `LISTEN_ADDR` | — | Full `host:port` override. Takes precedence over `PORT`. |
| `WHOISFREAKS_API_KEY` | — | Optional. When set, the WhoisFreaks API becomes the preferred `org` source; unset, `org` resolves via the ASN's RIR instead. Not required for `org` to work. |

## Caching

Successful WHOIS lookups are cached in memory for 5 minutes per ASN, so repeated
queries don't hit the upstream registry and risk rate limiting. Failed lookups
are not cached, so a transient outage doesn't lock out retries.

The cache stores the un-aggregated prefix list and aggregation is applied when
rendering, so `agg=0` and `agg=1` share a single upstream query. Organization
names are cached separately on the same 5-minute TTL, since the API is metered
and RIR whois servers rate-limit. That cache is keyed by source as well as ASN,
so a forced `rir=1` answer is never served to a default request, or vice versa.

Note that concurrent first-time requests for the same uncached ASN may each
trigger an upstream query; requests are not coalesced.

## Responses

| Status | Meaning |
| --- | --- |
| `200` | Success. A valid ASN with no IPv6 prefixes returns `200` with `# no IPv6 prefixes found`. |
| `400` | Malformed ASN, an ASN outside a permitted range, or an invalid parameter value. |
| `405` | Method other than `GET` or `HEAD`. |
| `502` | The upstream WHOIS query failed. |

Errors are plaintext comment lines, so output stays valid for a consumer that
ignores `#` lines:

```
# error: invalid ASN "abc", expected a numeric AS number: 0-65535 (16-bit) or 0-4294967295 (32-bit)
```

### ASN validation

An ASN must be numeric, within the 32-bit AS number space (`0`–`4294967295`),
and inside a range IANA has actually delegated to an RIR. Requests for
unallocated, reserved, documentation, or private-use ranges are rejected with
`400` instead of being sent upstream.

This applies to the 16-bit space as well as the 32-bit space, so these are
rejected despite being numerically valid:

| Rejected | Why |
| --- | --- |
| `0` | Reserved (RFC 7607) |
| `23456` | AS_TRANS, the 4-byte transition placeholder (RFC 6793) |
| `64496`–`64511` | Reserved for documentation and sample code (RFC 5398) |
| `64512`–`65534` | Reserved for private use (RFC 6996) |
| `65535` | Reserved (RFC 7300) |
| `65540`, `4200000001`, … | Reserved or unallocated in the 32-bit space |

> **Note:** private-use ASNs (`64512`–`65534`) previously returned `200` and now
> return `400`. If you query this service for internal AS numbers, that is a
> breaking change.

The allocation table is generated at build time from both IANA sub-registries
into `internal/asnreg/ranges_gen.go`, which is committed. The running service
therefore needs no network access to IANA. Refresh it when the registries
change:

```bash
go generate ./...
```

## Project layout

Each upstream data source is isolated in its own package, so the network code
for one cannot entangle with the others. Everything still compiles to a single
binary — `internal/` packages are linked in, not separate services.

```
main.go                        server wiring and graceful shutdown
handler.go                     HTTP handler, parameter parsing, output rendering
cache.go                       5-minute caches, org source resolution, test seams
asn.go                         ASN parsing and validation
prefixes.go                    route6 extraction, sorting, aggregation
gen_asn_ranges.go              generator (build-time only, //go:build ignore)
internal/asnreg/               ASN → RIR table (generated) and lookup
internal/radb/                 RADB WHOIS client (raw TCP, port 43)
internal/rirwhois/             RIR WHOIS client + per-registry parsing
internal/whoisfreaks/          WhoisFreaks organization lookup (HTTPS)
```

The packages expose narrow APIs — `radb.Query(asn)`,
`whoisfreaks.LookupOrgName(asn, apiKey)`, `rirwhois.LookupOrgName(reg, asn)`,
and `asnreg.Lookup(asn)` — and the main package reaches the network ones through
overridable variables, so tests substitute all of them without a network. The
`rirwhois` tests run against sanitized real responses in
`internal/rirwhois/testdata/`, with contact details redacted.

## Build and run

```bash
go run .
```

```bash
go test ./...
```

Tests make no network calls: the WHOIS client, organization lookup, clock, and
environment reader are all substituted, and a test that reaches the metered API
without an explicit hook fails loudly.

## Container

A multi-stage `Dockerfile` builds a static binary and copies it into `scratch`,
along with a CA certificate bundle so the optional `org` lookup can make its
HTTPS call. The service runs as a non-root UID.

```bash
docker build -t asn-ipv6-ranges .
```

```bash
docker run --rm -p 8080:8080 asn-ipv6-ranges
```

The container honors a platform-supplied `PORT` and shuts down gracefully on
`SIGTERM`, letting in-flight requests finish.

```bash
docker run --rm -e PORT=9090 -e WHOISFREAKS_API_KEY=... -p 9090:9090 asn-ipv6-ranges
```

> **Note:** the Docker image has not been built or tested — Docker was not
> available in the development environment. The Go build it runs is the same one
> verified by `go build`, but the image itself is unverified.

## Provenance

This project was generated with [Claude Code](https://claude.com/claude-code),
Anthropic's agentic coding tool. The source, tests, and this documentation were
written by Claude from a series of prompts describing the desired behavior.

What was verified during development:

- The service was run against the live RADB WHOIS server, the WhoisFreaks ASN
  API, and all five RIR whois servers; the documented request and response
  examples are real output.
- `go vet` and the unit test suite pass; tests make no network calls.
- The IANA allocation table in `internal/asnreg/ranges_gen.go` was generated
  from both live sub-registries.

What was not:

- The Docker image was never built or run, as noted above.
- Behavior has only been exercised against a handful of ASNs, and the upstream
  data sources are third parties whose responses may vary in ways not covered
  by the tests.

Review it as you would any other unfamiliar code before relying on it.

## License

MIT — see [LICENSE](LICENSE).
