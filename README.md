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

| Parameter | Default | Effect |
| --- | --- | --- |
| `agg` | `1` (on) | Remove prefixes already covered by a broader prefix in the list. |
| `org` | `0` (off) | Look up the ASN's organization name and report it in a comment. |
| `src` | `auto` | Choose which source answers the `org` lookup: `auto`, `api`, `whois`, `rdap`. |

`agg` and `org` accept `1`/`0` and `true`/`false` (case-insensitive; `t`/`f`
also work). An empty value (`?agg=`) falls back to the default. Any other value
returns `400`.

> **Breaking change:** the `rir` parameter has been removed in favour of `src`.
> `?rir=1` is now an unrecognized parameter and is **silently ignored**, so a
> caller relying on it gets `auto` behaviour rather than a forced registry
> lookup. Use `?src=whois` instead.

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

`org=1` looks up the ASN's organization name and adds an `# org:` comment naming
the source that answered:

```bash
curl 'http://localhost:8080/as/2906?org=1'
```

```
# IPv6 prefixes for AS2906 (source: whois.radb.net)
# org: Netflix Streaming Services Inc. (source: whois.arin.net)
...
```

There are three sources, and **no configuration is required** — the two registry
sources are always available:

| Source | Requires | Notes |
| --- | --- | --- |
| RIR whois (port 43) | nothing | Per-registry text formats; two queries for RIPE |
| RIR RDAP (HTTPS) | nothing | Structured JSON; one query |
| [WhoisFreaks API](https://whoisfreaks.com/documentation/asn-whois-api) | `WHOISFREAKS_API_KEY` | Normalized single-field answer |

With `src=auto` (the default) the API is tried first **when a key is set**, then
the two registry sources. Which registry source goes first depends on the
registry:

| Registry | Order | Why |
| --- | --- | --- |
| RIPE NCC | RDAP, then whois | RIPE aut-num objects carry the operator's full routing policy. AS24940 answers with 60,151 bytes over whois — 58,926 of them 1,306 `import:`/`export:` lines — and needs a second query to resolve the `org:` handle. RDAP returns the same name in 14,925 bytes and one request. |
| all others | whois, then RDAP | whois is smaller and single-query: ARIN AS2906 is 1,683 bytes versus 5,432 over RDAP. |

Port 43 offers no way to exclude attributes — `-K` drops the `org:` handle the
lookup needs and `-F` only abbreviates attribute names — so for RIPE the saving
has to come from switching protocol.

Both orders fall through to the other source on failure, so this is a cost
optimization rather than a change in which names resolve. The `(source: …)`
annotation always reports which one actually answered.

The lookup is never performed unless `org` is enabled, so the service contacts
none of these by default.

A failed lookup does not fail the request — the prefix list is the primary
output, so the response is still `200` with the reason in a comment:

```
# org: lookup failed: whois.arin.net: dial tcp: i/o timeout
```

The API key is stripped from any error text before it reaches the response, and
names from every source are flattened to a single line so they cannot escape
their comment and forge a prefix entry.

### `src` — choosing the org source

| `src` | Behavior |
| --- | --- |
| `auto` (default) | API when keyed, then the registry sources in the order above |
| `api` | WhoisFreaks only |
| `whois` | RIR whois only |
| `rdap` | RIR RDAP only |

```bash
curl 'http://localhost:8080/as/24940?org=1&src=rdap'
```

```
# org: Hetzner Online GmbH (source: rdap.db.ripe.net)
```

**An explicit source never falls back.** If `src=whois` fails, the failure is
reported rather than another source being tried silently — otherwise the
parameter could not be trusted to exercise one path. `src=api` without a key
configured is likewise a reported failure, not a silent skip:

```
# org: lookup failed: api selected but WHOISFREAKS_API_KEY is not set
```

`src` only modifies an org lookup. Supplied without `org=1` it does nothing, and
the response says so rather than passing silently:

```
# src: ignored (org lookup not requested)
```

An unrecognized value returns `400` naming the valid ones.

#### Why the registry sources need per-registry rules

Neither protocol is uniform across the five RIRs.

Over **whois**, ARIN serves flat `Key: value` lines, LACNIC uses `owner:`, APNIC
and AFRINIC use `descr:` on the `aut-num` object, and RIPE returns an `org:`
handle that costs a second query to resolve into `org-name:`. Responses also
contain the parent *as-block*, so the parser selects the object matching the
queried ASN rather than reading the first description it sees. Queries to RPSL
registries use `-r`, which suppresses personal contact objects — the data RIPE
rate-limits on.

Over **RDAP** the transport is uniform but the placement is not. The name is
taken from the entity whose role is `registrant` *and* whose vCard `kind` is
`org`; both halves matter, because RIPE returns several `registrant` entities
(maintainer handles such as `HOS-GUN` alongside the real `ORG-…` object) and a
`kind=group` contact role. APNIC omits the registrant entity on some objects —
AS9605 has only the delegating registry, JPNIC — so the name falls back to the
remark titled `description`, taking its first line only, since that array
continues into a postal address.

## Upstream data sources

| Source | URL | When it is contacted |
| --- | --- | --- |
| RADB WHOIS | `whois.radb.net:43` (raw WHOIS over TCP) | Every uncached request. |
| RIR whois servers | `whois.{arin,ripe,apnic,lacnic,afrinic}.net:43` | Only for `org` lookups, per the source order above, or when `src=whois`. |
| RIR RDAP endpoints | `https://rdap.arin.net/registry`<br>`https://rdap.db.ripe.net/`<br>`https://rdap.apnic.net/`<br>`https://rdap.lacnic.net/rdap/`<br>`https://rdap.afrinic.net/rdap/` | Only for `org` lookups, per the source order above, or when `src=rdap`. |
| WhoisFreaks ASN WHOIS API | `https://api.whoisfreaks.com/v2.0/asn-whois` | Only when `org` is enabled and an API key is set, unless `src` selects another source. |
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
formats are described under [`src`](#src--choosing-the-org-source).

### RIR RDAP endpoints

The base URL for each registry comes from the `RDAP` column of the same IANA
CSVs, so it is not hardcoded either. Requests are
`GET {base}/autnum/{asn}` with `Accept: application/rdap+json`:

```
https://rdap.db.ripe.net/autnum/24940
```

Implemented in `internal/rdap/rdap.go`.

> IANA publishes that column with two URLs concatenated for ARIN and AFRINIC
> (`https://rdap.arin.net/registryhttp://rdap.arin.net/registry`). The generator
> splits on the embedded scheme and keeps the `https` entry.

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
registry name, and the authoritative whois server and RDAP base from the CSV's
own `WHOIS` and `RDAP` columns. Rows marked `Unallocated`, `Reserved`, `Reserved for Private Use`,
`Reserved for use in documentation and sample code`, or `AS_TRANS` are excluded,
which is what makes those ASNs return `400`.

The result is written to `internal/asnreg/ranges_gen.go`, which is committed.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `8080` | Port to listen on. The convention used by most serverless container platforms. |
| `LISTEN_ADDR` | — | Full `host:port` override. Takes precedence over `PORT`. |
| `WHOISFREAKS_API_KEY` | — | Optional. When set, the WhoisFreaks API becomes the first `org` source tried; unset, `org` resolves from the ASN's registry instead. Not required for `org` to work. |

## Caching

Successful WHOIS lookups are cached in memory for 5 minutes per ASN, so repeated
queries don't hit the upstream registry and risk rate limiting. Failed lookups
are not cached, so a transient outage doesn't lock out retries.

The cache stores the un-aggregated prefix list and aggregation is applied when
rendering, so `agg=0` and `agg=1` share a single upstream query. Organization
names are cached separately on the same 5-minute TTL, since the API is metered
and registry servers rate-limit. That cache is keyed by the requested `src` as
well as the ASN, so a `src=rdap` answer is never served to an `auto` request, or
vice versa — the reported source is always the one that actually answered.

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
internal/asnreg/               ASN → RIR table (generated): whois host + RDAP base
internal/radb/                 RADB WHOIS client (raw TCP, port 43)
internal/rirwhois/             RIR WHOIS client + per-registry parsing
internal/rdap/                 RIR RDAP client + jCard extraction
internal/whoisfreaks/          WhoisFreaks organization lookup (HTTPS)
```

The packages expose narrow APIs — `radb.Query(asn)`,
`whoisfreaks.LookupOrgName(asn, apiKey)`, `rirwhois.LookupOrgName(reg, asn)`,
`rdap.LookupOrgName(reg, asn)`, and `asnreg.Lookup(asn)` — and the main package
reaches the network ones through overridable variables, so tests substitute all
of them without a network. The `rirwhois` and `rdap` tests run against sanitized
real responses in their `testdata/` directories, with contact details redacted
and a test that fails if an unredacted address or personal name reappears.

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
