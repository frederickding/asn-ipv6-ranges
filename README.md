# asn-ipv6-ranges

A minimal HTTP service that returns the IPv6 prefixes announced by an ASN as
`text/plain`, one prefix per line, with comments prefixed by `#`.

> Generated with [Claude Code](https://claude.com/claude-code). See
> [Provenance](#provenance).

Prefix data comes from the [RADB](https://www.radb.net/) Internet Routing
Registry, queried over the raw WHOIS protocol (TCP port 43) using native Go
networking — the service never shells out to a `whois` binary.

## Endpoints

| Endpoint | Purpose |
| --- | --- |
| `GET /as/{asn}` | IPv6 prefixes for an ASN |
| `GET /-/status` | Health check for probes and monitoring |

## `GET /as/{asn}`

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
| RIR RDAP endpoints | `https://rdap.{arin,apnic,lacnic,afrinic}...`, `https://rdap.db.ripe.net/` | Only for `org` lookups, per the source order above, or when `src=rdap`. |
| WhoisFreaks ASN WHOIS API | `https://api.whoisfreaks.com/v2.0/asn-whois` | Only when `org` is enabled and an API key is set, unless `src` selects another source. |
| IANA AS number registries | `as-numbers-1.csv`, `as-numbers-2.csv` | Build time only, via `go generate`. Never at runtime. |

**See [doc/networking.md](doc/networking.md)** for the full picture: exact
hostnames and ports for firewall and `NetworkPolicy` rules, the query format
each upstream is sent, the registries' published rate limits and the budgets
this service holds itself to, and the timeouts and body caps applied to each.

## `GET /-/status` — health check

Returns `200` with `ok` on the first line while the process is serving:

```bash
curl http://localhost:8080/-/status
```

```
ok
# uptime: 38s
# prefix cache: 1/256 ASNs
# org cache: 0/256 entries
```

The cache lines are reported against capacity: a cache sitting at its limit
means entries are being evicted, which is the signal that the cap is too low for
the traffic this pod sees.

Probes only need the status code; the `#` lines are detail for a human reading
the endpoint directly. The response carries `Cache-Control: no-store` so no
intermediary answers a probe from cache. `GET` and `HEAD` are accepted, anything
else returns `405`. The path is matched exactly — `/-/status/anything` is `404`.

**It performs no upstream I/O**, and that is deliberate. Probing RADB, a RIR, or
the WhoisFreaks API here would tie pod health to third parties: an outage at any
of them would fail the probe and make Kubernetes restart or depool pods that are
working fine. The service still answers from cache and returns useful errors
while an upstream is down, so the probe measures what it should — the process is
up and its listener is accepting requests. Typical response time is well under a
millisecond.

The same endpoint suits both probe types, since the service holds no startup
state that would make it live but not yet ready:

```yaml
livenessProbe:
  httpGet:
    path: /-/status
    port: 8080
  initialDelaySeconds: 3
  periodSeconds: 10
readinessProbe:
  httpGet:
    path: /-/status
    port: 8080
  periodSeconds: 5
```

To alert on upstream failures — which this endpoint intentionally ignores —
monitor the `502` rate on `/as/{asn}` instead.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `8080` | Port to listen on. The convention used by most serverless container platforms. |
| `LISTEN_ADDR` | — | Full `host:port` override. Takes precedence over `PORT`. |
| `WHOISFREAKS_API_KEY` | — | Optional. When set, the WhoisFreaks API becomes the first `org` source tried; unset, `org` resolves from the ASN's registry instead. Not required for `org` to work. |
| `ACCESS_LOG` | `1` | Request logging. Set `0`/`false` to disable. |
| `ACCESS_LOG_PROBES` | `0` | Include `/-/status` in the access log. Useful when debugging probes. |
| `MAX_INFLIGHT` | `32` | Concurrent requests held at once. Past it, requests get `503` with `Retry-After` rather than being queued. This is the hard bound on memory — raise it and the container memory limit together. |

A value that isn't a recognized boolean logs a warning and keeps the default —
misconfigured logging shouldn't stop the service from starting. `MAX_INFLIGHT`
behaves the same way; zero and negative values are rejected rather than treated
as unlimited, since unlimited is the behaviour the cap exists to remove.

## Logging

Two streams, deliberately separate, mirroring nginx's `access.log` / `error.log`
split:

| Stream | Destination | Contents |
| --- | --- | --- |
| Access log | **stdout** | One line per request, in nginx's `common` format |
| Operational | **stderr** | Startup, shutdown, cache sweeps, upstream pauses, periodic stats |

So they can be separated with a plain redirect:

```bash
./asn-ipv6-ranges 1>access.log 2>error.log
```

**See [doc/logging.md](doc/logging.md)** for the full picture: the access log
format and its escaping rules, how the client address is resolved and why it is
not an authorization signal, what is excluded and why, the fields in the
5-minute stats line, and the operational lines worth alerting on.

## Caching

Successful WHOIS lookups are cached in memory for 5 minutes per ASN, so repeated
queries don't hit the upstream registry and risk rate limiting. Failed lookups
are cached too, but only for 30 seconds: long enough that an ASN nobody can
resolve can't be replayed into one upstream query per request, short enough that
a transient outage doesn't lock out retries for the full 5 minutes.

The cache stores the un-aggregated prefix list and aggregation is applied when
rendering, so `agg=0` and `agg=1` share a single upstream query. Organization
names are cached separately on the same 5-minute TTL, since the API is metered
and registry servers rate-limit. That cache is keyed by the requested `src` as
well as the ASN, so a `src=rdap` answer is never served to an `auto` request, or
vice versa — the reported source is always the one that actually answered.

Concurrent first-time requests for the same uncached ASN are coalesced: 50
simultaneous requests for one cold ASN produce a single upstream query, and the
other 49 wait for its result. This is what keeps the upstream query rate tied to
the number of distinct ASNs rather than the number of requests — see
[doc/networking.md](doc/networking.md) for how it fits with the per-registry
rate limits.

### Eviction and bounds

Three separate limits apply, and they do different jobs:

| Limit | Value | Effect |
| --- | --- | --- |
| Freshness | 5 minutes | Past this an entry is re-queried upstream rather than served. |
| Freshness, failures | 30 seconds | A cached failure is retried sooner than a cached answer is refreshed. |
| Retention | 1 hour | Past this an entry is **deleted**. Only entries nobody has successfully refreshed get this old, so this reclaims ASNs queried once and never again. |
| Capacity | 256 entries | Hard cap per cache. At capacity, the least recently refreshed entry is evicted to make room. |

Pruning runs on every insert, and a reaper sweeps both caches once a minute so
retention still holds when the service is idle and no insert is happening —
otherwise a pod that went quiet would hold its last 256 entries indefinitely.

Both caches are bounded. The org cache is keyed by `{asn, src}`, so a single ASN
can occupy up to four of its slots.

### Memory

The caps exist to make memory a fixed ceiling rather than something that grows
with the number of distinct ASNs ever queried. Measured:

| Scenario | RSS |
| --- | --- |
| Idle | 8 MB |
| 256 cached ASNs, 50 IPv6 prefixes each (typical) | ~9 MB |
| 256 cached ASNs, 2000 prefixes each (far beyond any real ASN) | 51 MB |
| 64 concurrent requests for a 2.3 MB upstream response | 29 MB |

Concurrency is capped at `MAX_INFLIGHT` (32 by default), so the last row is a
measurement of twice what the service will now hold at once. A single RADB
response is separately capped at 8 MiB, so concurrency cannot spike without
bound. That cap is enforced rather than truncating: the largest
real responses measured are 1.12 MB (AS3356) and 2.43 MB (AS4134), and a
response over the cap returns an error instead of a silently shortened prefix
list.

The supplied Kubernetes manifest sets `limits.memory: 96Mi` with
`GOMEMLIMIT=80MiB`, so the Go GC works harder as it approaches the ceiling
instead of the pod being OOM-killed.

## Responses

For `/as/{asn}`:

| Status | Meaning |
| --- | --- |
| `200` | Success. A valid ASN with no IPv6 prefixes returns `200` with `# no IPv6 prefixes found`. |
| `400` | Malformed ASN, an ASN outside a permitted range, or an invalid parameter value. |
| `404` | Unknown path — neither `/as/{asn}` nor `/-/status`. |
| `405` | Method other than `GET` or `HEAD`. |
| `502` | The upstream WHOIS query failed. |
| `503` | The service is at `MAX_INFLIGHT`, or the query budget for the upstream this request needs is spent. Carries `Retry-After`. See [doc/networking.md](doc/networking.md). |
| `504` | The request exhausted its 20-second budget before an upstream answered. |

An org lookup failure is **not** in this table: it reports the reason in a
comment and still returns `200`, because the prefix list is the primary output.

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
handler.go                     /as/{asn} handler, parameter parsing, output rendering
health.go                      /-/status health check
accesslog.go                   nginx common-format request logging (stdout)
stats.go                       5-minute cache and memory stats (stderr)
cache.go                       caches, request coalescing, org source resolution, test seams
limits.go                      inbound concurrency cap (MAX_INFLIGHT)
upstream.go                    per-registry outbound query budgets
asn.go                         ASN parsing and validation
prefixes.go                    route6 extraction, sorting, aggregation
gen_asn_ranges.go              generator (build-time only, //go:build ignore)
internal/asnreg/               ASN → RIR table (generated): whois host + RDAP base
internal/radb/                 RADB WHOIS client (raw TCP, port 43)
internal/rirwhois/             RIR WHOIS client + per-registry parsing
internal/rdap/                 RIR RDAP client + jCard extraction
internal/whoisfreaks/          WhoisFreaks organization lookup (HTTPS)
internal/ratelimit/            token bucket + concurrency ceiling per upstream
doc/networking.md              ports, egress, upstream rate limits and budgets
doc/logging.md                 access log format, stats line, operational lines
```

The packages expose narrow APIs — `radb.Query(ctx, asn)`,
`whoisfreaks.LookupOrgName(ctx, asn, apiKey)`,
`rirwhois.LookupOrgName(ctx, reg, asn)`, `rdap.LookupOrgName(ctx, reg, asn)`,
and `asnreg.Lookup(asn)` — and the main package
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
