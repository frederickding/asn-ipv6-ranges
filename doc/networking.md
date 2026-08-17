# Networking

Everything this service needs from the network: what it listens on, what it
connects out to, and the limits that keep it inside what the upstream
registries allow.

This is the reference for writing a firewall rule or a Kubernetes
`NetworkPolicy`. The supplied manifest ships **no** egress policy, so nothing
here is enforced by default — the port 43 requirement in particular is easy to
miss when a cluster's default egress rules assume HTTPS is enough.

---

## Inbound

| Property | Value |
| --- | --- |
| Listen address | `LISTEN_ADDR` if set, else `:$PORT`, else `:8080` |
| Protocol | HTTP/1.1, cleartext (terminate TLS in front of it) |
| Routes | `GET\|HEAD /as/{asn}`, `GET\|HEAD /-/status` |

No authentication, no request body: parameters are read from the URL query
only, never from a body, so nothing is gained by POSTing to it.

### Server limits

| Limit | Value | What it stops |
| --- | --- | --- |
| `ReadHeaderTimeout` | 5s | A client that opens a connection and dribbles headers. |
| `ReadTimeout` | 10s | The same, for the whole request. |
| `WriteTimeout` | 30s | A client that stops reading mid-response and pins a goroutine holding a large prefix list. |
| `IdleTimeout` | 60s | Keep-alive connections accumulating unused. |
| `MaxHeaderBytes` | 16 KiB | Go's 1 MB default reaching the [access log](logging.md)'s escaper on every request. |
| `MAX_INFLIGHT` | 32 | Concurrent requests, and through them memory. |
| Request deadline | 20s | The total time one request may spend on upstream calls. |

`MAX_INFLIGHT` is the front-door bound. A request's cost is dominated by the
upstream response it holds — capped at 8 MiB for RADB — so without a ceiling on
concurrency a burst of requests for large ASNs walks past `GOMEMLIMIT` and the
pod is OOM-killed. Past the cap, requests are answered **`503` with
`Retry-After: 1`**, not queued: queueing would hold the goroutine and buffers
that the cap exists to limit.

`/-/status` is exempt from the cap. Shedding a readiness probe under load would
depool a pod that is behaving exactly as designed, turning overload into an
outage.

The request deadline is cancelled when the client disconnects, so an aborted
request stops its upstream work rather than running it to completion. A request
that exhausts the deadline is answered `504`.

---

## Outbound

Every destination, for firewall and `NetworkPolicy` purposes:

| Destination | Port | Protocol | When | Runtime? |
| --- | --- | --- | --- | --- |
| `whois.radb.net` | **43/tcp** | raw WHOIS | Every uncached `/as/{asn}` request | yes |
| `whois.afrinic.net`, `whois.apnic.net`, `whois.arin.net`, `whois.lacnic.net`, `whois.ripe.net` | **43/tcp** | raw WHOIS | `?org=1` with `src=auto` or `src=whois` | yes |
| `rdap.afrinic.net`, `rdap.apnic.net`, `rdap.arin.net`, `rdap.lacnic.net`, `rdap.db.ripe.net` | **443/tcp** | HTTPS (RDAP) | `?org=1` with `src=auto` or `src=rdap` | yes |
| `api.whoisfreaks.com` | **443/tcp** | HTTPS | `?org=1` and `WHOISFREAKS_API_KEY` set, unless `src` selects another source | yes |
| `www.iana.org` | 443/tcp | HTTPS | `go generate` only — two fetches, at build time | **no** |

DNS resolution for the above is also required. The registry hostnames are not
hardcoded: they come from the `WHOIS` and `RDAP` columns of the IANA CSVs, baked
into `internal/asnreg/ranges_gen.go` at build time. A regenerated table could in
principle introduce a new host, so the list above is accurate as of the
committed table rather than fixed forever.

A pod that can reach nothing at all still starts, serves `/-/status`, and
answers from cache; `/as/{asn}` returns `502` for anything not cached.

### RADB — prefix data

Queried on TCP port 43 with an inverse lookup on origin, terminated by CRLF:

```
-i origin AS2906
```

The response is scanned for `route6:` attributes. Defined in
`internal/radb/radb.go`.

### RIR whois — organization names

Which server is authoritative for an ASN comes from the generated IANA table.
The query is the ASN with an `AS` prefix, sent with `-r` to RPSL registries:

```
-r AS56554
```

`-r` asks the registry to omit referenced contact objects. Besides keeping
personal data out of the response, this is what RIPE's per-IP personal-data
quota counts, so the flag is what keeps this service clear of it entirely.
ARIN and LACNIC do not accept the flag.

RIPE-style registries answer with an `org:` handle rather than a name, so one
lookup may issue **two** queries. Implemented in `internal/rirwhois/rirwhois.go`.

### RIR RDAP — organization names

The base URL for each registry comes from the `RDAP` column of the same IANA
CSVs. Requests are `GET {base}/autnum/{asn}` with `Accept: application/rdap+json`:

```
https://rdap.db.ripe.net/autnum/24940
```

Implemented in `internal/rdap/rdap.go`.

> IANA publishes that column with two URLs concatenated for ARIN and AFRINIC
> (`https://rdap.arin.net/registryhttp://rdap.arin.net/registry`). The generator
> splits on the embedded scheme and keeps the `https` entry.

RDAP is preferred over whois for RIPE only. RIPE's `aut-num` objects carry the
operator's full routing policy — AS24940 answers with 60,151 bytes, of which
58,926 are 1,306 `import:`/`export:` lines — and its org name needs a second
whois query. RDAP returns the same name in 14,925 bytes and one request. Port 43
offers no way to exclude attributes, so the saving has to come from switching
protocol. Elsewhere whois is smaller and single-query (ARIN: 1,683 bytes vs
5,432).

### WhoisFreaks API — organization names

Documentation: <https://whoisfreaks.com/documentation/asn-whois-api>

`GET` with three query parameters — `apiKey`, `asn` (with an `AS` prefix), and
`format`:

```
https://api.whoisfreaks.com/v2.0/asn-whois?apiKey=YOUR_API_KEY&asn=AS2906&format=JSON
```

The organization name is read from the top-level `orgName`, falling back to
`asName`. The key appears in the URL and therefore in any error Go's HTTP client
produces, so every error leaving `internal/whoisfreaks` is redacted before a
caller can put it in a response body.

### IANA AS number registries — build time only

Registry page: <https://www.iana.org/assignments/as-numbers/as-numbers.xhtml>

`gen_asn_ranges.go` fetches `as-numbers-1.csv` (16-bit) and `as-numbers-2.csv`
(32-bit) exactly once each at build time, keeping only rows whose description
begins with `Assigned by ` (the five RIRs). Each kept row contributes its range,
the registry name, and the authoritative whois server and RDAP base from the
CSV's own `WHOIS` and `RDAP` columns. Rows marked `Unallocated`, `Reserved`,
`Reserved for Private Use`, `Reserved for use in documentation and sample code`,
or `AS_TRANS` are excluded, which is what makes those ASNs return `400`.

The result is written to `internal/asnreg/ranges_gen.go`, which is committed.
**The running service never contacts IANA.**

### Per-request fan-out

Worst case for one request (`?org=1&src=auto`, a RIPE ASN, every source
failing): 1 RADB query, 1 WhoisFreaks call, 1 RDAP request, and 2 whois queries
— five upstream calls. The 20s request deadline covers all of them together.

---

## Upstream rate limits

### What the registries actually publish

Only LACNIC publishes numbers usable as a target. The rest either publish
nothing or publish limits that do not apply to this service's query pattern.

| Upstream | Documented / reported limit | Source |
| --- | --- | --- |
| **RADB** | Not published. The support page says only that "the RADb WHOIS service is rate-limited" and recommends the API for bulk work. Reported behaviour: 4 concurrent connections per source IP, with the fifth reset, and ~3.3 sessions/sec or 200 sessions/min. | [Querying RADb via WHOIS](https://radb.atlassian.net/wiki/spaces/RADb/pages/46105167/Querying+RADb+via+WHOIS), [ixpmanager thread](https://www.inex.ie/pipermail/ixpmanager/2023-June/003631.html) |
| **LACNIC** | The strictest, and the only one with published figures: ~100 queries per 5 minutes and 1,000 per 60 minutes. Refuses with `429`, or `403` carrying `rate limit exceeded for IP: …`. API keys are available for a higher quota. Aggressive enough that a first query from a fresh IP is sometimes refused. | [Accessing RDAP](https://www.lacnic.net/676/2/lacnic/request-rdap-access) |
| **RIPE NCC** | AUP: **3 simultaneous connections** to the database server; 1,000 personal-data sets per IP per 24 hours (20,000 for a proxy IP). Exceeding the personal-data limit blocks until the end of the UTC day; repeat offences block permanently. The AUP does not state separate RDAP figures. | [RIPE Database AUP](https://www.ripe.net/manage-ips-and-asns/db/support/acceptable-use-policy), [Access to Personal Data](https://docs.db.ripe.net/Access-to-Personal-Data) |
| **ARIN** | No published numbers. The Whois Terms of Use covers permitted purposes, not query rates. Throttling surfaces as `429`. | [Whois Terms of Use](https://www.arin.net/resources/registry/whois/tou/) |
| **APNIC** | No published numbers. States that whois access is subject to daily and rate-based limits which APNIC "monitors and adjusts". Throttling surfaces as `429`. | [APNIC RDAP](https://www.apnic.net/about-apnic/whois_search/about/rdap/) |
| **AFRINIC** | No published numbers. | — |
| **WhoisFreaks** | Metered commercial API; the limit is contractual, and every call costs. | [ASN WHOIS API](https://whoisfreaks.com/documentation/asn-whois-api) |

RIPE's personal-data quota is the one limit this service is structurally clear
of: the `-r` flag suppresses exactly the contact objects it counts. The
connection limit is therefore the binding RIPE constraint.

### What this service allows itself

Configured in `upstream.go`, enforced in `internal/ratelimit` at the point each
outbound call is made. Every budget is a token bucket (a sustained rate plus a
burst depth) **and** a concurrency ceiling, because the registries limit both.

| Upstream | Rate | Burst | Concurrent | Rationale |
| --- | --- | --- | --- | --- |
| `whois.radb.net` | 2/s | 5 | 3 | Under the reported 4-connection cap, with one slot spare. |
| LACNIC (whois + RDAP) | 8/min | 4 | 2 | 8/min doubled across replicas is 80 per 5 minutes, under the published ~100. |
| RIPE (whois + RDAP) | 2/s | 5 | 2 | The AUP allows 3 simultaneous connections; 2 leaves margin. |
| ARIN, APNIC, AFRINIC | 2/s | 5 | 2 | No published number, so low enough not to be noticed. |
| `api.whoisfreaks.com` | 1/s | 3 | 2 | Every call is billed. |

A registry's whois and RDAP front ends share one budget: they are the same
service behind two protocols, and per-registry is how the registries themselves
count.

One nuance: an RIR whois lookup spends one token but may issue two queries when
it has to resolve an `org:` handle. The rates above account for that, and the
concurrency slot — which is what RIPE actually limits — is held across both.

> **These budgets are per process.** The manifest runs `replicas: 2`, so a
> registry sees up to twice these rates. Halve them, or run a single replica, if
> a registry objects.

### When a budget is spent

Fail fast. The request is answered **`503` with `Retry-After`** derived from
when the bucket next refills, and the upstream is not contacted. Under `src=auto`
a budget refusal also stops the fallback chain: trying the next source would
spend a second registry's budget on a request the first already declined.

A refusal is never cached — it is not an answer about the ASN — so a later
request gets a real lookup once the budget recovers.

### When an upstream pushes back

A `429` or `503` from RDAP, or LACNIC's `403` naming a rate limit, parks that
host entirely until its `Retry-After` elapses (5 minutes if it sends none). The
registry's own verdict on our rate outranks the budget configured here, which is
only ever an estimate of a limit it does not publish.

### What keeps the steady-state rate far below these ceilings

The budgets are the last line, not the first. Three things sit in front:

1. **ASN validation.** An ASN outside every IANA-delegated range is rejected
   with `400` before any network call. Scanning the unallocated AS space
   generates no upstream traffic at all.
2. **Caching.** Successful answers are cached for 5 minutes; failures for 30
   seconds. Without the negative cache, an ASN whose lookup fails could be
   replayed into one upstream query per request indefinitely.
3. **Coalescing.** Concurrent requests for the same uncached ASN are collapsed
   into a single upstream query — 50 simultaneous requests for one cold ASN cost
   one query, not 50. This is what makes the budgets meaningful: without it the
   cache only helps requests arriving *after* an answer is stored, so a burst of
   misses scaled straight through to the upstream.

---

## Timeouts, body caps, and retries

| Upstream | Connect + read timeout | Body cap | On overrun |
| --- | --- | --- | --- |
| RADB | 15s | 8 MiB | Error. Deliberately not truncation: a short read would silently report fewer prefixes than the ASN originates. |
| RIR whois | 15s | 1 MiB | Silent truncation. |
| RIR RDAP | 15s | 1 MiB | Silent truncation. Status is checked *before* the body is read, so a rate-limit response costs nothing to discover. |
| WhoisFreaks | 10s | 1 MiB | Silent truncation. |

**There are no retries anywhere, by design.** A failed upstream call is
reported, not repeated. Retrying is how a service turns one upstream's bad
minute into a self-inflicted rate-limit block, and the failure cache already
prevents the client from retrying it into one.

All four clients take a `context.Context` and are cancelled by it. The two
HTTPS clients share a package-level transport (`MaxIdleConnsPerHost: 4`,
`MaxConnsPerHost: 4`, `IdleConnTimeout: 90s`), so concurrent queries to a
registry reuse connections instead of paying a TLS handshake each, and
`MaxConnsPerHost` acts as a transport-level backstop under the budget.

The two raw-WHOIS clients open one connection per query — port 43 has no
multiplexing — and close it on cancellation, so an abandoned request stops
occupying a connection slot the registry is counting.
