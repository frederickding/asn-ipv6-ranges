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
| Routes | `GET\|HEAD /as/{asn}`, `GET\|HEAD /-/status`, `GET\|HEAD /-/version` |

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
| `MAX_INFLIGHT` | 20 | Concurrent requests, and through them memory. |
| Request deadline | 20s | The total time one request may spend on upstream calls. |

`MAX_INFLIGHT` is the front-door bound, but it is not what actually caps
concurrent large-response memory — the per-upstream budgets below are. Every
uncached request needs a budget slot before it does any real work, and a spent
budget fails fast (`503`) rather than queuing, so at most `radbBudget.concurrency`
(3) requests can ever be holding a RADB response at once regardless of
`MAX_INFLIGHT`. Measured: 32 concurrent requests for 32 distinct, uncached
real ASNs sitting at the then-8 MiB `radb.maxBody` cap produced exactly 3 successes
and 9 immediate sub-5ms `503`s — the rest of a larger `MAX_INFLIGHT` would
never have been reachable.

20 is sized to that reality: the sum of every upstream's own concurrency
ceiling (radb 3 + lacnic 2 + ripe 2 + registry 2 + cymru 8 + peeringdb 2 (the
keyed tier) = 19, +1 headroom), so a burst that legitimately maxes out every
registry at once still finds a free slot, with the rest available for cache
hits — which never touch a budget and are the traffic this number should flex
for. Cymru's ceiling dominates the sum because its DNS zone is deliberately
budgeted far looser than everything else here (see below). Past the cap,
requests are answered **`503` with `Retry-After: 1`**, not queued: queueing
would hold the goroutine and buffers that the cap exists to limit.

`/-/status` is exempt from the cap. Shedding a readiness probe under load would
depool a pod that is behaving exactly as designed, turning overload into an
outage.

`/-/version` is **not** exempt, despite sharing the `/-/` prefix. Nothing polls
it on an interval, so it is ordinary traffic; exempting an unauthenticated
endpoint would hand out a way past the shed limit. It performs no I/O and
touches no shared state, so it answers even while every upstream is unreachable
— which is when you most want to know which image is live. What it reports and
how that string is produced is in [version.md](version.md).

The request deadline is cancelled when the client disconnects, so an aborted
request stops its upstream work rather than running it to completion. A request
that exhausts the deadline is answered `504`.

---

## Outbound

Every destination, for firewall and `NetworkPolicy` purposes:

| Destination | Port | Protocol | When | Runtime? |
| --- | --- | --- | --- | --- |
| `whois.radb.net` | **43/tcp** | raw WHOIS | Every uncached `/as/{asn}` request | yes |
| the resolver in `CYMRU_DNS_RESOLVER` (default `1.1.1.1`) | **53/udp** | DNS | `?org=1` with `src=auto` or `src=cymru` (alias `src=dns`) | yes |
| `www.peeringdb.com` | **443/tcp** | HTTPS | `?org=1` with `src=auto` or `src=peeringdb`, **plus one request at startup** when `PEERINGDB_API_KEY` is set | yes |
| `whois.afrinic.net`, `whois.apnic.net`, `whois.arin.net`, `whois.lacnic.net`, `whois.ripe.net` | **43/tcp** | raw WHOIS | `?org=1` with `src=auto` or `src=whois` | yes |
| `rdap.afrinic.net`, `rdap.apnic.net`, `rdap.arin.net`, `rdap.lacnic.net`, `rdap.db.ripe.net` | **443/tcp** | HTTPS (RDAP) | `?org=1` with `src=auto` or `src=rdap` | yes |
| `www.iana.org` | 443/tcp | HTTPS | `go generate` only — two fetches, at build time | **no** |

Every destination above is reached because a request asked for it, with one
exception: the PeeringDB key check runs once at startup, before any request
arrives. It is the only outbound call this service makes on its own initiative.

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

RADB is the narrowest upstream here and the only source of prefixes, so a
failure degrades before it errors: when the budget is spent or RADB is
unreachable, an expired-but-retained cache entry is served with `200` in
preference to a `503`, since that costs RADB nothing and an error would only
invite a retry. See [caching.md](caching.md#serving-stale-entries).

### Team Cymru DNS zone — organization names

One DNS TXT query, over the resolver in `CYMRU_DNS_RESOLVER` (default
Cloudflare, `1.1.1.1:53`) rather than directly against Cymru's own
authoritative servers:

```
dig TXT AS2906.asn.cymru.com
```

The answer is pipe-delimited — `ASN | Country | Registry | Allocated | AS
Name` — and the AS Name field, taken as-is, is the organization name. Cymru
built this zone specifically for high-volume bulk lookups, unlike its
rate-limited whois-over-port-43 service, which is why it gets the loosest
budget of any upstream here (see below). Implemented in
`internal/cymrudns/cymrudns.go`.

### PeeringDB API — organization names

Documentation: <https://www.peeringdb.com/apidocs/>

A single ASN is one `GET`:

```
https://www.peeringdb.com/api/org?asn=2906
```

The organization name is the `data[0].name` field. An optional
`PEERINGDB_API_KEY` is sent as `Authorization: Api-Key <key>` — a header, not
a URL parameter, so unlike WhoisFreaks previously, the key cannot leak into a
transport error and needs no redaction.

**Key verification at startup.** A wrong or expired key is worse than no key:
every lookup still succeeds — the key only raises a rate limit — while
`budgetFor` sees a non-empty key and selects the authenticated 15/min budget
for a process with no working credential. That is how this service would start
over-querying PeeringDB with nothing visibly broken.

So when `PEERINGDB_API_KEY` is set, `startPeeringDBKeyCheck` (`sources.go`)
verifies it once, in a goroutine, through the same per-host budget as every
other outbound call:

```
GET https://www.peeringdb.com/api/as_set/3856      →  48 bytes
{"data": [{"3856": "RADB::AS-PCH"}], "meta": {}}
```

The smallest authenticated `GET` the API offers — `/api/net?asn=…` is 142
bytes — for AS3856 (Packet Clearing House), chosen only because its record is
about as stable as PeeringDB records get. The response is discarded:
PeeringDB evaluates the credential *before* the lookup (a bad key against a
nonexistent ASN returns `401`, not `404`, confirmed against the live API), so
the status alone settles the question.

Only `peeringdb.ErrInvalidKey` — `401` or `403` — drops the key. The rejection
sets a process-wide flag read by `peeringDBAPIKey()`, which every call site
goes through instead of reading the environment, and calls `forgetLimiter` so
the cached `www.peeringdb.com` limiter is rebuilt at the anonymous 6/min rate
rather than keeping the authenticated one. A `404`, a `5xx`, or a timeout is
inconclusive and leaves the key alone; nothing retries, so disabling a good key
on a transient failure would cost the higher rate limit until the next restart.

**Batching (forced `src=peeringdb` only):** `/api/org` has no real `asn`
field — `asn=<n>` is a special single-value filter, and `asn__in` silently
ignores the list and returns PeeringDB's entire ~34,000-row org table instead
of filtering (confirmed against the live API, not assumed). `/api/net` does
have a real, properly `__in`-filterable `asn` field, so a batch is a two-step
join instead of one request: `/api/net?asn__in=<up to 150 ASNs>` maps each
ASN to an `org_id`, then `/api/org?id__in=<the distinct org_ids>` resolves
those to names.

Every forced `src=peeringdb` request goes through one function
(`lookupPeeringDBBatched` in `peeringdb_batch.go`), which checks whether a
round is already in flight: if nothing is, it calls the plain single-ASN
endpoint immediately — an uncontended request is never held waiting for
company. If something is, it queues and gets folded into the next round
along with whatever else queues up before that round fires. This is worth
recording because an earlier version got it wrong: it gated batching behind
a requests-per-second counter and let calls under it bypass this
coordination entirely, straight to the single-ASN endpoint — live
smoke-testing caught that a real concurrent burst could fragment into
several *uncoordinated* direct calls all racing each other for
PeeringDB's tight budget, rather than merging into the shared call batching
exists to produce. Routing every forced-peeringdb request through one place
with one piece of shared state is what makes "nothing else in flight" an
actual guarantee. Like the RIR whois `org:`-handle case above, a round —
however many ASNs it covers — spends exactly one budget token
regardless of how many ASNs it covers.

Implemented in `internal/peeringdb/peeringdb.go` (`LookupOrgName`,
`LookupOrgNames`) and `peeringdb_batch.go` (the batching/dispatch logic).

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
failing *ambiguously* — a budget refusal, a timeout, a malformed record,
anything short of both cheap sources confirming an empty result): 1 RADB
query, 1 Cymru DNS query, 1 PeeringDB call, 1 RDAP request, and 2 whois
queries — six upstream calls. The 20s request deadline covers all of them
together.

That worst case only applies when the outcome is genuinely unresolved,
though. If Cymru DNS and PeeringDB both return their own confirmed "no
record" answer (`cymrudns.ErrNotFound` / `peeringdb.ErrNotFound` — see
`resolveOrgName` in `cache.go`), the registries are skipped rather than
queried and (almost certainly) also come back empty: two upstream calls
total, not six. A budget refusal or any other ambiguous failure from either
cheap source does not trigger this — only an unambiguous confirmed-empty
result from both.

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
| **Team Cymru DNS zone** | No published number for the DNS zone itself (distinct from, and far looser than, its rate-limited whois-over-port-43 service, which this service does not use) — it's built for exactly this kind of high-volume bulk lookup. | [IP to ASN Mapping](https://www.team-cymru.com/ip-asn-mapping) |
| **PeeringDB** | Documented: **20 requests/minute per IP anonymous, 40/minute with an API key.** Stricter limits apply to repeated *identical* requests (2/min, or 1/hour above 100 KB) — not relevant here, since every request carries a different ASN. | [Work Within PeeringDB's Query Limits](https://docs.peeringdb.com/howto/work_within_peeringdbs_query_limits/) |

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
| Team Cymru DNS zone | 20/s | 40 | 8 | Built for high-volume bulk lookups, so it can run far looser than everything else here — see `cymruBudget`'s comment in `upstream.go`. |
| PeeringDB, anonymous | 6/min | 3 | 1 | Well under the documented 20/min, leaving headroom for the two-replica default and any other client sharing the egress IP. |
| PeeringDB, keyed | 15/min | 5 | 2 | Well under the documented 40/min the key unlocks. Selected automatically once `PEERINGDB_API_KEY` is set — see `budgetFor` in `upstream.go`. A key the startup check finds invalid drops back to the anonymous row above. |

A registry's whois and RDAP front ends share one budget: they are the same
service behind two protocols, and per-registry is how the registries themselves
count.

One nuance: an RIR whois lookup spends one token but may issue two queries when
it has to resolve an `org:` handle. The rates above account for that, and the
concurrency slot — which is what RIPE actually limits — is held across both. A
forced-`src=peeringdb` batch round (see the PeeringDB subsection above) is the
same idea applied further: however many ASNs it covers (up to 150), it still
spends exactly one token.

> **These budgets are per process.** The manifest runs `replicas: 2`, so a
> registry sees up to twice these rates. Halve them, or run a single replica, if
> a registry objects.

### When a budget is spent

Fail fast. The request is answered **`503` with `Retry-After`** derived from
when the bucket next refills, and the upstream is not contacted. Under
`src=auto`, a budget refusal from a *registry* (whois or RDAP) also stops the
fallback chain there: trying the other registry source would spend a second
registry's budget on a request the first already declined. Cymru DNS and
PeeringDB are exempt from that rule — they exist precisely to keep load off
the registries, so a refusal from either one falls through to the next source
instead of giving up.

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
2. **Caching.** Prefix lookups are cached for 5 minutes; organization names
   for 6 hours, since they change on the timescale of ASN reassignment, not
   minutes — a longer TTL here is itself a mitigation against the tightly-
   budgeted registries above. Failures are cached for 30 seconds either way.
   Without the negative cache, an ASN whose lookup fails could be replayed
   into one upstream query per request indefinitely. See
   [doc/caching.md](caching.md) for the full mechanics.
3. **Coalescing.** Concurrent requests for the same uncached ASN are collapsed
   into a single upstream query — 50 simultaneous requests for one cold ASN cost
   one query, not 50. This is what makes the budgets meaningful: without it the
   cache only helps requests arriving *after* an answer is stored, so a burst of
   misses scaled straight through to the upstream.

---

## Timeouts, body caps, and retries

| Upstream | Connect + read timeout | Body cap | On overrun |
| --- | --- | --- | --- |
| RADB | 15s | 20 MiB | Error (`radb.ErrTooLarge`). Deliberately not truncation: a short read would silently report fewer prefixes than the ASN originates. Sized to AS13335's measured 16.28 MB response. With `org=1` the request still returns an org name; only the prefix section is reported unavailable. |
| Team Cymru DNS zone | 5s | N/A — a DNS message's size is already bounded by the protocol, not by an application-level cap | Error (`LookupTXT` fails; there's nothing to truncate). |
| RIR whois | 15s | 1 MiB | Silent truncation. |
| RIR RDAP | 15s | 1 MiB | Silent truncation. Status is checked *before* the body is read, so a rate-limit response costs nothing to discover. |
| PeeringDB | 10s | 8 MiB | Silent truncation. Larger than the other HTTPS caps because a batch response (up to 150 net objects, some with multi-KB free-text fields) can be sizable; a single-ASN response is a few hundred bytes in practice. |

**There are no retries anywhere, by design.** A failed upstream call is
reported, not repeated. Retrying is how a service turns one upstream's bad
minute into a self-inflicted rate-limit block, and the failure cache already
prevents the client from retrying it into one.

All clients take a `context.Context` and are cancelled by it. The HTTPS
clients each share their own package-level transport (`MaxIdleConnsPerHost:
4`, `MaxConnsPerHost: 4`, `IdleConnTimeout: 90s`), so concurrent queries to a
registry reuse connections instead of paying a TLS handshake each, and
`MaxConnsPerHost` acts as a transport-level backstop under the budget.

The raw-WHOIS clients open one connection per query — port 43 has no
multiplexing — and close it on cancellation, so an abandoned request stops
occupying a connection slot the registry is counting.
