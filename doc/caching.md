# Caching

Two independent in-memory caches: one for prefix lists, one for organization
names. [README.md](../README.md#caching) has the summary table. This covers
why the bounds differ, how eviction runs, how coalescing works, and memory
cost.

Implemented in `cache.go`.

---

## The bounds, per cache

Three separate limits apply to each cache, and they do different jobs:

| | Prefix cache | Org cache |
| --- | --- | --- |
| Freshness (TTL) | 5 minutes | 6 hours |
| Freshness, failures | 30 seconds | 30 seconds |
| Retention (max age) | 1 hour | 3 days |
| Capacity | 256 ASNs | 512 entries |

- **Freshness** is how long an entry is served without a new upstream query.
  Past it, the next request for that key triggers a re-query.
- **Retention** is a hard delete, independent of whether anything asked for
  the entry again. Only entries nobody has successfully refreshed reach this
  age — it exists to reclaim an ASN that was queried once and never again,
  which freshness alone wouldn't do, since a stale-but-present entry just sits
  there until something either refreshes or deletes it.
- **Capacity** is the memory backstop. Without it, the maps would grow with
  the number of distinct ASNs ever queried across the process's lifetime —
  scanning the allocated AS space would be an unbounded allocation.
- **Failure TTL** is shared between the two caches: a failed lookup is
  remembered for only 30 seconds, far shorter than a successful one. See
  [Negative caching](#negative-caching-and-what-is-never-cached) below.

**Retention must stay above freshness**, or an entry would be deleted before
it ever goes stale — forcing a needless re-query and quietly defeating the
TTL. Both caches keep roughly the same ~12x margin between the two (1h / 5m
for prefixes, 3d / 6h for org names), which is a safety margin against thrash
near the boundary rather than a value with independent meaning of its own.

### Why the org cache is different

An ASN's announced IPv6 prefixes can change whenever the operator updates
their routing — a 5-minute TTL is about not missing that for long. An ASN's
*registered organization*, by contrast, is stable on the timescale of RIR
allocation: assignments run for years, and an org name changing at all
usually means the ASN itself changed hands. Treating it like the prefix data —
re-querying every 5 minutes — bought no real freshness and cost real upstream
traffic against exactly the registries [doc/networking.md](networking.md)
budgets most carefully: LACNIC's org lookups (~100 queries/5 min published)
and RIPE's whois AUP (3 simultaneous connections) are both reached through
`getOrgName`, never `getPrefixes`. A 6-hour TTL is itself a rate-limit
mitigation, on top of the budgets and coalescing described there — one query
per ASN per source per six hours, instead of one every five minutes, is a
~72x reduction in steady-state org-lookup traffic.

The org cache's capacity is correspondingly larger — 512 vs. 256 — partly
because it's cheap to: an entry here is an organization name and a source
string, not a prefix list, so doubling it costs single-digit kilobytes, not
megabytes. See [Memory](#memory) below.

---

## Eviction mechanics

Enforced by the generic `pruneLocked[K, V]`, called with each cache's own
`maxAge` and `maxEntries`:

1. **Age sweep.** Every entry older than `maxAge` is deleted outright, except
   the one just written (see below).
2. **Capacity sweep.** If the map is still over `maxEntries`, the least
   recently refreshed entry is dropped, repeated until it fits. "Recently
   refreshed" is the entry's stored timestamp — rewritten only when a request
   actually triggers a new upstream query, so an entry served repeatedly from
   cache within its TTL doesn't count as freshly touched for eviction
   purposes.

The entry just written by the current request is always exempt from both
sweeps: having just paid for the upstream query, discarding the result
immediately would be pointless. This is why a full cache never fails to cache
its own most recent answer, even mid-eviction.

Pruning runs **on every insert** — the cost is bounded by `maxEntries`, so
it's a scan of at most a few hundred entries on a path that has already done
network I/O. That covers a pod under steady traffic, but not an idle one: with
no requests arriving, there's no insert to trigger a prune, so a quiet pod
would hold its last `maxEntries` entries indefinitely. A background reaper
(`startCacheReaper`, `sweepCaches`) covers that case, sweeping both caches
once a minute regardless of traffic — retention shouldn't depend on someone
happening to make a request.

---

## Serving stale entries

Freshness and retention are deliberately far apart — 5 minutes against 1 hour
for the prefix cache — so for roughly 55 minutes an entry is *present but not
served*: too old to answer with, too young to delete. That window is free data,
and when RADB cannot be reached it is the difference between an answer and an
error.

**By default, any prefix lookup failure falls back to it.** A spent RADB
budget, a refused connection, a timeout, an oversized response — if the entry
still holds prefixes, they are served with `200` instead of the `502`/`503`/
`504` the failure would otherwise produce. The response says so on the line
that already reports when the data was obtained:

```
# queried: 2026-08-16T12:00:00Z (EXPIRED 18m ago)
```

The duration is time since the TTL expired, not the age of the data — the
timestamp already gives you that.

This is the cheapest possible response: it costs RADB nothing. RADB is the
narrowest upstream in the service (2 qps, concurrency 3, and the only source of
prefixes), so the alternative is worse than it looks — an error denies the
client an answer *and* invites the retry that costs another query.

Two bounds still hold:

- **Retention is enforced on the fallback.** An entry past `maxAge` is never
  served, even though lazy sweeping means it may still be sitting in the map.
  Serving it would make the documented bound meaningless.
- **A cold failure is still a failure.** The fallback only softens failures for
  ASNs already answered once; a first-ever query that fails has nothing to fall
  back to.

### How a failure keeps the data it replaces

A cached failure used to overwrite the entry outright, which destroyed exactly
the data the fallback needs. So `cacheEntry` carries both, with two timestamps:

- `queriedAt` — when the prefixes were obtained. Drives the TTL, the retention
  sweep, and the `# queried:` line.
- `failedAt` — when the most recent attempt failed. Drives `failureTTL` alone.

That separation is what lets one entry mean *"here are prefixes from 18 minutes
ago, and the attempt to refresh them 5 seconds ago failed"*. Negative caching
keeps working — the failure still suppresses re-queries for 30 seconds — while
the data survives to answer them.

The alternative, simply not writing the failure so the good entry survives,
was rejected: it abandons negative caching for that ASN, so every request
during an outage re-queries RADB until the budget is spent. That is the
hammering this exists to prevent.

### `stale=0`

A client that must not be given expired data can opt out per request:

```bash
curl 'http://localhost:8080/as/2906?stale=0'
```

It restores the old behaviour exactly — the upstream failure is returned as
`502`/`503`/`504`, with `Retry-After` on a spent budget. It generates no extra
upstream traffic to do so: a request that opts out still respects the cached
failure and simply reports it rather than re-querying.

**This parameter is documented here and not in the [README](../README.md), on
purpose.** The default is what protects RADB. A client that sets `stale=0` as a
matter of course converts every upstream hiccup back into an error plus the
retry that follows it — which is the load the default exists to avoid. It is
here for the caller who genuinely cannot use data of unknown age, not as a
general-purpose knob.

It is read-only with respect to the cache: `stale=0` changes what one request
is *shown*, never what is stored, so it cannot affect what another client is
served.

---

## Coalescing

Concurrent first-time requests for the same key — an ASN for the prefix
cache, an `{asn, src}` pair for the org cache — are collapsed into one
upstream query. A generic single-flight `group[K, T]` tracks in-flight calls
by key; the first request becomes the leader and does the real work, and
every other request for the same key waits on the leader's result instead of
starting its own.

Concretely: 50 simultaneous requests for one cold ASN produce exactly one
upstream WHOIS query, not 50. This is what makes the upstream budgets in
[doc/networking.md](networking.md) hold in practice — without it, the cache
only helps requests that arrive *after* an answer is already stored, so a
burst of concurrent misses (a bot hammering one ASN, or a fleet of clients
starting cold at once) would scale straight through to the upstream, one
query per request.

A follower observes the leader's own context being cancelled — if the leader
itself gives up, followers see that failure too — but a follower's own
cancellation never cancels the leader or the other followers still waiting on
it. The org cache is keyed by `{asn, src}` specifically so a `src=rdap`
request is never coalesced with (and never served the answer of) an `auto` or
`src=whois` request for the same ASN; the response always reports the source
that actually answered.

---

## Negative caching, and what is never cached

A failed lookup is cached too, for the much shorter `failureTTL` (30 seconds,
shared by both caches) — without this, an ASN that cannot be resolved, or one
chosen specifically because it fails, would be re-queried on every single
request, turning inbound rate directly into upstream rate with the cache
contributing nothing.

For the prefix cache this suppresses the *query*, not the *answer*: a cached
failure sitting on top of expired-but-retained prefixes still serves them, so
the 30 seconds cost nobody an answer. See
[Serving stale entries](#serving-stale-entries).

Not every failure is cacheable, though — `cacheable(ctx, err)` excludes two
kinds:

- **Context cancellation or deadline** (`context.Canceled`,
  `context.DeadlineExceeded`, or `ctx.Err() != nil`). A cancelled request
  says nothing about the ASN itself — caching it would deny the next,
  unrelated caller an answer they could otherwise have had.
- **A refusal from this service's own rate limiter**
  (`ratelimit.ErrLimited`). The limiter already backs off on its own terms;
  caching its refusal on top would compound two independent backoffs for no
  reason.

Both exclusions matter for the same principle: only the *upstream's own
answer* — success or a real failure it returned — is worth remembering. See
`budgetError` and `withUpstreamBudget` in `upstream.go` for how a spent budget
surfaces as this kind of non-cacheable error.

---

## Memory

The prefix cache dominates the memory story; the org cache barely registers.
Measured, for the prefix cache specifically:

| Scenario | RSS |
| --- | --- |
| 256 cached ASNs, 50 IPv6 prefixes each (typical) | ~9 MB |
| 256 cached ASNs, 2000 prefixes each (far beyond any real ASN) | 51 MB |

The org cache's 512-entry capacity — double the prefix cache's — adds
negligible memory on top of either figure: an entry is an organization name
and a source string, not a prefix list, so even a full org cache is on the
order of tens of kilobytes rather than megabytes. Doubling its capacity from
256 to 512 was effectively free.

See [README.md](../README.md#memory) for the request-concurrency side of the
memory budget (`MAX_INFLIGHT`, the per-response body cap, and how they relate
to the Kubernetes `limits.memory`/`GOMEMLIMIT` settings) — that part is
unrelated to cache sizing and unaffected by anything on this page.
