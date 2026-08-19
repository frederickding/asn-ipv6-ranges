# Caching

Answers are cached in memory so that repeated requests don't re-query the
registries, which strictly limit how often they can be asked. This page covers
what that means for you as a client: how old an answer can be, when you might
get an expired one, and what happens when a lookup fails.

[README.md](../README.md#caching) has the summary table.

---

## How current is an answer?

Every `/as/{asn}` response ends with the time the data was actually obtained:

```
# queried: 2026-08-16T12:00:00Z
```

That timestamp is the thing to trust — not the time of your request. Within
these windows, a repeat request is answered from memory and the timestamp
won't move:

| | Prefixes | Organization names (`org=1`) |
| --- | --- | --- |
| Freshness (TTL) | 5 minutes | 6 hours |
| Freshness, failures | 30 seconds | 30 seconds |
| Retention (max age) | 1 hour | 3 days |
| Capacity | 256 ASNs | 512 entries |

- **Freshness** is how long an answer is reused before the upstream is asked
  again. Prefixes stay short because an ASN's announcements can change at any
  time; organization names get 6 hours because an ASN's registered
  organization is stable for years, so asking more often buys nothing.
- **Freshness, failures** is the same idea for a lookup that failed — see
  [When a lookup fails](#when-a-lookup-fails).
- **Retention** is how long an entry is kept at all. It matters to you only as
  the hard limit on how old an expired answer can be during an outage, below.
- **Capacity** is how many entries fit before the least recently refreshed are
  dropped.

Aggregation is applied after caching, so `agg=0` and `agg=1` are answered from
the same stored data. Organization names are cached per `src`, so a `src=rdap`
answer is never handed to a request that asked for a different source.

---

## Expired answers during an outage

RADB is the only source of prefix data and the most tightly rate-limited
upstream here. When it can't be reached — it's down, unreachable, or has
temporarily cut us off — a recent-but-expired answer is served instead of an
error, and says so:

```
# queried: 2026-08-16T12:00:00Z (EXPIRED 18m ago)
```

The `EXPIRED` figure is how long ago the data went stale, not its total age;
the timestamp already tells you that. **Prefix data is never served more than
an hour old**, so past that point you get an error rather than something
misleading.

This is the default because an error helps nobody: you get no answer, and the
retry that follows costs RADB another query it just refused. An hour-old prefix
list is almost always the more useful response.

Two things it never does: it won't invent an answer for an ASN that has never
been looked up successfully, and it doesn't apply to organization names.

### Opting out with `stale=0`

If you cannot use data of unknown age, add `stale=0` and an upstream failure
comes back as an error instead:

```bash
curl 'http://localhost:8080/as/2906?stale=0'
```

Please use it only if you genuinely need it, and not as a default setting. The
normal behaviour is what keeps load off RADB; a client that always sends
`stale=0` turns every upstream hiccup back into an error plus a retry. It
changes only what you are shown — never what is stored, and never what anyone
else is served.

---

## When a lookup fails

A failure is remembered for **30 seconds**. Retrying inside that window returns
the same error without contacting the upstream, so immediate retries won't
help — wait half a minute.

The exception is a refusal from this service's own rate limiter, answered as
`503` with a `Retry-After` header. That isn't cached, and `Retry-After` tells
you exactly when to come back. See
[networking.md](networking.md#when-a-budget-is-spent).

An organization lookup that fails never sinks the prefix list; the response
reports the failure in a comment and returns the prefixes anyway.

---

## What the cache does not do

- **It doesn't survive a restart.** The cache is in memory only, so a restarted
  or redeployed instance begins cold and the first request for each ASN goes
  upstream again.
- **It isn't shared between instances.** Running more than one replica (the
  sample deployment runs two) means each holds its own cache, so two identical
  requests can land on different instances and return different `# queried:`
  timestamps. Both answers are valid; neither is more current than its
  timestamp says.
- **It doesn't hold every ASN forever.** Once capacity is reached, an ASN
  nobody has asked about for a while is dropped to make room. The only effect
  is that the next request for it is slower. `GET /-/status` reports current
  occupancy against the limits.

---

## Sending a burst of requests

Concurrent requests for the same ASN are combined into a single upstream query
— 50 simultaneous requests for one uncached ASN cost one query, not 50. You
don't need to stagger or de-duplicate requests on your side to be a good
citizen.

Requests for *different* uncached ASNs each need their own upstream query, and
that is where the rate limits in [networking.md](networking.md) apply.

---

## Memory

A full prefix cache is the largest thing this service holds: roughly 9 MB for
256 typical ASNs, and 51 MB in a deliberately extreme test. The organization
cache is negligible beside it. See [README.md](../README.md#memory) for sizing
a container against this.
