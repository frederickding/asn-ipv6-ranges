# Logging

Two streams, deliberately separate, mirroring nginx's `access.log` /
`error.log` split:

| Stream | Destination | Contents |
| --- | --- | --- |
| Access log | **stdout** | One line per request, no prefix |
| Operational | **stderr** | Startup, shutdown, cache sweeps, upstream pauses, periodic stats |

So they can be separated with a plain redirect:

```bash
./asn-ipv6-ranges 1>access.log 2>error.log
```

Configured by `ACCESS_LOG` (default `1`) and `ACCESS_LOG_PROBES` (default `0`).
A value that isn't a recognized boolean logs a warning and keeps the default —
misconfigured logging shouldn't stop the service from starting.

---

## Access log

On by default, in nginx's `common` log format:

```
$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
```

```
203.0.113.45 - - [16/Aug/2026:23:34:21 +0000] "GET /as/24940?org=1 HTTP/1.1" 200 446
127.0.0.1 - - [16/Aug/2026:23:34:20 +0000] "POST /as/2906 HTTP/1.1" 405 42
127.0.0.1 - - [16/Aug/2026:23:34:21 +0000] "HEAD /as/2906 HTTP/1.1" 200 0
```

Access lines do **not** go through Go's standard logger, which would prefix each
one with its own date and time and break the format for anything that parses
nginx logs.

- `$remote_user` is always `-`: the service has no authentication.
- `$body_bytes_sent` counts the body only, excluding headers, and is `0` for
  `HEAD` — matching nginx, since the body is discarded.
- The request line is escaped the way nginx escapes values (`"` and `\`
  backslash-escaped, control bytes as `\xHH`). Without this, a request target
  containing a quote could close the `"$request"` field early and forge the
  status and byte count, or inject an entire extra line.

**`/-/status` is excluded by default.** The liveness and readiness probes run
every 20s and 10s, so on a quiet pod they would outnumber real queries several
times over. Set `ACCESS_LOG_PROBES=1` to include them.

**Shed requests are logged.** The concurrency cap sits inside the access log
middleware, not in front of it, so a request refused with `503` produces a line
like any other. A burst of `503`s is exactly what an operator needs to see, and
losing it would make an overloaded pod look idle.

**Client address**: the left-most `X-Forwarded-For` entry is used when present,
otherwise the socket address with the port stripped — the equivalent of nginx's
realip module. This matters because the supplied Service uses
`externalTrafficPolicy: Cluster`, so MetalLB SNATs the caller and the socket
address is whichever node forwarded the packet. Note that `X-Forwarded-For` is
supplied by the caller and trivially spoofed: it is fine for attribution in a
log, and must never be treated as an authorization signal. The alternative is
`externalTrafficPolicy: Local`, which preserves the real source IP at the
network level.

Implemented in `accesslog.go`.

---

## Periodic stats

Every 5 minutes, plus once at startup for a baseline, to stderr:

```
2026/08/16 23:35:10 cache prefix=2/256 org=0/512 | mem heap=8.2MiB sys=35.2MiB rss=26.9MiB limit=80.0MiB gc=9
```

| Field | Meaning |
| --- | --- |
| `prefix`, `org` | Cache occupancy against each cache's own capacity — 256 for prefixes, 512 for organization names. A cache pinned at its limit means entries are being evicted; see [doc/caching.md](caching.md). |
| `heap` | Live heap (`HeapAlloc`). |
| `sys` | Total memory obtained from the OS. |
| `rss` | Resident set size, from `/proc/self/status`. This is what the kernel OOM-kills on and what a container memory limit governs; `heap` alone understates it. Omitted where `/proc` is unavailable. |
| `limit` | Current `GOMEMLIMIT`, for direct comparison against the manifest. Omitted when unset. |
| `gc` | Completed GC cycles. |

The sample above is a real trace: the heap rose to 8.2 MiB while parsing AS3356's
1.12 MB WHOIS response, then fell back to 1.4 MiB after the next GC.

Implemented in `stats.go`.

---

## Other operational lines

On stderr, via Go's standard logger:

```
2026/08/17 00:59:20 data sources: prefixes=whois.radb.net | org=asn.cymru.com (resolver 1.1.1.1:53 (default)), www.peeringdb.com (api key set, verifying), RIR whois, RDAP
2026/08/17 00:59:21 asn-ipv6-ranges v1.1.0 listening on :8080
2026/08/17 00:59:21 www.peeringdb.com: api key verified
2026/08/17 01:01:23 shutting down
2026/08/17 01:04:00 cache sweep removed 12 expired entries
2026/08/17 01:07:14 upstream rdap.lacnic.net rate-limited us, pausing queries until 2026-08-17T01:12:14Z
```

The data-sources line is the configuration inventory, logged before the
listener comes up. No source can be turned off — they are gated by per-host
rate budgets, not by configuration — so it is not a list of toggles; it exists
so a fresh pod's log answers the two questions its environment can get wrong:
which resolver Cymru lookups will use, and whether `PEERINGDB_API_KEY` was
picked up at all. The key itself is never logged, only its presence.

When a key is set, a background check verifies it and logs one of three
outcomes (see [networking.md](networking.md) for the endpoint and the rule):

```
2026/08/17 00:59:21 www.peeringdb.com: api key verified
2026/08/17 00:59:21 www.peeringdb.com: api key rejected (api key rejected: api returned 401: Invalid API key); it will not be used, continuing anonymously at the lower rate limit
2026/08/17 00:59:51 www.peeringdb.com: could not verify api key (context deadline exceeded); keeping it and continuing
```

The rejection line is worth alerting on. Nothing breaks when it appears —
PeeringDB never requires a key — but it means an operator believes they
configured something that is not in effect, and it will not be retried until
the process restarts.

The startup line carries the build, so a log stream alone is enough to tell
which version was serving at any point — useful for pinning a behaviour change
to a rollout. An unstamped local build reports `dev-<short sha>` there instead.
The same string is served by `/-/version`; see [version.md](version.md).

The rate-limit line is worth alerting on: it means a registry refused a query
because we were going too fast, and that source is parked until its `Retry-After`
elapses. See [networking.md](networking.md) for the budgets meant to prevent it.
