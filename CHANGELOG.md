# Changelog

What changed for anyone using the service, per release. Technical detail lives
in the commit history and `doc/`.

## Unreleased

- **Organization lookups no longer need a paid API key.** The WhoisFreaks API
  is replaced by Team Cymru's DNS zone and PeeringDB, both free and neither
  requiring credentials. `PEERINGDB_API_KEY` is optional and only raises a rate
  limit.
- **`src=api` is gone**, replaced by `src=cymru` and `src=peeringdb`
  (`src=dns` is accepted as an alias for `src=cymru`). A request still using
  `src=api` is now rejected as invalid.
- **Prefix results survive an upstream outage.** When RADB is unreachable or
  rate-limited, an expired-but-retained result is served with `200` instead of
  an error, marked `# queried: <timestamp> (EXPIRED 18m ago)`. Opt out per
  request with `stale=0`.
- **Very large ASNs now answer.** The response cap rose to 20 MiB, covering the
  largest real networks; if it is still exceeded with `org=1`, the organization
  name is returned rather than the whole request failing.
- **Faster "no record" answers.** When both free sources agree an ASN has no
  organization record, the registries are no longer queried.
- **A misconfigured PeeringDB key is caught at startup**, reported in the log,
  and ignored for the rest of the run instead of silently degrading lookups.
  Enabled data sources are now logged at startup.

## v1.1.2 — 2026-08-17

_Refactor: no client-facing or API changes._

- Organization names are cached for 6 hours instead of 5 minutes, cutting
  steady-state query load against the registries that limit it most tightly.
- Inbound concurrency limit corrected to match the real upstream ceiling, so
  the advertised capacity reflects what the service can actually serve.
- Container memory limit raised for headroom under worst-case load.

## v1.1.1 — 2026-08-17

- **New `GET /-/version` endpoint**, plus a `-version` flag and a startup log
  line, so a running instance reports exactly which build it is — answerable
  even while every upstream is down.
- Released images carry the version they were built from, so the image tag and
  the binary can no longer disagree.
- Unrecognized command-line arguments are now rejected rather than ignored.

## v1.1.0 — 2026-08-17

- **Per-upstream query budgets** keep the service inside the registries'
  published and reported rate limits regardless of inbound traffic.
- A spent budget answers `503` with `Retry-After` instead of contacting the
  upstream, so clients are told when to come back.
- An upstream that pushes back (`429`, or a registry's own rate-limit refusal)
  parks that source until its own `Retry-After` elapses.
- Excess concurrent requests are shed rather than queued.

## v1.0.0 — 2026-08-17

First tagged release.

- **`GET /as/{asn}`** returns an ASN's registered IPv6 prefixes as plain text,
  sourced from RADB.
- `agg` (default on) removes prefixes already covered by a broader one.
- `org=1` adds the ASN's registered organization name, with `src` selecting the
  source: `auto`, `api`, `whois`, or `rdap`. An organization lookup that fails
  never sinks the prefix list.
- ASNs outside the IANA-delegated ranges — unallocated, reserved, or private —
  are rejected with `400` without any upstream query.
- Results are cached, and concurrent requests for the same ASN are collapsed
  into a single upstream query.
- **`GET /-/status`** reports uptime and cache occupancy for probes and
  monitoring; access logs cover every request.
