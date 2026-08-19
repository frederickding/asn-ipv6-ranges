# Notes for Claude

## Releases are published on GitHub, not GitLab

This is counterintuitive, so check here before acting on it: **GitLab is the
working development repository, but releases live on GitHub.**

- Development, merge requests, and CI: <https://gitlab.fjd.io/frederick/asn-ipv6-ranges>
- Releases: <https://github.com/frederickding/asn-ipv6-ranges/releases>

GitLab push-mirrors to GitHub, so commits and tags reach GitHub on their own
and nothing needs pushing there by hand.

Consequences worth remembering:

- **Do not propose creating GitLab Releases.** The project deliberately has
  none; an empty releases list there is the expected state, not a gap to fill.
- Tagging still happens on GitLab (typically from the web UI, against the
  current state of `main`). The tag mirrors to GitHub, where
  `.github/workflows/docker-publish.yml` builds and publishes the image to
  `ghcr.io` on `v*.*.*` tags and on published releases. GitLab CI builds its
  own image to the GitLab registry from the same tag.
- `CHANGELOG.md` is the source text for a GitHub release's notes. Because a tag
  captures the tree as it was, rename its `## Unreleased` heading to the
  version in a commit *before* creating the tag, or the tagged tree will
  describe that release's changes as unreleased.

## Documentation is written for a homelab user, not a coder

When writing or editing any `.md` file, keep it **concise** and describe **what
the service does and why it matters to someone running it** — not how the code
achieves it.

- Write for someone self-hosting this who is not a Go developer: what a
  parameter does for them, what an error means, what to set and why.
- Leave implementation detail — types, function names, control flow, internal
  refactors — in the code and its comments, where it is already explained.
- Prefer the shortest version that stays accurate. If a paragraph only tells the
  reader how something is built, cut it.

This governs new and edited prose. It is not a standing instruction to rewrite
pages that already exist.

## Kubernetes manifests pin the GitHub image at minor version

Canonical image references in `deploy/kubernetes/*.yaml` use the GitHub-built
image published to `ghcr.io` by `.github/workflows/docker-publish.yml`:

<https://github.com/frederickding/asn-ipv6-ranges/pkgs/container/asn-ipv6-ranges>

```yaml
image: ghcr.io/frederickding/asn-ipv6-ranges:v1.1
```

**Pin the minor version (`v1.1`), not the patch (`v1.1.2`)** — the manifests
should not need editing on every release. The workflow publishes both
`type=semver,pattern=v{{version}}` and `type=semver,pattern=v{{major}}.{{minor}}`,
so each patch release moves the `v1.1` tag forward and the manifests keep
working untouched. Bump them only when the minor version changes.

**`ghcr.io` is the canonical registry.** GitLab CI builds and pushes its own
image from the same tag, but that registry may not be publicly reachable, so it
is never the reference to publish, document, or put in a manifest — even though
GitLab is where the build was triggered.
