# Versioning

How this binary knows what it is, and how that string gets there.

The problem it solves: a container tag lives outside the artifact. A pod running
`asn-ipv6-ranges:v1.0.0` tells you what someone *named* the image, not what was
built into it. Without a version inside the binary, a manifest pinning `:v1.0.0`
while the deployed build is actually something else is invisible.

---

## Where a version can be reported

Three surfaces, all reporting the same string.

### `GET /-/version`

```bash
curl http://localhost:8080/-/version
```

```json
{
  "version": "v1.1.0",
  "revision": "b2bb7ae57e96621a6cf5a0cdb577457ab99a92b1",
  "modified": true,
  "go": "go1.24.4"
}
```

| Field | Meaning | When absent |
| --- | --- | --- |
| `version` | The release name, or a `dev` fallback. Always present. | — |
| `revision` | Full commit hash, from Go's automatic VCS stamping. | Container builds — see [below](#why-the-tag-has-to-be-passed-in). |
| `modified` | The working tree had uncommitted changes at build time. | Omitted when false or unknown. |
| `go` | Toolchain that compiled it. Confirms a pod picked up a patched runtime. | — |

The handler performs no I/O and takes no locks, so it answers even while every
upstream is unreachable — which is exactly when you want to know which build is
live. It carries `Cache-Control: no-store`, since a cached response would name
the *previous* deploy.

It is deliberately **not** exempt from `MAX_INFLIGHT`, unlike `/-/status`. See
[networking.md](networking.md#server-limits).

### `-version`

The image `ENTRYPOINT` is the binary, so this interrogates an image without
starting a server:

```bash
docker run --rm ghcr.io/<owner>/asn-ipv6-ranges:v1.1.0 -version
```

```
v1.1.0
```

Prints `version` alone, to stdout, and exits 0. `--version` works identically.

> Introducing flag parsing means unrecognized arguments are now **rejected**
> rather than ignored. `docker run <image> --whatever` exits non-zero where it
> previously started the server.

### The startup log line

```
2026/08/17 03:33:02 asn-ipv6-ranges v1.1.0 listening on :8080
```

So a log stream alone is enough to attribute a behaviour change to a rollout.
See [logging.md](logging.md).

---

## Why the tag has to be passed in

Go stamps build metadata automatically, and it is *almost* enough — but not
quite, for two independent reasons.

**1. Go records the revision, never the tag.** `debug.ReadBuildInfo()` yields
`vcs.revision`, `vcs.time`, and `vcs.modified`. There is no `vcs.tag`.
`BuildInfo.Main.Version` looks promising and is not: it is `(devel)` for
anything not fetched as a module via `go install <module>@<version>`.

**2. In a container build there is no repository at all.** `.dockerignore`
excludes `.git`, and the Dockerfile copies only `go.mod`, `*.go`, and
`internal/`. Go finds no VCS directory, emits no VCS block, and does not error.
This is why `revision` and `modified` are absent from a container's
`/-/version` response.

So the release name is passed **into** the build as a `VERSION` argument and
linked in:

```
Dockerfile ARG VERSION ─→ -ldflags "-X main.version=$VERSION" ─→ var version string
```

---

## How the version is resolved

`resolveBuild` in `version.go`, in strict precedence order:

1. **Linker-stamped `version`**, if non-empty. It is the only input carrying a
   release name, so it wins outright — including over VCS data, which it is
   then reported alongside.
2. **`dev-<short revision>`**, from Go's automatic stamping. This is what a
   developer building locally gets, and it identifies the commit exactly.
3. **`dev`**, when there is neither. An unstamped container build.

A dirty tree appends `-dirty`, because a modified working tree cannot be
reproduced from the revision alone and the hash would otherwise promise more
than it can deliver.

| Build | `VERSION` passed | Reports |
| --- | --- | --- |
| GitLab tag job | `$CI_COMMIT_TAG` | `v1.1.0` |
| GitHub Actions | `github.ref_name` | `v1.1.0` |
| GitLab branch job | `$VERSION_TAG` (`<date>-<short sha>`) | `20260817-b2bb7ae` |
| `docker build` with no arg | `dev` (Dockerfile default) | `dev` |
| `go build` in a clone | none | `dev-b2bb7ae`, `-dirty` if modified |

---

## The rule CI follows

**The stamped version is the image tag.** Every pipeline computes one string,
passes it as `--build-arg VERSION=`, and tags the pushed image with that same
string. That is what makes `/-/version` name the exact image to pull rather than
merely resembling it.

### GitLab — `.gitlab-ci.yml`

Both jobs take the same shape, with `VERSION_TAG` computed *before* the build so
it can be passed into it:

```yaml
- export VERSION_TAG="$CI_COMMIT_TAG"          # or <date>-<short sha> on branches
- podman build --build-arg VERSION="$VERSION_TAG" -t "$IMAGE_NAME" .
- podman tag "$IMAGE_NAME" "$IMAGE_NAME:$VERSION_TAG"
```

Not `git describe`: GitLab clones shallow by default and does not fetch tags, so
it would fail or silently degrade unless `GIT_DEPTH: 0` were also set.
`VERSION_TAG` is already exact.

### GitHub Actions — `.github/workflows/docker-publish.yml`

```yaml
build-args: |
  VERSION=${{ github.ref_name }}
```

`github.ref_name` is the tag verbatim for both triggers this workflow fires on
(`push` to `v*.*.*` and `release: published`).

### Keeping the two consistent

**A given git tag must report identically whichever CI built it.** GitLab's
`$CI_COMMIT_TAG` is the tag verbatim — `v1.1.0`, `v` included — so GitHub is
configured to match, which takes two deliberate choices rather than one:

| | Tempting | Actually used | Why |
| --- | --- | --- | --- |
| Build arg | `steps.meta.outputs.version` | `github.ref_name` | The former is `1.1.0`; `type=semver,pattern={{version}}` strips the `v`. |
| Image tags | `pattern={{version}}` | `pattern=v{{version}}` | Same stripping, so GitHub would push `:1.1.0` while GitLab pushes `:v1.1.0`. |

Net result, end to end:

```
git tag v1.1.0  ─→  image tag v1.1.0  ─→  binary reports v1.1.0
```

If you ever prefer the unprefixed `1.1.0` convention, both sides have to change
together — the GitHub `pattern=` values *and* GitLab's `VERSION_TAG`. Changing
one alone reintroduces exactly the split this table exists to prevent.

---

## Building a stamped binary yourself

```bash
go build -ldflags="-X main.version=$(git describe --tags)" -o asn-ipv6-ranges .
```

```bash
docker build --build-arg VERSION=v1.1.0 -t asn-ipv6-ranges:v1.1.0 .
```

`-trimpath` (which the Dockerfile uses) does not interfere with `-X`.

Omitting the flag is fine and honest — you get the `dev-<sha>` fallback, which
is more useful for local work than a stale tag would be.
