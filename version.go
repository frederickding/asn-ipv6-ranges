package main

import (
	"encoding/json"
	"net/http"
	"runtime"
	"runtime/debug"
)

// versionPath reports what this binary is. It shares the /-/ operational prefix
// with statusPath, but it is not a probe: unlike /-/status it stays subject to
// the in-flight cap in limits.go and stays in the access log, because nothing
// polls it on an interval and an unauthenticated endpoint should not get a free
// pass past the shed limit.
const versionPath = "/-/version"

// version is the release this binary was built from, set at link time:
//
//	go build -ldflags="-X main.version=v1.1.0"
//
// which is what the Dockerfile does with its VERSION build argument, fed by
// $CI_COMMIT_TAG on GitLab and github.ref_name on GitHub Actions. Left empty —
// a plain `go build` — resolveBuild falls back to the VCS data Go stamps on its
// own, so an unstamped binary still identifies the commit it came from.
var version string

// buildInfo is this binary's identity, as served by /-/version.
type buildInfo struct {
	Version  string `json:"version"`
	Revision string `json:"revision,omitempty"`
	Modified bool   `json:"modified,omitempty"`
	Go       string `json:"go"`
}

// build is resolved once at startup; the answer cannot change while the process
// runs.
var build = readBuild()

func readBuild() buildInfo {
	bi, ok := debug.ReadBuildInfo()
	return resolveBuild(version, bi, ok)
}

// shortRevision is how many hex digits of a commit hash to report, matching
// git's own abbreviation.
const shortRevision = 7

// resolveBuild determines what this binary should call itself.
//
// A linker-stamped tag wins outright: it is the only input that carries a
// release name, because Go's automatic VCS stamping records the revision, time,
// and dirty flag but never the tag. (BuildInfo.Main.Version is likewise no help
// — it is "(devel)" for anything not fetched as a module.)
//
// Failing that, the VCS data identifies the commit, which is what a developer
// building locally actually wants. A container build has neither: .dockerignore
// excludes .git and the Dockerfile copies only sources, so Go emits no VCS block
// there and an unstamped image honestly reports "dev".
//
// Split out as a pure function so the precedence can be tested without
// producing real builds, in the same spirit as the nowFunc and readMem seams.
func resolveBuild(stamped string, bi *debug.BuildInfo, ok bool) buildInfo {
	b := buildInfo{Version: stamped, Go: runtime.Version()}

	if ok && bi != nil {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				b.Revision = s.Value
			case "vcs.modified":
				b.Modified = s.Value == "true"
			}
		}
	}

	if b.Version != "" {
		return b
	}

	b.Version = "dev"
	if b.Revision != "" {
		rev := b.Revision
		if len(rev) > shortRevision {
			rev = rev[:shortRevision]
		}
		b.Version += "-" + rev
	}
	// A dirty tree cannot be reproduced from the revision alone, so say so
	// rather than letting the hash imply more than it can promise.
	if b.Modified {
		b.Version += "-dirty"
	}
	return b
}

// versionHandler serves the build identity as JSON.
//
// It performs no I/O and touches no shared state, so it answers even when every
// upstream is unreachable — the point is to identify the running image, which
// has to work precisely when something is wrong.
func versionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, http.StatusMethodNotAllowed, "method %s not allowed, use GET", r.Method)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// The value is constant per process but changes on deploy, and this is the
	// endpoint an operator uses to confirm which build is live. A cached answer
	// would defeat that.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	// buildInfo holds only strings and a bool, so encoding cannot fail for any
	// reason but a dead connection, which there is nothing useful to do about.
	_ = enc.Encode(build)
}
