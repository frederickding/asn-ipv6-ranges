package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

// vcs builds the BuildInfo Go stamps automatically, so the fallback path can be
// exercised without producing a real build.
func vcs(settings ...debug.BuildSetting) *debug.BuildInfo {
	return &debug.BuildInfo{Settings: settings}
}

func setting(k, v string) debug.BuildSetting {
	return debug.BuildSetting{Key: k, Value: v}
}

// TestResolveBuild pins the precedence: a linker-stamped tag is the only input
// that carries a release name, so it must win over VCS data, and the absence of
// both must be reported honestly rather than guessed at.
func TestResolveBuild(t *testing.T) {
	const sha = "9fbe999abc1234567890"

	tests := []struct {
		name    string
		stamped string
		bi      *debug.BuildInfo
		ok      bool
		want    string
		wantRev string
		wantMod bool
	}{
		{
			name:    "stamped tag wins over VCS data",
			stamped: "v1.1.0",
			bi:      vcs(setting("vcs.revision", sha), setting("vcs.modified", "true")),
			ok:      true,
			want:    "v1.1.0",
			wantRev: sha,
			wantMod: true,
		},
		{
			name:    "stamped tag with no VCS data at all, as in a container build",
			stamped: "v1.1.0",
			bi:      nil,
			ok:      false,
			want:    "v1.1.0",
		},
		{
			name:    "unstamped falls back to the abbreviated revision",
			bi:      vcs(setting("vcs.revision", sha)),
			ok:      true,
			want:    "dev-9fbe999",
			wantRev: sha,
		},
		{
			name:    "a dirty tree says so, since the hash alone cannot reproduce it",
			bi:      vcs(setting("vcs.revision", sha), setting("vcs.modified", "true")),
			ok:      true,
			want:    "dev-9fbe999-dirty",
			wantRev: sha,
			wantMod: true,
		},
		{
			name: "unstamped with nothing to fall back on",
			bi:   nil,
			ok:   false,
			want: "dev",
		},
		{
			name:    "a revision shorter than the abbreviation is not truncated past its end",
			bi:      vcs(setting("vcs.revision", "abc")),
			ok:      true,
			want:    "dev-abc",
			wantRev: "abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveBuild(tt.stamped, tt.bi, tt.ok)
			if got.Version != tt.want {
				t.Errorf("Version = %q, want %q", got.Version, tt.want)
			}
			if got.Revision != tt.wantRev {
				t.Errorf("Revision = %q, want %q", got.Revision, tt.wantRev)
			}
			if got.Modified != tt.wantMod {
				t.Errorf("Modified = %v, want %v", got.Modified, tt.wantMod)
			}
			if got.Go != runtime.Version() {
				t.Errorf("Go = %q, want %q", got.Go, runtime.Version())
			}
		})
	}
}

// swapBuild substitutes the resolved build identity for one test.
func swapBuild(t *testing.T, b buildInfo) {
	t.Helper()
	orig := build
	build = b
	t.Cleanup(func() { build = orig })
}

func TestVersionHandler(t *testing.T) {
	clock := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	swapTestHooks(t, &clock, func(string) (string, error) {
		t.Error("the version endpoint queried an upstream")
		return "", errors.New("unexpected upstream query")
	})
	swapBuild(t, buildInfo{Version: "v1.1.0", Revision: "9fbe999abc", Go: "go1.24.4"})

	rec := httptest.NewRecorder()
	versionHandler(rec, httptest.NewRequest(http.MethodGet, versionPath, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("got content-type %q", ct)
	}
	// An intermediary caching this would report the previous deploy.
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("got cache-control %q, want no-store", cc)
	}

	var got buildInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body is not valid JSON: %v\n%s", err, rec.Body.String())
	}
	if got.Version != "v1.1.0" {
		t.Errorf("version = %q, want v1.1.0", got.Version)
	}
	if got.Revision != "9fbe999abc" {
		t.Errorf("revision = %q", got.Revision)
	}
	if got.Go != "go1.24.4" {
		t.Errorf("go = %q", got.Go)
	}
}

// TestVersionHandlerOmitsEmptyVCSFields covers the container case: no .git in
// the build context means no revision, and reporting `"revision": ""` would
// imply the field was looked up and found empty.
func TestVersionHandlerOmitsEmptyVCSFields(t *testing.T) {
	clock := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	swapTestHooks(t, &clock, func(string) (string, error) { return sampleWhois, nil })
	swapBuild(t, buildInfo{Version: "v1.1.0", Go: "go1.24.4"})

	rec := httptest.NewRecorder()
	versionHandler(rec, httptest.NewRequest(http.MethodGet, versionPath, nil))

	body := rec.Body.String()
	for _, absent := range []string{"revision", "modified"} {
		if strings.Contains(body, absent) {
			t.Errorf("expected %q to be omitted from:\n%s", absent, body)
		}
	}
}

func TestVersionHandlerMethods(t *testing.T) {
	clock := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	swapTestHooks(t, &clock, func(string) (string, error) { return sampleWhois, nil })

	t.Run("HEAD is allowed", func(t *testing.T) {
		rec := httptest.NewRecorder()
		versionHandler(rec, httptest.NewRequest(http.MethodHead, versionPath, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("got status %d, want 200", rec.Code)
		}
	})

	t.Run("POST is rejected", func(t *testing.T) {
		rec := httptest.NewRecorder()
		versionHandler(rec, httptest.NewRequest(http.MethodPost, versionPath, nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("got status %d, want 405", rec.Code)
		}
		if allow := rec.Header().Get("Allow"); allow != "GET, HEAD" {
			t.Errorf("got Allow %q", allow)
		}
	})
}

// TestVersionRouting checks the mux wiring, and in particular that /-/version
// and /-/status stay distinct exact paths rather than one swallowing the other.
func TestVersionRouting(t *testing.T) {
	clock := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	swapTestHooks(t, &clock, func(string) (string, error) { return sampleWhois, nil })
	swapBuild(t, buildInfo{Version: "v1.1.0", Go: "go1.24.4"})

	mux := http.NewServeMux()
	mux.HandleFunc("/as/", asHandler)
	mux.HandleFunc(statusPath, statusHandler)
	mux.HandleFunc(versionPath, versionHandler)

	tests := []struct {
		path       string
		wantStatus int
		wantBody   string
	}{
		{versionPath, http.StatusOK, `"version": "v1.1.0"`},
		{statusPath, http.StatusOK, "ok"},
		{"/-/version/extra", http.StatusNotFound, ""},
		{"/-/", http.StatusNotFound, ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))
			if rec.Code != tt.wantStatus {
				t.Errorf("got status %d, want %d", rec.Code, tt.wantStatus)
			}
			if tt.wantBody != "" && !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Errorf("missing %q in:\n%s", tt.wantBody, rec.Body.String())
			}
		})
	}
}

// TestStatusDoesNotReportVersion guards a deliberate decision: the version is
// served from its own endpoint, not folded into the health check.
func TestStatusDoesNotReportVersion(t *testing.T) {
	clock := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	swapTestHooks(t, &clock, func(string) (string, error) { return sampleWhois, nil })
	swapBuild(t, buildInfo{Version: "v9.9.9-sentinel", Go: "go1.24.4"})

	rec := httptest.NewRecorder()
	statusHandler(rec, httptest.NewRequest(http.MethodGet, statusPath, nil))

	if strings.Contains(rec.Body.String(), "9.9.9") {
		t.Errorf("/-/status leaked the version:\n%s", rec.Body.String())
	}
}
