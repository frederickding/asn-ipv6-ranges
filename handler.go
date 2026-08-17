package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"asn-ipv6-ranges/internal/radb"
)

// requestTimeout bounds all the upstream work one request may do.
//
// An org lookup can try three sources in turn, each with its own 10-15s client
// timeout, so without an overall budget a single request could hold a goroutine
// and its buffers for over a minute. This is deliberately shorter than the
// server's WriteTimeout so the deadline fires as a rendered error rather than a
// dropped connection.
const requestTimeout = 20 * time.Second

func writeError(w http.ResponseWriter, status int, format string, args ...any) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, "# error: "+format+"\n", args...)
}

// singleLine flattens third-party text to one line. Without this, a newline in
// an API-supplied name would escape its "# " comment prefix and inject what
// looks like a prefix entry into the plaintext output.
func singleLine(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}

// parseBoolParam reads a GET toggle. Reading from r.URL.Query rather than
// r.FormValue keeps these strictly GET parameters: the URL query is the only
// source consulted, never a request body.
func parseBoolParam(r *http.Request, name string, def bool) (bool, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("invalid %s value %q, expected 1/0 or true/false", name, raw)
	}
	return v, nil
}

// parseEnumParam reads a GET parameter restricted to a fixed set of values,
// from the URL query only, like parseBoolParam.
func parseEnumParam(r *http.Request, name string, allowed []string, def string) (string, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def, nil
	}
	v := strings.ToLower(raw)
	for _, a := range allowed {
		if v == a {
			return v, nil
		}
	}
	return "", fmt.Errorf("invalid %s value %q, expected one of %s", name, raw, strings.Join(allowed, ", "))
}

func asHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, http.StatusMethodNotAllowed, "method %s not allowed, use GET", r.Method)
		return
	}

	raw := strings.Trim(strings.TrimPrefix(r.URL.Path, "/as/"), "/")

	v, asn, err := parseASN(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	if !isPermittedASN(v) {
		writeError(w, http.StatusBadRequest, "AS%s is not in a permitted range (unallocated, reserved, or reserved for private use per IANA)", asn)
		return
	}

	aggregate, err := parseBoolParam(r, "agg", true)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	wantOrg, err := parseBoolParam(r, "org", false)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	orgSrc, err := parseEnumParam(r, "src", orgSources, srcAuto)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}

	// One deadline for every upstream call this request makes, cancelled with
	// the request itself: a client that disconnects must not leave queries
	// running against registries that count them.
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()

	prefixes, queriedAt, err := getPrefixes(ctx, asn)
	if err != nil {
		writeUpstreamError(w, "whois query failed", err)
		return
	}
	if aggregate {
		prefixes = aggregatePrefixes(prefixes)
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	// Written straight through rather than assembled in memory first. The
	// prefix list for a large ASN is the biggest thing this process holds, and
	// buffering the rendered copy alongside the cached one doubled that for
	// every concurrent request.
	b := bufio.NewWriter(w)
	defer b.Flush()

	fmt.Fprintf(b, "# IPv6 prefixes for AS%s (source: %s)\n", asn, radb.Host)
	switch {
	case wantOrg:
		// An org lookup failure must not sink the prefix list.
		if res, err := getOrgName(ctx, asn, v, orgSrc); err != nil {
			fmt.Fprintf(b, "# org: lookup failed: %s\n", singleLine(err.Error()))
		} else {
			fmt.Fprintf(b, "# org: %s (source: %s)\n", singleLine(res.name), res.source)
		}
	case r.URL.Query().Get("src") != "":
		b.WriteString("# src: ignored (org lookup not requested)\n")
	}
	if aggregate {
		b.WriteString("# aggregate: on (more-specifics covered by a broader prefix removed)\n")
	} else {
		b.WriteString("# aggregate: off (all registered prefixes)\n")
	}
	if len(prefixes) == 0 {
		b.WriteString("# no IPv6 prefixes found\n")
	} else {
		fmt.Fprintf(b, "# count: %d\n", len(prefixes))
		for _, p := range prefixes {
			b.WriteString(p.String())
			b.WriteString("\n")
		}
	}
	fmt.Fprintf(b, "# queried: %s\n", queriedAt.UTC().Format(time.RFC3339))
}

// writeUpstreamError renders a failed upstream lookup.
//
// A spent query budget is reported as 503 with Retry-After rather than 502: the
// upstream did not fail, we declined to ask it, and the client can usefully
// wait. Anything else stays 502 — a genuine upstream problem is not something
// the client can fix by retrying at a particular time.
func writeUpstreamError(w http.ResponseWriter, what string, err error) {
	var budget *budgetError
	if errors.As(err, &budget) {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterFor(budget.host)))
		writeError(w, http.StatusServiceUnavailable, "%s: %v", what, err)
		return
	}
	// The request ran out of its own time rather than the upstream failing.
	if errors.Is(err, context.DeadlineExceeded) {
		writeError(w, http.StatusGatewayTimeout, "%s: %v", what, err)
		return
	}
	writeError(w, http.StatusBadGateway, "%s: %v", what, err)
}
