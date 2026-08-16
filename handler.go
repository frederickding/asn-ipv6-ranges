package main

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"asn-ipv6-ranges/internal/radb"
	"asn-ipv6-ranges/internal/whoisfreaks"
)

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

	prefixes, queriedAt, err := getPrefixes(asn)
	if err != nil {
		writeError(w, http.StatusBadGateway, "whois query failed: %v", err)
		return
	}
	if aggregate {
		prefixes = aggregatePrefixes(prefixes)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# IPv6 prefixes for AS%s (source: %s)\n", asn, radb.Host)
	if wantOrg {
		switch apiKey := getenv(whoisfreaks.KeyEnv); {
		case apiKey == "":
			fmt.Fprintf(&b, "# org: not looked up (%s is not set, org parameter has no effect)\n", whoisfreaks.KeyEnv)
		default:
			// An org lookup failure must not sink the prefix list.
			if name, err := getOrgName(asn, apiKey); err != nil {
				fmt.Fprintf(&b, "# org: lookup failed: %s\n", singleLine(err.Error()))
			} else {
				fmt.Fprintf(&b, "# org: %s\n", singleLine(name))
			}
		}
	}
	if aggregate {
		b.WriteString("# aggregate: on (more-specifics covered by a broader prefix removed)\n")
	} else {
		b.WriteString("# aggregate: off (all registered prefixes)\n")
	}
	if len(prefixes) == 0 {
		b.WriteString("# no IPv6 prefixes found\n")
	} else {
		fmt.Fprintf(&b, "# count: %d\n", len(prefixes))
		for _, p := range prefixes {
			b.WriteString(p.String())
			b.WriteString("\n")
		}
	}
	fmt.Fprintf(&b, "# queried: %s\n", queriedAt.UTC().Format(time.RFC3339))

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, b.String())
}
