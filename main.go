// Command asn-ipv6-ranges serves IPv6 prefixes for a given ASN as text/plain.
package main

//go:generate go run gen_asn_ranges.go

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	whoisHost    = "whois.radb.net"
	whoisAddr    = whoisHost + ":43"
	whoisTimeout = 15 * time.Second
	cacheTTL     = 5 * time.Minute
	max16BitASN  = 65535

	orgAPITimeout = 10 * time.Second
	orgAPIKeyEnv  = "WHOISFREAKS_API_KEY"
)

// Overridden in tests to point at a stub server.
var orgAPIURL = "https://api.whoisfreaks.com/v2.0/asn-whois"

var route6Pattern = regexp.MustCompile(`(?im)^route6:\s*(\S+)`)

// Overridable in tests to avoid real network calls and real waiting.
var (
	whoisQuery = queryWhois
	orgLookup  = lookupOrgName
	nowFunc    = time.Now
	getenv     = os.Getenv
)

type cacheEntry struct {
	prefixes  []netip.Prefix
	queriedAt time.Time
}

type orgCacheEntry struct {
	name      string
	fetchedAt time.Time
}

var (
	cacheMu sync.RWMutex
	cache   = make(map[string]cacheEntry)

	// Separate from the prefix cache: the org API is metered, so results are
	// reused for the same TTL to avoid repeat billing on refreshes.
	orgCacheMu sync.RWMutex
	orgCache   = make(map[string]orgCacheEntry)
)

func parseASN(s string) (uint64, string, error) {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, "", fmt.Errorf("invalid ASN %q, expected a numeric AS number: 0-65535 (16-bit) or 0-4294967295 (32-bit)", s)
	}
	return v, strconv.FormatUint(v, 10), nil
}

func isPermittedASN(v uint64) bool {
	if v <= max16BitASN {
		return true
	}
	for _, r := range allocatedASNRanges {
		if v >= uint64(r.start) && v <= uint64(r.end) {
			return true
		}
	}
	return false
}

func queryWhois(asn string) (string, error) {
	conn, err := net.DialTimeout("tcp", whoisAddr, whoisTimeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(whoisTimeout)); err != nil {
		return "", err
	}
	if _, err := fmt.Fprintf(conn, "-i origin AS%s\r\n", asn); err != nil {
		return "", err
	}
	body, err := io.ReadAll(conn)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// extractIPv6Prefixes returns every distinct route6 prefix, in numeric order.
// More-specifics are retained here; see aggregatePrefixes.
func extractIPv6Prefixes(whoisOutput string) []netip.Prefix {
	seen := make(map[string]bool)
	var parsed []netip.Prefix
	for _, m := range route6Pattern.FindAllStringSubmatch(whoisOutput, -1) {
		p, err := netip.ParsePrefix(m[1])
		if err != nil || !p.Addr().Is6() {
			continue
		}
		p = p.Masked()
		if key := p.String(); !seen[key] {
			seen[key] = true
			parsed = append(parsed, p)
		}
	}

	// Numeric order, so a covering prefix always precedes its more-specifics.
	slices.SortFunc(parsed, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	return parsed
}

// aggregatePrefixes drops prefixes already covered by a broader one. Given the
// sort order from extractIPv6Prefixes, the most recently kept prefix is the
// only possible cover: anything sorting between a cover and the prefixes it
// covers must itself start inside that cover, and would have been dropped here
// already.
//
// The result is a fresh slice; prefixes may be a shared cache entry, so it must
// never be mutated in place.
func aggregatePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	kept := make([]netip.Prefix, 0, len(prefixes))
	for _, p := range prefixes {
		if n := len(kept); n > 0 && kept[n-1].Contains(p.Addr()) {
			continue
		}
		kept = append(kept, p)
	}
	return kept
}

// singleLine flattens third-party text to one line. Without this, a newline in
// an API-supplied name would escape its "# " comment prefix and inject what
// looks like a prefix entry into the plaintext output.
func singleLine(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}

// redactKey strips the API key from text destined for a response body or log.
// Go's http errors embed the full request URL, which carries apiKey=...
func redactKey(s, key string) string {
	if key == "" {
		return s
	}
	return strings.ReplaceAll(s, key, "REDACTED")
}

// lookupOrgName resolves an ASN's organization name via the WhoisFreaks ASN
// WHOIS API. Errors are redacted before being returned to the caller.
func lookupOrgName(asn, apiKey string) (string, error) {
	endpoint, err := url.Parse(orgAPIURL)
	if err != nil {
		return "", err
	}
	endpoint.RawQuery = url.Values{
		"apiKey": {apiKey},
		"asn":    {"AS" + asn},
		"format": {"JSON"},
	}.Encode()

	client := &http.Client{Timeout: orgAPITimeout}
	resp, err := client.Get(endpoint.String())
	if err != nil {
		return "", errors.New(redactKey(err.Error(), apiKey))
	}
	defer resp.Body.Close()

	// Bounded read: this is third-party input.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", errors.New(redactKey(err.Error(), apiKey))
	}

	var payload struct {
		OrgName string `json:"orgName"`
		ASName  string `json:"asName"`
		Message string `json:"message"`
	}
	// A non-JSON body is not fatal by itself; the status check below reports it.
	jsonErr := json.Unmarshal(body, &payload)

	if resp.StatusCode != http.StatusOK {
		if payload.Message != "" {
			return "", fmt.Errorf("api returned %d: %s", resp.StatusCode, redactKey(payload.Message, apiKey))
		}
		return "", fmt.Errorf("api returned %d", resp.StatusCode)
	}
	if jsonErr != nil {
		return "", errors.New(redactKey(jsonErr.Error(), apiKey))
	}

	// orgName is the company; fall back to the AS handle when it is blank.
	name := strings.TrimSpace(payload.OrgName)
	if name == "" {
		name = strings.TrimSpace(payload.ASName)
	}
	if name == "" {
		return "", errors.New("no organization name in response")
	}
	return name, nil
}

func getOrgName(asn, apiKey string) (string, error) {
	orgCacheMu.RLock()
	entry, ok := orgCache[asn]
	orgCacheMu.RUnlock()
	if ok && nowFunc().Sub(entry.fetchedAt) < cacheTTL {
		return entry.name, nil
	}

	name, err := orgLookup(asn, apiKey)
	if err != nil {
		return "", err
	}

	orgCacheMu.Lock()
	orgCache[asn] = orgCacheEntry{name: name, fetchedAt: nowFunc()}
	orgCacheMu.Unlock()
	return name, nil
}

func getPrefixes(asn string) ([]netip.Prefix, time.Time, error) {
	cacheMu.RLock()
	entry, ok := cache[asn]
	cacheMu.RUnlock()
	if ok && nowFunc().Sub(entry.queriedAt) < cacheTTL {
		return entry.prefixes, entry.queriedAt, nil
	}

	output, err := whoisQuery(asn)
	if err != nil {
		return nil, time.Time{}, err
	}

	// Cached un-aggregated, so both agg=1 and agg=0 share one upstream query.
	prefixes := extractIPv6Prefixes(output)
	queriedAt := nowFunc()
	cacheMu.Lock()
	cache[asn] = cacheEntry{prefixes: prefixes, queriedAt: queriedAt}
	cacheMu.Unlock()
	return prefixes, queriedAt, nil
}

func writeError(w http.ResponseWriter, status int, format string, args ...any) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, "# error: "+format+"\n", args...)
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
	fmt.Fprintf(&b, "# IPv6 prefixes for AS%s (source: %s)\n", asn, whoisHost)
	if wantOrg {
		switch apiKey := getenv(orgAPIKeyEnv); {
		case apiKey == "":
			fmt.Fprintf(&b, "# org: not looked up (%s is not set, org parameter has no effect)\n", orgAPIKeyEnv)
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

func listenAddr() string {
	if addr := os.Getenv("LISTEN_ADDR"); addr != "" {
		return addr
	}
	if port := os.Getenv("PORT"); port != "" {
		return ":" + port
	}
	return ":8080"
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/as/", asHandler)

	srv := &http.Server{
		Addr:              listenAddr(),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("listening on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
}
