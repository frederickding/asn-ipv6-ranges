package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// nginx's $time_local layout: 16/Aug/2026:23:15:42 +0000.
const accessTimeLayout = "02/Jan/2006:15:04:05 -0700"

// accessLogger writes the access log.
//
// It is a separate logger from the standard one on purpose. log.Printf prefixes
// every line with a date and time, which would sit in front of the remote
// address and break the format for anything that parses nginx logs. Flags are
// cleared because the line carries its own bracketed timestamp.
//
// Access lines go to stdout and operational lines stay on stderr, mirroring
// nginx's access.log/error.log split, so the two can be separated with a plain
// shell redirect.
var accessLogger = log.New(os.Stdout, "", 0)

// Access log configuration, read once at startup.
var (
	accessLogEnabled = true
	accessLogProbes  = false
)

// initAccessLog reads the access log configuration from the environment.
//
// An unparseable value warns and keeps the default rather than refusing to
// start: losing log configuration should not take the service down.
func initAccessLog() {
	accessLogEnabled = envBool("ACCESS_LOG", true)
	accessLogProbes = envBool("ACCESS_LOG_PROBES", false)
}

func envBool(name string, def bool) bool {
	raw := getenv(name)
	if raw == "" {
		return def
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		log.Printf("invalid %s value %q, using %v", name, raw, def)
		return def
	}
	return v
}

// recordingWriter captures what the access log reports: the status code and the
// number of body bytes written.
//
// It intentionally does not forward http.Flusher or http.Hijacker. This service
// streams nothing and upgrades no protocols, so implementing them would be dead
// code; anything added later that needs them must add them here too.
type recordingWriter struct {
	http.ResponseWriter
	status      int
	bytes       int
	wroteHeader bool
}

func (w *recordingWriter) WriteHeader(status int) {
	if !w.wroteHeader {
		w.status = status
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *recordingWriter) Write(b []byte) (int, error) {
	// A handler that writes without calling WriteHeader has implicitly sent
	// 200 — the /as/{asn} success path does exactly this.
	if !w.wroteHeader {
		w.status = http.StatusOK
		w.wroteHeader = true
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

// clientAddr resolves the address to log, equivalent to nginx's realip module.
//
// X-Forwarded-For is used when present because the Kubernetes Service SNATs the
// real client away: with externalTrafficPolicy Cluster the socket address is
// whichever node forwarded the packet.
//
// The header is supplied by the caller and trivially spoofed. It is fine for
// attribution in a log and must never be used as an authorization signal.
func clientAddr(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Left-most entry is the original client; the rest are proxies.
		first, _, _ := strings.Cut(xff, ",")
		if v := strings.TrimSpace(first); v != "" {
			return v
		}
	}

	// nginx's $remote_addr carries no port. SplitHostPort also unwraps the
	// bracketed IPv6 form, [::1]:1234 -> ::1.
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// escapeLogValue mirrors nginx's default escaping for logged values.
//
// The request line is attacker-controlled. Without escaping, an embedded quote
// would let a caller close the "$request" field early and forge the status and
// byte count that follow, and a control byte could inject an entire extra line.
func escapeLogValue(s string) string {
	var b strings.Builder
	for i := range len(s) {
		c := s[i]
		switch {
		case c == '"':
			b.WriteString(`\"`)
		case c == '\\':
			b.WriteString(`\\`)
		case c < 0x20 || c == 0x7f:
			fmt.Fprintf(&b, `\x%02X`, c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// withAccessLog logs each request in nginx's "common" log format:
//
//	$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
//
// $remote_user is always "-": the service has no authentication.
//
// This wraps the mux rather than living inside the handlers so that the
// handlers stay directly callable in tests.
func withAccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !accessLogEnabled || (!accessLogProbes && r.URL.Path == statusPath) {
			next.ServeHTTP(w, r)
			return
		}

		rec := &recordingWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		// Go's server discards the body of a HEAD response, so report 0 as
		// nginx does rather than what the handler offered.
		sent := rec.bytes
		if r.Method == http.MethodHead {
			sent = 0
		}

		accessLogger.Printf("%s - - [%s] \"%s\" %d %d",
			clientAddr(r),
			nowFunc().Format(accessTimeLayout),
			escapeLogValue(r.Method+" "+r.RequestURI+" "+r.Proto),
			rec.status,
			sent,
		)
	})
}

// setAccessLogOutput redirects the access log, so tests can capture it.
func setAccessLogOutput(w io.Writer) {
	accessLogger.SetOutput(w)
}
