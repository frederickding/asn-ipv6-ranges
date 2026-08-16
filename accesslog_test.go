package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// captureAccessLog redirects the access log into a buffer and pins the clock,
// restoring both afterwards.
func captureAccessLog(t *testing.T, at time.Time) *bytes.Buffer {
	t.Helper()

	var buf bytes.Buffer
	origOut := accessLogger.Writer()
	setAccessLogOutput(&buf)

	origNow := nowFunc
	origEnabled, origProbes := accessLogEnabled, accessLogProbes
	nowFunc = func() time.Time { return at }
	accessLogEnabled, accessLogProbes = true, false

	t.Cleanup(func() {
		setAccessLogOutput(origOut)
		nowFunc = origNow
		accessLogEnabled, accessLogProbes = origEnabled, origProbes
	})
	return &buf
}

// okHandler writes a fixed body without calling WriteHeader, exercising the
// implicit-200 path that the real /as/{asn} success path takes.
func okHandler(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	})
}

func serve(h http.Handler, r *http.Request) {
	h.ServeHTTP(httptest.NewRecorder(), r)
}

// TestAccessLogGoldenLine asserts the whole line byte for byte. Format drift is
// the entire risk with a log format other tools parse, so this is equality
// rather than Contains.
func TestAccessLogGoldenLine(t *testing.T) {
	at := time.Date(2026, 8, 16, 23, 15, 42, 0, time.UTC)
	buf := captureAccessLog(t, at)

	req := httptest.NewRequest(http.MethodGet, "/as/2906?org=1", nil)
	req.RemoteAddr = "203.0.113.45:54321"
	serve(withAccessLog(okHandler(strings.Repeat("x", 512))), req)

	want := `203.0.113.45 - - [16/Aug/2026:23:15:42 +0000] "GET /as/2906?org=1 HTTP/1.1" 200 512` + "\n"
	if got := buf.String(); got != want {
		t.Errorf("access line mismatch\n got: %q\nwant: %q", got, want)
	}
}

func TestAccessLogClientAddr(t *testing.T) {
	at := time.Date(2026, 8, 16, 23, 15, 42, 0, time.UTC)

	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		want       string
	}{
		{"socket address, port stripped", "203.0.113.45:54321", "", "203.0.113.45"},
		{"IPv6 socket address unwrapped", "[2001:db8::1]:54321", "", "2001:db8::1"},
		{"XFF wins over socket", "10.42.0.1:33333", "203.0.113.45", "203.0.113.45"},
		{"left-most XFF entry", "10.42.0.1:33333", "203.0.113.45, 10.0.0.1, 10.0.0.2", "203.0.113.45"},
		{"XFF whitespace trimmed", "10.42.0.1:33333", "  203.0.113.45  ,10.0.0.1", "203.0.113.45"},
		{"empty XFF falls back", "10.42.0.1:33333", "   ", "10.42.0.1"},
		{"unparseable RemoteAddr used raw", "unix-socket", "", "unix-socket"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := captureAccessLog(t, at)
			req := httptest.NewRequest(http.MethodGet, "/as/2906", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			serve(withAccessLog(okHandler("ok")), req)

			addr, _, _ := strings.Cut(buf.String(), " ")
			if addr != tt.want {
				t.Errorf("logged addr %q, want %q", addr, tt.want)
			}
		})
	}
}

func TestAccessLogStatusAndBytes(t *testing.T) {
	at := time.Date(2026, 8, 16, 23, 15, 42, 0, time.UTC)

	tests := []struct {
		name    string
		method  string
		handler http.Handler
		want    string
	}{
		{
			name:    "implicit 200 when WriteHeader is never called",
			method:  http.MethodGet,
			handler: okHandler("hello"),
			want:    `"GET /as/2906 HTTP/1.1" 200 5`,
		},
		{
			name:   "explicit error status and body",
			method: http.MethodGet,
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeError(w, http.StatusBadGateway, "upstream down")
			}),
			// "# error: upstream down\n" is 23 bytes.
			want: `"GET /as/2906 HTTP/1.1" 502 23`,
		},
		{
			name:   "status recorded even with no body",
			method: http.MethodGet,
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
			}),
			want: `"GET /as/2906 HTTP/1.1" 400 0`,
		},
		{
			// Go discards a HEAD body, so nginx-parity means reporting 0.
			name:    "HEAD reports zero bytes",
			method:  http.MethodHead,
			handler: okHandler("hello"),
			want:    `"HEAD /as/2906 HTTP/1.1" 200 0`,
		},
		{
			name:   "only the first WriteHeader counts",
			method: http.MethodGet,
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				w.WriteHeader(http.StatusOK)
			}),
			want: `"GET /as/2906 HTTP/1.1" 404 0`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := captureAccessLog(t, at)
			req := httptest.NewRequest(tt.method, "/as/2906", nil)
			req.RemoteAddr = "203.0.113.45:1"
			serve(withAccessLog(tt.handler), req)

			if !strings.Contains(buf.String(), tt.want) {
				t.Errorf("logged %q, want it to contain %q", buf.String(), tt.want)
			}
		})
	}
}

// TestAccessLogSkipsProbes: Kubernetes probes would otherwise outnumber real
// traffic several-fold on a quiet service.
func TestAccessLogSkipsProbes(t *testing.T) {
	at := time.Date(2026, 8, 16, 23, 15, 42, 0, time.UTC)

	t.Run("excluded by default", func(t *testing.T) {
		buf := captureAccessLog(t, at)
		h := withAccessLog(okHandler("ok"))
		serve(h, httptest.NewRequest(http.MethodGet, statusPath, nil))
		serve(h, httptest.NewRequest(http.MethodGet, "/as/2906", nil))

		if strings.Contains(buf.String(), statusPath) {
			t.Errorf("probe request was logged: %q", buf.String())
		}
		if !strings.Contains(buf.String(), "/as/2906") {
			t.Errorf("real request was not logged: %q", buf.String())
		}
	})

	t.Run("included when ACCESS_LOG_PROBES is on", func(t *testing.T) {
		buf := captureAccessLog(t, at)
		accessLogProbes = true
		serve(withAccessLog(okHandler("ok")), httptest.NewRequest(http.MethodGet, statusPath, nil))

		if !strings.Contains(buf.String(), statusPath) {
			t.Errorf("probe request was not logged: %q", buf.String())
		}
	})
}

func TestAccessLogDisabled(t *testing.T) {
	at := time.Date(2026, 8, 16, 23, 15, 42, 0, time.UTC)
	buf := captureAccessLog(t, at)
	accessLogEnabled = false

	rec := httptest.NewRecorder()
	withAccessLog(okHandler("ok")).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/as/2906", nil))

	if buf.Len() != 0 {
		t.Errorf("logged %q with ACCESS_LOG off", buf.String())
	}
	// Disabling the log must not disable the service.
	if rec.Body.String() != "ok" {
		t.Errorf("handler did not run: %q", rec.Body.String())
	}
}

// TestAccessLogEscapesRequestLine guards against log forging: the request
// target is attacker-controlled, and an unescaped quote would close the
// "$request" field early and let a caller write their own status and byte
// count, or inject a whole extra line.
func TestAccessLogEscapesRequestLine(t *testing.T) {
	at := time.Date(2026, 8, 16, 23, 15, 42, 0, time.UTC)
	buf := captureAccessLog(t, at)

	req := httptest.NewRequest(http.MethodGet, "/as/2906", nil)
	req.RemoteAddr = "203.0.113.45:1"
	// A forged tail: close the quote, fake a 200, and start a second line.
	req.RequestURI = "/as/2906\" 200 0\n10.0.0.1 - - [x] \"GET /evil HTTP/1.1"
	serve(withAccessLog(okHandler("ok")), req)

	got := buf.String()
	if strings.Count(got, "\n") != 1 {
		t.Errorf("request line injected a newline, produced %d lines:\n%s", strings.Count(got, "\n"), got)
	}
	if strings.Contains(got, `2906" 200 0`) {
		t.Errorf("unescaped quote allowed field forging: %q", got)
	}
	if !strings.Contains(got, `\"`) || !strings.Contains(got, `\x0A`) {
		t.Errorf("quote and newline should be escaped: %q", got)
	}
}

func TestEscapeLogValue(t *testing.T) {
	tests := []struct{ in, want string }{
		{"GET /as/2906 HTTP/1.1", "GET /as/2906 HTTP/1.1"},
		{`quote"here`, `quote\"here`},
		{`back\slash`, `back\\slash`},
		{"tab\there", `tab\x09here`},
		{"nl\nhere", `nl\x0Ahere`},
		{"del\x7fhere", `del\x7Fhere`},
	}
	for _, tt := range tests {
		if got := escapeLogValue(tt.in); got != tt.want {
			t.Errorf("escapeLogValue(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestEnvBool(t *testing.T) {
	orig := getenv
	t.Cleanup(func() { getenv = orig })

	tests := []struct {
		raw  string
		def  bool
		want bool
	}{
		{"", true, true},
		{"", false, false},
		{"0", true, false},
		{"false", true, false},
		{"1", false, true},
		{"true", false, true},
		// Unparseable keeps the default: losing log configuration must not
		// take the service down.
		{"yes please", true, true},
		{"garbage", false, false},
	}
	for _, tt := range tests {
		getenv = func(string) string { return tt.raw }
		if got := envBool("ACCESS_LOG", tt.def); got != tt.want {
			t.Errorf("envBool(%q, default %v) = %v, want %v", tt.raw, tt.def, got, tt.want)
		}
	}
}
