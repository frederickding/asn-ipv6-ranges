package whoisfreaks

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// swapAPIURL points the lookup at a stub server; the returned func restores it.
func swapAPIURL(t *testing.T, u string) func() {
	t.Helper()
	orig := apiURL
	apiURL = u
	return func() { apiURL = orig }
}

func TestRedactKey(t *testing.T) {
	const key = "0123456789abcdef0123456789abcdef" // dummy, shaped like a real key
	in := `Get "https://api.whoisfreaks.com/v2.0/asn-whois?apiKey=` + key + `&asn=AS2906": dial tcp: timeout`

	got := redactKey(in, key)
	if strings.Contains(got, key) {
		t.Errorf("API key leaked: %q", got)
	}
	if !strings.Contains(got, "REDACTED") {
		t.Errorf("expected redaction marker, got %q", got)
	}
	if redactKey("no key here", "") != "no key here" {
		t.Error("empty key must be a no-op")
	}
}

func TestLookupOrgName(t *testing.T) {
	const key = "test-key-123"

	t.Run("parses orgName", func(t *testing.T) {
		var gotQuery url.Values
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotQuery = r.URL.Query()
			io.WriteString(w, `{"asNumber":"2906","asName":"AS-SSI","orgName":"Netflix Streaming Services Inc."}`)
		}))
		defer srv.Close()
		defer swapAPIURL(t, srv.URL)()

		got, err := LookupOrgName("2906", key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "Netflix Streaming Services Inc." {
			t.Errorf("got %q", got)
		}
		if gotQuery.Get("apiKey") != key || gotQuery.Get("asn") != "AS2906" {
			t.Errorf("unexpected query: %v", gotQuery)
		}
	})

	t.Run("falls back to asName", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `{"orgName":"","asName":"IETF-MEETING"}`)
		}))
		defer srv.Close()
		defer swapAPIURL(t, srv.URL)()

		got, err := LookupOrgName("56554", key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "IETF-MEETING" {
			t.Errorf("got %q", got)
		}
	})

	t.Run("surfaces api error message without the key", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"status":401,"error":"Api Access Exception","message":"Provided API key is invalid."}`)
		}))
		defer srv.Close()
		defer swapAPIURL(t, srv.URL)()

		_, err := LookupOrgName("2906", key)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "Provided API key is invalid.") {
			t.Errorf("unhelpful error: %v", err)
		}
		if strings.Contains(err.Error(), key) {
			t.Errorf("API key leaked in error: %v", err)
		}
	})

	t.Run("transport error does not leak the key", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		srv.Close() // refuse connections
		defer swapAPIURL(t, srv.URL)()

		_, err := LookupOrgName("2906", key)
		if err == nil {
			t.Fatal("expected error")
		}
		if strings.Contains(err.Error(), key) {
			t.Errorf("API key leaked in transport error: %v", err)
		}
	})

	t.Run("empty name is an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `{"orgName":"","asName":""}`)
		}))
		defer srv.Close()
		defer swapAPIURL(t, srv.URL)()

		if _, err := LookupOrgName("2906", key); err == nil {
			t.Error("expected error for missing name")
		}
	})
}
