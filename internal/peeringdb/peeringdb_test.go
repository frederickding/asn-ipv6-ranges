package peeringdb

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// swapAPIBase points the lookup at a stub server; the returned func restores it.
func swapAPIBase(t *testing.T, u string) func() {
	t.Helper()
	orig := apiBase
	apiBase = u
	return func() { apiBase = orig }
}

func TestLookupOrgName(t *testing.T) {
	t.Run("parses name", func(t *testing.T) {
		var gotPath string
		var gotQuery string
		var gotAuth string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			gotQuery = r.URL.RawQuery
			gotAuth = r.Header.Get("Authorization")
			io.WriteString(w, `{"data":[{"id":6483,"name":"Netflix"}],"meta":{}}`)
		}))
		defer srv.Close()
		defer swapAPIBase(t, srv.URL)()

		got, err := LookupOrgName(context.Background(), "2906", "test-key")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "Netflix" {
			t.Errorf("got %q", got)
		}
		if gotPath != "/org" {
			t.Errorf("got path %q, want /org", gotPath)
		}
		if gotQuery != "asn=2906" {
			t.Errorf("got query %q", gotQuery)
		}
		if gotAuth != "Api-Key test-key" {
			t.Errorf("got Authorization %q", gotAuth)
		}
	})

	t.Run("anonymous request sends no Authorization header", func(t *testing.T) {
		var gotAuth string
		gotAuthSet := false
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotAuth, gotAuthSet = r.Header.Get("Authorization"), r.Header.Get("Authorization") != ""
			io.WriteString(w, `{"data":[{"id":1,"name":"Anon Org"}],"meta":{}}`)
		}))
		defer srv.Close()
		defer swapAPIBase(t, srv.URL)()

		if _, err := LookupOrgName(context.Background(), "2906", ""); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if gotAuthSet {
			t.Errorf("expected no Authorization header, got %q", gotAuth)
		}
	})

	t.Run("empty data array is ErrNotFound", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `{"data":[],"meta":{}}`)
		}))
		defer srv.Close()
		defer swapAPIBase(t, srv.URL)()

		_, err := LookupOrgName(context.Background(), "999999999", "")
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("got %v, want ErrNotFound", err)
		}
	})

	t.Run("empty name is ErrNotFound", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `{"data":[{"id":1,"name":""}],"meta":{}}`)
		}))
		defer srv.Close()
		defer swapAPIBase(t, srv.URL)()

		_, err := LookupOrgName(context.Background(), "2906", "")
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("got %v, want ErrNotFound", err)
		}
	})

	t.Run("surfaces api error message", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
			io.WriteString(w, `{"data":[],"meta":{"error":"Throttled"}}`)
		}))
		defer srv.Close()
		defer swapAPIBase(t, srv.URL)()

		_, err := LookupOrgName(context.Background(), "2906", "")
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "429") || !strings.Contains(err.Error(), "Throttled") {
			t.Errorf("unhelpful error: %v", err)
		}
	})

	t.Run("key never appears in a transport error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		srv.Close() // refuse connections
		defer swapAPIBase(t, srv.URL)()

		const key = "super-secret-key"
		_, err := LookupOrgName(context.Background(), "2906", key)
		if err == nil {
			t.Fatal("expected error")
		}
		if strings.Contains(err.Error(), key) {
			t.Errorf("API key leaked in transport error: %v", err)
		}
	})
}

func TestLookupOrgNames(t *testing.T) {
	t.Run("single ASN delegates to the single-value endpoint", func(t *testing.T) {
		var hitNet, hitOrg bool
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/net":
				hitNet = true
			case "/org":
				hitOrg = true
				if r.URL.RawQuery != "asn=2906" {
					t.Errorf("expected the single-value asn= query, got %q", r.URL.RawQuery)
				}
				io.WriteString(w, `{"data":[{"id":6483,"name":"Netflix"}],"meta":{}}`)
			}
		}))
		defer srv.Close()
		defer swapAPIBase(t, srv.URL)()

		got, err := LookupOrgNames(context.Background(), []string{"2906"}, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if hitNet {
			t.Error("a batch of one must not hit /net — it should cost one request, not two")
		}
		if !hitOrg {
			t.Error("expected /org to be hit")
		}
		if got["2906"] != "Netflix" {
			t.Errorf("got %v", got)
		}
	})

	t.Run("single ASN not found returns an empty map, not an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `{"data":[],"meta":{}}`)
		}))
		defer srv.Close()
		defer swapAPIBase(t, srv.URL)()

		got, err := LookupOrgNames(context.Background(), []string{"999999999"}, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("got %v, want empty", got)
		}
	})

	t.Run("multiple ASNs join net org_id to org name, deduped", func(t *testing.T) {
		var netQuery, orgQuery string
		var orgHits int
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/net":
				netQuery = r.URL.RawQuery
				// AS2906 and AS7018 are both operated by the same org (org_id 1),
				// AS3356 by a different one (org_id 2). AS64500 has no net object.
				io.WriteString(w, `{"data":[
					{"asn":2906,"org_id":1},
					{"asn":7018,"org_id":1},
					{"asn":3356,"org_id":2}
				],"meta":{}}`)
			case "/org":
				orgHits++
				orgQuery = r.URL.RawQuery
				io.WriteString(w, `{"data":[{"id":1,"name":"Org One"},{"id":2,"name":"Org Two"}],"meta":{}}`)
			}
		}))
		defer srv.Close()
		defer swapAPIBase(t, srv.URL)()

		got, err := LookupOrgNames(context.Background(), []string{"2906", "7018", "3356", "64500"}, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := map[string]string{"2906": "Org One", "7018": "Org One", "3356": "Org Two"}
		if len(got) != len(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		for asn, name := range want {
			if got[asn] != name {
				t.Errorf("asn %s: got %q, want %q", asn, got[asn], name)
			}
		}
		if _, ok := got["64500"]; ok {
			t.Errorf("AS64500 has no net object and must be absent, got %v", got)
		}
		if orgHits != 1 {
			t.Errorf("expected one deduped /org call, got %d", orgHits)
		}
		if !strings.Contains(netQuery, "asn__in=") {
			t.Errorf("expected asn__in filter, got %q", netQuery)
		}
		// Two distinct org_ids (1 and 2), regardless of order.
		if !strings.Contains(orgQuery, "id__in=") {
			t.Errorf("expected id__in filter, got %q", orgQuery)
		}
	})

	t.Run("no matching nets short-circuits without an /org call", func(t *testing.T) {
		var orgHits int
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/net":
				io.WriteString(w, `{"data":[],"meta":{}}`)
			case "/org":
				orgHits++
			}
		}))
		defer srv.Close()
		defer swapAPIBase(t, srv.URL)()

		got, err := LookupOrgNames(context.Background(), []string{"2906", "3356"}, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("got %v, want empty", got)
		}
		if orgHits != 0 {
			t.Error("no ASNs resolved to an org_id, so /org should never be called")
		}
	})

	t.Run("more than maxBatch ASNs are capped", func(t *testing.T) {
		asns := make([]string, maxBatch+50)
		for i := range asns {
			asns[i] = "100"
		}
		var gotCount int
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/net" {
				gotCount = len(strings.Split(r.URL.Query().Get("asn__in"), ","))
				io.WriteString(w, `{"data":[],"meta":{}}`)
			}
		}))
		defer srv.Close()
		defer swapAPIBase(t, srv.URL)()

		if _, err := LookupOrgNames(context.Background(), asns, ""); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if gotCount != maxBatch {
			t.Errorf("got %d ASNs in the request, want %d (the cap)", gotCount, maxBatch)
		}
	})

	t.Run("net transport failure fails the whole batch", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		srv.Close()
		defer swapAPIBase(t, srv.URL)()

		if _, err := LookupOrgNames(context.Background(), []string{"2906", "3356"}, ""); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestHost(t *testing.T) {
	// Host is printed in service output, so keep it hostname-only (no port).
	if strings.Contains(Host, ":") {
		t.Errorf("Host must not include a port: %q", Host)
	}
}
