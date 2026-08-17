// Package whoisfreaks resolves an ASN's organization name via the WhoisFreaks
// ASN WHOIS API (https://whoisfreaks.com/documentation/asn-whois-api).
//
// The API key is passed as a query parameter, so it appears in the request URL
// and therefore inside any error Go's HTTP client produces. Every error leaving
// this package is redacted so a caller can safely surface it to a response body.
package whoisfreaks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// KeyEnv names the environment variable holding the API key. With no key set,
// callers should skip the lookup entirely.
const KeyEnv = "WHOISFREAKS_API_KEY"

// Host identifies this source in service output.
const Host = "api.whoisfreaks.com"

const (
	timeout = 10 * time.Second
	// maxBody bounds the read: this is third-party input.
	maxBody = 1 << 20
)

// Overridden in tests to point at a stub server.
var apiURL = "https://api.whoisfreaks.com/v2.0/asn-whois"

// client is shared across lookups. Built once for the same reason as the RDAP
// client: a per-call client falls back to http.DefaultTransport's two idle
// connections per host and pays a TLS handshake per query.
var client = &http.Client{
	Timeout: timeout,
	Transport: &http.Transport{
		MaxIdleConns:        8,
		MaxIdleConnsPerHost: 4,
		MaxConnsPerHost:     4,
		IdleConnTimeout:     90 * time.Second,
	},
}

// LookupOrgName resolves the organization name for an ASN (decimal, no "AS"
// prefix). It reads orgName, falling back to asName when that is blank.
//
// The context bounds the call so an abandoned request stops spending calls
// against a metered API nobody is waiting on.
func LookupOrgName(ctx context.Context, asn, apiKey string) (string, error) {
	endpoint, err := url.Parse(apiURL)
	if err != nil {
		return "", err
	}
	endpoint.RawQuery = url.Values{
		"apiKey": {apiKey},
		"asn":    {"AS" + asn},
		"format": {"JSON"},
	}.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return "", errors.New(redactKey(err.Error(), apiKey))
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New(redactKey(err.Error(), apiKey))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
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

	name := strings.TrimSpace(payload.OrgName)
	if name == "" {
		name = strings.TrimSpace(payload.ASName)
	}
	if name == "" {
		return "", errors.New("no organization name in response")
	}
	return name, nil
}

// redactKey strips the API key from text destined for a response body or log.
func redactKey(s, key string) string {
	if key == "" {
		return s
	}
	return strings.ReplaceAll(s, key, "REDACTED")
}
