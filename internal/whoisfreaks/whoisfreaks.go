// Package whoisfreaks resolves an ASN's organization name via the WhoisFreaks
// ASN WHOIS API (https://whoisfreaks.com/documentation/asn-whois-api).
//
// The API key is passed as a query parameter, so it appears in the request URL
// and therefore inside any error Go's HTTP client produces. Every error leaving
// this package is redacted so a caller can safely surface it to a response body.
package whoisfreaks

import (
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

const (
	timeout = 10 * time.Second
	// maxBody bounds the read: this is third-party input.
	maxBody = 1 << 20
)

// Overridden in tests to point at a stub server.
var apiURL = "https://api.whoisfreaks.com/v2.0/asn-whois"

// LookupOrgName resolves the organization name for an ASN (decimal, no "AS"
// prefix). It reads orgName, falling back to asName when that is blank.
func LookupOrgName(asn, apiKey string) (string, error) {
	endpoint, err := url.Parse(apiURL)
	if err != nil {
		return "", err
	}
	endpoint.RawQuery = url.Values{
		"apiKey": {apiKey},
		"asn":    {"AS" + asn},
		"format": {"JSON"},
	}.Encode()

	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(endpoint.String())
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
