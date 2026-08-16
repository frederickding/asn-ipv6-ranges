// Package radb queries the RADB Internet Routing Registry over the raw WHOIS
// protocol (TCP port 43) using native Go networking — it never shells out to a
// whois binary.
package radb

import (
	"fmt"
	"io"
	"net"
	"time"
)

// Host is the registry hostname, reported in service output.
const Host = "whois.radb.net"

const timeout = 15 * time.Second

// addr is the WHOIS endpoint; overridden in tests to point at a local listener.
var addr = Host + ":43"

// Query runs an inverse lookup on origin for the given ASN (decimal, no "AS"
// prefix) and returns the raw RPSL response.
func Query(asn string) (string, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
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
