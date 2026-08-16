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

// maxBody bounds the read: this is third-party input, and an inverse lookup on
// a large ASN returns every route object it originates. Measured responses:
// AS2906 35 KB, AS7018 0.77 MB, AS3356 1.12 MB, AS4134 2.43 MB. 8 MiB leaves
// roughly 3x headroom over the largest of those while capping a single
// request's allocation.
const maxBody = 8 << 20

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
	// Read one byte past the limit so truncation is detectable. A plain
	// LimitReader would look like a clean EOF, and the caller would parse a
	// partial response as a complete prefix list — reporting fewer prefixes
	// than the ASN actually originates, with nothing to indicate the loss.
	body, err := io.ReadAll(io.LimitReader(conn, maxBody+1))
	if err != nil {
		return "", err
	}
	if len(body) > maxBody {
		return "", fmt.Errorf("response exceeds %d bytes", maxBody)
	}
	return string(body), nil
}
