package cymrudns

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
)

// fakeDNS starts a local UDP listener speaking just enough DNS to answer a
// single TXT query, and returns its address. Every query it receives gets
// the same answer: txt as a single TXT record, or (if txt is empty) a
// NOERROR response with no records, simulating "no such record".
func fakeDNS(t *testing.T, txt string) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			resp, err := buildResponse(buf[:n], txt)
			if err != nil {
				continue
			}
			pc.WriteTo(resp, addr)
		}
	}()

	return pc.LocalAddr().String()
}

// buildResponse crafts a minimal DNS response to query: the question section
// is echoed back verbatim (via a name-compression pointer), and the answer
// section holds one TXT record for txt — or none at all when txt is empty.
func buildResponse(query []byte, txt string) ([]byte, error) {
	qEnd, err := questionEnd(query)
	if err != nil {
		return nil, err
	}

	ancount := uint16(1)
	if txt == "" {
		ancount = 0
	}

	header := make([]byte, 12)
	copy(header[0:2], query[0:2]) // echo the transaction ID
	header[2] = 0x81              // QR=1, Opcode=0, AA=0, TC=0, RD=1
	header[3] = 0x80              // RA=1, Z=0, RCODE=0 (NOERROR)
	binary.BigEndian.PutUint16(header[4:6], 1)
	binary.BigEndian.PutUint16(header[6:8], ancount)

	msg := append(header, query[12:qEnd]...)
	if txt == "" {
		return msg, nil
	}

	var answer bytes.Buffer
	answer.Write([]byte{0xC0, 0x0C}) // NAME: pointer to the question's name at offset 12
	answer.Write([]byte{0x00, 0x10}) // TYPE: TXT
	answer.Write([]byte{0x00, 0x01}) // CLASS: IN
	ttl := make([]byte, 4)
	binary.BigEndian.PutUint32(ttl, 300)
	answer.Write(ttl)

	var rdata bytes.Buffer
	remaining := []byte(txt)
	for {
		n := len(remaining)
		if n > 255 {
			n = 255
		}
		rdata.WriteByte(byte(n))
		rdata.Write(remaining[:n])
		remaining = remaining[n:]
		if len(remaining) == 0 {
			break
		}
	}
	rdlen := make([]byte, 2)
	binary.BigEndian.PutUint16(rdlen, uint16(rdata.Len()))
	answer.Write(rdlen)
	answer.Write(rdata.Bytes())

	return append(msg, answer.Bytes()...), nil
}

// questionEnd returns the offset just past the question section (name, type,
// class) of a DNS query message, so it can be copied verbatim into a
// response.
func questionEnd(msg []byte) (int, error) {
	i := 12
	for {
		if i >= len(msg) {
			return 0, errors.New("truncated question")
		}
		l := int(msg[i])
		if l == 0 {
			i++
			break
		}
		if l&0xC0 != 0 {
			return 0, errors.New("unexpected compressed name in query")
		}
		i += 1 + l
	}
	i += 4 // QTYPE + QCLASS
	if i > len(msg) {
		return 0, errors.New("truncated question")
	}
	return i, nil
}

func TestLookupOrgName(t *testing.T) {
	addr := fakeDNS(t, "33020 | US | arin | 2024-07-25 | DEEPLY2 - Deeply II LLC, US")

	name, err := LookupOrgName(context.Background(), "33020", addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	const want = "DEEPLY2 - Deeply II LLC, US"
	if name != want {
		t.Errorf("got %q, want %q", name, want)
	}
}

// TestLookupOrgNameNoRecord: a NOERROR response with zero answers is what a
// nonexistent AS<n>.asn.cymru.com name actually gets back from a real
// resolver. Go's LookupTXT surfaces that as a *net.DNSError (its own "no such
// host" text, not this package's), so this only asserts an error comes back
// — the len(txts) == 0 check in LookupOrgName is defensive belt-and-braces
// for a case the stdlib's own DNSError already covers in practice.
func TestLookupOrgNameNoRecord(t *testing.T) {
	addr := fakeDNS(t, "")

	if _, err := LookupOrgName(context.Background(), "999999999", addr); err == nil {
		t.Fatal("expected an error for a name with no TXT record")
	}
}

func TestLookupOrgNameMalformedRecord(t *testing.T) {
	addr := fakeDNS(t, "33020 | US")

	_, err := LookupOrgName(context.Background(), "33020", addr)
	if err == nil {
		t.Fatal("expected an error for a record with fewer than 5 fields")
	}
	if !strings.Contains(err.Error(), "unexpected record format") {
		t.Errorf("unhelpful error: %v", err)
	}
}

func TestLookupOrgNameEmptyNameField(t *testing.T) {
	addr := fakeDNS(t, "33020 | US | arin | 2024-07-25 |   ")

	_, err := LookupOrgName(context.Background(), "33020", addr)
	if err == nil {
		t.Fatal("expected an error for a blank AS Name field")
	}
	if !strings.Contains(err.Error(), "no organization name") {
		t.Errorf("unhelpful error: %v", err)
	}
}

func TestLookupOrgNameDefaultResolver(t *testing.T) {
	if resolverAddr := DefaultResolver; !strings.Contains(resolverAddr, ":") {
		t.Errorf("DefaultResolver %q must include a port", resolverAddr)
	}
}

func TestHost(t *testing.T) {
	// Host is printed in service output, so keep it hostname-only (no port).
	if strings.Contains(Host, ":") {
		t.Errorf("Host must not include a port: %q", Host)
	}
}
