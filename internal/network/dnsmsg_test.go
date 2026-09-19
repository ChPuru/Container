package network

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"
)

// goldenCompressedResponse is a hand-built DNS response for www.example.com
// carrying a CNAME to example.com. Both names in the answer use compression
// pointers, which is exactly the shape a real upstream resolver emits and the
// shape a parser must handle.
//
//	offset 0  : header, id 0x1234, flags 0x8180 (QR RD RA), qd=1 an=1
//	offset 12 : question name  "\x03www\x07example\x03com\x00"
//	offset 16 : the "example.com" suffix, which the answer points at
//	offset 33 : answer name    0xc00c -> offset 12 (www.example.com)
//	offset 45 : answer rdata   0xc010 -> offset 16 (example.com)
var goldenCompressedResponse = []byte{
	0x12, 0x34, // id
	0x81, 0x80, // QR=1 RD=1 RA=1 rcode=0
	0x00, 0x01, // qdcount
	0x00, 0x01, // ancount
	0x00, 0x00, // nscount
	0x00, 0x00, // arcount
	// question at offset 12
	0x03, 'w', 'w', 'w',
	0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
	0x03, 'c', 'o', 'm',
	0x00,
	0x00, 0x05, // qtype CNAME
	0x00, 0x01, // qclass IN
	// answer at offset 33
	0xc0, 0x0c, // name -> offset 12
	0x00, 0x05, // type CNAME
	0x00, 0x01, // class IN
	0x00, 0x00, 0x00, 0x3c, // ttl 60
	0x00, 0x02, // rdlength
	0xc0, 0x10, // rdata -> offset 16 ("example.com")
}

func TestParseMessageFollowsCompressionPointers(t *testing.T) {
	m, err := ParseMessage(goldenCompressedResponse)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if m.Header.ID != 0x1234 || !m.Header.Response || !m.Header.RecursionDesired || !m.Header.RecursionAvailable {
		t.Fatalf("header mis-decoded: %+v", m.Header)
	}
	if m.Header.Rcode != RcodeSuccess {
		t.Fatalf("rcode = %d", m.Header.Rcode)
	}
	if len(m.Questions) != 1 || m.Questions[0].Name != "www.example.com." {
		t.Fatalf("questions = %+v", m.Questions)
	}
	if len(m.Answers) != 1 {
		t.Fatalf("answers = %+v", m.Answers)
	}
	a := m.Answers[0]
	if a.Name != "www.example.com." {
		t.Fatalf("answer name = %q, the pointer at offset 33 was not followed", a.Name)
	}
	if a.Type != TypeCNAME || a.Class != ClassINET || a.TTL != 60 {
		t.Fatalf("answer header = %+v", a)
	}
	// The rdata pointer must have been expanded into a standalone name.
	wantRData, err := packName(nil, "example.com.")
	if err != nil {
		t.Fatalf("packName: %v", err)
	}
	if !bytes.Equal(a.Data, wantRData) {
		t.Fatalf("rdata = %v, want the expanded name %v", a.Data, wantRData)
	}
}

func TestPackThenParseRoundTripsACompressedMessage(t *testing.T) {
	m, err := ParseMessage(goldenCompressedResponse)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	// Packing is uncompressed, so the result must be longer than the original.
	if len(wire) <= len(goldenCompressedResponse) {
		t.Fatalf("packed %d bytes, expected an uncompressed message longer than %d",
			len(wire), len(goldenCompressedResponse))
	}
	back, err := ParseMessage(wire)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if back.Questions[0] != m.Questions[0] {
		t.Fatalf("question changed: %+v vs %+v", back.Questions[0], m.Questions[0])
	}
	if back.Answers[0].Name != m.Answers[0].Name || !bytes.Equal(back.Answers[0].Data, m.Answers[0].Data) {
		t.Fatalf("answer changed: %+v vs %+v", back.Answers[0], m.Answers[0])
	}
}

func TestPackGoldenARecord(t *testing.T) {
	rr, err := aRecord("web.", 30, net.ParseIP("10.66.0.2"))
	if err != nil {
		t.Fatalf("aRecord: %v", err)
	}
	m := &Message{
		Header: Header{ID: 0xbeef, Response: true, Authoritative: true,
			RecursionDesired: true, RecursionAvailable: true},
		Questions: []Question{{Name: "web.", Type: TypeA, Class: ClassINET}},
		Answers:   []ResourceRecord{rr},
	}
	got, err := m.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	want := []byte{
		0xbe, 0xef,
		0x85, 0x80, // QR AA RD RA
		0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x03, 'w', 'e', 'b', 0x00,
		0x00, 0x01, 0x00, 0x01,
		0x03, 'w', 'e', 'b', 0x00,
		0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x1e,
		0x00, 0x04,
		10, 66, 0, 2,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("packed message mismatch\n got: % x\nwant: % x", got, want)
	}
}

func TestParseMessageRejectsHostileInput(t *testing.T) {
	// A pointer that points at itself: the classic decompression loop.
	selfPointer := append([]byte(nil), goldenCompressedResponse[:12]...)
	selfPointer = append(selfPointer, 0xc0, 0x0c)
	selfPointer = append(selfPointer, 0x00, 0x01, 0x00, 0x01)

	// A pointer past the end of the message.
	forward := append([]byte(nil), goldenCompressedResponse[:12]...)
	forward = append(forward, 0xc0, 0x40)
	forward = append(forward, 0x00, 0x01, 0x00, 0x01)

	// A label whose length runs past the buffer.
	longLabel := append([]byte(nil), goldenCompressedResponse[:12]...)
	longLabel = append(longLabel, 0x3f, 'a', 'b')

	tests := []struct {
		name string
		in   []byte
	}{
		{"too short for a header", []byte{0x00, 0x01}},
		{"self pointer", selfPointer},
		{"forward pointer", forward},
		{"label past the end", longLabel},
		{"reserved label type", append(append([]byte(nil), goldenCompressedResponse[:12]...), 0x80, 0x00)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseMessage(tc.in); err == nil {
				t.Fatal("expected a parse error")
			} else if !errors.Is(err, ErrBadMessage) {
				t.Fatalf("want ErrBadMessage, got %v", err)
			}
		})
	}
}

func TestPackNameLimits(t *testing.T) {
	long := ""
	for i := 0; i < 64; i++ {
		long += "a"
	}
	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"root", ".", false},
		{"empty means root", "", false},
		{"simple", "web.", false},
		{"no trailing dot still packs", "web", false},
		{"empty label", "a..b.", true},
		{"label over 63 bytes", long + ".", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := packName(nil, tc.in)
			if tc.wantErr != (err != nil) {
				t.Fatalf("packName(%q) error = %v, wantErr = %v", tc.in, err, tc.wantErr)
			}
		})
	}
}

func TestExpandRDataForSRVAndSOA(t *testing.T) {
	// Build a message whose SRV rdata target is a compression pointer.
	msg := make([]byte, headerLen)
	binary.BigEndian.PutUint16(msg[0:2], 1)
	binary.BigEndian.PutUint16(msg[2:4], 0x8180)
	binary.BigEndian.PutUint16(msg[4:6], 1) // qdcount
	binary.BigEndian.PutUint16(msg[6:8], 1) // ancount
	name, err := packName(nil, "svc.example.com.")
	if err != nil {
		t.Fatalf("packName: %v", err)
	}
	nameOff := len(msg)
	msg = append(msg, name...)
	msg = binary.BigEndian.AppendUint16(msg, TypeSRV)
	msg = binary.BigEndian.AppendUint16(msg, ClassINET)
	// answer: name pointer -> nameOff, SRV, class IN, ttl 10, rdata 6 bytes + pointer
	msg = append(msg, 0xc0|byte(nameOff>>8), byte(nameOff))
	msg = binary.BigEndian.AppendUint16(msg, TypeSRV)
	msg = binary.BigEndian.AppendUint16(msg, ClassINET)
	msg = binary.BigEndian.AppendUint32(msg, 10)
	msg = binary.BigEndian.AppendUint16(msg, 8) // rdlength: 6 + 2-byte pointer
	msg = binary.BigEndian.AppendUint16(msg, 1) // priority
	msg = binary.BigEndian.AppendUint16(msg, 2) // weight
	msg = binary.BigEndian.AppendUint16(msg, 8080)
	msg = append(msg, 0xc0|byte(nameOff>>8), byte(nameOff))

	parsed, err := ParseMessage(msg)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if len(parsed.Answers) != 1 {
		t.Fatalf("answers = %d", len(parsed.Answers))
	}
	rr := parsed.Answers[0]
	if rr.Type != TypeSRV {
		t.Fatalf("type = %d", rr.Type)
	}
	wantTail, err := packName(nil, "svc.example.com.")
	if err != nil {
		t.Fatalf("packName: %v", err)
	}
	if len(rr.Data) != 6+len(wantTail) {
		t.Fatalf("rdata is %d bytes, want %d (the target must be expanded)", len(rr.Data), 6+len(wantTail))
	}
	if binary.BigEndian.Uint16(rr.Data[4:6]) != 8080 {
		t.Fatalf("SRV port = %d", binary.BigEndian.Uint16(rr.Data[4:6]))
	}
	if !bytes.Equal(rr.Data[6:], wantTail) {
		t.Fatalf("SRV target not expanded: % x", rr.Data[6:])
	}
}

func TestRecordConstructors(t *testing.T) {
	if _, err := aRecord("x.", 1, net.ParseIP("::1")); err == nil {
		t.Fatal("aRecord must refuse an IPv6 address")
	}
	if _, err := aaaaRecord("x.", 1, net.ParseIP("10.0.0.1")); err == nil {
		t.Fatal("aaaaRecord must refuse an IPv4 address")
	}
	rr, err := aaaaRecord("x.", 1, net.ParseIP("fd00::1"))
	if err != nil {
		t.Fatalf("aaaaRecord: %v", err)
	}
	if got := rdataIP(rr); got == nil || got.String() != "fd00::1" {
		t.Fatalf("rdataIP = %v", got)
	}
	srv, err := srvRecord("_http._tcp.web.", 30, 1, 2, 8080, "web.")
	if err != nil {
		t.Fatalf("srvRecord: %v", err)
	}
	if srv.Type != TypeSRV || len(srv.Data) != 6+len("\x03web\x00") {
		t.Fatalf("srv = %+v", srv)
	}
	ptr, err := ptrRecord("2.0.66.10.in-addr.arpa.", 30, "web.hull.internal.")
	if err != nil {
		t.Fatalf("ptrRecord: %v", err)
	}
	if ptr.Type != TypePTR {
		t.Fatalf("ptr type = %d", ptr.Type)
	}
	cn, err := cnameRecord("a.", 30, "b.")
	if err != nil || cn.Type != TypeCNAME {
		t.Fatalf("cnameRecord = %+v, %v", cn, err)
	}
	if opt := optRecord(EDNSUDPSize); opt.Type != TypeOPT || opt.Class != EDNSUDPSize || opt.Name != "." {
		t.Fatalf("optRecord = %+v", opt)
	}
}

func TestNameHelpers(t *testing.T) {
	tests := []struct{ in, canonical, trimmed string }{
		{"Web", "web.", "web"},
		{"web.", "web.", "web"},
		{"", ".", ""},
		{".", ".", ""},
	}
	for _, tc := range tests {
		if got := canonicalName(tc.in); got != tc.canonical {
			t.Errorf("canonicalName(%q) = %q, want %q", tc.in, got, tc.canonical)
		}
		if got := trimName(canonicalName(tc.in)); got != tc.trimmed {
			t.Errorf("trimName(canonicalName(%q)) = %q, want %q", tc.in, got, tc.trimmed)
		}
	}
	if got := reverseName(net.ParseIP("10.66.0.2")); got != "2.0.66.10.in-addr.arpa." {
		t.Fatalf("reverseName = %q", got)
	}
	if ip := parseReverseName("2.0.66.10.in-addr.arpa."); ip == nil || ip.String() != "10.66.0.2" {
		t.Fatalf("parseReverseName = %v", ip)
	}
	if ip := parseReverseName("web.hull.internal."); ip != nil {
		t.Fatalf("parseReverseName of a forward name = %v", ip)
	}
}
