package network

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

// DNS record types hull understands. Values are from the IANA registry.
const (
	// TypeA is an IPv4 address record.
	TypeA uint16 = 1
	// TypeNS is an authoritative name server record.
	TypeNS uint16 = 2
	// TypeCNAME is a canonical name record.
	TypeCNAME uint16 = 5
	// TypeSOA is a start-of-authority record.
	TypeSOA uint16 = 6
	// TypePTR is a reverse (domain pointer) record.
	TypePTR uint16 = 12
	// TypeMX is a mail exchanger record.
	TypeMX uint16 = 15
	// TypeTXT is a text record.
	TypeTXT uint16 = 16
	// TypeAAAA is an IPv6 address record.
	TypeAAAA uint16 = 28
	// TypeSRV is a service location record.
	TypeSRV uint16 = 33
	// TypeOPT is the EDNS0 pseudo-record carried in the additional section.
	TypeOPT uint16 = 41
	// TypeANY matches every type in a query.
	TypeANY uint16 = 255
)

// ClassINET is the only DNS class hull serves.
const ClassINET uint16 = 1

// DNS response codes.
const (
	// RcodeSuccess means the query was answered.
	RcodeSuccess uint8 = 0
	// RcodeFormatError means the query could not be parsed.
	RcodeFormatError uint8 = 1
	// RcodeServerFailure means resolution failed for an internal reason.
	RcodeServerFailure uint8 = 2
	// RcodeNameError is NXDOMAIN: the name does not exist. musl's resolver
	// retries forever against an empty NOERROR, so hull must return this.
	RcodeNameError uint8 = 3
	// RcodeNotImplemented means the opcode or query shape is unsupported.
	RcodeNotImplemented uint8 = 4
	// RcodeRefused means the server declined to answer.
	RcodeRefused uint8 = 5
)

// Wire-format limits from RFC 1035 and RFC 6891.
const (
	// MaxLabelLen is the longest single DNS label.
	MaxLabelLen = 63
	// MaxNameLen is the longest encoded domain name, including length bytes.
	MaxNameLen = 255
	// MinUDPSize is the DNS payload every resolver must accept without EDNS0.
	MinUDPSize = 512
	// EDNSUDPSize is the buffer size hull advertises in its OPT records. 1232
	// is the DNS-flag-day recommendation: it fits in the smallest plausible
	// path MTU without IP fragmentation.
	EDNSUDPSize = 1232
	// headerLen is the fixed size of a DNS message header.
	headerLen = 12
	// maxCompressionHops bounds pointer chasing so a malicious message with a
	// pointer loop cannot spin the parser.
	maxCompressionHops = 64
)

// ErrBadMessage is returned when a DNS message cannot be parsed. Callers reply
// with RcodeFormatError.
var ErrBadMessage = errors.New("network: malformed DNS message")

// Header is a decoded DNS message header. The section counts are not stored:
// they are derived from the slices when packing and validated when parsing.
type Header struct {
	// ID is the query identifier echoed in the response.
	ID uint16
	// Response is the QR bit: true in a response.
	Response bool
	// Opcode is the query kind; 0 is a standard query.
	Opcode uint8
	// Authoritative is the AA bit.
	Authoritative bool
	// Truncated is the TC bit, set when a UDP answer did not fit.
	Truncated bool
	// RecursionDesired is the RD bit copied from the query.
	RecursionDesired bool
	// RecursionAvailable is the RA bit. hull always sets it in responses,
	// because it does forward to upstream resolvers.
	RecursionAvailable bool
	// AuthenticData is the AD bit.
	AuthenticData bool
	// CheckingDisabled is the CD bit.
	CheckingDisabled bool
	// Rcode is the response code.
	Rcode uint8
}

// Question is one entry of the question section.
type Question struct {
	// Name is the queried name in canonical trailing-dot form, e.g. "web.".
	Name string
	// Type is the query type.
	Type uint16
	// Class is the query class, normally ClassINET.
	Class uint16
}

// ResourceRecord is one answer, authority or additional record.
//
// Data holds the record payload in wire form with every embedded domain name
// already expanded, so a record parsed out of one message can be packed into
// another without dangling compression pointers. For an OPT pseudo-record,
// Class carries the advertised UDP payload size and TTL the extended rcode and
// flags, as RFC 6891 specifies.
type ResourceRecord struct {
	// Name is the owner name in canonical trailing-dot form.
	Name string
	// Type is the record type.
	Type uint16
	// Class is the record class.
	Class uint16
	// TTL is the time to live in seconds.
	TTL uint32
	// Data is the decompressed RDATA.
	Data []byte
}

// Message is a decoded DNS message.
type Message struct {
	// Header carries the identifier and flags.
	Header Header
	// Questions is the question section.
	Questions []Question
	// Answers is the answer section.
	Answers []ResourceRecord
	// Authority is the authority section.
	Authority []ResourceRecord
	// Additional is the additional section, including any OPT record.
	Additional []ResourceRecord
}

// ParseMessage decodes a DNS message, following compression pointers in both
// names and the RDATA of name-bearing record types. Every offset is bounds
// checked and pointer chains are capped, so a hostile packet cannot loop or
// read out of range.
func ParseMessage(b []byte) (*Message, error) {
	if len(b) < headerLen {
		return nil, fmt.Errorf("%w: %d bytes is shorter than a header", ErrBadMessage, len(b))
	}
	m := &Message{}
	m.Header = unpackHeader(b)
	qd := int(binary.BigEndian.Uint16(b[4:6]))
	an := int(binary.BigEndian.Uint16(b[6:8]))
	ns := int(binary.BigEndian.Uint16(b[8:10]))
	ar := int(binary.BigEndian.Uint16(b[10:12]))

	off := headerLen
	var err error
	for i := 0; i < qd; i++ {
		var q Question
		q, off, err = parseQuestion(b, off)
		if err != nil {
			return nil, err
		}
		m.Questions = append(m.Questions, q)
	}
	if m.Answers, off, err = parseRRs(b, off, an); err != nil {
		return nil, err
	}
	if m.Authority, off, err = parseRRs(b, off, ns); err != nil {
		return nil, err
	}
	if m.Additional, _, err = parseRRs(b, off, ar); err != nil {
		return nil, err
	}
	return m, nil
}

// Pack encodes a message. Names are written uncompressed: parsing compression
// is mandatory for interoperability, emitting it is not, and the answers hull
// generates are small enough that the saving does not matter.
func (m *Message) Pack() ([]byte, error) {
	buf := make([]byte, headerLen, 512)
	packHeader(buf, m.Header)
	binary.BigEndian.PutUint16(buf[4:6], uint16(len(m.Questions)))
	binary.BigEndian.PutUint16(buf[6:8], uint16(len(m.Answers)))
	binary.BigEndian.PutUint16(buf[8:10], uint16(len(m.Authority)))
	binary.BigEndian.PutUint16(buf[10:12], uint16(len(m.Additional)))

	var err error
	for _, q := range m.Questions {
		if buf, err = packName(buf, q.Name); err != nil {
			return nil, err
		}
		buf = binary.BigEndian.AppendUint16(buf, q.Type)
		buf = binary.BigEndian.AppendUint16(buf, q.Class)
	}
	for _, section := range [][]ResourceRecord{m.Answers, m.Authority, m.Additional} {
		for _, rr := range section {
			if buf, err = packRR(buf, rr); err != nil {
				return nil, err
			}
		}
	}
	return buf, nil
}

// unpackHeader decodes the 12-byte header.
func unpackHeader(b []byte) Header {
	flags := binary.BigEndian.Uint16(b[2:4])
	return Header{
		ID:                 binary.BigEndian.Uint16(b[0:2]),
		Response:           flags&0x8000 != 0,
		Opcode:             uint8(flags>>11) & 0x0f,
		Authoritative:      flags&0x0400 != 0,
		Truncated:          flags&0x0200 != 0,
		RecursionDesired:   flags&0x0100 != 0,
		RecursionAvailable: flags&0x0080 != 0,
		AuthenticData:      flags&0x0020 != 0,
		CheckingDisabled:   flags&0x0010 != 0,
		Rcode:              uint8(flags & 0x000f),
	}
}

// packHeader writes the 12-byte header into buf, which must be at least
// headerLen long. Section counts are filled in by the caller.
func packHeader(buf []byte, h Header) {
	binary.BigEndian.PutUint16(buf[0:2], h.ID)
	var flags uint16
	if h.Response {
		flags |= 0x8000
	}
	flags |= uint16(h.Opcode&0x0f) << 11
	if h.Authoritative {
		flags |= 0x0400
	}
	if h.Truncated {
		flags |= 0x0200
	}
	if h.RecursionDesired {
		flags |= 0x0100
	}
	if h.RecursionAvailable {
		flags |= 0x0080
	}
	if h.AuthenticData {
		flags |= 0x0020
	}
	if h.CheckingDisabled {
		flags |= 0x0010
	}
	flags |= uint16(h.Rcode & 0x0f)
	binary.BigEndian.PutUint16(buf[2:4], flags)
}

// parseQuestion decodes one question entry starting at off.
func parseQuestion(b []byte, off int) (Question, int, error) {
	name, next, err := parseName(b, off)
	if err != nil {
		return Question{}, 0, err
	}
	if next+4 > len(b) {
		return Question{}, 0, fmt.Errorf("%w: question truncated at offset %d", ErrBadMessage, next)
	}
	q := Question{
		Name:  name,
		Type:  binary.BigEndian.Uint16(b[next : next+2]),
		Class: binary.BigEndian.Uint16(b[next+2 : next+4]),
	}
	return q, next + 4, nil
}

// parseRRs decodes n resource records starting at off.
func parseRRs(b []byte, off, n int) ([]ResourceRecord, int, error) {
	if n == 0 {
		return nil, off, nil
	}
	out := make([]ResourceRecord, 0, n)
	for i := 0; i < n; i++ {
		name, next, err := parseName(b, off)
		if err != nil {
			return nil, 0, err
		}
		if next+10 > len(b) {
			return nil, 0, fmt.Errorf("%w: record header truncated at offset %d", ErrBadMessage, next)
		}
		rr := ResourceRecord{
			Name:  name,
			Type:  binary.BigEndian.Uint16(b[next : next+2]),
			Class: binary.BigEndian.Uint16(b[next+2 : next+4]),
			TTL:   binary.BigEndian.Uint32(b[next+4 : next+8]),
		}
		rdlen := int(binary.BigEndian.Uint16(b[next+8 : next+10]))
		rdOff := next + 10
		if rdOff+rdlen > len(b) {
			return nil, 0, fmt.Errorf("%w: rdata of %d bytes at offset %d exceeds the message",
				ErrBadMessage, rdlen, rdOff)
		}
		data, err := expandRData(b, rr.Type, rdOff, rdlen)
		if err != nil {
			return nil, 0, err
		}
		rr.Data = data
		out = append(out, rr)
		off = rdOff + rdlen
	}
	return out, off, nil
}

// packRR appends one resource record to buf.
func packRR(buf []byte, rr ResourceRecord) ([]byte, error) {
	var err error
	if buf, err = packName(buf, rr.Name); err != nil {
		return nil, err
	}
	buf = binary.BigEndian.AppendUint16(buf, rr.Type)
	buf = binary.BigEndian.AppendUint16(buf, rr.Class)
	buf = binary.BigEndian.AppendUint32(buf, rr.TTL)
	if len(rr.Data) > 0xffff {
		return nil, fmt.Errorf("%w: rdata for %s is %d bytes", ErrBadMessage, rr.Name, len(rr.Data))
	}
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(rr.Data)))
	return append(buf, rr.Data...), nil
}

// parseName decodes a domain name at off, following compression pointers. It
// returns the name in canonical trailing-dot form and the offset of the first
// byte after the name *in the original record* (pointers do not advance it).
func parseName(msg []byte, off int) (string, int, error) {
	var sb strings.Builder
	start := off
	next := -1
	hops := 0
	total := 0
	for {
		if off < 0 || off >= len(msg) {
			return "", 0, fmt.Errorf("%w: name at offset %d runs past the message", ErrBadMessage, start)
		}
		l := int(msg[off])
		switch l & 0xc0 {
		case 0x00:
			if l == 0 {
				off++
				if next < 0 {
					next = off
				}
				if sb.Len() == 0 {
					return ".", next, nil
				}
				return sb.String(), next, nil
			}
			if off+1+l > len(msg) {
				return "", 0, fmt.Errorf("%w: label at offset %d runs past the message", ErrBadMessage, off)
			}
			total += l + 1
			if total > MaxNameLen {
				return "", 0, fmt.Errorf("%w: name at offset %d exceeds %d bytes", ErrBadMessage, start, MaxNameLen)
			}
			sb.Write(msg[off+1 : off+1+l])
			sb.WriteByte('.')
			off += 1 + l
		case 0xc0:
			if off+1 >= len(msg) {
				return "", 0, fmt.Errorf("%w: compression pointer at offset %d is truncated", ErrBadMessage, off)
			}
			ptr := int(binary.BigEndian.Uint16(msg[off:off+2]) & 0x3fff)
			if next < 0 {
				next = off + 2
			}
			hops++
			if hops > maxCompressionHops {
				return "", 0, fmt.Errorf("%w: compression pointer loop at offset %d", ErrBadMessage, start)
			}
			if ptr >= off {
				// A forward or self pointer is the classic decompression bomb.
				return "", 0, fmt.Errorf("%w: compression pointer at offset %d does not point backwards",
					ErrBadMessage, off)
			}
			off = ptr
		default:
			return "", 0, fmt.Errorf("%w: reserved label type 0x%02x at offset %d", ErrBadMessage, l, off)
		}
	}
}

// packName appends the wire encoding of a canonical domain name.
func packName(buf []byte, name string) ([]byte, error) {
	if name == "" || name == "." {
		return append(buf, 0), nil
	}
	n := strings.TrimSuffix(name, ".")
	encoded := 1
	for _, label := range strings.Split(n, ".") {
		if len(label) == 0 {
			return nil, fmt.Errorf("%w: empty label in name %q", ErrBadMessage, name)
		}
		if len(label) > MaxLabelLen {
			return nil, fmt.Errorf("%w: label %q in %q is longer than %d bytes",
				ErrBadMessage, label, name, MaxLabelLen)
		}
		encoded += len(label) + 1
		if encoded > MaxNameLen {
			return nil, fmt.Errorf("%w: name %q is longer than %d bytes", ErrBadMessage, name, MaxNameLen)
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	return append(buf, 0), nil
}

// expandRData copies rdlen bytes of RDATA, rewriting any embedded domain name
// so it no longer depends on compression pointers into the source message.
func expandRData(msg []byte, typ uint16, off, rdlen int) ([]byte, error) {
	end := off + rdlen
	switch typ {
	case TypeCNAME, TypePTR, TypeNS:
		name, _, err := parseName(msg, off)
		if err != nil {
			return nil, err
		}
		return packName(nil, name)
	case TypeMX:
		if off+2 > end {
			return nil, fmt.Errorf("%w: MX rdata is %d bytes", ErrBadMessage, rdlen)
		}
		name, _, err := parseName(msg, off+2)
		if err != nil {
			return nil, err
		}
		out := append([]byte(nil), msg[off:off+2]...)
		return packName(out, name)
	case TypeSRV:
		if off+6 > end {
			return nil, fmt.Errorf("%w: SRV rdata is %d bytes", ErrBadMessage, rdlen)
		}
		name, _, err := parseName(msg, off+6)
		if err != nil {
			return nil, err
		}
		out := append([]byte(nil), msg[off:off+6]...)
		return packName(out, name)
	case TypeSOA:
		mname, n1, err := parseName(msg, off)
		if err != nil {
			return nil, err
		}
		rname, n2, err := parseName(msg, n1)
		if err != nil {
			return nil, err
		}
		if n2+20 > end {
			return nil, fmt.Errorf("%w: SOA rdata is %d bytes", ErrBadMessage, rdlen)
		}
		out, err := packName(nil, mname)
		if err != nil {
			return nil, err
		}
		if out, err = packName(out, rname); err != nil {
			return nil, err
		}
		return append(out, msg[n2:n2+20]...), nil
	default:
		return append([]byte(nil), msg[off:end]...), nil
	}
}

// ---------- record constructors ----------

// aRecord builds an A record. ip must be IPv4.
func aRecord(name string, ttl uint32, ip net.IP) (ResourceRecord, error) {
	v4 := ip.To4()
	if v4 == nil {
		return ResourceRecord{}, fmt.Errorf("%w: %s is not an IPv4 address", ErrInvalidConfig, ip)
	}
	return ResourceRecord{Name: name, Type: TypeA, Class: ClassINET, TTL: ttl, Data: append([]byte(nil), v4...)}, nil
}

// aaaaRecord builds an AAAA record. ip must be IPv6 (or an IPv4-mapped form,
// which is rejected because handing a v4-mapped address to a container's musl
// resolver produces an unusable address).
func aaaaRecord(name string, ttl uint32, ip net.IP) (ResourceRecord, error) {
	if ip.To4() != nil || ip.To16() == nil {
		return ResourceRecord{}, fmt.Errorf("%w: %s is not an IPv6 address", ErrInvalidConfig, ip)
	}
	return ResourceRecord{Name: name, Type: TypeAAAA, Class: ClassINET, TTL: ttl, Data: append([]byte(nil), ip.To16()...)}, nil
}

// cnameRecord builds a CNAME record pointing at target.
func cnameRecord(name string, ttl uint32, target string) (ResourceRecord, error) {
	data, err := packName(nil, target)
	if err != nil {
		return ResourceRecord{}, err
	}
	return ResourceRecord{Name: name, Type: TypeCNAME, Class: ClassINET, TTL: ttl, Data: data}, nil
}

// ptrRecord builds a PTR record pointing at target.
func ptrRecord(name string, ttl uint32, target string) (ResourceRecord, error) {
	data, err := packName(nil, target)
	if err != nil {
		return ResourceRecord{}, err
	}
	return ResourceRecord{Name: name, Type: TypePTR, Class: ClassINET, TTL: ttl, Data: data}, nil
}

// srvRecord builds an SRV record.
func srvRecord(name string, ttl uint32, priority, weight, port uint16, target string) (ResourceRecord, error) {
	head := make([]byte, 0, 6)
	head = binary.BigEndian.AppendUint16(head, priority)
	head = binary.BigEndian.AppendUint16(head, weight)
	head = binary.BigEndian.AppendUint16(head, port)
	data, err := packName(head, target)
	if err != nil {
		return ResourceRecord{}, err
	}
	return ResourceRecord{Name: name, Type: TypeSRV, Class: ClassINET, TTL: ttl, Data: data}, nil
}

// optRecord builds the EDNS0 pseudo-record hull echoes back, advertising
// EDNSUDPSize as the buffer it can receive.
func optRecord(size uint16) ResourceRecord {
	return ResourceRecord{Name: ".", Type: TypeOPT, Class: size, TTL: 0}
}

// findOPT returns the first OPT record in a section, or nil.
func findOPT(rrs []ResourceRecord) *ResourceRecord {
	for i := range rrs {
		if rrs[i].Type == TypeOPT {
			return &rrs[i]
		}
	}
	return nil
}

// rdataIP decodes an A or AAAA record payload into a net.IP, returning nil for
// anything else or for a malformed payload.
func rdataIP(rr ResourceRecord) net.IP {
	switch rr.Type {
	case TypeA:
		if len(rr.Data) == net.IPv4len {
			return net.IP(append([]byte(nil), rr.Data...))
		}
	case TypeAAAA:
		if len(rr.Data) == net.IPv6len {
			return net.IP(append([]byte(nil), rr.Data...))
		}
	}
	return nil
}

// canonicalName normalises a name for comparison: lowercase with exactly one
// trailing dot. The root stays ".".
func canonicalName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || s == "." {
		return "."
	}
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}

// trimName strips the trailing dot, giving the form users type.
func trimName(s string) string {
	if s == "." {
		return ""
	}
	return strings.TrimSuffix(s, ".")
}

// reverseName renders an address as its in-addr.arpa or ip6.arpa name.
func reverseName(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", v4[3], v4[2], v4[1], v4[0])
	}
	v6 := ip.To16()
	if v6 == nil {
		return ""
	}
	const hexDigits = "0123456789abcdef"
	buf := make([]byte, 0, 72)
	for i := len(v6) - 1; i >= 0; i-- {
		buf = append(buf, hexDigits[v6[i]&0x0f], '.', hexDigits[v6[i]>>4], '.')
	}
	return string(buf) + "ip6.arpa."
}

// parseReverseName turns an in-addr.arpa name back into an IPv4 address,
// returning nil when the name is not a v4 reverse name.
func parseReverseName(name string) net.IP {
	n := strings.ToLower(trimName(name))
	const suffix = ".in-addr.arpa"
	if !strings.HasSuffix(n, suffix) {
		return nil
	}
	parts := strings.Split(strings.TrimSuffix(n, suffix), ".")
	if len(parts) != 4 {
		return nil
	}
	return net.ParseIP(parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0]).To4()
}
