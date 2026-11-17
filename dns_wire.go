package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"strings"
)

func parseQuestion(p []byte) (string, uint16, int, error) {
	if len(p) < 12 {
		return "", 0, 0, errors.New("DNS header too short")
	}
	qd := binary.BigEndian.Uint16(p[4:6])
	if qd < 1 {
		return "", 0, 0, errors.New("DNS message has no question")
	}
	name, off, e := decodeName(p, 12)
	if e != nil {
		return "", 0, 0, e
	}
	if off+4 > len(p) {
		return "", 0, 0, errors.New("DNS question truncated")
	}
	return name, binary.BigEndian.Uint16(p[off : off+2]), off + 4, nil
}
func decodeName(p []byte, start int) (string, int, error) {
	labels := []string{}
	off := start
	end := -1
	// The bounded step count also terminates compression-pointer loops without
	// allocating a map for every decoded DNS name.
	for steps := 0; steps < 128; steps++ {
		if off >= len(p) {
			return "", 0, errors.New("DNS name out of range")
		}
		l := int(p[off])
		if l&0xc0 == 0xc0 {
			if off+1 >= len(p) {
				return "", 0, errors.New("DNS pointer truncated")
			}
			ptr := ((l & 0x3f) << 8) | int(p[off+1])
			if ptr >= len(p) {
				return "", 0, errors.New("DNS pointer out of range")
			}
			if end < 0 {
				end = off + 2
			}
			off = ptr
			continue
		}
		off++
		if l == 0 {
			if end < 0 {
				end = off
			}
			return strings.Join(labels, "."), end, nil
		}
		if l&0xc0 != 0 || l > 63 || off+l > len(p) {
			return "", 0, errors.New("invalid DNS label")
		}
		labels = append(labels, string(p[off:off+l]))
		off += l
	}
	return "", 0, errors.New("DNS name too deep")
}
func makeDNSQuery(name string, qtype uint16) []byte {
	p := make([]byte, 12)
	_, _ = rand.Read(p[:2])
	binary.BigEndian.PutUint16(p[2:4], 0x0100)
	binary.BigEndian.PutUint16(p[4:6], 1)
	for _, label := range strings.Split(normalizeDomain(name), ".") {
		if len(label) > 63 {
			continue
		}
		p = append(p, byte(len(label)))
		p = append(p, []byte(label)...)
	}
	p = append(p, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return p
}
func dnsRCode(p []byte) int {
	if len(p) < 4 {
		return -1
	}
	return int(binary.BigEndian.Uint16(p[2:4]) & 0x000f)
}
func dnsTruncated(p []byte) bool { return len(p) >= 4 && (binary.BigEndian.Uint16(p[2:4])&0x0200) != 0 }

func truncateDNSUDPResponse(packet []byte, limit int) []byte {
	if len(packet) <= limit || limit < 12 || len(packet) < 12 {
		return packet
	}
	questionEnd := 12
	qd := int(binary.BigEndian.Uint16(packet[4:6]))
	for i := 0; i < qd; i++ {
		next, err := skipName(packet, questionEnd)
		if err != nil || next+4 > len(packet) {
			return dnsTruncatedHeader(packet)
		}
		questionEnd = next + 4
	}
	if questionEnd > limit {
		return dnsTruncatedHeader(packet)
	}
	out := append([]byte(nil), packet[:questionEnd]...)
	counts := [3]uint16{}
	off := questionEnd
	truncated := false
	for section := 0; section < 3; section++ {
		count := int(binary.BigEndian.Uint16(packet[6+section*2 : 8+section*2]))
		for i := 0; i < count; i++ {
			start := off
			next, err := skipName(packet, off)
			if err != nil || next+10 > len(packet) {
				truncated = true
				break
			}
			rdlen := int(binary.BigEndian.Uint16(packet[next+8 : next+10]))
			off = next + 10 + rdlen
			if off > len(packet) || len(out)+(off-start) > limit {
				truncated = true
				break
			}
			out = append(out, packet[start:off]...)
			counts[section]++
		}
		if truncated {
			break
		}
	}
	for i, count := range counts {
		binary.BigEndian.PutUint16(out[6+i*2:8+i*2], count)
	}
	if truncated || len(out) < len(packet) {
		flags := binary.BigEndian.Uint16(out[2:4]) | 0x0200
		binary.BigEndian.PutUint16(out[2:4], flags)
	}
	return out
}

func dnsTruncatedHeader(packet []byte) []byte {
	if len(packet) < 12 {
		return packet
	}
	out := append([]byte(nil), packet[:12]...)
	binary.BigEndian.PutUint16(out[2:4], binary.BigEndian.Uint16(out[2:4])|0x0200)
	for i := 4; i < 12; i += 2 {
		binary.BigEndian.PutUint16(out[i:i+2], 0)
	}
	return out
}
func dnsAnswerCount(p []byte) int {
	if len(p) < 8 {
		return 0
	}
	return int(binary.BigEndian.Uint16(p[6:8]))
}
func formerrResponse(q []byte) []byte  { return errorResponse(q, 1) }
func servfailResponse(q []byte) []byte { return errorResponse(q, 2) }
func errorResponse(q []byte, rcode uint16) []byte {
	if len(q) < 12 {
		return []byte{}
	}
	// Keep QDCOUNT consistent with the bytes we echo. Malformed or
	// multi-question packets receive a header-only error response.
	end, qd := 12, uint16(0)
	if _, _, questionEnd, err := parseQuestion(q); err == nil &&
		binary.BigEndian.Uint16(q[4:6]) == 1 && questionEnd <= len(q) {
		end, qd = questionEnd, 1
	}
	p := append([]byte(nil), q[:end]...)
	flags := binary.BigEndian.Uint16(p[2:4])
	flags = (flags | 0x8000) &^ 0x0200
	flags = (flags &^ 0x000f) | (rcode & 0x000f)
	binary.BigEndian.PutUint16(p[2:4], flags)
	binary.BigEndian.PutUint16(p[4:6], qd)
	for i := 6; i < 12; i += 2 {
		binary.BigEndian.PutUint16(p[i:i+2], 0)
	}
	return p
}
func parseARecords(p []byte) ([]string, error) {
	if len(p) < 12 {
		return nil, errors.New("short DNS response")
	}
	off := 12
	qd := int(binary.BigEndian.Uint16(p[4:6]))
	an := int(binary.BigEndian.Uint16(p[6:8]))
	ns := int(binary.BigEndian.Uint16(p[8:10]))
	ar := int(binary.BigEndian.Uint16(p[10:12]))
	for i := 0; i < qd; i++ {
		_, n, e := decodeName(p, off)
		if e != nil {
			return nil, e
		}
		off = n + 4
		if off > len(p) {
			return nil, errors.New("truncated question")
		}
	}
	ips := []string{}
	for i := 0; i < an+ns+ar; i++ {
		_, n, e := decodeName(p, off)
		if e != nil {
			return ips, e
		}
		off = n
		if off+10 > len(p) {
			return ips, errors.New("truncated RR")
		}
		typ := binary.BigEndian.Uint16(p[off : off+2])
		rd := int(binary.BigEndian.Uint16(p[off+8 : off+10]))
		off += 10
		if off+rd > len(p) {
			return ips, errors.New("truncated RDATA")
		}
		if i < an && typ == 1 && rd == 4 {
			ips = append(ips, net.IP(p[off:off+4]).String())
		}
		off += rd
	}
	return ips, nil
}
func skipName(p []byte, off int) (int, error) { _, n, e := decodeName(p, off); return n, e }
func rrTTLPositions(p []byte) ([]int, error) {
	if len(p) < 12 {
		return nil, errors.New("short DNS message")
	}
	off := 12
	qd := int(binary.BigEndian.Uint16(p[4:6]))
	counts := []int{int(binary.BigEndian.Uint16(p[6:8])), int(binary.BigEndian.Uint16(p[8:10])), int(binary.BigEndian.Uint16(p[10:12]))}
	for i := 0; i < qd; i++ {
		n, e := skipName(p, off)
		if e != nil {
			return nil, e
		}
		off = n + 4
		if off > len(p) {
			return nil, errors.New("truncated question")
		}
	}
	pos := []int{}
	for _, cnt := range counts {
		for i := 0; i < cnt; i++ {
			n, e := skipName(p, off)
			if e != nil {
				return nil, e
			}
			off = n
			if off+10 > len(p) {
				return nil, errors.New("truncated RR")
			}
			typ := binary.BigEndian.Uint16(p[off : off+2])
			// OPT (type 41) uses this field for EDNS flags, not a record TTL.
			if typ != 41 {
				pos = append(pos, off+4)
			}
			rd := int(binary.BigEndian.Uint16(p[off+8 : off+10]))
			off += 10 + rd
			if off > len(p) {
				return nil, errors.New("truncated RDATA")
			}
		}
	}
	return pos, nil
}
func minResponseTTL(p []byte) (uint32, bool) {
	pos, e := rrTTLPositions(p)
	if e != nil || len(pos) == 0 {
		return 0, false
	}
	var min uint32 = ^uint32(0)
	for _, o := range pos {
		v := binary.BigEndian.Uint32(p[o : o+4])
		if v < min {
			min = v
		}
	}
	return min, true
}
func decrementTTLs(p []byte, elapsed uint32) {
	pos, e := rrTTLPositions(p)
	if e != nil {
		return
	}
	for _, o := range pos {
		v := binary.BigEndian.Uint32(p[o : o+4])
		if v > elapsed {
			v -= elapsed
		} else {
			v = 0
		}
		binary.BigEndian.PutUint32(p[o:o+4], v)
	}
}


 
// negativeSOATTL returns the RFC 2308 negative-cache TTL from the authority
// SOA: min(SOA RR TTL, SOA.MINIMUM). It returns false when no usable SOA exists.
func negativeSOATTL(packet []byte) (uint32, bool) {
	if len(packet) < 12 {
		return 0, false
	}
	off := 12
	qd := int(binary.BigEndian.Uint16(packet[4:6]))
	for i := 0; i < qd; i++ {
		n, err := skipName(packet, off)
		if err != nil || n+4 > len(packet) {
			return 0, false
		}
		off = n + 4
	}
	an := int(binary.BigEndian.Uint16(packet[6:8]))
	ns := int(binary.BigEndian.Uint16(packet[8:10]))
	ar := int(binary.BigEndian.Uint16(packet[10:12]))
	for section, count := range []int{an, ns, ar} {
		for i := 0; i < count; i++ {
			_, n, err := decodeName(packet, off)
			if err != nil || n+10 > len(packet) {
				return 0, false
			}
			typ := binary.BigEndian.Uint16(packet[n : n+2])
			ttl := binary.BigEndian.Uint32(packet[n+4 : n+8])
			rdlen := int(binary.BigEndian.Uint16(packet[n+8 : n+10]))
			rdata := n + 10
			end := rdata + rdlen
			if end > len(packet) {
				return 0, false
			}
			if section == 1 && typ == 6 {
				mnameEnd, err := skipName(packet, rdata)
				if err == nil {
					rnameEnd, err2 := skipName(packet, mnameEnd)
					if err2 == nil && rnameEnd+20 == end {
						minimum := binary.BigEndian.Uint32(packet[end-4 : end])
						if minimum < ttl {
							ttl = minimum
						}
						return ttl, true
					}
				}
			}
			off = end
		}
	}
	return 0, false
}

// minimalResponseOPT echoes only the EDNS UDP size, extended RCODE/version,
// and DO bit. Client options such as COOKIE and ECS are never reflected.
func minimalResponseOPT(query []byte) []byte {
	opt := extractEDNSOPT(query)
	if len(opt) < 11 {
		return nil
	}
	out := make([]byte, 11)
	out[0] = 0
	copy(out[1:9], opt[1:9])
	out[7] &= 0x80
	out[8] = 0
	out[9], out[10] = 0, 0
	return out
}
