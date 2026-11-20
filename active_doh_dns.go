package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"lucx-doh-health-monitor/internal/activedoh"
)

const activeDoHAnswerTTL = 60 * time.Second

// activeDoHDNSResponse constructs the default mode-1 answer: the selected DoH
// endpoint's bootstrap IPs, not the IPs of the requested website.
func (r *Runtime) activeDoHDNSResponse(query []byte, snapshot *Snapshot) []byte {
	if r.activeDoHSelector == nil || snapshot == nil {
		return emptyNoErrorDNSResponse(query)
	}
	// A DNS request may have captured an old snapshot immediately before reload.
	// Never serve a selection unless both the request and current runtime snapshot
	// agree with the configuration generation used to probe that endpoint.
	current := r.currentSnapshot()
	if current == nil || current.activeDoHGeneration != snapshot.activeDoHGeneration {
		return emptyNoErrorDNSResponse(query)
	}

	now := time.Now()
	selection, ok := r.activeDoHSelector.Current(now)
	if !ok || selection.Candidate.ConfigGeneration != current.activeDoHGeneration {
		return emptyNoErrorDNSResponse(query)
	}

	name, qtype, questionEnd, err := parseQuestion(query)
	if err != nil || len(query) < 12 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return formerrResponse(query)
	}
	if qtype != 1 && qtype != 28 {
		return emptyNoErrorDNSResponse(query)
	}
	if questionEnd < 2 || binary.BigEndian.Uint16(query[questionEnd-2:questionEnd]) != 1 {
		return emptyNoErrorDNSResponse(query)
	}

	key := fmt.Sprintf("mode1:%d:%s", selection.Generation, cacheKey(query))
	cacheConfig := snapshot.cfg.Cache
	if cacheConfig.Enabled {
		if cached, found := r.cacheGet(key, packetID(query)); found {
			r.cacheHits.Add(1)
			if !r.activeDoHConfigMatches(snapshot) ||
				selection.Candidate.ConfigGeneration != snapshot.activeDoHGeneration {
				return emptyNoErrorDNSResponse(query)
			}
			return cached
		}
	}

	response, cacheable := buildActiveDoHResponse(query, name, qtype, questionEnd, selection, now)
	if !r.activeDoHConfigMatches(snapshot) ||
		selection.Candidate.ConfigGeneration != snapshot.activeDoHGeneration {
		return emptyNoErrorDNSResponse(query)
	}
	if cacheable && cacheConfig.Enabled && r.activeDoHSelector.Generation() == selection.Generation &&
		r.activeDoHConfigMatches(snapshot) {
		cacheConfig.MaxTTL = int(activeDoHAnswerTTL / time.Second)
		cacheConfig.MinTTL = 0 // preserve cache entries shorter than the general minimum TTL
		cacheConfig.NegativeTTL = 0 // synthetic NODATA answers are deliberately not cached
		r.cachePut(key, response, cacheConfig)
	}
	return response
}

// buildActiveDoHResponse returns (response, cacheable). Unsupported QTYPEs,
// missing address families and stale selections produce NOERROR with an empty
// Answer section. These synthetic empty answers are never cached.
func buildActiveDoHResponse(query []byte, qname string, qtype uint16, questionEnd int, selection activedoh.Selection, now time.Time) ([]byte, bool) {
	if len(query) < 12 || questionEnd < 12 || questionEnd > len(query) {
		return formerrResponse(query), false
	}
	remaining := selection.FreshUntil.Sub(now)
	if remaining < time.Second {
		return emptyNoErrorDNSResponse(query), false
	}
	ttl := uint32(remaining / time.Second)
	if ttl > uint32(activeDoHAnswerTTL/time.Second) {
		ttl = uint32(activeDoHAnswerTTL / time.Second)
	}
	if ttl == 0 {
		return emptyNoErrorDNSResponse(query), false
	}

	rawIPs := selection.Candidate.IPv4
	wantIPv4 := qtype == 1
	if qtype == 28 {
		rawIPs = selection.Candidate.IPv6
	} else if qtype != 1 {
		return emptyNoErrorDNSResponse(query), false
	}

	ips := make([]net.IP, 0, len(rawIPs))
	seen := make(map[string]struct{}, len(rawIPs))
	for _, raw := range rawIPs {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil {
			continue
		}
		if wantIPv4 {
			ip = ip.To4()
		} else if ip.To4() == nil {
			ip = ip.To16()
		} else {
			ip = nil
		}
		if ip == nil {
			continue
		}
		value := ip.String()
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		return emptyNoErrorDNSResponse(query), false
	}

	response := newDNSResponseHeader(query)
	response = append(response, query[12:questionEnd]...)
	for _, ip := range ips {
		response = append(response, 0xc0, 0x0c) // owner name points to QNAME
		response = append(response, byte(qtype>>8), byte(qtype), 0, 1)
		var ttlBytes [4]byte
		binary.BigEndian.PutUint32(ttlBytes[:], ttl)
		response = append(response, ttlBytes[:]...)
		response = append(response, byte(len(ip)>>8), byte(len(ip)))
		response = append(response, ip...)
	}
	binary.BigEndian.PutUint16(response[6:8], uint16(len(ips)))
	response = appendMinimalResponseOPT(response, query)
	return response, true
}

func emptyNoErrorDNSResponse(query []byte) []byte {
	if len(query) < 12 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return formerrResponse(query)
	}
	_, _, questionEnd, err := parseQuestion(query)
	if err != nil || questionEnd > len(query) {
		return formerrResponse(query)
	}
	response := newDNSResponseHeader(query)
	response = append(response, query[12:questionEnd]...)
	return appendMinimalResponseOPT(response, query)
}

func newDNSResponseHeader(query []byte) []byte {
	response := make([]byte, 12)
	copy(response[:2], query[:2])
	queryFlags := binary.BigEndian.Uint16(query[2:4])
	// Preserve opcode and RD; set QR and RA. Do not assert AD on a synthetic answer.
	responseFlags := (queryFlags & 0x7900) | 0x8080
	binary.BigEndian.PutUint16(response[2:4], responseFlags)
	binary.BigEndian.PutUint16(response[4:6], 1)
	return response
}

// appendMinimalResponseOPT preserves the client's UDP payload size and DO bit,
// but does not reflect request options such as COOKIE or ECS into the response.
func appendMinimalResponseOPT(response, query []byte) []byte {
	raw := extractEDNSOPT(query)
	if len(raw) < 11 {
		return response
	}
	payloadSize := binary.BigEndian.Uint16(raw[3:5])
	version := raw[6]
	requestFlags := binary.BigEndian.Uint16(raw[7:9])
	responseFlags := requestFlags & 0x8000 // retain only DNSSEC OK
	response = append(response,
		0,       // root owner name
		0, 41,   // OPT
		byte(payloadSize>>8), byte(payloadSize),
		0, version, byte(responseFlags>>8), byte(responseFlags),
		0, 0, // zero-length RDATA: no client COOKIE/ECS reflection
	)
	binary.BigEndian.PutUint16(response[10:12], 1)
	return response
}

func (r *Runtime) clearActiveDoHCache() {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	for key, item := range r.cache {
		if strings.HasPrefix(key, "mode1:") {
			delete(r.cache, key)
			r.cacheBytes -= item.size
		}
	}
	if r.cacheBytes < 0 {
		r.cacheBytes = 0
	}
	maxEntries := 8192
	if snapshot := r.currentSnapshot(); snapshot != nil && snapshot.cfg.Cache.MaxEntries > 0 {
		maxEntries = snapshot.cfg.Cache.MaxEntries
	}
	r.compactCacheOrderLocked(maxEntries)
}
