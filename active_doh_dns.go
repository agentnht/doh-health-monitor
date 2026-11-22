package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"lucx-doh-health-monitor/internal/activedoh"
)

const activeDoHMaxCacheTTL = 300 * time.Second

// activeDoHDNSResponse forwards the original A/AAAA query through the healthy
// DoH endpoint selected by ActiveDoHSelector and returns its DNS response.
func (r *Runtime) activeDoHDNSResponse(query []byte, snapshot *Snapshot) []byte {
	_, qtype, questionEnd, err := parseQuestion(query)
	if err != nil || len(query) < 12 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return formerrResponse(query)
	}
	// The Geosite listener currently handles address lookups only. Forward the
	// original A/AAAA query to the selected DoH endpoint; do not synthesize the
	// endpoint's bootstrap address as the answer for the requested name.
	if qtype != 1 && qtype != 28 {
		return emptyNoErrorDNSResponse(query)
	}
	if questionEnd < 2 || binary.BigEndian.Uint16(query[questionEnd-2:questionEnd]) != 1 {
		return emptyNoErrorDNSResponse(query)
	}
	if r.activeDoHSelector == nil || snapshot == nil {
		return servfailResponse(query)
	}

	current := r.currentSnapshot()
	if current == nil || current.activeDoHGeneration != snapshot.activeDoHGeneration {
		return servfailResponse(query)
	}
	selection, ok := r.activeDoHSelector.Current(time.Now())
	if !ok || selection.Candidate.ConfigGeneration != current.activeDoHGeneration {
		return servfailResponse(query)
	}

	key := fmt.Sprintf("mode1:%d:%s", selection.Generation, cacheKey(query))
	cacheConfig := snapshot.cfg.Cache
	if cacheConfig.Enabled {
		if cached, found := r.cacheGet(key, packetID(query)); found {
			r.cacheHits.Add(1)
			if !r.activeDoHConfigMatches(snapshot) ||
				selection.Candidate.ConfigGeneration != snapshot.activeDoHGeneration ||
				r.activeDoHSelector.Generation() != selection.Generation {
				return servfailResponse(query)
			}
			return cached
		}
	}

	totalTimeout := 15 * time.Second
	if snapshot.cfg.DNSQueryTimeoutSeconds > 0 {
		totalTimeout = time.Duration(snapshot.cfg.DNSQueryTimeoutSeconds) * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), totalTimeout)
	dohTimeout := 10 * time.Second
	if snapshot.cfg.DoHTimeoutSeconds > 0 {
		dohTimeout = time.Duration(snapshot.cfg.DoHTimeoutSeconds) * time.Second
	}
	if totalTimeout < dohTimeout {
		dohTimeout = totalTimeout
	}
	response, queryErr := sendActiveDoH(ctx, selection.Candidate, query, dohTimeout)
	cancel()
	if queryErr != nil {
		r.failures.Add(1)
		// Prompt a fresh selector cycle instead of waiting for the regular
		// probe interval after the selected endpoint fails during live traffic.
		select {
		case r.activeDoHTrigger <- struct{}{}:
		default:
		}
		return servfailResponse(query)
	}

	// Do not return a response obtained from an endpoint after a concurrent
	// configuration reload or selector switch invalidated that selection.
	if !r.activeDoHConfigMatches(snapshot) ||
		selection.Candidate.ConfigGeneration != snapshot.activeDoHGeneration ||
		r.activeDoHSelector.Generation() != selection.Generation {
		return servfailResponse(query)
	}

	if cacheConfig.Enabled {
		cacheResponse := append([]byte(nil), response...)
		maxTTL := activeDoHMaxCacheTTL
		if cacheConfig.MaxTTL > 0 && time.Duration(cacheConfig.MaxTTL)*time.Second < maxTTL {
			maxTTL = time.Duration(cacheConfig.MaxTTL) * time.Second
		}
		cacheable := prepareMode2ResponseForCache(cacheResponse, uint32(maxTTL/time.Second))
		if cacheable && r.activeDoHSelector.Generation() == selection.Generation &&
			r.activeDoHConfigMatches(snapshot) {
			cacheConfig.MinTTL = 0
			cacheConfig.MaxTTL = int(maxTTL / time.Second)
			r.cachePut(key, cacheResponse, cacheConfig)
		}
	}
	return response
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
		0,     // root owner name
		0, 41, // OPT
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
