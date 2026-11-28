package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	smartDNSProbeTimeout  = 3 * time.Second
	smartDNSMaxCandidates = 8
	smartDNSProbeWorkers  = 4
)

type smartDNSProbeResult struct {
	ip      string
	latency time.Duration
	ok      bool
}

// smartDNSSelectResponse validates the address records returned by the selected
// DoH provider using HTTPS with the original QNAME as TLS SNI and HTTP Host.
// Probes deliberately use the VPS default route; they do not enter Xray outbounds.
func (r *Runtime) smartDNSSelectResponse(query, response []byte) []byte {
	if len(response) < 12 || dnsRCode(response) != 0 || dnsTruncated(response) {
		return response
	}
	flags := binary.BigEndian.Uint16(response[2:4])
	// Rewriting an authenticated DNS answer would invalidate DNSSEC. Leave
	// signed/DO responses untouched rather than returning misleading AD data.
	if flags&0x0020 != 0 || dnsQueryDO(query) {
		return response
	}
	name, qtype, _, err := parseQuestion(query)
	if err != nil || (qtype != 1 && qtype != 28) {
		return response
	}
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if host == "" || strings.Contains(host, "/") {
		return response
	}
	ips, err := parseActiveDoHAddressRecords(response, qtype)
	if err != nil || len(ips) == 0 {
		return response
	}
	if len(ips) > smartDNSMaxCandidates {
		ips = ips[:smartDNSMaxCandidates]
	}
	probeCtx, cancel := context.WithTimeout(context.Background(), smartDNSProbeTimeout)
	defer cancel()
	jobs := make(chan string)
	results := make(chan smartDNSProbeResult, len(ips))
	workers := smartDNSProbeWorkers
	if workers > len(ips) {
		workers = len(ips)
	}
	var wg sync.WaitGroup
	targetURL := (&url.URL{Scheme: "https", Host: host, Path: "/"}).String()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				started := time.Now()
				status, _, probeErr := probeActiveDoHIP(probeCtx, targetURL, host, ip)
				accepted := probeErr == nil && status >= 200 && status < 400
				results <- smartDNSProbeResult{ip: ip, latency: time.Since(started), ok: accepted}
			}
		}()
	}
send:
	for _, ip := range ips {
		if !isPublicDoHIP(net.ParseIP(ip)) {
			continue
		}
		select {
		case jobs <- ip:
		case <-probeCtx.Done():
			break send
		}
	}
	close(jobs)
	wg.Wait()
	close(results)
	best := smartDNSProbeResult{}
	for result := range results {
		if result.ok && (!best.ok || result.latency < best.latency) {
			best = result
		}
	}
	if !best.ok {
		logLine("DEBUG", "SMARTDNS no verified address for %s; preserving DoH response", host)
		return response
	}
	rewritten, err := smartDNSKeepAddress(response, qtype, best.ip)
	if err != nil {
		logLine("WARN", "SMARTDNS could not rewrite DNS answer for %s: %v", host, err)
		return response
	}
	logLine("DEBUG", "SMARTDNS selected %s for %s latency=%s", best.ip, host, best.latency.Round(time.Millisecond))
	return rewritten
}

func dnsQueryDO(query []byte) bool {
	opt := extractEDNSOPT(query)
	return len(opt) >= 9 && binary.BigEndian.Uint16(opt[7:9])&0x8000 != 0
}

// smartDNSKeepAddress preserves the question, CNAME chain, authority and
// additional sections while retaining only the selected A/AAAA RR in the
// answer section. All offsets are validated before any response is returned.
func smartDNSKeepAddress(packet []byte, qtype uint16, selected string) ([]byte, error) {
	if len(packet) < 12 || (qtype != 1 && qtype != 28) {
		return nil, fmt.Errorf("invalid DNS packet or qtype")
	}
	selectedIP := net.ParseIP(selected)
	if qtype == 1 {
		selectedIP = selectedIP.To4()
	} else {
		selectedIP = selectedIP.To16()
		if selectedIP != nil && selectedIP.To4() != nil {
			return nil, fmt.Errorf("selected address family does not match qtype")
		}
	}
	if selectedIP == nil {
		return nil, fmt.Errorf("invalid selected IP")
	}
	_, _, offset, err := parseQuestion(packet)
	if err != nil || offset > len(packet) {
		return nil, fmt.Errorf("invalid DNS question")
	}
	out := append([]byte(nil), packet...)
	counts := [3]int{
		int(binary.BigEndian.Uint16(packet[6:8])),
		int(binary.BigEndian.Uint16(packet[8:10])),
		int(binary.BigEndian.Uint16(packet[10:12])),
	}
	found := false
	for section, count := range counts {
		for i := 0; i < count; i++ {
			_, next, nameErr := decodeName(packet, offset)
			if nameErr != nil || next+10 > len(packet) {
				return nil, fmt.Errorf("malformed DNS RR")
			}
			typ := binary.BigEndian.Uint16(packet[next : next+2])
			class := binary.BigEndian.Uint16(packet[next+2 : next+4])
			rdlen := int(binary.BigEndian.Uint16(packet[next+8 : next+10]))
			end := next + 10 + rdlen
			if end > len(packet) {
				return nil, fmt.Errorf("truncated DNS RDATA")
			}
			if section == 0 && typ == 46 && rdlen >= 2 && binary.BigEndian.Uint16(packet[next+10:next+12]) == qtype {
				return nil, fmt.Errorf("DNSSEC RRSIG covers rewritten RRset")
			}
			if section == 0 && typ == qtype && class == 1 {
				expected := net.IPv4len
				if qtype == 28 {
					expected = net.IPv6len
				}
				if rdlen == expected {
					copy(out[next+10:end], selectedIP)
					found = true
				}
			}
			offset = end
		}
	}
	if offset != len(packet) {
		return nil, fmt.Errorf("unexpected trailing DNS bytes")
	}
	if !found {
		return nil, fmt.Errorf("selected address record not found")
	}
	return out, nil
}

// activeDoHCacheKey isolates raw DoH answers from SmartDNS-selected answers.
func activeDoHCacheKey(query []byte, snapshot *Snapshot) string {
	key := cacheKey(query)
	if snapshot != nil && snapshot.cfg.SmartDNSEnabled {
		return key + "|smartdns"
	}
	return key
}
