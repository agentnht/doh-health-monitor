package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	smartDNSProbeTimeout  = 10 * time.Second
	smartDNSMaxCandidates = 8
	smartDNSProbeWorkers  = 16
)

type smartDNSProbeJob struct {
	ip        string
	check     Check
	required  bool
}

type smartDNSProbeResult struct {
	ip             string
	latency        time.Duration
	score          int
	requiredFailed bool
}

// smartDNSSelectResponse validates every answer IP against the editable checks
// from tst-domen.txt. Each check pins the candidate IP while retaining that
// check's hostname as TLS SNI and HTTP Host. Probes use the VPS default route.
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
	_, qtype, _, err := parseQuestion(query)
	if err != nil || (qtype != 1 && qtype != 28) {
		return response
	}
	ips, err := parseActiveDoHAddressRecords(response, qtype)
	if err != nil || len(ips) == 0 {
		return response
	}
	if len(ips) > smartDNSMaxCandidates {
		ips = ips[:smartDNSMaxCandidates]
	}
	snapshot := r.currentSnapshot()
	checks := smartDNSConfiguredChecks(snapshot)
	if len(checks) == 0 {
		logLine("WARN", "SMARTDNS no checks configured in tst-domen.txt; preserving DoH response")
		return response
	}

	candidates := make([]string, 0, len(ips))
	for _, ip := range ips {
		if isPublicDoHIP(net.ParseIP(ip)) {
			candidates = append(candidates, ip)
		}
	}
	if len(candidates) == 0 {
		return response
	}

	probeCtx, cancel := context.WithTimeout(context.Background(), smartDNSProbeTimeout)
	defer cancel()
	jobCount := len(candidates) * len(checks)
	jobs := make(chan smartDNSProbeJob)
	results := make(chan smartDNSProbeResult, jobCount)
	workers := smartDNSProbeWorkers
	if workers > jobCount {
		workers = jobCount
	}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				started := time.Now()
				checkCtx, checkCancel := context.WithTimeout(probeCtx, activeDoHProbeTimeout)
				ok := smartDNSProbeConfiguredDomain(checkCtx, job.check, job.ip)
				checkCancel()
				results <- smartDNSProbeResult{
					ip: job.ip, latency: time.Since(started),
					score: boolScore(ok), requiredFailed: job.required && !ok,
				}
			}
		}()
	}

sendJobs:
	for _, ip := range candidates {
		for _, check := range checks {
			select {
			case jobs <- smartDNSProbeJob{ip: ip, check: check, required: check.Required}:
			case <-probeCtx.Done():
				break sendJobs
			}
		}
	}
	close(jobs)
	wg.Wait()
	close(results)
	if probeCtx.Err() != nil {
		logLine("DEBUG", "SMARTDNS checks timed out; preserving original DoH response")
		return response
	}

	byIP := make(map[string]*smartDNSProbeResult, len(candidates))
	for _, ip := range candidates {
		byIP[ip] = &smartDNSProbeResult{ip: ip}
	}
	for result := range results {
		current := byIP[result.ip]
		if current == nil {
			continue
		}
		current.score += result.score
		current.latency += result.latency
		current.requiredFailed = current.requiredFailed || result.requiredFailed
	}
	best := smartDNSBestCandidate(byIP)
	if best == nil {
		logLine("DEBUG", "SMARTDNS no IP passed configured checks; preserving DoH response")
		return response
	}

	// Compare mean latency among candidates with the same number of successful
	// checks. Required checks are hard gates; optional checks contribute score.
	successCount := 0
	for _, result := range byIP {
		if result.score > 0 && !result.requiredFailed {
			successCount++
		}
	}
	if successCount == 0 {
		return response
	}
	bestLatency := best.latency / time.Duration(best.score)
	rewritten, err := smartDNSKeepAddress(response, qtype, best.ip)
	if err != nil {
		logLine("WARN", "SMARTDNS could not rewrite DNS answer for selected IP: %v", err)
		return response
	}
	logLine("DEBUG", "SMARTDNS selected %s after configured checks score=%d/%d latency=%s",
		best.ip, best.score, len(checks), bestLatency.Round(time.Millisecond))
	return rewritten
}

func boolScore(ok bool) int {
	if ok {
		return 1
	}
	return 0
}

func smartDNSConfiguredChecks(snapshot *Snapshot) []Check {
	if snapshot == nil {
		return nil
	}
	groupIDs := make([]string, 0, len(snapshot.groups))
	for id := range snapshot.groups {
		groupIDs = append(groupIDs, id)
	}
	sort.Strings(groupIDs)
	seen := make(map[string]bool)
	var checks []Check
	for _, groupID := range groupIDs {
		for _, check := range snapshot.groups[groupID].Checks {
			domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(check.Domain)), ".")
			if domain == "" || seen[domain] {
				continue
			}
			check.Domain = domain
			seen[domain] = true
			checks = append(checks, check)
		}
	}
	return checks
}

func smartDNSProbeConfiguredDomain(ctx context.Context, check Check, ip string) bool {
	domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(check.Domain)), ".")
	if domain == "" || !isPublicDoHIP(net.ParseIP(ip)) {
		return false
	}
	targetURL := strings.TrimSpace(check.HTTPURL)
	if targetURL == "" {
		targetURL = (&url.URL{Scheme: "https", Host: domain, Path: "/"}).String()
	}
	parsed, err := url.Parse(targetURL)
	if err != nil || !validActiveDoHProbeURL(parsed, domain) {
		return false
	}
	status, body, err := probeActiveDoHIP(ctx, targetURL, domain, ip)
	if err != nil {
		return false
	}
	accepted := len(check.ExpectedStatus) == 0 && status >= 200 && status < 400
	for _, expected := range check.ExpectedStatus {
		if status == expected {
			accepted = true
			break
		}
	}
	if strings.EqualFold(domain, "gemini.google.com") {
		accepted = status >= 200 && status < 400 && !geminiRegionBlocked(body)
	}
	if !accepted {
		return false
	}
	if check.VerifyOIDC && verifyOIDCIssuer(body, targetURL) != nil {
		return false
	}
	return true
}

func smartDNSBestCandidate(results map[string]*smartDNSProbeResult) *smartDNSProbeResult {
	var best *smartDNSProbeResult
	for _, candidate := range results {
		if candidate == nil || candidate.score == 0 || candidate.requiredFailed {
			continue
		}
		if best == nil || candidate.score > best.score ||
			(candidate.score == best.score && candidate.latency/time.Duration(candidate.score) < best.latency/time.Duration(best.score)) {
			best = candidate
		}
	}
	return best
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
