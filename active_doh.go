package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"lucx-doh-health-monitor/internal/activedoh"
)

const (
	activeDoHProbeInterval     = 5 * time.Minute
	activeDoHProbeTimeout      = 9 * time.Second
	activeDoHLookupTimeout     = 4 * time.Second
	activeDoHBootstrapTimeout  = 5 * time.Second
	activeDoHProbeWorkers      = 6
	activeDoHMaxServers        = 64
	activeDoHMaxWebsiteIPs     = 32
	activeDoHUserAgent         = "LucX-DoH-HealthMonitor/2.3.2"
)

type activeDoHProbeJob struct {
	serverID string
	upstream *UpstreamRuntime
	domain   string
	check    Check
}

type ActiveDoHStatus struct {
	ServerID   string    `json:"server_id"`
	URL        string    `json:"-"` // DoH URLs may contain credentials or query-string secrets.
	Hostname   string    `json:"hostname"`
	IPv4       []string  `json:"ipv4,omitempty"`
	IPv6       []string  `json:"ipv6,omitempty"`
	ResolvedAt time.Time `json:"resolved_at"`
	SelectedAt time.Time `json:"selected_at"`
	FreshUntil time.Time `json:"fresh_until"`
	Generation uint64    `json:"generation"`
	Score      int       `json:"score"`
	CheckCount int       `json:"check_count"`
}

func (r *Runtime) activeDoHLoop(ctx context.Context) {
	for {
		r.runActiveDoHSelection(ctx)
		timer := time.NewTimer(activeDoHProbeInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-r.activeDoHTrigger:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-timer.C:
		}
	}
}

func (r *Runtime) runActiveDoHSelection(parent context.Context) {
	if r.activeDoHSelector == nil {
		return
	}
	ctx, cancel := context.WithTimeout(parent, 2*activeDoHProbeInterval)
	defer cancel()

	s := r.currentSnapshot()
	if s == nil {
		return
	}
	candidates := r.activeDoHCandidates(ctx, s)
	if ctx.Err() != nil {
		return
	}
	if !r.activeDoHConfigMatches(s) {
		logLine("INFO", "ACTIVE_DOH selection cycle discarded: configuration changed during bootstrap lookup")
		return
	}
	// Capture the selection timestamp after bootstrap lookups: a successful lookup may
	// have refreshed ResolvedAt during candidate collection, so it must not appear future-dated.
	now := time.Now().UTC()
	if len(candidates) == 0 {
		previousGeneration := r.activeDoHSelector.Generation()
		_, _ = r.activeDoHSelector.Select(nil, nil, now)
		if r.activeDoHSelector.Generation() != previousGeneration {
			r.clearActiveDoHCache()
		}
		logLine("WARN", "ACTIVE_DOH no fresh bootstrap endpoints are eligible")
		return
	}

	checks := activeDoHChecks(s)
	jobs := make(chan activeDoHProbeJob)
	resultsCh := make(chan activedoh.ProbeResult, len(candidates)*len(activedoh.ControlDomains()))
	workerCount := activeDoHProbeWorkers
	jobCount := len(candidates) * len(activedoh.ControlDomains())
	if workerCount > jobCount {
		workerCount = jobCount
	}
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				probeCtx, probeCancel := context.WithTimeout(ctx, activeDoHProbeTimeout)
				result := r.probeActiveDoHDomain(probeCtx, job, now)
				probeCancel()
				resultsCh <- result
			}
		}()
	}

sendJobs:
	for _, candidate := range candidates {
		upstream := s.upstreams[candidate.ServerID]
		if upstream == nil {
			continue
		}
		for _, domain := range activedoh.ControlDomains() {
			check := checks[domain]
			check.Domain = domain
			select {
			case jobs <- activeDoHProbeJob{serverID: candidate.ServerID, upstream: upstream, domain: domain, check: check}:
			case <-ctx.Done():
				break sendJobs
			}
		}
	}
	close(jobs)
	wg.Wait()
	close(resultsCh)
	if ctx.Err() != nil {
		return
	}

	results := make([]activedoh.ProbeResult, 0, jobCount)
	successes := 0
	for result := range resultsCh {
		results = append(results, result)
		if result.Success {
			successes++
		}
	}
	if !r.activeDoHConfigMatches(s) {
		logLine("INFO", "ACTIVE_DOH selection cycle discarded: configuration changed during probes")
		return
	}
	previousGeneration := r.activeDoHSelector.Generation()
	selected, ok := r.activeDoHSelector.Select(candidates, results, now)
	if r.activeDoHSelector.Generation() != previousGeneration {
		r.clearActiveDoHCache()
	}
	if !ok {
		logLine("WARN", "ACTIVE_DOH no healthy endpoint selected candidates=%d successful_checks=%d", len(candidates), successes)
		return
	}
	logLine("INFO", "ACTIVE_DOH selected server=%s score=%d/%d ipv4=%d ipv6=%d generation=%d freshness_until=%s",
		selected.Candidate.ServerID, selected.Score, selected.CheckCount,
		len(selected.Candidate.IPv4), len(selected.Candidate.IPv6), selected.Generation,
		selected.FreshUntil.UTC().Format(time.RFC3339))
}

func (r *Runtime) activeDoHCandidates(ctx context.Context, snapshot *Snapshot) []activedoh.Candidate {
	ids := make([]string, 0, len(snapshot.upstreams))
	for id := range snapshot.upstreams {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) > activeDoHMaxServers {
		logLine("WARN", "ACTIVE_DOH endpoint limit reached configured=%d limit=%d", len(ids), activeDoHMaxServers)
		ids = ids[:activeDoHMaxServers]
	}

	candidates := make([]activedoh.Candidate, 0, len(ids))
	for _, id := range ids {
		if ctx.Err() != nil {
			return candidates
		}
		upstream := snapshot.upstreams[id]
		if upstream == nil || upstream.systemDNS != nil || upstream.bootstrap == nil || strings.TrimSpace(upstream.cfg.URL) == "" {
			continue
		}

		resolveCtx, cancel := context.WithTimeout(ctx, activeDoHBootstrapTimeout)
		ips, resolveErr := upstream.bootstrap.addresses(resolveCtx, false)
		cancel()
		status := upstream.bootstrap.status()
		if resolveErr != nil {
			logLine("WARN", "ACTIVE_DOH bootstrap refresh warning server=%s error=%s", id, safeLog(resolveErr.Error()))
		}
		if len(ips) == 0 {
			continue
		}

		candidate := activedoh.Candidate{
			ServerID: id,
			URL: upstream.cfg.URL,
			Hostname: status.Hostname,
			ResolvedAt: status.ResolvedAt,
			ConfigGeneration: snapshot.activeDoHGeneration,
		}
		for _, raw := range ips {
			ip := net.ParseIP(raw)
			if !isPublicDoHIP(ip) {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				candidate.IPv4 = append(candidate.IPv4, v4.String())
			} else if v6 := ip.To16(); v6 != nil {
				candidate.IPv6 = append(candidate.IPv6, v6.String())
			}
		}
		if len(candidate.IPv4)+len(candidate.IPv6) == 0 {
			logLine("WARN", "ACTIVE_DOH endpoint rejected: no globally routable IP server=%s", id)
			continue
		}
		candidates = append(candidates, candidate)
	}
	return candidates
}

func activeDoHChecks(snapshot *Snapshot) map[string]Check {
	out := make(map[string]Check, len(activedoh.ControlDomains()))
	groupIDs := make([]string, 0, len(snapshot.groups))
	for id := range snapshot.groups {
		groupIDs = append(groupIDs, id)
	}
	sort.Strings(groupIDs)
	for _, groupID := range groupIDs {
		group := snapshot.groups[groupID]
		for _, check := range group.Checks {
			domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(check.Domain)), ".")
			if domain == "" {
				continue
			}
			for _, control := range activedoh.ControlDomains() {
				if domain == control {
					if _, exists := out[control]; !exists {
						out[control] = check
					}
					break
				}
			}
		}
	}
	return out
}

func (r *Runtime) probeActiveDoHDomain(ctx context.Context, job activeDoHProbeJob, now time.Time) (result activedoh.ProbeResult) {
	result = activedoh.ProbeResult{
		ServerID: job.serverID,
		Domain: job.domain,
		CheckedAt: now,
	}
	started := time.Now()
	defer func() { result.Duration = time.Since(started) }()

	websiteIPs := make([]string, 0, 8)
	var lastErr error
	for _, qtype := range []uint16{1, 28} {
		query := makeDNSQuery(job.domain, qtype)
		queryCtx, cancel := context.WithTimeout(ctx, activeDoHLookupTimeout)
		response, _, queryErr := r.queryVia(queryCtx, job.upstream, query)
		cancel()
		if queryErr != nil {
			lastErr = fmt.Errorf("DoH A/AAAA query: %w", queryErr)
			continue
		}
		if err := validateDNSResponse(query, response, job.serverID); err != nil {
			lastErr = fmt.Errorf("invalid DoH DNS response: %w", err)
			continue
		}
		if dnsRCode(response) != 0 {
			lastErr = fmt.Errorf("DNS qtype=%d rcode=%d", qtype, dnsRCode(response))
			continue
		}
		if dnsTruncated(response) {
			lastErr = fmt.Errorf("DNS qtype=%d response is truncated", qtype)
			continue
		}
		ips, parseErr := parseActiveDoHAddressRecords(response, qtype)
		if parseErr != nil {
			lastErr = fmt.Errorf("DNS qtype=%d parse: %w", qtype, parseErr)
			continue
		}
		for _, raw := range ips {
			if !isPublicDoHIP(net.ParseIP(raw)) {
				continue
			}
			websiteIPs = appendUniqueString(websiteIPs, raw)
			if len(websiteIPs) >= activeDoHMaxWebsiteIPs {
				break
			}
		}
	}
	if len(websiteIPs) == 0 {
		if lastErr == nil {
			lastErr = fmt.Errorf("DNS returned no globally routable A/AAAA addresses")
		}
		result.Error = lastErr.Error()
		return result
	}

	probeURL := strings.TrimSpace(job.check.HTTPURL)
	if probeURL == "" {
		probeURL = "https://" + job.domain + "/"
	}
	parsed, err := url.Parse(probeURL)
	if err != nil || !validActiveDoHProbeURL(parsed, job.domain) {
		result.Error = "HTTP probe URL must be HTTPS on port 443 and use the checked hostname"
		return result
	}

	for _, ip := range websiteIPs {
		status, body, probeErr := probeActiveDoHIP(ctx, probeURL, parsed.Hostname(), ip)
		if probeErr != nil {
			lastErr = probeErr
			continue
		}
		accepted := len(job.check.ExpectedStatus) == 0 && status >= 200 && status < 400
		for _, expected := range job.check.ExpectedStatus {
			if status == expected {
				accepted = true
				break
			}
		}
		if strings.EqualFold(job.domain, "gemini.google.com") {
			// probeActiveDoHIP already rejected redirects outside Google's allowed hosts.
			accepted = status >= 200 && status < 400
			if geminiRegionBlocked(body) {
				lastErr = fmt.Errorf("Gemini regional restriction detected")
				continue
			}
		}
		if !accepted {
			lastErr = fmt.Errorf("unexpected HTTP status %d", status)
			continue
		}
		if job.check.VerifyOIDC {
			if err := verifyOIDCIssuer(body, probeURL); err != nil {
				lastErr = err
				continue
			}
		}
		result.Success = true
		result.Error = ""
		return result
	}
	if lastErr != nil {
		result.Error = "HTTPS probe: " + lastErr.Error()
	}
	return result
}

func validActiveDoHProbeURL(parsed *url.URL, domain string) bool {
	if parsed == nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" ||
		parsed.Fragment != "" {
		return false
	}
	if parsed.Port() != "" && parsed.Port() != "443" {
		return false
	}
	return strings.EqualFold(strings.TrimSuffix(parsed.Hostname(), "."), domain)
}

func probeActiveDoHIP(ctx context.Context, targetURL, host, ip string) (int, []byte, error) {
	if !isPublicDoHIP(net.ParseIP(ip)) {
		return 0, nil, fmt.Errorf("refusing non-public website IP")
	}
	client := newPinnedHTTPClient(ip, host, activeDoHProbeTimeout)
	defer client.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("User-Agent", activeDoHUserAgent)
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	body, err := readHTTPProbeBody(response.Body)
	if err != nil {
		return response.StatusCode, nil, err
	}
	if response.StatusCode >= 300 && response.StatusCode < 400 && strings.EqualFold(host, "gemini.google.com") {
		if !geminiRedirectAllowed(response) {
			location := ""
			if target, locationErr := response.Location(); locationErr == nil {
				location = target.String()
			}
			return response.StatusCode, body, fmt.Errorf("unexpected Gemini redirect to %q", location)
		}
	}
	return response.StatusCode, body, nil
}

func parseActiveDoHAddressRecords(packet []byte, qtype uint16) ([]string, error) {
	if len(packet) < 12 {
		return nil, fmt.Errorf("short DNS response")
	}
	if qtype != 1 && qtype != 28 {
		return nil, fmt.Errorf("unsupported address qtype %d", qtype)
	}
	questionCount := int(binary.BigEndian.Uint16(packet[4:6]))
	answerCount := int(binary.BigEndian.Uint16(packet[6:8]))
	authorityCount := int(binary.BigEndian.Uint16(packet[8:10]))
	additionalCount := int(binary.BigEndian.Uint16(packet[10:12]))
	offset := 12
	for i := 0; i < questionCount; i++ {
		_, next, err := decodeName(packet, offset)
		if err != nil {
			return nil, err
		}
		offset = next + 4
		if offset > len(packet) {
			return nil, fmt.Errorf("truncated DNS question")
		}
	}
	var ips []string
	totalRecords := answerCount + authorityCount + additionalCount
	for i := 0; i < totalRecords; i++ {
		_, next, err := decodeName(packet, offset)
		if err != nil {
			return ips, err
		}
		offset = next
		if offset+10 > len(packet) {
			return ips, fmt.Errorf("truncated DNS RR header")
		}
		recordType := binary.BigEndian.Uint16(packet[offset : offset+2])
		recordClass := binary.BigEndian.Uint16(packet[offset+2 : offset+4])
		recordLength := int(binary.BigEndian.Uint16(packet[offset+8 : offset+10]))
		offset += 10
		if offset+recordLength > len(packet) {
			return ips, fmt.Errorf("truncated DNS RDATA")
		}
		if i < answerCount && recordClass == 1 && recordType == qtype {
			if qtype == 1 && recordLength == net.IPv4len {
				ips = appendUniqueString(ips, net.IP(packet[offset:offset+recordLength]).String())
			} else if qtype == 28 && recordLength == net.IPv6len {
				ips = appendUniqueString(ips, net.IP(packet[offset:offset+recordLength]).String())
			}
		}
		offset += recordLength
	}
	return ips, nil
}

func filterPublicDoHIPs(values []string) []string {
	filtered := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, raw := range values {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if !isPublicDoHIP(ip) {
			continue
		}
		value := ip.String()
		if !seen[value] {
			seen[value] = true
			filtered = append(filtered, value)
		}
	}
	return filtered
}

func isPublicDoHIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		a, b := int(v4[0]), int(v4[1])
		switch {
		case a == 0 || a == 10 || a == 127 || a >= 224:
			return false
		case a == 100 && b >= 64 && b <= 127:
			return false
		case a == 169 && b == 254:
			return false
		case a == 172 && b >= 16 && b <= 31:
			return false
		case a == 192 && b == 168:
			return false
		case a == 192 && b == 0 && (v4[2] == 0 || v4[2] == 2):
			return false
		case a == 192 && b == 88 && v4[2] == 99:
			return false
		case a == 198 && (b == 18 || b == 19):
			return false
		case a == 198 && b == 51 && v4[2] == 100:
			return false
		case a == 203 && b == 0 && v4[2] == 113:
			return false
		}
		return true
	}
	v6 := ip.To16()
	if v6 == nil || (v6[0]&0xe0) != 0x20 {
		return false
	}
	if v6[0] == 0x20 && v6[1] == 0x01 && v6[2] <= 0x01 {
		return false
	}
	if v6[0] == 0x20 && v6[1] == 0x01 && v6[2] == 0x0d && v6[3] == 0xb8 {
		return false
	}
	if v6[0] == 0x20 && v6[1] == 0x02 {
		return false
	}
	return true
}

func statusSafeDoHURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	parsed.User = nil
	parsed.Path = ""
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func (r *Runtime) activeDoHConfigMatches(snapshot *Snapshot) bool {
	if snapshot == nil {
		return false
	}
	current := r.currentSnapshot()
	return current != nil && current.activeDoHGeneration == snapshot.activeDoHGeneration
}

func (r *Runtime) activeDoHStatus() *ActiveDoHStatus {
	if r.activeDoHSelector == nil {
		return nil
	}
	snapshot := r.currentSnapshot()
	if snapshot == nil {
		return nil
	}
	selection, ok := r.activeDoHSelector.Current(time.Now())
	if !ok || selection.Candidate.ConfigGeneration != snapshot.activeDoHGeneration ||
		!r.activeDoHConfigMatches(snapshot) {
		return nil
	}
	return &ActiveDoHStatus{
		ServerID: selection.Candidate.ServerID,
		URL: statusSafeDoHURL(selection.Candidate.URL),
		Hostname: selection.Candidate.Hostname,
		IPv4: append([]string(nil), selection.Candidate.IPv4...),
		IPv6: append([]string(nil), selection.Candidate.IPv6...),
		ResolvedAt: selection.Candidate.ResolvedAt,
		SelectedAt: selection.SelectedAt,
		FreshUntil: selection.FreshUntil,
		Generation: selection.Generation,
		Score: selection.Score,
		CheckCount: selection.CheckCount,
	}
}
