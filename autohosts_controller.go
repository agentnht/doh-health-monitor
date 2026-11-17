package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"lucx-doh-health-monitor/internal/autohosts"
)

var autoHostsDomains = []string{
	"chatgpt.com",
	"claude.ai",
	"gemini.google.com",
	"elevenlabs.io",
	"grok.com",
	"www.perplexity.ai",
	"notebooklm.google.com",
	"aistudio.google.com",
}

const (
	autoHostsProbeWorkers = 6
	autoHostsMaxServers = 64
	autoHostsProbeTimeout = 9 * time.Second
	autoHostsFailureCycles = 2
	autoHostsMinimumHold = 10 * time.Minute
	autoHostsSwitchCooldown = 10 * time.Minute
)

type autoHostsController struct {
	runtime *Runtime
	manager *autohosts.Manager
	trigger chan struct{}
	mu sync.Mutex
	activeSince time.Time
	lastSwitch time.Time
	activeFailures int
	betterCandidate string
	betterCandidateStreak int
	consecutiveFailures int
}

func newAutoHostsController(r *Runtime, manager *autohosts.Manager) *autoHostsController {
	return &autoHostsController{runtime:r, manager:manager, trigger:make(chan struct{},1)}
}

func (c *autoHostsController) run(ctx context.Context) {
	for {
		state := c.manager.State()
		interval := state.Config.CheckInterval
		if interval < 10*time.Second { interval = 5*time.Minute }
		delay := interval
		if state.Config.Enabled && !state.Config.EmergencyOff {
			cycleCtx, cancel := context.WithTimeout(ctx, 2*interval)
			err := c.runCycle(cycleCtx, time.Now().UTC())
			cancel()
			c.mu.Lock()
			if err != nil && !errors.Is(err, context.Canceled) {
				c.consecutiveFailures++
				logLine("WARN", "AUTO_HOSTS cycle failed streak=%d: %v", c.consecutiveFailures, err)
				capDelay := time.Hour
				if interval > capDelay { capDelay = interval }
				for i:=0; i<c.consecutiveFailures && delay<capDelay; i++ { delay *= 2; if delay > capDelay { delay = capDelay } }
			} else if err == nil { c.consecutiveFailures = 0 }
			c.mu.Unlock()
		}
		timer := time.NewTimer(autoHostsJitter(delay))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-c.trigger:
			if !timer.Stop() { select { case <-timer.C: default: } }
		case <-timer.C:
		}
	}
}

func autoHostsJitter(interval time.Duration) time.Duration {
	spread := interval / 10
	if spread <= 0 { return interval }
	jitter := time.Duration(time.Now().UnixNano() % int64(spread))
	return interval - spread/2 + jitter
}

func (c *autoHostsController) Trigger() { select { case c.trigger <- struct{}{}: default: } }

type autoHostsProbeJob struct {
	serverID string
	upstream *UpstreamRuntime
	domain string
	check Check
}

func (c *autoHostsController) runCycle(ctx context.Context, now time.Time) error {
	endpoints, results, err := c.probeAll(ctx, now)
	if err != nil { c.recordPinnedFailure(err, now); return err }
	activeID, err := c.chooseActive(endpoints, results, now)
	if err != nil { c.recordPinnedFailure(err, now); return err }
	if err := c.manager.ApplyFullCycle(activeID, endpoints, results, now); err != nil { return err }
	successCount := 0
	totalSuccess := 0
	for _, result := range results { if result.Success { totalSuccess++ }; if result.ServerID == activeID && result.Success { successCount++ } }
	logLine("INFO", "AUTO_HOSTS cycle completed servers=%d pairs=%d active=%s active_domains=%d total_success=%d", len(endpoints), len(results), activeID, successCount, totalSuccess)
	if totalSuccess == 0 { return errors.New("all DoH server/domain probes failed") }
	return nil
}

func (c *autoHostsController) recordPinnedFailure(cause error, now time.Time) {
	state := c.manager.State()
	if state.Config.Mode == "pinned" && state.Config.PinnedServerID != "" {
		_ = c.manager.RecordProbeFailures(state.Config.PinnedServerID, autoHostsDomains, cause.Error(), now)
	}
}

type autoHostsDryRunPreview struct {
	ActiveServer string `json:"active_server"`
	EndpointIPv4 []string `json:"endpoint_ipv4,omitempty"`
	EndpointIPv6 []string `json:"endpoint_ipv6,omitempty"`
	Domains []string `json:"domains"`
	Results []autohosts.ProbeResult `json:"results"`
}

func (c *autoHostsController) dryRunCycle(ctx context.Context, now time.Time) (autoHostsDryRunPreview, error) {
	endpoints, results, err := c.probeAll(ctx, now)
	if err != nil { return autoHostsDryRunPreview{}, err }
	state := c.manager.State()
	scores := make(map[string]int, len(endpoints))
	for _, result := range results { if result.Success { scores[result.ServerID]++ } }
	activeID := ""
	if state.Config.Mode == "pinned" {
		for _, endpoint := range endpoints { if endpoint.ServerID == state.Config.PinnedServerID { activeID = endpoint.ServerID; break } }
		if activeID == "" { return autoHostsDryRunPreview{}, fmt.Errorf("pinned DoH server %q is not currently reachable/resolved", state.Config.PinnedServerID) }
	} else {
		bestScore := 0
		for _, endpoint := range endpoints {
			score := scores[endpoint.ServerID]
			if score > bestScore || (score == bestScore && score > 0 && endpoint.ServerID == state.ActiveServer) {
				activeID, bestScore = endpoint.ServerID, score
			}
		}
		if activeID == "" {
			for _, endpoint := range endpoints { if endpoint.ServerID == state.ActiveServer { activeID = endpoint.ServerID; break } }
		}
		if activeID == "" { activeID = endpoints[0].ServerID }
	}
	var activeEndpoint autohosts.Endpoint
	for _, endpoint := range endpoints { if endpoint.ServerID == activeID { activeEndpoint = endpoint; break } }
	activeResults := make([]autohosts.ProbeResult, 0, len(autoHostsDomains))
	for _, result := range results { if result.ServerID == activeID { activeResults = append(activeResults, result) } }
	proposed, err := c.manager.DryRun(activeID, activeEndpoint, activeResults, now)
	if err != nil { return autoHostsDryRunPreview{}, err }
	domains := make([]string, 0, len(proposed))
	for domain := range proposed { domains = append(domains, domain) }
	sort.Strings(domains)
	return autoHostsDryRunPreview{ActiveServer:activeID, EndpointIPv4:append([]string(nil),activeEndpoint.IPv4...), EndpointIPv6:append([]string(nil),activeEndpoint.IPv6...), Domains:domains, Results:results}, nil
}

func (c *autoHostsController) probeAll(ctx context.Context, now time.Time) ([]autohosts.Endpoint, []autohosts.ProbeResult, error) {
	s := c.runtime.currentSnapshot()
	if s == nil { return nil, nil, errors.New("runtime snapshot is unavailable") }
	endpoints := make([]autohosts.Endpoint, 0, len(s.upstreams))
	checks := make(map[string]Check)
	for _, group := range s.groups {
		for _, check := range group.Checks {
			domain := normalizeDomain(check.Domain)
			if _, exists := checks[domain]; !exists { checks[domain] = check }
		}
	}
	serverIDs := make([]string, 0, len(s.upstreams))
	for id := range s.upstreams { serverIDs = append(serverIDs, id) }
	sort.Strings(serverIDs)
	if len(serverIDs) > autoHostsMaxServers { logLine("WARN", "AUTO_HOSTS server limit reached configured=%d limit=%d", len(serverIDs), autoHostsMaxServers); serverIDs = serverIDs[:autoHostsMaxServers] }
	for _, id := range serverIDs {
		upstream := s.upstreams[id]
		if upstream == nil || upstream.systemDNS != nil || upstream.bootstrap == nil || strings.TrimSpace(upstream.cfg.URL) == "" { continue }
		u, err := url.Parse(upstream.cfg.URL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil { continue }
		resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		ips, resolveErr := upstream.bootstrap.addresses(resolveCtx, false)
		cancel()
		if len(ips) == 0 {
			logLine("WARN", "AUTO_HOSTS endpoint resolution failed server=%s error=%v", id, resolveErr)
			continue
		}
		bootstrapStatus := upstream.bootstrap.status()
		endpointUpdatedAt := bootstrapStatus.ResolvedAt
		if endpointUpdatedAt.IsZero() { endpointUpdatedAt = now.UTC() }
		if resolveErr != nil { logLine("WARN", "AUTO_HOSTS using cached/fallback endpoint IPs server=%s error=%v", id, resolveErr) }
		ep := autohosts.Endpoint{ServerID:id, URL:upstream.cfg.URL, Hostname:u.Hostname(), UpdatedAt:endpointUpdatedAt}
		for _, raw := range ips {
			ip := net.ParseIP(raw)
			if !isAutoHostsPublicIP(ip) { continue }
			if ip.To4() != nil { ep.IPv4 = append(ep.IPv4, ip.To4().String()) } else { ep.IPv6 = append(ep.IPv6, ip.String()) }
		}
		if len(ep.IPv4)+len(ep.IPv6) == 0 {
			logLine("WARN", "AUTO_HOSTS endpoint rejected: no public IP server=%s", id)
			continue
		}
		endpoints = append(endpoints, ep)
	}
	if len(endpoints) == 0 { return nil, nil, errors.New("no eligible public DoH endpoints") }

	jobs := make(chan autoHostsProbeJob)
	resultsCh := make(chan autohosts.ProbeResult, len(endpoints)*len(autoHostsDomains))
	jobList := make([]autoHostsProbeJob, 0, len(endpoints)*len(autoHostsDomains))
	for _, ep := range endpoints {
		upstream := s.upstreams[ep.ServerID]
		for _, domain := range autoHostsDomains {
			check := checks[domain]
			check.Domain = domain
			jobList = append(jobList, autoHostsProbeJob{serverID:ep.ServerID, upstream:upstream, domain:domain, check:check})
		}
	}
	workerCount := autoHostsProbeWorkers
	if workerCount > len(jobList) { workerCount = len(jobList) }
	var wg sync.WaitGroup
	for i:=0; i<workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				probeCtx, cancel := context.WithTimeout(ctx, autoHostsProbeTimeout)
				result := c.probeDomain(probeCtx, job, now)
				cancel()
				resultsCh <- result
			}
		}()
	}
	for _, job := range jobList { jobs <- job }
	close(jobs)
	wg.Wait()
	close(resultsCh)
	results := make([]autohosts.ProbeResult, 0, len(jobList))
	for result := range resultsCh { results = append(results, result) }
	return endpoints, results, nil
}

func (c *autoHostsController) chooseActive(endpoints []autohosts.Endpoint, results []autohosts.ProbeResult, now time.Time) (string, error) {
	available := make(map[string]bool, len(endpoints))
	for _, ep := range endpoints { available[ep.ServerID] = true }
	state := c.manager.State()
	if state.Config.Mode == "pinned" {
		if !available[state.Config.PinnedServerID] { return "", fmt.Errorf("pinned DoH server %q is not currently reachable/resolved", state.Config.PinnedServerID) }
		return state.Config.PinnedServerID, nil
	}
	scores := make(map[string]int, len(endpoints))
	for _, result := range results { if result.Success { scores[result.ServerID]++ } }
	c.mu.Lock()
	defer c.mu.Unlock()
	current := state.ActiveServer
	if current == "" || !available[current] {
		bestID, bestScore := "", 0
		for _, ep := range endpoints {
			if scores[ep.ServerID] > bestScore { bestID, bestScore = ep.ServerID, scores[ep.ServerID] }
		}
		if bestID == "" { bestID = endpoints[0].ServerID }
		c.activeSince, c.lastSwitch = now, now
		c.activeFailures, c.betterCandidate, c.betterCandidateStreak = 0, "", 0
		return bestID, nil
	}
	currentScore := scores[current]
	if currentScore == 0 { c.activeFailures++ } else { c.activeFailures = 0 }
	bestID, bestScore := current, currentScore
	for _, ep := range endpoints {
		score := scores[ep.ServerID]
		if score > bestScore { bestID, bestScore = ep.ServerID, score }
	}
	if bestID == current || bestScore == 0 {
		c.betterCandidate, c.betterCandidateStreak = "", 0
		return current, nil
	}
	if c.betterCandidate == bestID { c.betterCandidateStreak++ } else {
		c.betterCandidate, c.betterCandidateStreak = bestID, 1
	}
	if c.activeSince.IsZero() { c.activeSince = now }
	holdElapsed := now.Sub(c.activeSince) >= autoHostsMinimumHold
	cooldownElapsed := c.lastSwitch.IsZero() || now.Sub(c.lastSwitch) >= autoHostsSwitchCooldown
	repeatedFailure := currentScore == 0 && c.activeFailures >= autoHostsFailureCycles
	repeatedImprovement := c.betterCandidateStreak >= 2
	if (repeatedFailure || repeatedImprovement) && holdElapsed && cooldownElapsed {
		c.lastSwitch, c.activeSince = now, now
		c.activeFailures, c.betterCandidate, c.betterCandidateStreak = 0, "", 0
		return bestID, nil
	}
	return current, nil
}

func (c *autoHostsController) probeDomain(ctx context.Context, job autoHostsProbeJob, now time.Time) (result autohosts.ProbeResult) {
	result = autohosts.ProbeResult{ServerID:job.serverID,Domain:job.domain,CheckedAt:now.UTC()}
	start:=time.Now()
	defer func(){ result.DurationMS=time.Since(start).Milliseconds() }()
	var websiteIPs []string
	for _, qtype := range []uint16{1,28} {
		queryCtx,cancel:=context.WithTimeout(ctx,4*time.Second)
		response,_,err:=c.runtime.queryVia(queryCtx,job.upstream,makeDNSQuery(job.domain,qtype))
		cancel()
		if err!=nil { result.Error="DoH query: "+err.Error(); continue }
		if dnsRCode(response)!=0 { result.Error=fmt.Sprintf("DNS qtype=%d rcode=%d",qtype,dnsRCode(response)); continue }
		if dnsTruncated(response) { result.Error=fmt.Sprintf("DNS qtype=%d response is truncated",qtype); continue }
		ips,err:=parseAddressRecords(response,qtype)
		if err!=nil { result.Error="DNS parse: "+err.Error(); continue }
		for _,ip:=range ips { if len(websiteIPs)>=32 { break }; if isAutoHostsPublicIP(net.ParseIP(ip)) { websiteIPs=appendUniqueString(websiteIPs,ip) } }
	}
	if len(websiteIPs)==0 {
		if result.Error=="" { result.Error="DNS returned no public A/AAAA address" }
		return result
	}
	result.WebsiteIPs=append([]string(nil),websiteIPs...)
	probeURL:=job.check.HTTPURL
	if probeURL=="" { probeURL="https://"+job.domain+"/" }
	parsed,err:=url.Parse(probeURL)
	if err!=nil || !validAutoHostsProbeURL(parsed,job.domain) {
		result.Error="HTTP probe URL must use HTTPS on port 443 and the checked domain as host"
		return result
	}
	var lastErr error
	for _,ip:=range websiteIPs {
		status,body,probeErr:=probeHTTPSAtIP(ctx,probeURL,parsed.Hostname(),ip)
		if probeErr!=nil { lastErr=probeErr; continue }
		if len(job.check.ExpectedStatus)>0 {
			accepted:=false
			for _,want:=range job.check.ExpectedStatus { if status==want { accepted=true; break } }
			if !accepted { lastErr=fmt.Errorf("unexpected HTTP status %d",status); continue }
		} else if status<200 || status>=400 {
			lastErr=fmt.Errorf("unexpected HTTP status %d",status); continue
		}
		if strings.EqualFold(job.domain,"gemini.google.com") && geminiRegionBlocked(body) {
			lastErr=errors.New("Gemini regional restriction detected"); continue
		}
		if job.check.VerifyOIDC {
			if err:=verifyOIDCIssuer(body,probeURL); err!=nil { lastErr=err; continue }
		}
		result.Success=true
		result.Error=""
		return result
	}
	if lastErr!=nil { result.Error="HTTPS probe: "+lastErr.Error() }
	return result
}

func validAutoHostsProbeURL(parsed *url.URL, domain string) bool {
	if parsed == nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" {
		return false
	}
	if parsed.Port() != "" && parsed.Port() != "443" {
		return false
	}
	return strings.EqualFold(strings.TrimSuffix(parsed.Hostname(), "."), domain)
}

func probeHTTPSAtIP(ctx context.Context, targetURL, host, ip string) (int,[]byte,error) {
	if !isAutoHostsPublicIP(net.ParseIP(ip)) { return 0,nil,errors.New("refusing non-public website IP") }
	client:=newPinnedHTTPClient(ip,host,autoHostsProbeTimeout)
	defer client.CloseIdleConnections()
	req,err:=http.NewRequestWithContext(ctx,"GET",targetURL,nil)
	if err!=nil { return 0,nil,err }
	req.Header.Set("User-Agent","LucX-DoH-HealthMonitor/3.0.0")
	resp,err:=client.Do(req)
	if err!=nil { return 0,nil,err }
	defer resp.Body.Close()
	body,err:=readHTTPProbeBody(resp.Body)
	if err!=nil { return resp.StatusCode,nil,err }
	return resp.StatusCode,body,nil
}

func parseAddressRecords(packet []byte,qtype uint16)([]string,error) {
	if qtype==1 { return parseARecords(packet) }
	if qtype!=28 { return nil,fmt.Errorf("unsupported address qtype %d",qtype) }
	if len(packet)<12 { return nil,errors.New("short DNS response") }
	off:=12
	qd:=int(packet[4])<<8|int(packet[5])
	an:=int(packet[6])<<8|int(packet[7])
	ns:=int(packet[8])<<8|int(packet[9])
	ar:=int(packet[10])<<8|int(packet[11])
	for i:=0;i<qd;i++ {
		_,next,err:=decodeName(packet,off); if err!=nil{return nil,err}
		off=next+4; if off>len(packet){return nil,errors.New("truncated DNS question")}
	}
	var ips []string
	for i:=0;i<an+ns+ar;i++ {
		_,next,err:=decodeName(packet,off); if err!=nil{return ips,err}; off=next
		if off+10>len(packet){return ips,errors.New("truncated DNS RR")}
		typ:=uint16(packet[off])<<8|uint16(packet[off+1])
		rdlen:=int(packet[off+8])<<8|int(packet[off+9]); off+=10
		if off+rdlen>len(packet){return ips,errors.New("truncated DNS RDATA")}
		if i<an && typ==28 && rdlen==16 { ips=append(ips,net.IP(packet[off:off+16]).String()) }
		off+=rdlen
	}
	return ips,nil
}

func isAutoHostsPublicIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		a, b := int(v4[0]), int(v4[1])
		switch {
		case a == 0 || a == 10 || a == 127 || a >= 224:
			return false
		case a == 100 && b >= 64 && b <= 127: // shared address space (RFC 6598)
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
	// Only globally allocated unicast IPv6 space is accepted; documentation
	// prefixes are explicitly excluded to prevent non-routable probe targets.
	v6 := ip.To16()
	if v6 == nil || (v6[0]&0xe0) != 0x20 {
		return false
	}
	if v6[0] == 0x20 && v6[1] == 0x01 && v6[2] <= 0x01 {
		return false // 2001:0000::/23 special-purpose space
	}
	if v6[0] == 0x20 && v6[1] == 0x01 && v6[2] == 0x0d && v6[3] == 0xb8 {
		return false // 2001:db8::/32
	}
	if v6[0] == 0x20 && v6[1] == 0x02 {
		return false // 2002::/16 6to4 transition space
	}
	return true
}
