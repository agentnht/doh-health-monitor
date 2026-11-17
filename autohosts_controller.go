package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
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
	autoHostsProbeTimeout = 9 * time.Second
	autoHostsFailureCycles = 2
	autoHostsMinimumHold = 10 * time.Minute
	autoHostsSwitchCooldown = 10 * time.Minute
)

type autoHostsController struct {
	runtime *Runtime
	manager *autohosts.Manager
	mu sync.Mutex
	activeSince time.Time
	lastSwitch time.Time
	activeFailures int
}

func newAutoHostsController(r *Runtime, manager *autohosts.Manager) *autoHostsController {
	return &autoHostsController{runtime:r, manager:manager}
}

func (c *autoHostsController) run(ctx context.Context) {
	for {
		state := c.manager.State()
		interval := state.Config.CheckInterval
		if interval < 10*time.Second { interval = 5*time.Minute }
		if state.Config.Enabled && !state.Config.EmergencyOff {
			cycleCtx, cancel := context.WithTimeout(ctx, 2*interval)
			if err := c.runCycle(cycleCtx, time.Now().UTC()); err != nil && !errors.Is(err, context.Canceled) {
				logLine("WARN", "AUTO_HOSTS cycle failed: %v", err)
			}
			cancel()
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

type autoHostsProbeJob struct {
	serverID string
	upstream *UpstreamRuntime
	domain string
	check Check
}

func (c *autoHostsController) runCycle(ctx context.Context, now time.Time) error {
	s := c.runtime.currentSnapshot()
	if s == nil { return errors.New("runtime snapshot is unavailable") }
	jobs := make(chan autoHostsProbeJob)
	resultsCh := make(chan autohosts.ProbeResult, len(s.upstreams)*len(autoHostsDomains))
	endpoints := make([]autohosts.Endpoint, 0, len(s.upstreams))
	checks := make(map[string]Check)
	for _, group := range s.groups {
		for _, check := range group.Checks {
			domain := normalizeDomain(check.Domain)
			if _, exists := checks[domain]; !exists { checks[domain] = check }
		}
	}
	for id, upstream := range s.upstreams {
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
		ep := autohosts.Endpoint{ServerID:id, URL:upstream.cfg.URL, Hostname:u.Hostname()}
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
	if len(endpoints) == 0 { return errors.New("no eligible public DoH endpoints") }
	// Execute with a bounded worker pool to cap outbound requests.
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

	activeID, err := c.chooseActive(endpoints, results, now)
	if err != nil { return err }
	var activeEndpoint autohosts.Endpoint
	for _, endpoint := range endpoints { if endpoint.ServerID == activeID { activeEndpoint = endpoint; break } }
	if activeEndpoint.ServerID == "" { return fmt.Errorf("selected active endpoint %q is unavailable", activeID) }
	if err := c.manager.ApplyFullCycle(activeID, endpoints, results, now); err != nil { return err }
	successCount := 0
	for _, result := range results { if result.ServerID == activeID && result.Success { successCount++ } }
	logLine("INFO", "AUTO_HOSTS cycle completed servers=%d pairs=%d active=%s active_domains=%d", len(endpoints), len(results), activeID, successCount)
	return nil
}

func (c *autoHostsController) chooseActive(endpoints []autohosts.Endpoint, results []autohosts.ProbeResult, now time.Time) (string,error) {
	available := make(map[string]bool,len(endpoints))
	for _, ep := range endpoints { available[ep.ServerID]=true }
	state := c.manager.State()
	if state.Config.Mode == "pinned" {
		if !available[state.Config.PinnedServerID] { return "", fmt.Errorf("pinned DoH server %q is not currently reachable/resolved", state.Config.PinnedServerID) }
		return state.Config.PinnedServerID,nil
	}
	scores := make(map[string]int,len(endpoints))
	for _, result := range results { if result.Success { scores[result.ServerID]++ } }
	c.mu.Lock()
	defer c.mu.Unlock()
	current := state.ActiveServer
	if current != "" && available[current] {
		if scores[current] > 0 {
			c.activeFailures=0
			if c.activeSince.IsZero() { c.activeSince=now }
			return current,nil
		}
		c.activeFailures++
		if c.activeSince.IsZero() { c.activeSince=now }
		if c.activeFailures < autoHostsFailureCycles || now.Sub(c.activeSince) < autoHostsMinimumHold || (!c.lastSwitch.IsZero() && now.Sub(c.lastSwitch) < autoHostsSwitchCooldown) {
			return current,nil
		}
	}
	bestID := ""
	bestScore := 0
	for _, ep := range endpoints {
		score := scores[ep.ServerID]
		if score > bestScore || (score == bestScore && score > 0 && ep.ServerID == current) {
			bestID,bestScore=ep.ServerID,score
		}
	}
	if bestID == "" {
		if current != "" && available[current] { return current,nil }
		bestID=endpoints[0].ServerID
	}
	if bestID != current {
		c.lastSwitch=now
		c.activeSince=now
		c.activeFailures=0
	}
	return bestID,nil
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
		ips,err:=parseAddressRecords(response,qtype)
		if err!=nil { result.Error="DNS parse: "+err.Error(); continue }
		for _,ip:=range ips { if isAutoHostsPublicIP(net.ParseIP(ip)) { websiteIPs=appendUniqueString(websiteIPs,ip) } }
	}
	if len(websiteIPs)==0 {
		if result.Error=="" { result.Error="DNS returned no public A/AAAA address" }
		return result
	}
	result.WebsiteIPs=append([]string(nil),websiteIPs...)
	probeURL:=job.check.HTTPURL
	if probeURL=="" { probeURL="https://"+job.domain+"/" }
	parsed,err:=url.Parse(probeURL)
	if err!=nil || parsed.Scheme!="https" || parsed.User!=nil || !strings.EqualFold(strings.TrimSuffix(parsed.Hostname(),"."),job.domain) {
		result.Error="HTTP probe URL must be HTTPS and use the checked domain as host"
		return result
	}
	var lastErr error
	for _,ip:=range websiteIPs {
		status,body,probeErr:=probeHTTPSAtIP(ctx,probeURL,parsed.Hostname(),ip,job.domain)
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

func probeHTTPSAtIP(ctx context.Context, targetURL, host, ip, domain string) (int,[]byte,error) {
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

func appendUniqueString(values []string,value string) []string {
	for _,existing:=range values { if existing==value { return values } }
	return append(values,value)
}

func isAutoHostsPublicIP(ip net.IP) bool {
	if ip==nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() { return false }
	return true
}
