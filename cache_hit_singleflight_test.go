package main

import (
	"fmt"
	"testing"
	"time"

	"lucx-doh-health-monitor/internal/activedoh"
)

func TestResolverFreshCacheHitBypassesSingleflight(t *testing.T) {
	query := makeDNSQuery("cache-hit.example", 1)
	snapshot := &Snapshot{
		cfg: Config{
			DNSMode: "resolver",
			Cache: CacheConfig{Enabled: true, MaxEntries: 8, MaxBytes: 4096, MaxTTL: 300},
		},
		resolverGeneration: 17,
	}
	runtime := &Runtime{cache: make(map[string]cacheItem)}
	runtime.snapshot.Store(snapshot)
	runtime.cachePut("mode2:17:"+cacheKey(query), testAResponse(query, 60), snapshot.cfg.Cache)

	for i := 0; i < 2; i++ {
		response := runtime.resolverDNSResponse(query, snapshot)
		if dnsRCode(response) != 0 || dnsAnswerCount(response) != 1 {
			t.Fatalf("cache hit %d returned rcode=%d answers=%d", i, dnsRCode(response), dnsAnswerCount(response))
		}
	}
	if got := runtime.dnsCoalesced.Load(); got != 0 {
		t.Fatalf("cache hits entered singleflight %d times; want 0", got)
	}
	if got := runtime.cacheHits.Load(); got != 2 {
		t.Fatalf("cache hit counter=%d, want 2", got)
	}
}

func TestActiveDoHFreshCacheHitBypassesSingleflight(t *testing.T) {
	now := time.Now().UTC()
	selector := activedoh.NewSelector(activedoh.DefaultPolicy())
	candidate := activedoh.Candidate{
		ServerID: "cache-hit", URL: "https://doh.example/dns-query", Hostname: "doh.example",
		IPv4: []string{"1.1.1.1"}, ResolvedAt: now, ConfigGeneration: 23,
	}
	probes := make([]activedoh.ProbeResult, 0, len(activedoh.ControlDomains()))
	for _, domain := range activedoh.ControlDomains() {
		probes = append(probes, activedoh.ProbeResult{
			ServerID: candidate.ServerID, Domain: domain, Success: true, CheckedAt: now,
		})
	}
	if _, ok := selector.Select([]activedoh.Candidate{candidate}, probes, now); !ok {
		t.Fatal("failed to seed active DoH selector")
	}
	selection, ok := selector.Current(now)
	if !ok {
		t.Fatal("active DoH selection is unavailable")
	}

	query := activeDoHTestQuery(1, false)
	snapshot := &Snapshot{
		cfg: Config{
			DNSMode: "endpoint_ip",
			Cache: CacheConfig{Enabled: true, MaxEntries: 8, MaxBytes: 4096, MaxTTL: 300},
		},
		activeDoHGeneration: 23,
	}
	runtime := &Runtime{
		activeDoHSelector: selector,
		cache: make(map[string]cacheItem),
	}
	runtime.snapshot.Store(snapshot)
	runtime.cachePut(fmt.Sprintf("mode1:%d:%s", selection.Generation, cacheKey(query)),
		testAResponse(query, 60), snapshot.cfg.Cache)

	for i := 0; i < 2; i++ {
		response := runtime.activeDoHDNSResponse(query, snapshot)
		if dnsRCode(response) != 0 || dnsAnswerCount(response) != 1 {
			t.Fatalf("cache hit %d returned rcode=%d answers=%d", i, dnsRCode(response), dnsAnswerCount(response))
		}
	}
	if got := runtime.dnsCoalesced.Load(); got != 0 {
		t.Fatalf("cache hits entered singleflight %d times; want 0", got)
	}
	if got := runtime.cacheHits.Load(); got != 2 {
		t.Fatalf("cache hit counter=%d, want 2", got)
	}
}
