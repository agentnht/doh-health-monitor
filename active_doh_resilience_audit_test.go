package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"lucx-doh-health-monitor/internal/activedoh"
)

func TestActiveDoHStaleCacheSurvivesSelectionWithdrawal(t *testing.T) {
	now := time.Now().UTC()
	selector := activedoh.NewSelector(activedoh.DefaultPolicy())
	candidate := activedoh.Candidate{
		ServerID: "selected", URL: "https://doh.example/dns-query", Hostname: "doh.example",
		IPv4: []string{"1.1.1.1"}, ResolvedAt: now, ConfigGeneration: 41,
	}
	probes := make([]activedoh.ProbeResult, 0, len(activedoh.ControlDomains()))
	for _, domain := range activedoh.ControlDomains() {
		probes = append(probes, activedoh.ProbeResult{ServerID: "selected", Domain: domain, Success: true, CheckedAt: now})
	}
	if _, ok := selector.Select([]activedoh.Candidate{candidate}, probes, now); !ok {
		t.Fatal("failed to seed active selection")
	}

	query := activeDoHTestQuery(1, false)
	staleKey := fmt.Sprintf("mode1-stale:%d:%s", 41, cacheKey(query))
	cached := testAResponse(query, 60)
	runtime := &Runtime{
		activeDoHSelector: selector,
		cache: map[string]cacheItem{
			staleKey: {
				packet: cached, expires: time.Now().Add(-time.Second),
				inserted: time.Now().Add(-61 * time.Second), size: len(cached),
			},
		},
	}
	snapshot := &Snapshot{
		cfg:                 Config{DNSMode: "endpoint_ip", Cache: CacheConfig{Enabled: true, StaleTTL: 60}},
		activeDoHGeneration: 41,
	}
	runtime.snapshot.Store(snapshot)

	// The selector's withdrawal increments its generation, which previously
	// made the generation-scoped stale entry unreachable.
	selector.Select(nil, nil, time.Now().UTC())
	response := runtime.activeDoHDNSResponse(query, snapshot)
	if dnsRCode(response) != 0 || dnsAnswerCount(response) != 1 {
		t.Fatalf("stale response not served after selection withdrawal: rcode=%d answers=%d", dnsRCode(response), dnsAnswerCount(response))
	}
	positions, err := rrTTLPositions(response)
	if err != nil || len(positions) != 1 {
		t.Fatalf("stale TTL positions: %v err=%v", positions, err)
	}
	if got := binary.BigEndian.Uint32(response[positions[0] : positions[0]+4]); got != 1 {
		t.Fatalf("stale TTL=%d, want 1", got)
	}
	if runtime.resilience.staleCacheHits.Load() != 1 {
		t.Fatalf("stale cache hits=%d, want 1", runtime.resilience.staleCacheHits.Load())
	}
}

func TestActiveDoHTriggerDebouncesTransportFailures(t *testing.T) {
	runtime := &Runtime{activeDoHTrigger: make(chan struct{}, 1)}
	runtime.triggerActiveDoHOnTransportFailure()
	if len(runtime.activeDoHTrigger) != 1 {
		t.Fatal("first transport failure should trigger a selector cycle")
	}
	<-runtime.activeDoHTrigger
	runtime.triggerActiveDoHOnTransportFailure()
	if len(runtime.activeDoHTrigger) != 0 {
		t.Fatal("second trigger inside debounce interval should be suppressed")
	}
	runtime.activeDoHTriggerLast.Store(time.Now().Add(-activeDoHTriggerMinInterval - time.Second).UnixNano())
	runtime.triggerActiveDoHOnTransportFailure()
	if len(runtime.activeDoHTrigger) != 1 {
		t.Fatal("trigger should be allowed after debounce interval")
	}
}

func TestSendActiveDoHReturnsSERVFAILAfterOneAlternateIP(t *testing.T) {
	query := makeDNSQuery("policy.example.test", 1)
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(mode2ResponseWithRCode(query, 2))
	}))
	defer server.Close()

	candidate := activedoh.Candidate{
		ServerID: "selected", URL: server.URL + "/dns-query", Hostname: "127.0.0.1",
		IPv4: []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"}, ResolvedAt: time.Now(),
	}
	response, err := sendActiveDoHWithClientFactory(
		context.Background(), candidate, query, 2*time.Second,
		func(string, string, time.Duration) *http.Client { return server.Client() },
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("SERVFAIL request count=%d, want exactly one initial + one alternate", got)
	}
	if dnsRCode(response) != 2 {
		t.Fatalf("returned DNS RCODE=%d, want original provider SERVFAIL(2)", dnsRCode(response))
	}
}
