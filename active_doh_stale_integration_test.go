package main

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"lucx-doh-health-monitor/internal/activedoh"
)

func newActiveDoHStaleFixture(t *testing.T) (*Runtime, *Snapshot, []byte) {
	t.Helper()
	now := time.Now().UTC()
	selector := activedoh.NewSelector(activedoh.DefaultPolicy())
	candidate := activedoh.Candidate{
		ServerID: "selected", URL: "https://doh.example/dns-query", Hostname: "doh.example",
		IPv4: []string{"1.1.1.1"}, ResolvedAt: now, ConfigGeneration: 41,
	}
	probes := make([]activedoh.ProbeResult, 0, len(activedoh.ControlDomains()))
	for _, domain := range activedoh.ControlDomains() {
		probes = append(probes, activedoh.ProbeResult{
			ServerID: "selected", Domain: domain, Success: true, CheckedAt: now,
		})
	}
	if _, ok := selector.Select([]activedoh.Candidate{candidate}, probes, now); !ok {
		t.Fatal("failed to seed active DoH selection")
	}
	query := activeDoHTestQuery(1, false)
	staleKey := fmt.Sprintf("mode1-stale:%d:%s", 41, cacheKey(query))
	cached := testAResponse(query, 60)
	r := &Runtime{
		activeDoHSelector: selector,
		activeDoHTrigger:  make(chan struct{}, 1),
		cache: map[string]cacheItem{
			staleKey: {
				packet: cached, expires: time.Now().Add(-time.Second),
				inserted: time.Now().Add(-61 * time.Second), size: len(cached),
			},
		},
	}
	snapshot := &Snapshot{
		cfg: Config{
			DNSMode: "endpoint_ip",
			Cache: CacheConfig{
				Enabled: true, MaxEntries: 32, MaxBytes: 4096, MaxTTL: 300,
				NegativeTTL: 15, StaleTTL: 60,
			},
		},
		activeDoHGeneration: 41,
	}
	r.snapshot.Store(snapshot)
	return r, snapshot, query
}

func TestActiveDoHForwardingGoroutineRecoversPanic(t *testing.T) {
	r, snapshot, query := newActiveDoHStaleFixture(t)
	staleKey := fmt.Sprintf("mode1-stale:%d:%s", snapshot.activeDoHGeneration, cacheKey(query))
	delete(r.cache, staleKey)

	r.activeDoHForwarder = func(context.Context, activedoh.Candidate, []byte, time.Duration, *activeDoHForwardMetrics) ([]byte, error) {
		panic("synthetic async forwarder panic")
	}

	done := make(chan []byte, 1)
	go func() {
		done <- r.activeDoHDNSResponse(query, snapshot)
	}()
	select {
	case response := <-done:
		if got := dnsRCode(response); got != 2 {
			t.Fatalf("panic response rcode=%d, want SERVFAIL (2)", got)
		}
	case <-time.After(time.Second):
		t.Fatal("request did not complete after forwarding goroutine panic")
	}
	if got := r.failures.Load(); got != 1 {
		t.Fatalf("failure counter=%d, want 1", got)
	}
}

func TestActiveDoHReturnsStaleWithinClientBudgetAndSuppressesRecheck(t *testing.T) {
	r, snapshot, query := newActiveDoHStaleFixture(t)
	var forwardCalls atomic.Int32
	forwardCancelled := make(chan struct{}, 1)
	r.activeDoHForwarder = func(ctx context.Context, _ activedoh.Candidate, _ []byte, _ time.Duration, _ *activeDoHForwardMetrics) ([]byte, error) {
		forwardCalls.Add(1)
		<-ctx.Done()
		forwardCancelled <- struct{}{}
		return nil, ctx.Err()
	}

	started := time.Now()
	response := r.activeDoHDNSResponse(query, snapshot)
	if elapsed := time.Since(started); elapsed > activeDoHStaleResponseBudget+500*time.Millisecond {
		t.Fatalf("stale answer returned after %s, budget is %s", elapsed, activeDoHStaleResponseBudget)
	}
	if dnsRCode(response) != 0 || dnsAnswerCount(response) != 1 {
		t.Fatalf("stale response rcode=%d answers=%d", dnsRCode(response), dnsAnswerCount(response))
	}
	select {
	case <-forwardCancelled:
	case <-time.After(time.Second):
		t.Fatal("upstream attempt was not cancelled after stale response")
	}
	if got := forwardCalls.Load(); got != 1 {
		t.Fatalf("forwarder calls=%d, want 1", got)
	}

	// A request arriving during the failure recheck window must receive stale
	// immediately rather than starting another upstream attempt.
	second := r.activeDoHDNSResponse(query, snapshot)
	if dnsRCode(second) != 0 || dnsAnswerCount(second) != 1 {
		t.Fatalf("second stale response rcode=%d answers=%d", dnsRCode(second), dnsAnswerCount(second))
	}
	if got := forwardCalls.Load(); got != 1 {
		t.Fatalf("forwarder calls after suppressed recheck=%d, want 1", got)
	}
}
