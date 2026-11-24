package main

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"lucx-doh-health-monitor/internal/activedoh"
)

func TestActiveDoHProviderSERVFAILCacheIsShortAndSelectionScoped(t *testing.T) {
	r, snapshot, query := newActiveDoHStaleFixture(t)
	var calls atomic.Int32
	providerSERVFAIL := mode2ResponseWithRCode(query, 2)
	r.activeDoHForwarder = func(context.Context, activedoh.Candidate, []byte, time.Duration, *activeDoHForwardMetrics) ([]byte, error) {
		calls.Add(1)
		return providerSERVFAIL, nil
	}
	first := r.activeDoHDNSResponse(query, snapshot)
	if dnsRCode(first) != 2 {
		t.Fatalf("first response rcode=%d, want provider SERVFAIL", dnsRCode(first))
	}
	second := r.activeDoHDNSResponse(query, snapshot)
	if dnsRCode(second) != 2 {
		t.Fatalf("cached response rcode=%d, want SERVFAIL", dnsRCode(second))
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream calls=%d, want one because SERVFAIL was briefly cached", calls.Load())
	}
	selectorGeneration := r.activeDoHSelector.Generation()
	key := fmt.Sprintf("mode1-servfail:%d:%d:%s", snapshot.activeDoHGeneration, selectorGeneration, cacheKey(query))
	r.cacheMu.Lock()
	item, ok := r.cache[key]
	r.cacheMu.Unlock()
	if !ok {
		t.Fatal("provider SERVFAIL cache entry missing")
	}
	if ttl := item.expires.Sub(item.inserted); ttl <= 0 || ttl > 5*time.Second {
		t.Fatalf("provider SERVFAIL TTL=%s, want (0,5s]", ttl)
	}
}
