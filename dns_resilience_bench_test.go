package main

import (
	"testing"
	"time"
)

func BenchmarkResolverFreshCacheHit(b *testing.B) {
	query := makeDNSQuery("cache-hit.example.test", 1)
	const generation = 17
	key := "mode2:17:" + cacheKey(query)
	response := testAResponse(query, 300)
	r := &Runtime{
		cache: map[string]cacheItem{
			key: {packet: response, inserted: time.Now(), expires: time.Now().Add(time.Hour), size: len(response)},
		},
	}
	snapshot := &Snapshot{
		cfg:                Config{DNSMode: "resolver", Cache: CacheConfig{Enabled: true, StaleTTL: 3600}},
		resolverGeneration: generation,
	}
	r.snapshot.Store(snapshot)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.resolverDNSResponse(query, snapshot)
	}
}

func BenchmarkDNSFlightCoalescing(b *testing.B) {
	r := &Runtime{}
	query := makeDNSQuery("coalesce.example.test", 1)
	response := testAResponse(query, 60)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.coalesceDNSResponse("mode2:benchmark", query, func() []byte {
			return response
		})
	}
}

func BenchmarkPinnedDoHTransportReuse(b *testing.B) {
	r := &Runtime{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.pinnedDoHHTTPClient("8.8.8.8", "dns.example.test", time.Second)
	}
}

func BenchmarkStaleFallbackBudget(b *testing.B) {
	stale := []byte{1, 2, 3}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := make(chan dnsAttemptResult)
		_, _, served := awaitDNSWithStaleBudget(result, time.Nanosecond, func() ([]byte, bool) {
			return stale, true
		})
		if !served {
			b.Fatal("expected stale fallback")
		}
	}
}
