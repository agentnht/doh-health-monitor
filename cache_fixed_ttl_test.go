package main

import (
	"testing"
	"time"
)

func TestCachePutFixedTTLBoundsTransientSERVFAIL(t *testing.T) {
	query := makeDNSQuery("temporary.example.test", 1)
	response := mode2ResponseWithRCode(query, 2)
	r := &Runtime{cache: make(map[string]cacheItem)}
	config := CacheConfig{Enabled: true, NegativeTTL: 15, MaxEntries: 16, MaxBytes: 4096}
	r.cachePutFixedTTL("servfail:test", response, time.Duration(config.NegativeTTL)*time.Second, 5*time.Second, config)

	r.cacheMu.Lock()
	item, ok := r.cache["servfail:test"]
	r.cacheMu.Unlock()
	if !ok {
		t.Fatal("provider SERVFAIL was not cached")
	}
	if ttl := item.expires.Sub(item.inserted); ttl <= 0 || ttl > 5*time.Second {
		t.Fatalf("cached SERVFAIL TTL=%s, want (0,5s]", ttl)
	}
	if got, found := r.cacheGet("servfail:test", packetID(query), 0); !found || dnsRCode(got) != 2 {
		t.Fatalf("cached response found=%t rcode=%d, want SERVFAIL", found, dnsRCode(got))
	}
}

func TestCachePutFixedTTLHonorsDisabledAndBounds(t *testing.T) {
	query := makeDNSQuery("temporary.example.test", 1)
	response := mode2ResponseWithRCode(query, 2)
	r := &Runtime{cache: make(map[string]cacheItem)}
	config := CacheConfig{Enabled: true, NegativeTTL: 0, MaxEntries: 16, MaxBytes: 4096}
	r.cachePutFixedTTL("disabled", response, 2*time.Second, 5*time.Second, config)
	if len(r.cache) != 0 {
		t.Fatal("zero negative TTL must disable transient SERVFAIL caching")
	}
	config.NegativeTTL = 30
	r.cachePutFixedTTL("bounded", response, 30*time.Second, 5*time.Second, config)
	if ttl := r.cache["bounded"].expires.Sub(r.cache["bounded"].inserted); ttl > 5*time.Second {
		t.Fatalf("cached SERVFAIL TTL=%s exceeds 5s cap", ttl)
	}
}
