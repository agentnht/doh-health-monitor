package main

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestCacheGetStaleReturnsExpiredAnswerWithTTLOne(t *testing.T) {
	query := makeDNSQuery("stale.example", 1)
	response := testAResponse(query, 60)
	runtime := &Runtime{cache: make(map[string]cacheItem)}
	config := CacheConfig{Enabled: true, MinTTL: 0, MaxTTL: 300, MaxEntries: 10, MaxBytes: 4096}
	key := "mode1:9:" + cacheKey(query)
	runtime.cachePut(key, response, config)

	runtime.cacheMu.Lock()
	item := runtime.cache[key]
	item.expires = time.Now().Add(-5 * time.Second)
	runtime.cache[key] = item
	runtime.cacheMu.Unlock()

	requestID := uint16(0x4321)
	if _, found := runtime.cacheGet(key, requestID, 60); found {
		t.Fatal("expired entry must not be returned as a fresh cache hit")
	}
	if _, exists := runtime.cache[key]; !exists {
		t.Fatal("expired entry inside stale window was deleted")
	}
	stale, found := runtime.cacheGetStale(key, requestID, 60)
	if !found {
		t.Fatal("expected stale answer inside configured stale window")
	}
	if got := binary.BigEndian.Uint16(stale[:2]); got != requestID {
		t.Fatalf("stale response ID = %#x, want %#x", got, requestID)
	}
	positions, err := rrTTLPositions(stale)
	if err != nil || len(positions) == 0 {
		t.Fatalf("failed to inspect stale response TTLs: positions=%v err=%v", positions, err)
	}
	for _, offset := range positions {
		if got := binary.BigEndian.Uint32(stale[offset : offset+4]); got != 1 {
			t.Fatalf("stale TTL = %d, want 1", got)
		}
	}
	if got := runtime.resilience.staleCacheHits.Load(); got != 1 {
		t.Fatalf("stale cache hit counter = %d, want 1", got)
	}
}

func TestCacheGetStaleExpiresAfterWindow(t *testing.T) {
	query := makeDNSQuery("stale-expired.example", 1)
	runtime := &Runtime{cache: make(map[string]cacheItem)}
	config := CacheConfig{Enabled: true, MinTTL: 0, MaxTTL: 300, MaxEntries: 10, MaxBytes: 4096}
	key := "mode2:9:" + cacheKey(query)
	runtime.cachePut(key, testAResponse(query, 60), config)

	runtime.cacheMu.Lock()
	item := runtime.cache[key]
	item.expires = time.Now().Add(-2 * time.Minute)
	runtime.cache[key] = item
	runtime.cacheMu.Unlock()

	if _, found := runtime.cacheGet(key, packetID(query), 60); found {
		t.Fatal("expired entry must not be a fresh hit")
	}
	if _, found := runtime.cacheGetStale(key, packetID(query), 60); found {
		t.Fatal("stale answer beyond stale window must not be returned")
	}
	if _, exists := runtime.cache[key]; exists {
		t.Fatal("entry beyond stale window should be deleted")
	}
}
