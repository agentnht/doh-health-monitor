package main

import (
	"testing"
	"time"
)

func FuzzStaleAndTTLParsers(f *testing.F) {
	f.Add(makeDNSQuery("seed.example.test", 1))
	f.Add([]byte{})
	f.Add([]byte{0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > maxDNSMessage {
			return
		}
		_, _ = rrTTLPositions(packet)
		_, _ = minResponseTTL(packet)
		_, _ = negativeSOATTL(packet)
		copyPacket := append([]byte(nil), packet...)
		decrementTTLs(copyPacket, uint32(len(packet)%300))
		r := &Runtime{
			cache: map[string]cacheItem{
				"fuzz": {packet: append([]byte(nil), packet...), expires: time.Now().Add(-time.Second), inserted: time.Now().Add(-2 * time.Second), size: len(packet)},
				},
			}
		_, _ = r.cacheGetStale("fuzz", packetID(packet), 60)
	})
}

func FuzzHandleDNSInput(f *testing.F) {
	f.Add(makeDNSQuery("seed.example.test", 1))
	f.Add([]byte{})
	f.Add([]byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > maxDNSMessage {
			return
		}
		r := &Runtime{
			dnsSem: make(chan struct{}, 1),
			cache:  make(map[string]cacheItem),
		}
		r.snapshot.Store(&Snapshot{
			cfg: Config{
				DNSMode: "resolver",
				Cache: CacheConfig{Enabled: true, MaxEntries: 16, MaxBytes: 4096, StaleTTL: 60},
			},
		})
		_ = r.handleDNS(packet)
	})
}
