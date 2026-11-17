package main

import (
	"crypto/sha256"
	"encoding/binary"
	"time"
)

type cacheFlight struct {
	done   chan struct{}
	packet []byte
	err    error
}

type cacheItem struct {
	packet     []byte
	expires    time.Time
	inserted   time.Time
	size       int
	generation uint64
}
type cacheOrderEntry struct {
	key        string
	generation uint64
}

func (r *Runtime) deleteCacheEntryLocked(key string, item cacheItem) {
	if current, ok := r.cache[key]; ok && current.generation == item.generation {
		delete(r.cache, key)
		r.cacheBytes -= current.size
		if r.cacheBytes < 0 {
			r.cacheBytes = 0
		}
	}
}

func (r *Runtime) cacheDo(key string, id uint16, resolve func() ([]byte, error)) ([]byte, error) {
	if cached, ok := r.cacheGet(key, id); ok {
		return cached, nil
	}
	r.cacheMu.Lock()
	if flight := r.cacheFlights[key]; flight != nil {
		r.cacheMu.Unlock()
		<-flight.done
		if flight.err != nil {
			return nil, flight.err
		}
		if cached, ok := r.cacheGet(key, id); ok {
			return cached, nil
		}
		response := append([]byte(nil), flight.packet...)
		if len(response) >= 2 {
			binary.BigEndian.PutUint16(response[:2], id)
		}
		return response, nil
	}
	if r.cacheFlights == nil {
		r.cacheFlights = make(map[string]*cacheFlight)
	}
	flight := &cacheFlight{done: make(chan struct{})}
	r.cacheFlights[key] = flight
	r.cacheMu.Unlock()

	response, err := resolve()
	r.cacheMu.Lock()
	flight.packet = append([]byte(nil), response...)
	flight.err = err
	delete(r.cacheFlights, key)
	close(flight.done)
	r.cacheMu.Unlock()
	return response, err
}

func (r *Runtime) cacheGet(key string, id uint16) ([]byte, bool) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	v, ok := r.cache[key]
	if !ok {
		return nil, false
	}
	if !time.Now().Before(v.expires) {
		r.deleteCacheEntryLocked(key, v)
		return nil, false
	}
	b := append([]byte(nil), v.packet...)
	binary.BigEndian.PutUint16(b[:2], id)
	decrementTTLs(b, uint32(time.Since(v.inserted).Seconds()))
	return b, true
}

func (r *Runtime) evictOldestCacheLocked() bool {
	for r.cacheOrderHead < len(r.cacheOrder) {
		entry := r.cacheOrder[r.cacheOrderHead]
		r.cacheOrderHead++
		if current, ok := r.cache[entry.key]; ok && current.generation == entry.generation {
			delete(r.cache, entry.key)
			r.cacheBytes -= current.size
			if r.cacheBytes < 0 {
				r.cacheBytes = 0
			}
			return true
		}
	}
	return false
}

func (r *Runtime) compactCacheOrderLocked(maxEntries int) {
	if len(r.cacheOrder) <= 2*maxEntries+1024 {
		return
	}
	compact := make([]cacheOrderEntry, 0, len(r.cache))
	for i := r.cacheOrderHead; i < len(r.cacheOrder); i++ {
		entry := r.cacheOrder[i]
		if current, ok := r.cache[entry.key]; ok && current.generation == entry.generation {
			compact = append(compact, entry)
		}
	}
	r.cacheOrder = compact
	r.cacheOrderHead = 0
}

func (r *Runtime) cachePut(key string, packet []byte, c CacheConfig) {
	if !c.Enabled || c.MaxEntries < 1 || c.MaxBytes < 1024 {
		return
	}
	negative := dnsRCode(packet) == 3 || (dnsRCode(packet) == 0 && dnsAnswerCount(packet) == 0)
	var ttl uint32
	var ok bool
	if negative {
		// RFC 2308: negative TTL is min(SOA RR TTL, SOA.MINIMUM).
		ttl, ok = negativeSOATTL(packet)
		if !ok {
			ttl = uint32(c.NegativeTTL)
			ok = ttl > 0
		}
	} else {
		ttl, ok = minResponseTTL(packet)
	}
	if !ok {
		return
	}
	if ttl == 0 || (c.MinTTL > 0 && ttl < uint32(c.MinTTL)) {
		return
	}
	if ttl > uint32(c.MaxTTL) {
		ttl = uint32(c.MaxTTL)
	}
	if ttl == 0 {
		return
	}
	const cacheItemOverheadEstimate = 128
	cost := len(key) + len(packet) + cacheItemOverheadEstimate
	if cost > c.MaxBytes {
		return
	}

	now := time.Now()
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	if previous, exists := r.cache[key]; exists {
		delete(r.cache, key)
		r.cacheBytes -= previous.size
	}
	r.cacheSeq++
	item := cacheItem{
		packet:   append([]byte(nil), packet...),
		expires:  now.Add(time.Duration(ttl) * time.Second),
		inserted: now, size: cost, generation: r.cacheSeq,
	}
	r.cache[key] = item
	r.cacheBytes += cost
	r.cacheOrder = append(r.cacheOrder, cacheOrderEntry{key: key, generation: item.generation})

	for len(r.cache) > c.MaxEntries || r.cacheBytes > c.MaxBytes {
		if !r.evictOldestCacheLocked() {
			break
		}
	}
	r.compactCacheOrderLocked(c.MaxEntries)
}

func cacheKey(p []byte) string {
	b := append([]byte(nil), p...)
	if len(b) >= 2 {
		b[0] = 0
		b[1] = 0
	}
	sum := sha256.Sum256(b)
	return string(sum[:])
}
func packetID(p []byte) uint16 {
	if len(p) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(p[:2])
}
func (r *Runtime) cacheStats() (int, int) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	return len(r.cache), r.cacheBytes
}
func (r *Runtime) cacheLen() int {
	entries, _ := r.cacheStats()
	return entries
}
