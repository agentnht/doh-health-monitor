package main

import "time"

// cachePutFixedTTL stores a short-lived protocol response without requiring
// resource-record TTLs (for example, a provider-originated SERVFAIL). Callers
// must choose the response class explicitly; synthesized local errors should
// not be cached through this helper.
func (r *Runtime) cachePutFixedTTL(key string, packet []byte, ttl, maxTTL time.Duration, config CacheConfig) {
	if !config.Enabled || ttl <= 0 || maxTTL <= 0 || len(packet) < 12 ||
		config.MaxEntries < 1 || config.MaxBytes < 1024 {
		return
	}
	if ttl > maxTTL {
		ttl = maxTTL
	}
	cost := len(key) + len(packet) + 128
	if cost > config.MaxBytes {
		return
	}
	now := time.Now()
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	if r.cache == nil {
		r.cache = make(map[string]cacheItem)
	}
	if previous, exists := r.cache[key]; exists {
		delete(r.cache, key)
		r.cacheBytes -= previous.size
	}
	r.cacheSeq++
	item := cacheItem{
		packet: append([]byte(nil), packet...), expires: now.Add(ttl),
		inserted: now, size: cost, generation: r.cacheSeq,
	}
	r.cache[key] = item
	r.cacheBytes += cost
	r.cacheOrder = append(r.cacheOrder, cacheOrderEntry{key: key, generation: item.generation})
	for len(r.cache) > config.MaxEntries || r.cacheBytes > config.MaxBytes {
		if !r.evictOldestCacheLocked() {
			break
		}
	}
	r.compactCacheOrderLocked(config.MaxEntries)
}
