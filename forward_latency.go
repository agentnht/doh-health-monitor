package main

import "time"

var forwardLatencyBounds = [...]time.Duration{
	50 * time.Millisecond,
	100 * time.Millisecond,
	200 * time.Millisecond,
	400 * time.Millisecond,
	800 * time.Millisecond,
	1600 * time.Millisecond,
	3200 * time.Millisecond,
	60000 * time.Millisecond,
}

// recordDoHForwardLatency stores fixed-bucket samples only; no endpoint, domain,
// or client dimensions are retained, so cardinality and memory are constant.
func (r *Runtime) recordDoHForwardLatency(elapsed time.Duration) {
	if elapsed < 0 {
		return
	}
	bucket := len(forwardLatencyBounds) - 1
	for i, bound := range forwardLatencyBounds {
		if elapsed <= bound {
			bucket = i
			break
		}
	}
	r.forwardLatencyMu.Lock()
	r.forwardLatencyBuckets[bucket]++
	r.forwardLatencySamples++
	r.forwardLatencyMu.Unlock()
}

func (r *Runtime) forwardLatencyPercentile(percentile uint64) uint64 {
	r.forwardLatencyMu.Lock()
	defer r.forwardLatencyMu.Unlock()
	if r.forwardLatencySamples == 0 {
		return 0
	}
	if percentile == 0 {
		percentile = 1
	}
	rank := (r.forwardLatencySamples*percentile + 99) / 100
	var cumulative uint64
	for i, count := range r.forwardLatencyBuckets {
		cumulative += count
		if cumulative >= rank {
			return uint64(forwardLatencyBounds[i] / time.Millisecond)
		}
	}
	return uint64(forwardLatencyBounds[len(forwardLatencyBounds)-1] / time.Millisecond)
}

func (r *Runtime) forwardLatencySampleCount() uint64 {
	r.forwardLatencyMu.Lock()
	defer r.forwardLatencyMu.Unlock()
	return r.forwardLatencySamples
}
