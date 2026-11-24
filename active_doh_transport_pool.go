package main

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"lucx-doh-health-monitor/internal/activedoh"
)

const (
	maxPinnedDoHTransports = 64
	pinnedDoHTransportMaxIdleAge = 10 * time.Minute
)

type pinnedDoHTransportEntry struct {
	transport  *http.Transport
	lastUsed   time.Time
	latencyEWMA time.Duration
}

// pinnedDoHHTTPClient reuses an HTTP transport only for the exact endpoint
// hostname and bootstrap IP pair. TLS SNI and certificate verification remain
// bound to the hostname while dialing remains pinned to the selected IP.
func (r *Runtime) pinnedDoHHTTPClient(ip, host string, timeout time.Duration) *http.Client {
	key := strings.ToLower(strings.TrimSuffix(host, ".")) + "|" + ip
	now := time.Now()
	r.activeDoHTransportMu.Lock()
	if r.activeDoHTransports == nil {
		r.activeDoHTransports = make(map[string]*pinnedDoHTransportEntry)
	}
	for existing, entry := range r.activeDoHTransports {
		if now.Sub(entry.lastUsed) >= pinnedDoHTransportMaxIdleAge {
			entry.transport.CloseIdleConnections()
			delete(r.activeDoHTransports, existing)
		}
	}
	entry := r.activeDoHTransports[key]
	if entry == nil {
		if len(r.activeDoHTransports) >= maxPinnedDoHTransports {
			var oldestKey string
			var oldest time.Time
			for existing, candidate := range r.activeDoHTransports {
				if oldest.IsZero() || candidate.lastUsed.Before(oldest) {
					oldestKey, oldest = existing, candidate.lastUsed
				}
			}
			if evicted := r.activeDoHTransports[oldestKey]; evicted != nil {
				evicted.transport.CloseIdleConnections()
				delete(r.activeDoHTransports, oldestKey)
			}
		}
		entry = &pinnedDoHTransportEntry{transport: newPinnedHTTPTransport(ip, host, timeout)}
		r.activeDoHTransports[key] = entry
	}
	entry.lastUsed = now
	transport := entry.transport
	r.activeDoHTransportMu.Unlock()

	return &http.Client{
		Transport: transport,
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}


// recordPinnedDoHLatency keeps a bounded EWMA of actual DNS-forwarding request
// durations for each pinned bootstrap identity.
func (r *Runtime) recordPinnedDoHLatency(host, ip string, elapsed time.Duration) {
	if elapsed <= 0 {
		return
	}
	key := strings.ToLower(strings.TrimSuffix(host, ".")) + "|" + ip
	r.activeDoHTransportMu.Lock()
	defer r.activeDoHTransportMu.Unlock()
	if entry := r.activeDoHTransports[key]; entry != nil {
		if entry.latencyEWMA <= 0 {
			entry.latencyEWMA = elapsed
		} else {
			entry.latencyEWMA = (entry.latencyEWMA*7 + elapsed*3) / 10
		}
		entry.lastUsed = time.Now()
	}
}

// activeDoHHedgeDelay uses the median of recent observed per-bootstrap request
// durations. It falls back conservatively until enough live traffic exists.
func (r *Runtime) activeDoHHedgeDelay(candidate activedoh.Candidate) time.Duration {
	r.activeDoHTransportMu.Lock()
	defer r.activeDoHTransportMu.Unlock()
	var samples []time.Duration
	host := strings.ToLower(strings.TrimSuffix(candidate.Hostname, "."))
	for _, ip := range append(append([]string(nil), candidate.IPv4...), candidate.IPv6...) {
		if entry := r.activeDoHTransports[host+"|"+ip]; entry != nil && entry.latencyEWMA > 0 {
			samples = append(samples, entry.latencyEWMA)
		}
	}
	if len(samples) == 0 {
		return activeDoHHedgeDelay
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	median := samples[len(samples)/2]
	delay := median + median/2
	if delay < 100*time.Millisecond {
		delay = 100 * time.Millisecond
	}
	if delay > 1500*time.Millisecond {
		delay = 1500 * time.Millisecond
	}
	return delay
}
