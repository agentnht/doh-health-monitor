package main

import (
	"net/http"
	"strings"
	"time"
)

const (
	maxPinnedDoHTransports = 64
	pinnedDoHTransportMaxIdleAge = 10 * time.Minute
)

type pinnedDoHTransportEntry struct {
	transport *http.Transport
	lastUsed  time.Time
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
