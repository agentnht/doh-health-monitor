package main

import (
	"net/http"
	"testing"
	"time"

	"lucx-doh-health-monitor/internal/activedoh"
)

func TestPinnedDoHHTTPClientReusesTransportByEndpointAndBootstrap(t *testing.T) {
	r := &Runtime{}
	first := r.pinnedDoHHTTPClient("8.8.8.8", "dns.example", time.Second)
	reused := r.pinnedDoHHTTPClient("8.8.8.8", "dns.example", 2*time.Second)
	otherIP := r.pinnedDoHHTTPClient("8.8.4.4", "dns.example", time.Second)
	otherHost := r.pinnedDoHHTTPClient("8.8.8.8", "other.example", time.Second)
	if first.Transport != reused.Transport {
		t.Fatal("same endpoint/bootstrap pair did not reuse transport")
	}
	if first.Transport == otherIP.Transport || first.Transport == otherHost.Transport {
		t.Fatal("transport was shared across distinct endpoint/bootstrap identities")
	}
	if client, ok := first.Transport.(*http.Transport); !ok || client.TLSClientConfig.ServerName != "dns.example" {
		t.Fatal("pooled transport did not retain endpoint TLS server name")
	}
}

func TestPinnedDoHTransportPoolIsBounded(t *testing.T) {
	r := &Runtime{}
	for i := 0; i < maxPinnedDoHTransports+8; i++ {
		r.pinnedDoHHTTPClient("8.8.8.8", "dns"+string(rune('a'+i))+".example", time.Second)
	}
	r.activeDoHTransportMu.Lock()
	defer r.activeDoHTransportMu.Unlock()
	if len(r.activeDoHTransports) > maxPinnedDoHTransports {
		t.Fatalf("pool contains %d transports; max is %d", len(r.activeDoHTransports), maxPinnedDoHTransports)
	}
}

func TestActiveDoHHedgeDelayUsesMedianPerIPLatencyAndBounds(t *testing.T) {
	r := &Runtime{activeDoHTransports: map[string]*pinnedDoHTransportEntry{
		"doh.example|8.8.8.8": {latencyEWMA: 100 * time.Millisecond},
		"doh.example|8.8.4.4": {latencyEWMA: 200 * time.Millisecond},
		"doh.example|1.1.1.1": {latencyEWMA: 300 * time.Millisecond},
	}}
	candidate := activedoh.Candidate{Hostname: "doh.example", IPv4: []string{"8.8.8.8", "8.8.4.4", "1.1.1.1"}}
	if got := r.activeDoHHedgeDelay(candidate); got != 300*time.Millisecond {
		t.Fatalf("hedge delay=%s, want 1.5x median (200ms)", got)
	}
	candidate.IPv4 = []string{"9.9.9.9"}
	if got := r.activeDoHHedgeDelay(candidate); got != activeDoHHedgeDelay {
		t.Fatalf("unknown IP hedge delay=%s, want conservative fallback %s", got, activeDoHHedgeDelay)
	}
	r.activeDoHTransports["doh.example|9.9.9.9"] = &pinnedDoHTransportEntry{latencyEWMA: time.Second}
	if got := r.activeDoHHedgeDelay(candidate); got != 1500*time.Millisecond {
		t.Fatalf("high-latency hedge delay=%s, want 1500ms cap", got)
	}
}
