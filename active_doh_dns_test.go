package main

import (
	"encoding/binary"
	"testing"
	"time"

	"lucx-doh-health-monitor/internal/activedoh"
)

func activeDoHTestQuery(qtype uint16, withEDNS bool) []byte {
	query := makeDNSQuery("geosite.example", qtype)
	if withEDNS {
		binary.BigEndian.PutUint16(query[10:12], 1)
		// UDP payload 1232, EDNS version 0, DO=1, no request options.
		// OPT RR: root, TYPE=41, UDP payload=1232, EDNS version=0, DO=1, RDLEN=0.
		query = append(query, 0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 0)
	}
	return query
}

func TestActiveDoHResponseRejectsSelectionFromStaleConfigGeneration(t *testing.T) {
	now := time.Now().UTC()
	selector := activedoh.NewSelector(activedoh.DefaultPolicy())
	candidate := activedoh.Candidate{
		ServerID:         "selected",
		URL:              "https://doh.example/dns-query",
		Hostname:         "doh.example",
		IPv4:             []string{"1.1.1.1"},
		ResolvedAt:       now,
		ConfigGeneration: 41,
	}
	var probes []activedoh.ProbeResult
	for _, domain := range activedoh.ControlDomains() {
		probes = append(probes, activedoh.ProbeResult{
			ServerID: "selected", Domain: domain, Success: true, CheckedAt: now,
		})
	}
	if _, ok := selector.Select([]activedoh.Candidate{candidate}, probes, now); !ok {
		t.Fatal("failed to seed active selector")
	}

	runtime := &Runtime{activeDoHSelector: selector, cache: map[string]cacheItem{}}
	requestSnapshot := &Snapshot{
		cfg:                 Config{Cache: CacheConfig{Enabled: true, MaxEntries: 10, MaxBytes: 4096, MaxTTL: 300}},
		activeDoHGeneration: 41,
	}
	currentSnapshot := &Snapshot{
		cfg:                 Config{Cache: CacheConfig{Enabled: true, MaxEntries: 10, MaxBytes: 4096, MaxTTL: 300}},
		activeDoHGeneration: 42,
	}
	runtime.snapshot.Store(currentSnapshot)

	response := runtime.activeDoHDNSResponse(activeDoHTestQuery(1, false), requestSnapshot)
	if dnsRCode(response) != 2 || dnsAnswerCount(response) != 0 {
		t.Fatalf("stale config selection must return SERVFAIL: rcode=%d answers=%d", dnsRCode(response), dnsAnswerCount(response))
	}
	runtime.cacheMu.Lock()
	cacheEntries := len(runtime.cache)
	runtime.cacheMu.Unlock()
	if cacheEntries != 0 {
		t.Fatalf("stale config response was cached: entries=%d", cacheEntries)
	}
	if status := runtime.activeDoHStatus(); status != nil {
		t.Fatalf("stale active selection was exposed in status: %+v", status)
	}
}

// TestEndpointIPUnsupportedQTypesReturnNoErrorNodata exercises the full
// endpoint_ip handler. The Geosite listener currently supports A/AAAA only; other QTYPEs
// remain NODATA and are not forwarded or cached.
func TestEndpointIPUnsupportedQTypesReturnNoErrorNodata(t *testing.T) {
	now := time.Now().UTC()
	selector := activedoh.NewSelector(activedoh.DefaultPolicy())
	candidate := activedoh.Candidate{
		ServerID:         "selected",
		URL:              "https://doh.example/dns-query",
		Hostname:         "doh.example",
		IPv4:             []string{"192.0.2.53"},
		ResolvedAt:       now,
		ConfigGeneration: 41,
	}
	probes := make([]activedoh.ProbeResult, 0, len(activedoh.ControlDomains()))
	for _, domain := range activedoh.ControlDomains() {
		probes = append(probes, activedoh.ProbeResult{
			ServerID: "selected", Domain: domain, Success: true, CheckedAt: now,
		})
	}
	if _, ok := selector.Select([]activedoh.Candidate{candidate}, probes, now); !ok {
		t.Fatal("failed to seed active DoH selector")
	}

	snapshot := &Snapshot{
		cfg: Config{
			DNSMode: "endpoint_ip",
			Cache: CacheConfig{
				Enabled: true, MaxEntries: 64, MaxBytes: 1 << 20, MaxTTL: 300,
			},
		},
		activeDoHGeneration: 41,
	}
	runtime := &Runtime{
		activeDoHSelector: selector,
		cache:             make(map[string]cacheItem),
	}
	runtime.snapshot.Store(snapshot)

	unsupported := []struct {
		name  string
		qtype uint16
	}{
		{name: "NS", qtype: 2},
		{name: "CNAME", qtype: 5},
		{name: "SOA", qtype: 6},
		{name: "PTR", qtype: 12},
		{name: "MX", qtype: 15},
		{name: "TXT", qtype: 16},
		{name: "SRV", qtype: 33},
		{name: "NAPTR", qtype: 35},
		{name: "DS", qtype: 43},
		{name: "RRSIG", qtype: 46},
		{name: "NSEC", qtype: 47},
		{name: "DNSKEY", qtype: 48},
		{name: "NSEC3", qtype: 50},
		{name: "TLSA", qtype: 52},
		{name: "SVCB", qtype: 64},
		{name: "HTTPS", qtype: 65},
		{name: "ANY", qtype: 255},
	}

	for _, tc := range unsupported {
		for _, withEDNS := range []bool{false, true} {
			name := tc.name + "/without-edns"
			if withEDNS {
				name = tc.name + "/with-edns-do"
			}
			t.Run(name, func(t *testing.T) {
				query := activeDoHTestQuery(tc.qtype, withEDNS)
				// A client may set AD/CD in its query; the synthetic response
				// must never claim authenticated data.
				queryFlags := binary.BigEndian.Uint16(query[2:4]) | 0x0030
				binary.BigEndian.PutUint16(query[2:4], queryFlags)
				if withEDNS {
					// Include a COOKIE option. The response should preserve only
					// the supported OPT metadata and DO bit, not echo the option.
					optStart := len(query) - 11
					binary.BigEndian.PutUint16(query[optStart+9:optStart+11], 8)
					query = append(query, 0, 10, 0, 4, 1, 2, 3, 4)
				}

				response := runtime.activeDoHDNSResponse(query, snapshot)
				if len(response) < 12 {
					t.Fatal("response is shorter than a DNS header")
				}
				if got := dnsRCode(response); got != 0 {
					t.Fatalf("rcode=%d, want NOERROR", got)
				}
				if got := binary.BigEndian.Uint16(response[6:8]); got != 0 {
					t.Fatalf("ANCOUNT=%d, want NODATA with no answers", got)
				}
				if got := binary.BigEndian.Uint16(response[8:10]); got != 0 {
					t.Fatalf("NSCOUNT=%d, synthetic NODATA must not include SOA", got)
				}

				flags := binary.BigEndian.Uint16(response[2:4])
				if flags&0x8000 == 0 || flags&0x0080 == 0 {
					t.Fatalf("response must set QR and RA, flags=%016b", flags)
				}
				if flags&0x0100 != queryFlags&0x0100 {
					t.Fatalf("RD flag changed: query=%016b response=%016b", queryFlags, flags)
				}
				if flags&0x0020 != 0 {
					t.Fatalf("synthetic response must not assert AD, flags=%016b", flags)
				}

				_, _, queryEnd, err := parseQuestion(query)
				if err != nil {
					t.Fatal(err)
				}
				_, _, responseEnd, err := parseQuestion(response)
				if err != nil {
					t.Fatal(err)
				}
				if binary.BigEndian.Uint16(response[4:6]) != 1 ||
					string(response[12:responseEnd]) != string(query[12:queryEnd]) {
					t.Fatal("response did not preserve the single original question")
				}

				opt := extractEDNSOPT(response)
				if !withEDNS {
					if binary.BigEndian.Uint16(response[10:12]) != 0 || len(opt) != 0 {
						t.Fatal("response added OPT although the query had no EDNS")
					}
				} else {
					if binary.BigEndian.Uint16(response[10:12]) != 1 || len(opt) != 11 {
						t.Fatalf("expected one minimal OPT RR, ARCOUNT=%d OPT length=%d",
							binary.BigEndian.Uint16(response[10:12]), len(opt))
					}
					if binary.BigEndian.Uint16(opt[1:3]) != 41 ||
						binary.BigEndian.Uint16(opt[3:5]) != 1232 ||
						opt[6] != 0 ||
						binary.BigEndian.Uint16(opt[7:9]) != 0x8000 ||
						binary.BigEndian.Uint16(opt[9:11]) != 0 {
						t.Fatalf("unexpected minimal OPT response (must preserve payload size and DO only): %v", opt)
					}
				}

				runtime.cacheMu.Lock()
				cacheEntries := len(runtime.cache)
				runtime.cacheMu.Unlock()
				if cacheEntries != 0 {
					t.Fatalf("synthetic NOERROR/NODATA response must not be cached; entries=%d", cacheEntries)
				}
			})
		}
	}
}

func TestEndpointIPUnavailableSelectionReturnsSERVFAIL(t *testing.T) {
	query := activeDoHTestQuery(1, false)
	snapshot := &Snapshot{
		cfg:                 Config{DNSMode: "endpoint_ip", Cache: CacheConfig{Enabled: false}},
		activeDoHGeneration: 7,
	}
	t.Run("missing selector", func(t *testing.T) {
		runtime := &Runtime{cache: make(map[string]cacheItem)}
		runtime.snapshot.Store(snapshot)
		if got := dnsRCode(runtime.activeDoHDNSResponse(query, snapshot)); got != 2 {
			t.Fatalf("rcode=%d, want SERVFAIL when selector is unavailable", got)
		}
	})
	t.Run("no selected endpoint", func(t *testing.T) {
		runtime := &Runtime{
			activeDoHSelector: activedoh.NewSelector(activedoh.DefaultPolicy()),
			cache:             make(map[string]cacheItem),
		}
		runtime.snapshot.Store(snapshot)
		if got := dnsRCode(runtime.activeDoHDNSResponse(query, snapshot)); got != 2 {
			t.Fatalf("rcode=%d, want SERVFAIL when no current selection exists", got)
		}
	})
	t.Run("unsupported QTYPE remains NODATA", func(t *testing.T) {
		runtime := &Runtime{cache: make(map[string]cacheItem)}
		runtime.snapshot.Store(snapshot)
		response := runtime.activeDoHDNSResponse(activeDoHTestQuery(65, false), snapshot)
		if dnsRCode(response) != 0 || dnsAnswerCount(response) != 0 {
			t.Fatalf("unsupported QTYPE should remain NOERROR/NODATA; rcode=%d answers=%d",
				dnsRCode(response), dnsAnswerCount(response))
		}
	})
}
