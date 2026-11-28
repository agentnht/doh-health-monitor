package main

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func smartDNSTestResponse(q []byte, ips ...string) []byte {
	_, _, end, err := parseQuestion(q)
	if err != nil {
		panic(err)
	}
	packet := append([]byte(nil), q[:end]...)
	binary.BigEndian.PutUint16(packet[2:4], 0x8180)
	binary.BigEndian.PutUint16(packet[6:8], uint16(len(ips)))
	for _, raw := range ips {
		ip := net.ParseIP(raw).To4()
		packet = append(packet, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
		packet = append(packet, ip...)
	}
	return packet
}

func TestSmartDNSKeepAddressSelectsSingleARecord(t *testing.T) {
	query := makeDNSQuery("chatgpt.com", 1)
	response := smartDNSTestResponse(query, "192.0.2.10", "192.0.2.20")
	got, err := smartDNSKeepAddress(response, 1, "192.0.2.20")
	if err != nil {
		t.Fatal(err)
	}
	if count := dnsAnswerCount(got); count != 2 {
		t.Fatalf("answer count=%d, want original RR count 2", count)
	}
	ips, err := parseActiveDoHAddressRecords(got, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "192.0.2.20" {
		t.Fatalf("selected answers=%v", ips)
	}
}

func TestSmartDNSKeepAddressRejectsMalformedPacket(t *testing.T) {
	if _, err := smartDNSKeepAddress([]byte{1, 2, 3}, 1, "192.0.2.20"); err == nil {
		t.Fatal("expected malformed packet error")
	}
}

func TestActiveDoHCacheKeySeparatesSmartDNSResults(t *testing.T) {
	query := makeDNSQuery("chatgpt.com", 1)
	raw := activeDoHCacheKey(query, &Snapshot{cfg: Config{SmartDNSEnabled: false}})
	selected := activeDoHCacheKey(query, &Snapshot{cfg: Config{SmartDNSEnabled: true}})
	if raw == selected {
		t.Fatal("raw and SmartDNS cache namespaces must differ")
	}
}

func TestSmartDNSUsesEditableConfiguredChecks(t *testing.T) {
	snapshot := &Snapshot{groups: map[string]Group{
		"google": {Checks: []Check{
			{Domain: "custom.example"},
			{Domain: "chatgpt.com"},
			{Domain: "CUSTOM.example."},
		}},
	}}
	checks := smartDNSConfiguredChecks(snapshot)
	if len(checks) != 2 {
		t.Fatalf("configured checks=%d, want 2 unique entries", len(checks))
	}
	if checks[0].Domain != "custom.example" || checks[1].Domain != "chatgpt.com" {
		t.Fatalf("configured domains=%v, want custom.example and chatgpt.com", []string{checks[0].Domain, checks[1].Domain})
	}
}

func TestSmartDNSBestCandidateScoresThenUsesMeanLatency(t *testing.T) {
	results := map[string]*smartDNSProbeResult{
		"192.0.2.10": {ip: "192.0.2.10", optionalScore: 2, successful: 3, latency: 400 * time.Millisecond},
		"192.0.2.20": {ip: "192.0.2.20", optionalScore: 3, successful: 4, latency: 900 * time.Millisecond},
		"192.0.2.30": {ip: "192.0.2.30", optionalScore: 3, successful: 4, latency: 300 * time.Millisecond},
	}
	best := smartDNSBestCandidate(results)
	if best == nil || best.ip != "192.0.2.30" {
		t.Fatalf("best candidate=%v, want 192.0.2.30", best)
	}
}

func TestSmartDNSBestCandidateUsesOptionalChecksForScore(t *testing.T) {
	results := map[string]*smartDNSProbeResult{
		// More successful required checks do not increase the optional score.
		"192.0.2.10": {ip: "192.0.2.10", optionalScore: 1, successful: 4, latency: 400 * time.Millisecond},
		"192.0.2.20": {ip: "192.0.2.20", optionalScore: 2, successful: 3, latency: 600 * time.Millisecond},
	}
	best := smartDNSBestCandidate(results)
	if best == nil || best.ip != "192.0.2.20" {
		t.Fatalf("best candidate=%v, want 192.0.2.20 (higher optional score)", best)
	}
}

func TestSmartDNSBestCandidateAllowsNoOptionalSuccess(t *testing.T) {
	results := map[string]*smartDNSProbeResult{
		"192.0.2.10": {ip: "192.0.2.10", optionalScore: 0, successful: 2, latency: 300 * time.Millisecond},
	}
	best := smartDNSBestCandidate(results)
	if best == nil || best.ip != "192.0.2.10" {
		t.Fatalf("best candidate=%v, want required-only passing IP", best)
	}
}

func TestSmartDNSBestCandidateDoesNotRejectOptionalFailures(t *testing.T) {
	results := map[string]*smartDNSProbeResult{
		"192.0.2.10": {ip: "192.0.2.10", optionalScore: 0, successful: 0},
		"192.0.2.20": {ip: "192.0.2.20", optionalScore: 0, successful: 0},
	}
	best := smartDNSBestCandidate(results)
	if best == nil || best.ip != "192.0.2.10" {
		t.Fatalf("best candidate=%v, want stable lexical tie winner 192.0.2.10", best)
	}
}

func TestSmartDNSBestCandidateRejectsRequiredCheckFailure(t *testing.T) {
	results := map[string]*smartDNSProbeResult{
		"192.0.2.10": {ip: "192.0.2.10", optionalScore: 7, successful: 8, latency: time.Second, requiredFailed: true},
		"192.0.2.20": {ip: "192.0.2.20", optionalScore: 2, successful: 3, latency: 500 * time.Millisecond},
	}
	best := smartDNSBestCandidate(results)
	if best == nil || best.ip != "192.0.2.20" {
		t.Fatalf("best candidate=%v, want 192.0.2.20", best)
	}
}
