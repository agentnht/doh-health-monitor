package main

import (
	"encoding/binary"
	"net"
	"testing"
)

func smartDNSTestResponse(q []byte, ips ...string) []byte {
	_, _, end, err := parseQuestion(q)
	if err != nil { panic(err) }
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
	if err != nil { t.Fatal(err) }
	if count := dnsAnswerCount(got); count != 1 { t.Fatalf("answer count=%d, want 1", count) }
	ips, err := parseActiveDoHAddressRecords(got, 1)
	if err != nil { t.Fatal(err) }
	if len(ips) != 1 || ips[0] != "192.0.2.20" { t.Fatalf("selected answers=%v", ips) }
}

func TestSmartDNSKeepAddressRejectsMalformedPacket(t *testing.T) {
	if _, err := smartDNSKeepAddress([]byte{1, 2, 3}, 1, "192.0.2.20"); err == nil {
		t.Fatal("expected malformed packet error")
	}
}

func TestActiveDoHCacheKeySeparatesSmartDNSResults(t *testing.T) {
	query := makeDNSQuery("chatgpt.com", 1)
	raw := activeDoHCacheKey(query, &Snapshot{cfg: Config{SmartDNSEnabled:false}})
	selected := activeDoHCacheKey(query, &Snapshot{cfg: Config{SmartDNSEnabled:true}})
	if raw == selected { t.Fatal("raw and SmartDNS cache namespaces must differ") }
}
