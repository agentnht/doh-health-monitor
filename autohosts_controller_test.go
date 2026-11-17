package main

import (
	"encoding/binary"
	"net"
	"path/filepath"
	"testing"
	"time"

	"lucx-doh-health-monitor/internal/autohosts"
)

func TestParseAAAARecordsAndRejectPrivateProbeTargets(t *testing.T) {
	query := makeDNSQuery("example.com", 28)
	response := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[6:8], 1)
	response = append(response, 0xc0, 0x0c)
	response = append(response, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16)
	ip := net.ParseIP("2001:4860:4860::8888").To16()
	response = append(response, ip...)
	ips, err := parseAddressRecords(response, 28)
	if err != nil { t.Fatal(err) }
	if len(ips) != 1 || ips[0] != "2001:4860:4860::8888" { t.Fatalf("unexpected AAAA records: %v", ips) }
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.1.1", "::1", "fc00::1"} {
		if isAutoHostsPublicIP(net.ParseIP(raw)) { t.Errorf("private/reserved address accepted: %s", raw) }
	}
	if !isAutoHostsPublicIP(net.ParseIP("8.8.8.8")) { t.Fatal("public IPv4 rejected") }
}

func TestAutoHostsControllerRequiresRepeatedFailureBeforeSwitch(t *testing.T) {
	now := time.Now().UTC()
	manager, err := autohosts.New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil { t.Fatal(err) }
	a := autohosts.Endpoint{ServerID:"a", URL:"https://a.example/dns-query", Hostname:"a.example", IPv4:[]string{"8.8.8.8"}}
	b := autohosts.Endpoint{ServerID:"b", URL:"https://b.example/dns-query", Hostname:"b.example", IPv4:[]string{"1.1.1.1"}}
	if err := manager.ApplyFullCycle("a", []autohosts.Endpoint{a,b}, nil, now); err != nil { t.Fatal(err) }
	controller := newAutoHostsController(nil, manager)
	controller.activeSince = now.Add(-20*time.Minute)
	first, err := controller.chooseActive([]autohosts.Endpoint{a,b}, []autohosts.ProbeResult{{ServerID:"b",Domain:"chatgpt.com",Success:true}}, now)
	if err != nil { t.Fatal(err) }
	if first != "a" { t.Fatalf("first failed cycle switched too early: %s", first) }
	second, err := controller.chooseActive([]autohosts.Endpoint{a,b}, []autohosts.ProbeResult{{ServerID:"b",Domain:"chatgpt.com",Success:true}}, now.Add(time.Minute))
	if err != nil { t.Fatal(err) }
	if second != "b" { t.Fatalf("expected switch after repeated failure, got %s", second) }
}
