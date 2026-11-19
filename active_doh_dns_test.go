package main

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"lucx-doh-health-monitor/internal/activedoh"
)

func activeDoHTestQuery(qtype uint16, withEDNS bool) []byte {
	query := makeDNSQuery("geosite.example", qtype)
	if withEDNS {
		binary.BigEndian.PutUint16(query[10:12], 1)
		// UDP payload 1232, EDNS version 0, DO=1, no request options.
		query = append(query, 0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0)
	}
	return query
}

func TestBuildActiveDoHResponseReturnsSelectedEndpointIPv4(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	query := activeDoHTestQuery(1, false)
	_, qtype, questionEnd, err := parseQuestion(query)
	if err != nil {
		t.Fatal(err)
	}
	selection := activedoh.Selection{
		Candidate: activedoh.Candidate{IPv4: []string{"1.1.1.1", "8.8.8.8"}},
		FreshUntil: now.Add(31 * time.Second),
	}
	response, cacheable := buildActiveDoHResponse(query, "geosite.example", qtype, questionEnd, selection, now)
	if !cacheable {
		t.Fatal("expected positive endpoint answer to be cacheable")
	}
	if dnsRCode(response) != 0 || dnsAnswerCount(response) != 2 {
		t.Fatalf("unexpected DNS response: rcode=%d answers=%d", dnsRCode(response), dnsAnswerCount(response))
	}
	ips, err := parseActiveDoHAddressRecords(response, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 2 || ips[0] != "1.1.1.1" || ips[1] != "8.8.8.8" {
		t.Fatalf("unexpected endpoint addresses: %v", ips)
	}
	ttl, ok := minResponseTTL(response)
	if !ok || ttl != 31 {
		t.Fatalf("TTL=(%d,%t), want 31 seconds", ttl, ok)
	}
}

func TestBuildActiveDoHResponseCapsTTLAtSixtySeconds(t *testing.T) {
	now := time.Now().UTC()
	query := activeDoHTestQuery(1, false)
	_, qtype, questionEnd, err := parseQuestion(query)
	if err != nil {
		t.Fatal(err)
	}
	selection := activedoh.Selection{
		Candidate: activedoh.Candidate{IPv4: []string{"9.9.9.9"}},
		FreshUntil: now.Add(2 * time.Minute),
	}
	response, cacheable := buildActiveDoHResponse(query, "geosite.example", qtype, questionEnd, selection, now)
	if !cacheable {
		t.Fatal("expected positive endpoint answer")
	}
	ttl, ok := minResponseTTL(response)
	if !ok || ttl != 60 {
		t.Fatalf("TTL=(%d,%t), want 60 seconds", ttl, ok)
	}
}

func TestBuildActiveDoHResponseReturnsSelectedEndpointIPv6(t *testing.T) {
	now := time.Now().UTC()
	query := activeDoHTestQuery(28, false)
	_, qtype, questionEnd, err := parseQuestion(query)
	if err != nil {
		t.Fatal(err)
	}
	selection := activedoh.Selection{
		Candidate: activedoh.Candidate{IPv6: []string{"2606:4700:4700::1111"}},
		FreshUntil: now.Add(time.Minute),
	}
	response, cacheable := buildActiveDoHResponse(query, "geosite.example", qtype, questionEnd, selection, now)
	if !cacheable {
		t.Fatal("expected positive endpoint answer")
	}
	ips, err := parseActiveDoHAddressRecords(response, 28)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || net.ParseIP(ips[0]).To16() == nil || net.ParseIP(ips[0]).To4() != nil {
		t.Fatalf("unexpected IPv6 endpoint address: %v", ips)
	}
}

func TestBuildActiveDoHResponseUsesNoErrorNodataForMissingFamilyAndUnsupportedQtype(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name  string
		qtype uint16
	}{
		{name: "missing IPv6", qtype: 28},
		{name: "HTTPS", qtype: 65},
		{name: "TXT", qtype: 16},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			query := activeDoHTestQuery(test.qtype, false)
			_, qtype, questionEnd, err := parseQuestion(query)
			if err != nil {
				t.Fatal(err)
			}
			selection := activedoh.Selection{
				Candidate: activedoh.Candidate{IPv4: []string{"1.1.1.1"}},
				FreshUntil: now.Add(time.Minute),
			}
			response, cacheable := buildActiveDoHResponse(query, "geosite.example", qtype, questionEnd, selection, now)
			if cacheable {
				t.Fatal("synthetic NODATA must not be cached")
			}
			if dnsRCode(response) != 0 || dnsAnswerCount(response) != 0 {
				t.Fatalf("expected NOERROR/NODATA, got rcode=%d answers=%d", dnsRCode(response), dnsAnswerCount(response))
			}
			if binary.BigEndian.Uint16(response[8:10]) != 0 {
				t.Fatalf("synthetic NODATA must not include SOA, NSCOUNT=%d", binary.BigEndian.Uint16(response[8:10]))
			}
		})
	}
}

func TestBuildActiveDoHResponseReturnsNoErrorNodataAfterFreshnessExpires(t *testing.T) {
	now := time.Now().UTC()
	query := activeDoHTestQuery(1, false)
	_, qtype, questionEnd, err := parseQuestion(query)
	if err != nil {
		t.Fatal(err)
	}
	selection := activedoh.Selection{
		Candidate: activedoh.Candidate{IPv4: []string{"1.1.1.1"}},
		FreshUntil: now,
	}
	response, cacheable := buildActiveDoHResponse(query, "geosite.example", qtype, questionEnd, selection, now)
	if cacheable || dnsRCode(response) != 0 || dnsAnswerCount(response) != 0 {
		t.Fatalf("expired endpoint should yield uncached NOERROR/NODATA")
	}
}

func TestActiveDoHResponsePreservesEDNSDOWithoutReflectingOptions(t *testing.T) {
	now := time.Now().UTC()
	query := activeDoHTestQuery(1, true)
	// Add a COOKIE option to the request OPT.
	query = query[:len(query)-2]
	query = append(query, 0, 8, 0, 4, 1, 2, 3, 4)
	_, qtype, questionEnd, err := parseQuestion(query)
	if err != nil {
		t.Fatal(err)
	}
	selection := activedoh.Selection{
		Candidate: activedoh.Candidate{IPv4: []string{"1.1.1.1"}},
		FreshUntil: now.Add(time.Minute),
	}
	response, _ := buildActiveDoHResponse(query, "geosite.example", qtype, questionEnd, selection, now)
	opt := extractEDNSOPT(response)
	if len(opt) != 11 || binary.BigEndian.Uint16(opt[3:5]) != 1232 {
		t.Fatalf("unexpected minimal response OPT: %v", opt)
	}
	if binary.BigEndian.Uint16(opt[7:9])&0x8000 == 0 {
		t.Fatal("DO bit was not preserved")
	}
	if binary.BigEndian.Uint16(opt[9:11]) != 0 {
		t.Fatal("response OPT must not reflect client EDNS options")
	}
}
