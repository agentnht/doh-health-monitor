package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"lucx-doh-health-monitor/internal/activedoh"
)

func TestSendActiveDoHForwardsOriginalQueryAndReturnsRealAnswer(t *testing.T) {
	query := mode2QueryWithEDNSDO("www.example.test", 1)
	var requestCount atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requestCount.Add(1)
		if req.Method != http.MethodPost {
			t.Errorf("method=%q, want POST", req.Method)
		}
		if req.URL.Path != "/dns-query" {
			t.Errorf("path=%q, want /dns-query", req.URL.Path)
		}
		if req.Header.Get("Content-Type") != "application/dns-message" ||
			req.Header.Get("Accept") != "application/dns-message" {
			t.Errorf("unexpected DoH headers: %+v", req.Header)
		}
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !bytes.Equal(body, query) {
			t.Errorf("DoH query differs from original client packet")
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(mode2CNAMEAddressResponse(body, 1, 120, 60))
	}))
	defer server.Close()

	candidate := activedoh.Candidate{
		ServerID: "selected", URL: server.URL + "/dns-query", Hostname: "127.0.0.1",
		IPv4: []string{"1.1.1.1"}, ResolvedAt: time.Now(),
	}
	response, err := sendActiveDoHWithClientFactory(
		context.Background(), candidate, query, 2*time.Second,
		func(ip, host string, timeout time.Duration) *http.Client {
			if ip != "1.1.1.1" || host != "127.0.0.1" || timeout != 2*time.Second {
				t.Errorf("client factory args ip=%q host=%q timeout=%s", ip, host, timeout)
			}
			return server.Client()
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if requestCount.Load() != 1 {
		t.Fatalf("DoH request count=%d, want 1", requestCount.Load())
	}
	if dnsRCode(response) != 0 {
		t.Fatalf("DNS RCODE=%d, want NOERROR", dnsRCode(response))
	}
	answers, err := dnsRRsInSection(response, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(answers) != 2 || answers[0].typeCode != 5 || answers[1].typeCode != 1 {
		t.Fatalf("expected CNAME plus A answer, got %+v", answers)
	}
	if got := response[answers[1].rdata:answers[1].end]; len(got) != 4 || got[0] != 203 || got[1] != 0 || got[2] != 113 || got[3] != 10 {
		t.Fatalf("unexpected terminal A record: %v", got)
	}
}

func TestSendActiveDoHRetriesNextBootstrapIPOnHTTPFailure(t *testing.T) {
	query := makeDNSQuery("retry.example.test", 1)
	var requestCount atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if requestCount.Add(1) == 1 {
			http.Error(w, "temporary failure", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(testAResponse(query, 30))
	}))
	defer server.Close()

	candidate := activedoh.Candidate{
		ServerID: "selected", URL: server.URL + "/dns-query", Hostname: "127.0.0.1",
		IPv4: []string{"1.1.1.1", "8.8.8.8"}, ResolvedAt: time.Now(),
	}
	factoryCalls := 0
	response, err := sendActiveDoHWithClientFactory(
		context.Background(), candidate, query, 2*time.Second,
		func(ip, host string, timeout time.Duration) *http.Client {
			factoryCalls++
			return server.Client()
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if requestCount.Load() != 2 || factoryCalls != 2 {
		t.Fatalf("requests=%d factory calls=%d, want 2 each", requestCount.Load(), factoryCalls)
	}
	if dnsRCode(response) != 0 || dnsAnswerCount(response) != 1 {
		t.Fatalf("unexpected retried DNS response: rcode=%d answers=%d", dnsRCode(response), dnsAnswerCount(response))
	}
}

func TestSendActiveDoHRejectsUnusableDNSAnswersAndTriesNextBootstrapIP(t *testing.T) {
	for _, tc := range []struct {
		name      string
		rcode     uint16
		truncated bool
	}{
		{name: "SERVFAIL", rcode: 2},
		{name: "REFUSED", rcode: 5},
		{name: "truncated", truncated: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := makeDNSQuery("quality.example.test", 1)
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				var response []byte
				if requests.Add(1) == 1 {
					if tc.truncated {
						response = testAResponse(query, 30)
						response[2] |= 0x02
					} else {
						response = mode2ResponseWithRCode(query, tc.rcode)
					}
				} else {
					response = testAResponse(query, 45)
				}
				w.Header().Set("Content-Type", "application/dns-message")
				_, _ = w.Write(response)
			}))
			defer server.Close()

			candidate := activedoh.Candidate{
				ServerID: "selected", URL: server.URL + "/dns-query", Hostname: "127.0.0.1",
				IPv4: []string{"1.1.1.1", "8.8.8.8"}, ResolvedAt: time.Now(),
			}
			response, err := sendActiveDoHWithClientFactory(
				context.Background(), candidate, query, 2*time.Second,
				func(ip, host string, timeout time.Duration) *http.Client {
					return server.Client()
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			if requests.Load() != 2 {
				t.Fatalf("request count=%d, want retry on second bootstrap IP", requests.Load())
			}
			if dnsRCode(response) != 0 || dnsAnswerCount(response) != 1 || dnsTruncated(response) {
				t.Fatalf("returned unusable response: rcode=%d answers=%d truncated=%t",
					dnsRCode(response), dnsAnswerCount(response), dnsTruncated(response))
			}
		})
	}
}

func TestSendActiveDoHDoesNotRetryNXDOMAIN(t *testing.T) {
	query := makeDNSQuery("missing.example.test", 1)
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(mode2ResponseWithRCode(query, 3))
	}))
	defer server.Close()

	candidate := activedoh.Candidate{
		ServerID: "selected", URL: server.URL + "/dns-query", Hostname: "127.0.0.1",
		IPv4: []string{"1.1.1.1", "8.8.8.8"}, ResolvedAt: time.Now(),
	}
	response, err := sendActiveDoHWithClientFactory(
		context.Background(), candidate, query, 2*time.Second,
		func(ip, host string, timeout time.Duration) *http.Client {
			return server.Client()
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 || dnsRCode(response) != 3 {
		t.Fatalf("NXDOMAIN should be returned without retry: requests=%d rcode=%d", requests.Load(), dnsRCode(response))
	}
}

