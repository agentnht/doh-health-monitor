package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"lucx-doh-health-monitor/internal/activedoh"
)

func TestSendActiveDoHMetricsRecordHedgeWinAndLatency(t *testing.T) {
	query := makeDNSQuery("hedge-metrics.example.test", 1)
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		attempt := requests.Add(1)
		if attempt == 1 {
			time.Sleep(100 * time.Millisecond)
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(testAResponse(query, 30))
	}))
	defer server.Close()

	candidate := activedoh.Candidate{
		ServerID: "selected", URL: server.URL + "/dns-query", Hostname: "127.0.0.1",
		IPv4: []string{"1.1.1.1", "8.8.8.8"}, ResolvedAt: time.Now(),
	}
	var extraAttempts, hedgeWins, qualityRejections atomic.Uint64
	var latencySamples atomic.Uint64
	response, err := sendActiveDoHWithClientFactoryAndMetrics(
		context.Background(), candidate, query, time.Second,
		func(string, string, time.Duration) *http.Client { return server.Client() },
		&activeDoHForwardMetrics{
			extraAttempts: &extraAttempts, hedgeWins: &hedgeWins,
			qualityRejections: &qualityRejections, hedgeDelay: 10 * time.Millisecond,
			recordLatency: func(string, string, time.Duration) { latencySamples.Add(1) },
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if dnsRCode(response) != 0 || dnsAnswerCount(response) != 1 {
		t.Fatalf("response rcode=%d answers=%d", dnsRCode(response), dnsAnswerCount(response))
	}
	if got := extraAttempts.Load(); got != 1 {
		t.Fatalf("extra attempts=%d, want 1", got)
	}
	if got := hedgeWins.Load(); got != 1 {
		t.Fatalf("hedge wins=%d, want 1", got)
	}
	deadline := time.Now().Add(time.Second)
	for latencySamples.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := latencySamples.Load(); got != 1 {
		t.Fatalf("latency samples=%d, want only the completed winning attempt", got)
	}
	if got := qualityRejections.Load(); got != 0 {
		t.Fatalf("quality rejections=%d, want 0", got)
	}
}
