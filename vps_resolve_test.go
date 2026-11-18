package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVPSResolveRequiresHTTP2(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	upstream := &UpstreamRuntime{
		cfg:    Upstream{ID: "vps-resolve", URL: server.URL},
		client: server.Client(),
	}
	_, err := sendDoH(context.Background(), upstream, []byte("dns-query"))
	if err == nil || !strings.Contains(err.Error(), "requires HTTP/2") {
		t.Fatalf("expected HTTP/2 requirement error, got %v", err)
	}
}

func TestNewVPSResolveUpstreamUsesDedicatedQuad9Endpoint(t *testing.T) {
	upstream, err := newVPSResolveUpstream(5e9)
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.client.CloseIdleConnections()
	if upstream.cfg.ID != "vps-resolve" || upstream.cfg.URL != "https://dns.quad9.net/dns-query" {
		t.Fatalf("unexpected dedicated upstream: %+v", upstream.cfg)
	}
	transport, ok := upstream.client.Transport.(*http.Transport)
	if !ok || !transport.ForceAttemptHTTP2 {
		t.Fatal("vps-resolve transport must attempt HTTP/2")
	}
}
