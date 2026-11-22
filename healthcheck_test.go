package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProbeDaemonHealth(t *testing.T) {
	t.Run("healthy response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/healthz" {
				t.Errorf("request=%s %s, want GET /healthz", r.Method, r.URL.Path)
			}
			_, _ = w.Write([]byte("ok\n"))
		}))
		defer server.Close()

		_, address, err := net.SplitHostPort(server.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		host, _, _ := net.SplitHostPort(server.Listener.Addr().String())
		client := &http.Client{Timeout: daemonHealthTimeout}
		if err := probeDaemonHealth(client, net.JoinHostPort(host, address)); err != nil {
			t.Fatalf("healthy endpoint rejected: %v", err)
		}
	})

	t.Run("unhealthy response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
		}))
		defer server.Close()

		client := &http.Client{Timeout: daemonHealthTimeout}
		if err := probeDaemonHealth(client, server.Listener.Addr().String()); err == nil {
			t.Fatal("unhealthy endpoint accepted")
		}
	})

	if err := probeDaemonHealth(&http.Client{Timeout: daemonHealthTimeout}, "not-a-listener"); err == nil {
		t.Fatal("invalid listener address accepted")
	}
}
