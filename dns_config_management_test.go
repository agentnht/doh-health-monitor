package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveDNSModeConfigBacksUpAndPreservesResolverOrder(t *testing.T) {
	dir := newTestWebUIData(t)
	configPath := filepath.Join(dir, "config.json")
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	resolvers := []ResolverUpstream{
		{ID: "primary", Name: "Primary UDP", Type: "udp", Address: "9.9.9.9"},
		{ID: "fallback", Name: "Fallback system", Type: "system"},
		{ID: "secure", Name: "Secure DoH", Type: "doh", URL: "https://dns.example/dns-query", BootstrapIPs: []string{"192.0.2.53"}},
	}
	got, err := saveDNSModeConfig(dir, "resolver", resolvers)
	if err != nil {
		t.Fatalf("save resolver config: %v", err)
	}
	if got.DNSMode != "resolver" || len(got.ResolverUpstreams) != len(resolvers) {
		t.Fatalf("saved config mode/upstreams = %q/%d", got.DNSMode, len(got.ResolverUpstreams))
	}
	for i := range resolvers {
		if got.ResolverUpstreams[i] != resolvers[i] {
			t.Fatalf("resolver order/config at %d = %+v, want %+v", i, got.ResolverUpstreams[i], resolvers[i])
		}
	}
	backup, err := os.ReadFile(configPath + ".bak")
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if !bytes.Equal(backup, before) {
		t.Fatal("config.json.bak does not contain the exact pre-change config")
	}
	info, err := os.Stat(configPath + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("backup permissions=%#o, want 0600", info.Mode().Perm())
	}
}

func TestSaveDNSModeConfigRejectsInvalidInputWithoutChangingConfig(t *testing.T) {
	dir := newTestWebUIData(t)
	configPath := filepath.Join(dir, "config.json")
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = saveDNSModeConfig(dir, "resolver", []ResolverUpstream{
		{ID: "bad", Type: "udp", Address: "dns.example:53"},
	})
	if err == nil {
		t.Fatal("hostname-based plain DNS resolver should be rejected")
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("invalid update changed config.json")
	}
	if _, err := os.Lstat(configPath + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("invalid update unexpectedly created backup: %v", err)
	}
}

func TestResolverModeRequiresAtLeastOneUpstream(t *testing.T) {
	cfg := defaultConfig()
	cfg.DNSMode = "resolver"
	cfg.ResolverUpstreams = []ResolverUpstream{}
	if err := validateConfig(cfg); err == nil {
		t.Fatal("resolver mode without upstreams should be rejected")
	}
}
