package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func autoDNSConfig() Config {
	cfg := defaultConfig()
	cfg.DNSPortMode = "auto"
	cfg.DNSListenUDP = "127.0.0.1:0"
	cfg.DNSListenTCP = "127.0.0.1:0"
	return cfg
}

func TestAutoDNSListenerBindsAndPersistsMatchingPort(t *testing.T) {
	dataDir := t.TempDir()
	cfg := autoDNSConfig()
	if err := validateConfig(cfg); err != nil {
		t.Fatal(err)
	}
	udpConn, tcpListener, udpAddress, tcpAddress, err := bindDNSListeners(cfg, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	udpHost, udpPort, err := net.SplitHostPort(udpAddress)
	if err != nil {
		t.Fatal(err)
	}
	tcpHost, tcpPort, err := net.SplitHostPort(tcpAddress)
	if err != nil {
		t.Fatal(err)
	}
	if udpHost != tcpHost || udpPort != tcpPort || udpPort == "0" {
		t.Fatalf("UDP/TCP listeners did not share one assigned port: udp=%s tcp=%s", udpAddress, tcpAddress)
	}
	selectedPort, err := strconv.Atoi(udpPort)
	if err != nil || selectedPort < 1 {
		t.Fatalf("invalid selected port %q: %v", udpPort, err)
	}
	_ = udpConn.Close()
	_ = tcpListener.Close()

	stateData, err := os.ReadFile(filepath.Join(dataDir, "dns-listener.json"))
	if err != nil {
		t.Fatal(err)
	}
	var saved dnsListenerState
	if err := json.Unmarshal(stateData, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Port != selectedPort || saved.Host != "127.0.0.1" {
		t.Fatalf("saved listener state=%+v; expected port %d on 127.0.0.1", saved, selectedPort)
	}
	udpConn, tcpListener, udpAddress, tcpAddress, err = bindDNSListeners(cfg, dataDir)
	if err != nil {
		t.Fatalf("restart should rebind persisted endpoint: %v", err)
	}
	defer udpConn.Close()
	defer tcpListener.Close()
	want := net.JoinHostPort(saved.Host, strconv.Itoa(saved.Port))
	if udpAddress != want || tcpAddress != want {
		t.Fatalf("restart changed the saved endpoint: udp=%s tcp=%s want=%s", udpAddress, tcpAddress, want)
	}
}

func TestAutoDNSListenerDoesNotSilentlyChangeBusyPersistedPort(t *testing.T) {
	dataDir := t.TempDir()
	tcpProbe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpProbe.Close()
	host, portText, err := net.SplitHostPort(tcpProbe.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(dnsListenerState{Version: dnsListenerStateVersion, Host: host, Port: port})
	if err := os.WriteFile(filepath.Join(dataDir, "dns-listener.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	_, _, _, _, err = bindDNSListeners(autoDNSConfig(), dataDir)
	if err == nil || !strings.Contains(err.Error(), "refusing to choose a different port") {
		t.Fatalf("expected explicit persisted-port conflict, got %v", err)
	}
}

func TestAutoDNSListenerRequiresMatchingLoopbackPortZero(t *testing.T) {
	cfg := autoDNSConfig()
	cfg.DNSListenTCP = "127.0.0.1:5355"
	if err := validateConfig(cfg); err == nil {
		t.Fatal("expected mismatched auto-mode listener endpoints to be rejected")
	}
	cfg = autoDNSConfig()
	cfg.DNSListenUDP = "0.0.0.0:0"
	if err := validateConfig(cfg); err == nil {
		t.Fatal("expected non-loopback auto-mode host to be rejected")
	}
	cfg = autoDNSConfig()
	cfg.DNSListenUDP = "[::1]:0"
	cfg.DNSListenTCP = "[::1]:0"
	if err := validateConfig(cfg); err == nil {
		t.Fatal("expected IPv6 loopback auto mode to be rejected until the Xray verifier supports it")
	}
}

func TestLegacyConfigDefaultsDNSPortModeToFixed(t *testing.T) {
	cfg := normalizeDNSPortMode(Config{})
	if cfg.DNSPortMode != "fixed" {
		t.Fatalf("legacy config mode=%q, want fixed", cfg.DNSPortMode)
	}
}

func TestEffectiveDNSListenerAddressesUsesPersistedAutoPort(t *testing.T) {
	dataDir := t.TempDir()
	state := dnsListenerState{Version: dnsListenerStateVersion, Host: "127.0.0.1", Port: 19453}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "dns-listener.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	udp, tcp, err := effectiveDNSListenerAddresses(dataDir, autoDNSConfig())
	if err != nil {
		t.Fatal(err)
	}
	want := "127.0.0.1:19453"
	if udp != want || tcp != want {
		t.Fatalf("effective listeners udp=%q tcp=%q, want %q", udp, tcp, want)
	}
}

func TestEffectiveDNSListenerAddressesRejectsMissingAutoPortState(t *testing.T) {
	if _, _, err := effectiveDNSListenerAddresses(t.TempDir(), autoDNSConfig()); err == nil {
		t.Fatal("expected a missing persisted listener state to be reported")
	}
}
