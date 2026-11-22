package main

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestServeUDPAndReloadLoopKeepLiveListener(t *testing.T) {
	dataDir := t.TempDir()
	if err := initializeConfigSourceFiles(dataDir); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dataDir, "config.json")
	dohPath := filepath.Join(dataDir, "doh-servers.txt")
	checksPath := filepath.Join(dataDir, "tst-domen.txt")
	hostsPath := filepath.Join(dataDir, localHostsSourceFile)

	initialHosts := []byte(localHostsSourceHeader + "\nalpha.test;192.0.2.10;\n")
	if err := writeAtomicFile(hostsPath, initialHosts, 0600); err != nil {
		t.Fatal(err)
	}
	sources, err := readConfigSources(dohPath, checksPath, hostsPath)
	if err != nil {
		t.Fatal(err)
	}

	cfg := defaultConfig()
	cfg.ReloadSecs = 1
	cfg.DNSQueryTimeoutSeconds = 2
	cfg, err = applyConfigSources(cfg, sources)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeConfigAtomic(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	snapshot, err := buildSnapshot(cfg, sources.DoHURLs)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(configPath); err == nil {
		snapshot.configMod = info.ModTime()
	} else {
		t.Fatal(err)
	}

	runtime := &Runtime{
		dataDir:            dataDir,
		configPath:         configPath,
		dohPath:            dohPath,
		checksPath:         checksPath,
		sourceHashes:       sources.Checksums,
		healthCheckTrigger: make(chan struct{}, 1),
		activeDoHTrigger:   make(chan struct{}, 1),
		dnsSem:             make(chan struct{}, cfg.DNSMaxConcurrent),
		health:             make(map[string]map[string]HealthEntry),
		active:             make(map[string]string),
		cache:              make(map[string]cacheItem),
		lastGemini:         make(map[string]time.Time),
	}
	runtime.snapshot.Store(snapshot)
	runtime.initHealth(snapshot)

	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	serverAddr := *server.LocalAddr().(*net.UDPAddr)

	ctx, cancel := context.WithCancel(context.Background())
	udpDone := make(chan struct{})
	reloadDone := make(chan struct{})
	go func() {
		defer close(udpDone)
		runtime.serveUDP(ctx, server)
	}()
	go func() {
		defer close(reloadDone)
		runtime.reloadLoop(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		select {
		case <-udpDone:
		case <-time.After(2 * time.Second):
			t.Error("serveUDP did not stop after cancellation")
		}
		select {
		case <-reloadDone:
		case <-time.After(2 * time.Second):
			t.Error("reloadLoop did not stop after cancellation")
		}
	})

	initialResponse := exchangeTestUDP(t, serverAddr, makeDNSQuery("alpha.test", 1))
	if got := firstTestAAnswer(initialResponse); !got.Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf("initial live UDP answer=%v, want 192.0.2.10", got)
	}

	reloadedConfig, err := loadConfigNoCreate(configPath)
	if err != nil {
		t.Fatal(err)
	}
	reloadedConfig.Health.TimeoutSeconds++
	if err := writeConfigAtomic(configPath, reloadedConfig); err != nil {
		t.Fatal(err)
	}
	reloadedHosts := []byte(localHostsSourceHeader + "\nalpha.test;192.0.2.10;\nbeta.test;192.0.2.20;\n")
	if err := writeAtomicFile(hostsPath, reloadedHosts, 0600); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		current := runtime.currentSnapshot()
		if current != nil && current.localHosts["beta.test"].IPv4 != nil &&
			current.cfg.Health.TimeoutSeconds == reloadedConfig.Health.TimeoutSeconds {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	current := runtime.currentSnapshot()
	if current == nil || len(current.localHosts["beta.test"].IPv4) != 1 ||
		current.cfg.Health.TimeoutSeconds != reloadedConfig.Health.TimeoutSeconds {
		t.Fatalf("reload did not apply config and local hosts: snapshot=%+v", current)
	}

	// The same UDP socket remains bound throughout the atomic snapshot reload.
	if got := server.LocalAddr().(*net.UDPAddr).Port; got != serverAddr.Port {
		t.Fatalf("live UDP listener port changed from %d to %d", serverAddr.Port, got)
	}
	alphaResponse := exchangeTestUDP(t, serverAddr, makeDNSQuery("alpha.test", 1))
	if got := firstTestAAnswer(alphaResponse); !got.Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf("existing name after reload=%v, want 192.0.2.10", got)
	}
	betaResponse := exchangeTestUDP(t, serverAddr, makeDNSQuery("beta.test", 1))
	if got := firstTestAAnswer(betaResponse); !got.Equal(net.ParseIP("192.0.2.20")) {
		t.Fatalf("new name on existing live listener=%v, want 192.0.2.20", got)
	}

	runtime.mu.Lock()
	lastReload := runtime.lastReload
	runtime.mu.Unlock()
	if lastReload.IsZero() {
		t.Fatal("reloadLoop did not record the successful reload")
	}
}

func exchangeTestUDP(t *testing.T, address net.UDPAddr, query []byte) []byte {
	t.Helper()
	client, err := net.DialUDP("udp", nil, &address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(query); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 2048)
	n, err := client.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), buffer[:n]...)
}

func firstTestAAnswer(response []byte) net.IP {
	if len(response) < 12 || dnsRCode(response) != 0 {
		return nil
	}
	_, _, offset, err := parseQuestion(response)
	if err != nil {
		return nil
	}
	answerCount := int(binary.BigEndian.Uint16(response[6:8]))
	for i := 0; i < answerCount; i++ {
		_, nameEnd, err := decodeName(response, offset)
		if err != nil || nameEnd+10 > len(response) {
			return nil
		}
		recordType := binary.BigEndian.Uint16(response[nameEnd : nameEnd+2])
		recordClass := binary.BigEndian.Uint16(response[nameEnd+2 : nameEnd+4])
		recordLength := int(binary.BigEndian.Uint16(response[nameEnd+8 : nameEnd+10]))
		dataStart := nameEnd + 10
		dataEnd := dataStart + recordLength
		if dataEnd > len(response) {
			return nil
		}
		if recordType == 1 && recordClass == 1 && recordLength == net.IPv4len {
			return append(net.IP(nil), response[dataStart:dataEnd]...)
		}
		offset = dataEnd
	}
	return nil
}
