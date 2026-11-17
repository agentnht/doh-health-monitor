package main

import (
	"encoding/binary"
	"testing"
	"time"
)

func testDNSQuestion() []byte {
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[0:2], 0x1234)
	binary.BigEndian.PutUint16(packet[2:4], 0x0100)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	packet = append(packet, 1, 'a', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1)
	return packet
}

func TestHandleDNSRecoversUnexpectedPanic(t *testing.T) {
	rt := &Runtime{dnsSem: make(chan struct{}, 1)}
	response := rt.handleDNS(testDNSQuestion())
	if len(response) < 12 || dnsRCode(response) != 2 {
		t.Fatalf("panic response=%x, want DNS SERVFAIL", response)
	}
	if got := rt.failures.Load(); got != 1 {
		t.Fatalf("failure counter=%d, want 1", got)
	}
}

func TestCacheDoResolverPanicReleasesFlightAndWaiters(t *testing.T) {
	rt := &Runtime{cache: make(map[string]cacheItem), cacheFlights: make(map[string]*cacheFlight)}
	started := make(chan struct{})
	release := make(chan struct{})
	leaderResult := make(chan error, 1)
	go func() {
		_, err := rt.cacheDo("panic-key", 1, func() ([]byte, error) {
			close(started)
			<-release
			panic("synthetic resolver panic")
		})
		leaderResult <- err
	}()
	<-started

	followerResult := make(chan error, 1)
	go func() {
		_, err := rt.cacheDo("panic-key", 2, func() ([]byte, error) {
			t.Error("follower unexpectedly became resolver")
			return nil, nil
		})
		followerResult <- err
	}()

	deadline := time.Now().Add(time.Second)
	for {
		rt.cacheMu.Lock()
		flight := rt.cacheFlights["panic-key"]
		joined := flight != nil && flight.waiters == 1
		rt.cacheMu.Unlock()
		if joined {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("follower did not join cache flight")
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	for name, result := range map[string]<-chan error{"leader": leaderResult, "follower": followerResult} {
		select {
		case err := <-result:
			if err == nil {
				t.Errorf("%s returned nil error after resolver panic", name)
			}
		case <-time.After(time.Second):
			t.Errorf("%s remained blocked after resolver panic", name)
		}
	}
	rt.cacheMu.Lock()
	defer rt.cacheMu.Unlock()
	if _, exists := rt.cacheFlights["panic-key"]; exists {
		t.Fatal("panicked cache flight was not removed")
	}
}

func TestValidateConfigRejectsInvalidHealthCheckDomain(t *testing.T) {
	cfg := defaultConfig()
	cfg.Groups[0].Checks = []Check{{Domain: "bad domain"}}
	if err := validateConfig(cfg); err == nil {
		t.Fatal("invalid health-check domain must be rejected")
	}
}
