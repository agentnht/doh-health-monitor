package main

import (
	"encoding/binary"
	"sync/atomic"
	"testing"
	"time"
)

func TestCoalesceDNSResponseSharesWorkAndRestoresIDs(t *testing.T) {
	runtime := &Runtime{}
	query1 := makeDNSQuery("coalesce.example", 1)
	query2 := append([]byte(nil), query1...)
	binary.BigEndian.PutUint16(query1[:2], 0x1111)
	binary.BigEndian.PutUint16(query2[:2], 0x2222)

	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	run := func() []byte {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return testAResponse(query1, 60)
	}

	first := make(chan []byte, 1)
	go func() {
		first <- runtime.coalesceDNSResponse("mode1:1:test", query1, run)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("leader did not start")
	}

	second := make(chan []byte, 1)
	go func() {
		second <- runtime.coalesceDNSResponse("mode1:1:test", query2, run)
	}()

	deadline := time.Now().Add(time.Second)
	for {
		value, ok := runtime.dnsFlights.Load("mode1:1:test")
		if ok && runtime.resilience.dnsCoalesced.Load() == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("follower did not join in-flight request")
		}
		time.Sleep(time.Millisecond)
	}
	close(release)

	got1 := <-first
	got2 := <-second
	if calls.Load() != 1 {
		t.Fatalf("upstream operation called %d times, want 1", calls.Load())
	}
	if got := runtime.resilience.dnsCoalesced.Load(); got != 1 {
		t.Fatalf("coalesced request counter = %d, want 1", got)
	}
	if got := binary.BigEndian.Uint16(got1[:2]); got != 0x1111 {
		t.Fatalf("leader response ID = %#x, want %#x", got, 0x1111)
	}
	if got := binary.BigEndian.Uint16(got2[:2]); got != 0x2222 {
		t.Fatalf("follower response ID = %#x, want %#x", got, 0x2222)
	}
}

func TestCoalesceDNSResponseRecoversPanicsAndCleansFlight(t *testing.T) {
	runtime := &Runtime{}
	query := makeDNSQuery("panic.example.test", 1)
	response := runtime.coalesceDNSResponse("panic-flight", query, func() []byte {
		panic("synthetic upstream panic")
	})
	if dnsRCode(response) != 2 {
		t.Fatalf("panic response rcode=%d, want SERVFAIL (2)", dnsRCode(response))
	}
	if _, exists := runtime.dnsFlights.Load("panic-flight"); exists {
		t.Fatal("in-flight entry was not removed after panic")
	}
}
