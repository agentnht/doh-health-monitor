package main

import (
	"context"
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func startMode2TestUDPResolver(t *testing.T, handler func([]byte) []byte) (string, *atomic.Int32) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil { t.Fatal(err) }
	t.Cleanup(func() { _ = conn.Close() })
	count := &atomic.Int32{}
	go func() {
		buffer := make([]byte, maxDNSMessage+1)
		for {
			n, address, readErr := conn.ReadFromUDP(buffer)
			if readErr != nil { return }
			query := append([]byte(nil), buffer[:n]...)
			count.Add(1)
			response := handler(query)
			if len(response) > 0 { _, _ = conn.WriteToUDP(response, address) }
		}
	}()
	return conn.LocalAddr().String(), count
}

func mode2ResponseWithRCode(query []byte, rcode uint16) []byte {
	response := newDNSResponseHeader(query)
	_, _, questionEnd, err := parseQuestion(query)
	if err == nil && questionEnd <= len(query) { response = append(response, query[12:questionEnd]...) }
	flags := binary.BigEndian.Uint16(response[2:4])
	binary.BigEndian.PutUint16(response[2:4], (flags&0xfff0)|(rcode&0x000f))
	return response
}

func mode2SOAResponse(query []byte, rcode uint16, soaTTL, minimum uint32) []byte {
	response := mode2ResponseWithRCode(query, rcode)
	rdata := appendDNSName(nil, "ns.example")
	rdata = appendDNSName(rdata, "hostmaster.example")
	for _, value := range []uint32{1, 3600, 600, 86400, minimum} {
		var raw [4]byte
		binary.BigEndian.PutUint32(raw[:], value)
		rdata = append(rdata, raw[:]...)
	}
	response = append(response, 0xc0, 0x0c, 0, 6, 0, 1)
	var ttl [4]byte
	binary.BigEndian.PutUint32(ttl[:], soaTTL)
	response = append(response, ttl[:]...)
	response = append(response, byte(len(rdata)>>8), byte(len(rdata)))
	response = append(response, rdata...)
	binary.BigEndian.PutUint16(response[8:10], 1)
	return response
}

func TestMode2FallsBackAfterSERVFAIL(t *testing.T) {
	badAddress, badCount := startMode2TestUDPResolver(t, func(query []byte) []byte { return mode2ResponseWithRCode(query, 2) })
	goodAddress, goodCount := startMode2TestUDPResolver(t, func(query []byte) []byte { return testAResponse(query, 90) })
	snapshot := &Snapshot{
		cfg: Config{DNSQueryTimeoutSeconds: 3, DoHTimeoutSeconds: 3},
		resolverUpstreams: []*ResolverRuntime{
			{cfg: ResolverUpstream{ID: "bad", Type: "udp"}, address: badAddress},
			{cfg: ResolverUpstream{ID: "good", Type: "udp"}, address: goodAddress},
		},
	}
	response, selected, err := (&Runtime{}).queryResolverUpstreams(context.Background(), snapshot, makeDNSQuery("mode2.example", 1))
	if err != nil { t.Fatal(err) }
	if selected != "good" || dnsRCode(response) != 0 || dnsAnswerCount(response) != 1 {
		t.Fatalf("selected=%q rcode=%d answers=%d", selected, dnsRCode(response), dnsAnswerCount(response))
	}
	if badCount.Load() != 1 || goodCount.Load() != 1 { t.Fatalf("upstream calls: bad=%d good=%d", badCount.Load(), goodCount.Load()) }
}

func TestMode2DoesNotFallbackAfterNXDOMAIN(t *testing.T) {
	firstAddress, firstCount := startMode2TestUDPResolver(t, func(query []byte) []byte { return mode2ResponseWithRCode(query, 3) })
	secondAddress, secondCount := startMode2TestUDPResolver(t, func(query []byte) []byte { return testAResponse(query, 90) })
	snapshot := &Snapshot{
		cfg: Config{DNSQueryTimeoutSeconds: 3, DoHTimeoutSeconds: 3},
		resolverUpstreams: []*ResolverRuntime{
			{cfg: ResolverUpstream{ID: "first", Type: "udp"}, address: firstAddress},
			{cfg: ResolverUpstream{ID: "second", Type: "udp"}, address: secondAddress},
		},
	}
	response, selected, err := (&Runtime{}).queryResolverUpstreams(context.Background(), snapshot, makeDNSQuery("missing.example", 1))
	if err != nil { t.Fatal(err) }
	if selected != "first" || dnsRCode(response) != 3 { t.Fatalf("selected=%q rcode=%d, want first/NXDOMAIN", selected, dnsRCode(response)) }
	if firstCount.Load() != 1 || secondCount.Load() != 0 { t.Fatalf("NXDOMAIN was retried: first=%d second=%d", firstCount.Load(), secondCount.Load()) }
}

func TestMode2ResolverTransportFailureFallsThrough(t *testing.T) {
	closed, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil { t.Fatal(err) }
	unusedAddress := closed.LocalAddr().String()
	_ = closed.Close()
	goodAddress, goodCount := startMode2TestUDPResolver(t, func(query []byte) []byte { return testAResponse(query, 30) })
	snapshot := &Snapshot{
		cfg: Config{DNSQueryTimeoutSeconds: 3, DoHTimeoutSeconds: 3},
		resolverUpstreams: []*ResolverRuntime{
			{cfg: ResolverUpstream{ID: "offline", Type: "udp"}, address: unusedAddress},
			{cfg: ResolverUpstream{ID: "good", Type: "udp"}, address: goodAddress},
		},
	}
	response, selected, err := (&Runtime{}).queryResolverUpstreams(context.Background(), snapshot, makeDNSQuery("mode2.example", 1))
	if err != nil { t.Fatal(err) }
	if selected != "good" || dnsRCode(response) != 0 || goodCount.Load() != 1 { t.Fatalf("selected=%q rcode=%d good calls=%d", selected, dnsRCode(response), goodCount.Load()) }
}

func TestMode2BlackholeIsUncachedNoErrorNodata(t *testing.T) {
	query := makeDNSQuery("mode2.example", 1)
	snapshot := &Snapshot{
		cfg: Config{DNSMode: "resolver", Cache: CacheConfig{Enabled: true, MaxEntries: 10, MaxBytes: 4096, MaxTTL: 300}, DNSQueryTimeoutSeconds: 2},
		resolverGeneration: 99,
		resolverUpstreams: []*ResolverRuntime{},
	}
	runtime := &Runtime{cache: map[string]cacheItem{}}
	runtime.snapshot.Store(snapshot)
	response := runtime.resolverDNSResponse(query, snapshot)
	if dnsRCode(response) != 0 || dnsAnswerCount(response) != 0 || binary.BigEndian.Uint16(response[8:10]) != 0 {
		t.Fatalf("expected NOERROR/NODATA without SOA; rcode=%d answers=%d authority=%d", dnsRCode(response), dnsAnswerCount(response), binary.BigEndian.Uint16(response[8:10]))
	}
	if entries, _ := runtime.cacheStats(); entries != 0 { t.Fatalf("synthetic NODATA was cached: %d entries", entries) }
}

func TestMode2NODATAAndNXDOMAINRequireSOAForNegativeCache(t *testing.T) {
	query := makeDNSQuery("negative.example", 1)
	for _, test := range []struct { name string; rcode uint16 }{
		{name: "NXDOMAIN", rcode: 3}, {name: "NODATA", rcode: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			packet := mode2SOAResponse(query, test.rcode, 120, 45)
			if !prepareMode2ResponseForCache(packet, 300) { t.Fatal("valid SOA negative response should be cacheable") }
			ttl, ok := minResponseTTL(packet)
			if !ok || ttl != 45 { t.Fatalf("negative cache TTL=(%d,%t), want 45", ttl, ok) }
			soaTTL, ok := negativeSOATTL(packet)
			if !ok || soaTTL != 45 { t.Fatalf("SOA negative TTL=(%d,%t), want 45", soaTTL, ok) }
		})
	}
	withoutSOA := mode2ResponseWithRCode(query, 3)
	if prepareMode2ResponseForCache(withoutSOA, 300) { t.Fatal("negative response without SOA must not be cached") }
}

func TestMode2PositiveTTLIsCappedAndZeroTTLIsNotCached(t *testing.T) {
	query := makeDNSQuery("positive.example", 1)
	packet := testAResponse(query, 900)
	if !prepareMode2ResponseForCache(packet, 300) { t.Fatal("positive answer should be cacheable") }
	ttl, ok := minResponseTTL(packet)
	if !ok || ttl != 300 { t.Fatalf("positive TTL=(%d,%t), want 300", ttl, ok) }
	zeroTTL := testAResponse(query, 0)
	if prepareMode2ResponseForCache(zeroTTL, 300) { t.Fatal("TTL=0 answer must not be cached") }
}

func TestRRMeaningOfOPTIsNotARecordTTL(t *testing.T) {
	query := makeDNSQuery("edns.example", 1)
	packet := testAResponse(query, 120)
	binary.BigEndian.PutUint16(packet[10:12], 1)
	packet = append(packet, 0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 0, 0)
	positions, err := rrTTLPositions(packet)
	if err != nil { t.Fatal(err) }
	if len(positions) != 1 { t.Fatalf("TTL positions=%v; OPT must be excluded", positions) }
	if got := binary.BigEndian.Uint32(packet[positions[0]:positions[0]+4]); got != 120 { t.Fatalf("answer TTL=%d, want 120", got) }
}

func TestMode2CacheInvalidationIsNamespaceScoped(t *testing.T) {
	runtime := &Runtime{cache: map[string]cacheItem{}}
	config := CacheConfig{Enabled: true, MaxEntries: 10, MaxBytes: 4096, MaxTTL: 300}
	query := makeDNSQuery("cache.example", 1)
	mode1Key, mode2Key := "mode1:7:"+cacheKey(query), "mode2:11:"+cacheKey(query)
	runtime.cachePut(mode1Key, testAResponse(query, 60), config)
	runtime.cachePut(mode2Key, testAResponse(query, 60), config)
	runtime.clearResolverCache()
	runtime.cacheMu.Lock()
	_, mode1Exists := runtime.cache[mode1Key]
	_, mode2Exists := runtime.cache[mode2Key]
	runtime.cacheMu.Unlock()
	if !mode1Exists || mode2Exists { t.Fatalf("namespace invalidation: mode1=%t mode2=%t", mode1Exists, mode2Exists) }
}

func TestMode2OldSnapshotCannotRefillCacheAfterResolverReload(t *testing.T) {
	requestReceived := make(chan struct{})
	releaseResponse := make(chan struct{})
	address, _ := startMode2TestUDPResolver(t, func(query []byte) []byte {
		select { case <-requestReceived: default: close(requestReceived) }
		<-releaseResponse
		return testAResponse(query, 60)
	})
	oldSnapshot := &Snapshot{
		cfg: Config{DNSMode: "resolver", Cache: CacheConfig{Enabled: true, MaxEntries: 10, MaxBytes: 4096, MaxTTL: 300}, DNSQueryTimeoutSeconds: 3},
		resolverGeneration: 100,
		resolverUpstreams: []*ResolverRuntime{{cfg: ResolverUpstream{ID: "old", Type: "udp"}, address: address}},
	}
	newSnapshot := &Snapshot{cfg: Config{DNSMode: "resolver"}, resolverGeneration: 101}
	runtime := &Runtime{cache: map[string]cacheItem{}}
	runtime.snapshot.Store(oldSnapshot)
	query := makeDNSQuery("race.example", 1)
	done := make(chan []byte, 1)
	go func() { done <- runtime.resolverDNSResponse(query, oldSnapshot) }()
	select {
	case <-requestReceived:
	case <-time.After(2 * time.Second): t.Fatal("resolver did not receive the query")
	}
	runtime.snapshot.Store(newSnapshot)
	close(releaseResponse)
	select {
	case response := <-done:
		if dnsRCode(response) != 0 || dnsAnswerCount(response) != 1 { t.Fatalf("unexpected response: rcode=%d answers=%d", dnsRCode(response), dnsAnswerCount(response)) }
	case <-time.After(3 * time.Second): t.Fatal("resolver response did not complete")
	}
	if entries, _ := runtime.cacheStats(); entries != 0 { t.Fatalf("old snapshot repopulated cache: %d", entries) }
}

func TestSystemResolverLoopGuardOnlyRejectsPort53Listener(t *testing.T) {
	tests := []struct { name string; listeners []string; server string; want bool }{
		{name: "same address and port", listeners: []string{"127.0.0.1:53"}, server: "127.0.0.1", want: true},
		{name: "plugin default port 5355 is not a loop", listeners: []string{"127.0.0.1:5355"}, server: "127.0.0.1", want: false},
		{name: "different address", listeners: []string{"127.0.0.1:53"}, server: "8.8.8.8", want: false},
		{name: "wildcard listener", listeners: []string{"0.0.0.0:53"}, server: "127.0.0.1", want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := &systemDNSResolver{listenerAddresses: test.listeners}
			if got := resolver.pointsBackToPluginListener(test.server); got != test.want { t.Fatalf("pointsBackToPluginListener(%q)=%t, want %t", test.server, got, test.want) }
		})
	}
}


func TestMode2FirstResponseKeepsUpstreamTTLWhileCacheCapsCopy(t *testing.T) {
	address, _ := startMode2TestUDPResolver(t, func(query []byte) []byte {
		return testAResponse(query, 900)
	})
	snapshot := &Snapshot{
		cfg: Config{
			DNSMode: "resolver",
				Cache: CacheConfig{Enabled: true, MinTTL: 0, MaxTTL: 300, MaxEntries: 10, MaxBytes: 4096},
			DNSQueryTimeoutSeconds: 3,
		},
		resolverGeneration: 77,
		resolverUpstreams: []*ResolverRuntime{
			{cfg: ResolverUpstream{ID: "test", Type: "udp"}, address: address},
		},
	}
	runtime := &Runtime{cache: map[string]cacheItem{}}
	runtime.snapshot.Store(snapshot)
	query := makeDNSQuery("ttl.example", 1)

	firstResponse := runtime.resolverDNSResponse(query, snapshot)
	firstTTL, ok := minResponseTTL(firstResponse)
	if !ok || firstTTL != 900 {
		t.Fatalf("first upstream response TTL=(%d,%t), want 900", firstTTL, ok)
	}

	cacheKey := "mode2:77:" + cacheKey(query)
	cachedResponse, found := runtime.cacheGet(cacheKey, packetID(query))
	if !found {
		t.Fatal("expected capped response in resolver cache")
	}
	cachedTTL, ok := minResponseTTL(cachedResponse)
	if !ok || cachedTTL != 300 {
		t.Fatalf("cached response TTL=(%d,%t), want 300", cachedTTL, ok)
	}
}
