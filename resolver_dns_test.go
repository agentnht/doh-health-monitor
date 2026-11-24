package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func startMode2TestUDPResolver(t *testing.T, handler func([]byte) []byte) (string, *atomic.Int32) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	count := &atomic.Int32{}
	go func() {
		buffer := make([]byte, maxDNSMessage+1)
		for {
			n, address, readErr := conn.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			query := append([]byte(nil), buffer[:n]...)
			count.Add(1)
			response := handler(query)
			if len(response) > 0 {
				_, _ = conn.WriteToUDP(response, address)
			}
		}
	}()
	return conn.LocalAddr().String(), count
}

func mode2ResponseWithRCode(query []byte, rcode uint16) []byte {
	response := newDNSResponseHeader(query)
	_, _, questionEnd, err := parseQuestion(query)
	if err == nil && questionEnd <= len(query) {
		response = append(response, query[12:questionEnd]...)
	}
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

func mode2CNAMEAndSOAResponse(query []byte, cnameTTL, soaTTL, minimum uint32) []byte {
	response := mode2ResponseWithRCode(query, 0)

	cnameTarget := appendDNSName(nil, "target.example")
	response = append(response, 0xc0, 0x0c, 0, 5, 0, 1) // CNAME, IN
	var cnameTTLBytes [4]byte
	binary.BigEndian.PutUint32(cnameTTLBytes[:], cnameTTL)
	response = append(response, cnameTTLBytes[:]...)
	response = append(response, byte(len(cnameTarget)>>8), byte(len(cnameTarget)))
	response = append(response, cnameTarget...)

	soaOwner := appendDNSName(nil, "example")
	response = append(response, soaOwner...)
	response = append(response, 0, 6, 0, 1) // SOA, IN
	var soaTTLBytes [4]byte
	binary.BigEndian.PutUint32(soaTTLBytes[:], soaTTL)
	response = append(response, soaTTLBytes[:]...)
	soaData := appendDNSName(nil, "ns.example")
	soaData = appendDNSName(soaData, "hostmaster.example")
	for _, value := range []uint32{1, 3600, 600, 86400, minimum} {
		var raw [4]byte
		binary.BigEndian.PutUint32(raw[:], value)
		soaData = append(soaData, raw[:]...)
	}
	response = append(response, byte(len(soaData)>>8), byte(len(soaData)))
	response = append(response, soaData...)

	binary.BigEndian.PutUint16(response[6:8], 1)  // one CNAME answer
	binary.BigEndian.PutUint16(response[8:10], 1) // one SOA authority RR
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
	if err != nil {
		t.Fatal(err)
	}
	if selected != "good" || dnsRCode(response) != 0 || dnsAnswerCount(response) != 1 {
		t.Fatalf("selected=%q rcode=%d answers=%d", selected, dnsRCode(response), dnsAnswerCount(response))
	}
	if badCount.Load() != 1 || goodCount.Load() != 1 {
		t.Fatalf("upstream calls: bad=%d good=%d", badCount.Load(), goodCount.Load())
	}
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
	if err != nil {
		t.Fatal(err)
	}
	if selected != "first" || dnsRCode(response) != 3 {
		t.Fatalf("selected=%q rcode=%d, want first/NXDOMAIN", selected, dnsRCode(response))
	}
	if firstCount.Load() != 1 || secondCount.Load() != 0 {
		t.Fatalf("NXDOMAIN was retried: first=%d second=%d", firstCount.Load(), secondCount.Load())
	}
}

func TestMode2ResolverTransportFailureFallsThrough(t *testing.T) {
	closed, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	if selected != "good" || dnsRCode(response) != 0 || goodCount.Load() != 1 {
		t.Fatalf("selected=%q rcode=%d good calls=%d", selected, dnsRCode(response), goodCount.Load())
	}
}

func TestMode2UpstreamFailureReturnsUncachedSERVFAIL(t *testing.T) {
	query := makeDNSQuery("mode2.example", 1)
	snapshot := &Snapshot{
		cfg:                Config{DNSMode: "resolver", Cache: CacheConfig{Enabled: true, MaxEntries: 10, MaxBytes: 4096, MaxTTL: 300}, DNSQueryTimeoutSeconds: 2},
		resolverGeneration: 99,
		resolverUpstreams:  []*ResolverRuntime{},
	}
	runtime := &Runtime{cache: map[string]cacheItem{}}
	runtime.snapshot.Store(snapshot)
	response := runtime.resolverDNSResponse(query, snapshot)
	if dnsRCode(response) != 2 || dnsAnswerCount(response) != 0 || binary.BigEndian.Uint16(response[8:10]) != 0 {
		t.Fatalf("expected SERVFAIL without answer/authority records; rcode=%d answers=%d authority=%d", dnsRCode(response), dnsAnswerCount(response), binary.BigEndian.Uint16(response[8:10]))
	}
	if entries, _ := runtime.cacheStats(); entries != 0 {
		t.Fatalf("synthetic SERVFAIL was cached: %d entries", entries)
	}
}

func TestMode2NODATAAndNXDOMAINRequireSOAForNegativeCache(t *testing.T) {
	query := makeDNSQuery("negative.example", 1)
	for _, test := range []struct {
		name  string
		rcode uint16
	}{
		{name: "NXDOMAIN", rcode: 3}, {name: "NODATA", rcode: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			packet := mode2SOAResponse(query, test.rcode, 120, 45)
			if !prepareMode2ResponseForCache(packet, 300) {
				t.Fatal("valid SOA negative response should be cacheable")
			}
			ttl, ok := minResponseTTL(packet)
			if !ok || ttl != 45 {
				t.Fatalf("negative cache TTL=(%d,%t), want 45", ttl, ok)
			}
			soaTTL, ok := negativeSOATTL(packet)
			if !ok || soaTTL != 45 {
				t.Fatalf("SOA negative TTL=(%d,%t), want 45", soaTTL, ok)
			}
		})
	}
	withoutSOA := mode2ResponseWithRCode(query, 3)
	if prepareMode2ResponseForCache(withoutSOA, 300) {
		t.Fatal("negative response without SOA must not be cached")
	}
}

func TestMode2PositiveTTLIsCappedAndZeroTTLIsNotCached(t *testing.T) {
	query := makeDNSQuery("positive.example", 1)
	packet := testAResponse(query, 900)
	if !prepareMode2ResponseForCache(packet, 300) {
		t.Fatal("positive answer should be cacheable")
	}
	ttl, ok := minResponseTTL(packet)
	if !ok || ttl != 300 {
		t.Fatalf("positive TTL=(%d,%t), want 300", ttl, ok)
	}
	zeroTTL := testAResponse(query, 0)
	if prepareMode2ResponseForCache(zeroTTL, 300) {
		t.Fatal("TTL=0 answer must not be cached")
	}
}

func TestRRMeaningOfOPTIsNotARecordTTL(t *testing.T) {
	query := makeDNSQuery("edns.example", 1)
	packet := testAResponse(query, 120)
	binary.BigEndian.PutUint16(packet[10:12], 1)
	packet = append(packet, 0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 0, 0)
	positions, err := rrTTLPositions(packet)
	if err != nil {
		t.Fatal(err)
	}
	if len(positions) != 1 {
		t.Fatalf("TTL positions=%v; OPT must be excluded", positions)
	}
	if got := binary.BigEndian.Uint32(packet[positions[0] : positions[0]+4]); got != 120 {
		t.Fatalf("answer TTL=%d, want 120", got)
	}
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
	if !mode1Exists || mode2Exists {
		t.Fatalf("namespace invalidation: mode1=%t mode2=%t", mode1Exists, mode2Exists)
	}
}

func TestMode2OldSnapshotCannotRefillCacheAfterResolverReload(t *testing.T) {
	requestReceived := make(chan struct{})
	releaseResponse := make(chan struct{})
	address, _ := startMode2TestUDPResolver(t, func(query []byte) []byte {
		select {
		case <-requestReceived:
		default:
			close(requestReceived)
		}
		<-releaseResponse
		return testAResponse(query, 60)
	})
	oldSnapshot := &Snapshot{
		cfg:                Config{DNSMode: "resolver", Cache: CacheConfig{Enabled: true, MaxEntries: 10, MaxBytes: 4096, MaxTTL: 300}, DNSQueryTimeoutSeconds: 3},
		resolverGeneration: 100,
		resolverUpstreams:  []*ResolverRuntime{{cfg: ResolverUpstream{ID: "old", Type: "udp"}, address: address}},
	}
	newSnapshot := &Snapshot{cfg: Config{DNSMode: "resolver"}, resolverGeneration: 101}
	runtime := &Runtime{cache: map[string]cacheItem{}}
	runtime.snapshot.Store(oldSnapshot)
	query := makeDNSQuery("race.example", 1)
	done := make(chan []byte, 1)
	go func() { done <- runtime.resolverDNSResponse(query, oldSnapshot) }()
	select {
	case <-requestReceived:
	case <-time.After(2 * time.Second):
		t.Fatal("resolver did not receive the query")
	}
	runtime.snapshot.Store(newSnapshot)
	close(releaseResponse)
	select {
	case response := <-done:
		if dnsRCode(response) != 0 || dnsAnswerCount(response) != 1 {
			t.Fatalf("unexpected response: rcode=%d answers=%d", dnsRCode(response), dnsAnswerCount(response))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("resolver response did not complete")
	}
	if entries, _ := runtime.cacheStats(); entries != 0 {
		t.Fatalf("old snapshot repopulated cache: %d", entries)
	}
}

func TestSystemResolverLoopGuardOnlyRejectsPort53Listener(t *testing.T) {
	tests := []struct {
		name      string
		listeners []string
		server    string
		want      bool
	}{
		{name: "same address and port", listeners: []string{"127.0.0.1:53"}, server: "127.0.0.1", want: true},
		{name: "plugin default port 5355 is not a loop", listeners: []string{"127.0.0.1:5355"}, server: "127.0.0.1", want: false},
		{name: "different address", listeners: []string{"127.0.0.1:53"}, server: "8.8.8.8", want: false},
		{name: "wildcard listener", listeners: []string{"0.0.0.0:53"}, server: "127.0.0.1", want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := &systemDNSResolver{listenerAddresses: test.listeners}
			if got := resolver.pointsBackToPluginListener(test.server); got != test.want {
				t.Fatalf("pointsBackToPluginListener(%q)=%t, want %t", test.server, got, test.want)
			}
		})
	}
}

func TestMode2FirstResponseKeepsUpstreamTTLWhileCacheCapsCopy(t *testing.T) {
	address, _ := startMode2TestUDPResolver(t, func(query []byte) []byte {
		return testAResponse(query, 900)
	})
	snapshot := &Snapshot{
		cfg: Config{
			DNSMode:                "resolver",
			Cache:                  CacheConfig{Enabled: true, MinTTL: 0, MaxTTL: 300, MaxEntries: 10, MaxBytes: 4096},
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
	cachedResponse, found := runtime.cacheGet(cacheKey, packetID(query), 0)
	if !found {
		t.Fatal("expected capped response in resolver cache")
	}
	cachedTTL, ok := minResponseTTL(cachedResponse)
	if !ok || cachedTTL != 300 {
		t.Fatalf("cached response TTL=(%d,%t), want 300", cachedTTL, ok)
	}
}

func TestMode2CNAMEToNODATAUsesSOANegativeTTL(t *testing.T) {
	query := makeDNSQuery("alias.example", 1)
	withoutSOA := mode2CNAMEAndSOAResponse(query, 900, 120, 45)
	cnameRecords, err := dnsRRsInSection(withoutSOA, 0)
	if err != nil || len(cnameRecords) != 1 {
		t.Fatalf("could not inspect CNAME-only response: records=%d err=%v", len(cnameRecords), err)
	}
	withoutSOA = withoutSOA[:cnameRecords[0].end]
	binary.BigEndian.PutUint16(withoutSOA[8:10], 0)
	if prepareMode2ResponseForCache(withoutSOA, 300) {
		t.Fatal("CNAME-only NODATA without SOA must not be cached")
	}

	packet := mode2CNAMEAndSOAResponse(query, 900, 120, 45)
	if !prepareMode2ResponseForCache(packet, 300) {
		t.Fatal("CNAME followed by SOA NODATA should be cacheable")
	}
	answers, err := dnsRRsInSection(packet, 0)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := dnsRRsInSection(packet, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(answers) != 1 || answers[0].typeCode != 5 {
		t.Fatalf("expected one CNAME answer, got %+v", answers)
	}
	if got := binary.BigEndian.Uint32(packet[answers[0].ttlOffset : answers[0].ttlOffset+4]); got != 300 {
		t.Fatalf("cached CNAME TTL=%d, want max-cache cap 300", got)
	}
	if len(authority) != 1 || authority[0].typeCode != 6 {
		t.Fatalf("expected one SOA authority RR, got %+v", authority)
	}
	soaTTL := binary.BigEndian.Uint32(packet[authority[0].ttlOffset : authority[0].ttlOffset+4])
	if soaTTL != 45 {
		t.Fatalf("cached SOA TTL=%d, want min(SOA TTL 120, SOA.MINIMUM 45)", soaTTL)
	}
	if ttl, ok := minResponseTTL(packet); !ok || ttl != 45 {
		t.Fatalf("cached response TTL=(%d,%t), want 45", ttl, ok)
	}
}

func TestMode2CNAMEToNODATAPreservesFirstUpstreamResponse(t *testing.T) {
	address, _ := startMode2TestUDPResolver(t, func(query []byte) []byte {
		return mode2CNAMEAndSOAResponse(query, 900, 120, 45)
	})
	snapshot := &Snapshot{
		cfg: Config{
			DNSMode:                "resolver",
			Cache:                  CacheConfig{Enabled: true, MinTTL: 0, MaxTTL: 300, MaxEntries: 10, MaxBytes: 4096},
			DNSQueryTimeoutSeconds: 3,
		},
		resolverGeneration: 78,
		resolverUpstreams: []*ResolverRuntime{
			{cfg: ResolverUpstream{ID: "test", Type: "udp"}, address: address},
		},
	}
	runtime := &Runtime{cache: map[string]cacheItem{}}
	runtime.snapshot.Store(snapshot)
	query := makeDNSQuery("alias.example", 1)

	firstResponse := runtime.resolverDNSResponse(query, snapshot)
	firstAnswers, err := dnsRRsInSection(firstResponse, 0)
	if err != nil {
		t.Fatal(err)
	}
	firstAuthority, err := dnsRRsInSection(firstResponse, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstAnswers) != 1 || len(firstAuthority) != 1 {
		t.Fatalf("unexpected first response sections: answers=%d authority=%d", len(firstAnswers), len(firstAuthority))
	}
	if got := binary.BigEndian.Uint32(firstResponse[firstAnswers[0].ttlOffset : firstAnswers[0].ttlOffset+4]); got != 900 {
		t.Fatalf("first CNAME TTL=%d, want upstream TTL 900", got)
	}
	if got := binary.BigEndian.Uint32(firstResponse[firstAuthority[0].ttlOffset : firstAuthority[0].ttlOffset+4]); got != 120 {
		t.Fatalf("first SOA TTL=%d, want upstream TTL 120", got)
	}

	cacheKey := "mode2:78:" + cacheKey(query)
	cachedResponse, found := runtime.cacheGet(cacheKey, packetID(query), 0)
	if !found {
		t.Fatal("expected CNAME/NODATA response in mode-2 cache")
	}
	cachedAnswers, err := dnsRRsInSection(cachedResponse, 0)
	if err != nil {
		t.Fatal(err)
	}
	cachedAuthority, err := dnsRRsInSection(cachedResponse, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(cachedAnswers) != 1 || len(cachedAuthority) != 1 {
		t.Fatalf("unexpected cached sections: answers=%d authority=%d", len(cachedAnswers), len(cachedAuthority))
	}
	if got := binary.BigEndian.Uint32(cachedResponse[cachedAnswers[0].ttlOffset : cachedAnswers[0].ttlOffset+4]); got != 300 {
		t.Fatalf("cached CNAME TTL=%d, want 300", got)
	}
	if got := binary.BigEndian.Uint32(cachedResponse[cachedAuthority[0].ttlOffset : cachedAuthority[0].ttlOffset+4]); got != 45 {
		t.Fatalf("cached SOA TTL=%d, want 45", got)
	}
}

// mode2QueryWithEDNSDO creates an A/AAAA query with EDNS0, DO and a COOKIE
// option so resolver forwarding can be checked byte-for-byte.
func mode2QueryWithEDNSDO(name string, qtype uint16) []byte {
	query := makeDNSQuery(name, qtype)
	binary.BigEndian.PutUint16(query[10:12], 1)
	// OPT: UDP payload=1400, EDNS version=0, DO=1, COOKIE option (4 bytes).
	return append(query, 0, 0, 41, 0x05, 0x78, 0, 0, 0x80, 0, 0, 8, 0, 10, 0, 4, 0x11, 0x22, 0x33, 0x44)
}

func mode2CNAMEAddressResponse(query []byte, qtype uint16, cnameTTL, addressTTL uint32) []byte {
	response := mode2ResponseWithRCode(query, 0)
	target := "target.example"

	// alias.example CNAME target.example
	cnameRData := appendDNSName(nil, target)
	response = append(response, 0xc0, 0x0c, 0, 5, 0, 1)
	var ttl [4]byte
	binary.BigEndian.PutUint32(ttl[:], cnameTTL)
	response = append(response, ttl[:]...)
	response = append(response, byte(len(cnameRData)>>8), byte(len(cnameRData)))
	response = append(response, cnameRData...)

	// target.example A/AAAA terminal address record.
	response = appendDNSName(response, target)
	response = append(response, byte(qtype>>8), byte(qtype), 0, 1)
	binary.BigEndian.PutUint32(ttl[:], addressTTL)
	response = append(response, ttl[:]...)
	var ip net.IP
	if qtype == 1 {
		ip = net.ParseIP("203.0.113.10").To4()
	} else if qtype == 28 {
		ip = net.ParseIP("2001:db8::10").To16()
	} else {
		return nil
	}
	response = append(response, byte(len(ip)>>8), byte(len(ip)))
	response = append(response, ip...)
	binary.BigEndian.PutUint16(response[6:8], 2)
	return response
}

func mode2AppendResponseOPT(response []byte) []byte {
	// Preserve the EDNS UDP size and DO bit. Include a COOKIE option to prove
	// that resolver mode returns upstream OPT data rather than synthesizing it.
	response = append(response, 0, 0, 41, 0x05, 0x78, 0, 0, 0x80, 0, 0, 8, 0, 10, 0, 4, 0x11, 0x22, 0x33, 0x44)
	binary.BigEndian.PutUint16(response[10:12], 1)
	return response
}

func TestMode2ResolverForwardsCNAMEAddressAndEDNSDO(t *testing.T) {
	for _, tc := range []struct {
		name  string
		qtype uint16
		want  string
	}{
		{name: "CNAME to A", qtype: 1, want: "203.0.113.10"},
		{name: "CNAME to AAAA", qtype: 28, want: "2001:db8::10"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			receivedQuery := make(chan []byte, 1)
			address, requestCount := startMode2TestUDPResolver(t, func(query []byte) []byte {
				receivedQuery <- append([]byte(nil), query...)
				return mode2AppendResponseOPT(mode2CNAMEAddressResponse(query, tc.qtype, 900, 600))
			})

			snapshot := &Snapshot{
				cfg: Config{
					DNSMode: "resolver",
					Cache: CacheConfig{
						Enabled: true, MinTTL: 0, MaxTTL: 300, MaxEntries: 10, MaxBytes: 4096,
					},
					DNSQueryTimeoutSeconds: 3,
				},
				resolverGeneration: 91,
				resolverUpstreams: []*ResolverRuntime{
					{cfg: ResolverUpstream{ID: "test", Type: "udp"}, address: address},
				},
			}
			runtime := &Runtime{cache: map[string]cacheItem{}}
			runtime.snapshot.Store(snapshot)

			query := mode2QueryWithEDNSDO("alias.example", tc.qtype)
			response := runtime.resolverDNSResponse(query, snapshot)
			if dnsRCode(response) != 0 {
				t.Fatalf("resolver response rcode=%d, want NOERROR", dnsRCode(response))
			}
			if requestCount.Load() != 1 {
				t.Fatalf("upstream request count=%d, want 1", requestCount.Load())
			}

			select {
			case forwarded := <-receivedQuery:
				if !bytes.Equal(forwarded, query) {
					t.Fatal("resolver query was modified; EDNS0/DO/COOKIE and DNS question must be forwarded unchanged")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("resolver did not receive the DNS query")
			}

			answers, err := dnsRRsInSection(response, 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(answers) != 2 || answers[0].typeCode != 5 || answers[1].typeCode != tc.qtype {
				t.Fatalf("expected CNAME plus terminal type %d, got %+v", tc.qtype, answers)
			}
			cnameTarget, cnameEnd, err := decodeName(response, answers[0].rdata)
			if err != nil || cnameEnd != answers[0].end || cnameTarget != "target.example" {
				t.Fatalf("CNAME target=%q end=%d err=%v, want target.example", cnameTarget, cnameEnd, err)
			}
			gotIP := net.IP(response[answers[1].rdata:answers[1].end]).String()
			if gotIP != tc.want {
				t.Fatalf("terminal address=%q, want %q", gotIP, tc.want)
			}

			opt := extractEDNSOPT(response)
			if len(opt) != 19 || binary.BigEndian.Uint16(opt[1:3]) != 41 ||
				binary.BigEndian.Uint16(opt[3:5]) != 1400 ||
				opt[6] != 0 || binary.BigEndian.Uint16(opt[7:9]) != 0x8000 ||
				binary.BigEndian.Uint16(opt[9:11]) != 8 ||
				binary.BigEndian.Uint16(opt[11:13]) != 10 ||
				binary.BigEndian.Uint16(opt[13:15]) != 4 ||
				!bytes.Equal(opt[15:19], []byte{0x11, 0x22, 0x33, 0x44}) {
				t.Fatalf("upstream OPT/DO/COOKIE was not preserved: %v", opt)
			}
			if binary.BigEndian.Uint16(response[2:4])&0x0020 != 0 {
				t.Fatal("test upstream response did not set AD; plugin must not add a false AD bit")
			}

			cached, found := runtime.cacheGet("mode2:91:"+cacheKey(query), packetID(query), 0)
			if !found {
				t.Fatal("expected positive CNAME/address response to be cached")
			}
			cachedAnswers, err := dnsRRsInSection(cached, 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(cachedAnswers) != 2 {
				t.Fatalf("cached answer count=%d, want 2", len(cachedAnswers))
			}
			for _, answer := range cachedAnswers {
				if ttl := binary.BigEndian.Uint32(cached[answer.ttlOffset : answer.ttlOffset+4]); ttl > 300 {
					t.Fatalf("cached RR TTL=%d exceeds 300 second cap", ttl)
				}
			}
			if cachedOPT := extractEDNSOPT(cached); !bytes.Equal(cachedOPT, opt) {
				t.Fatalf("cached response changed upstream OPT: got %v want %v", cachedOPT, opt)
			}
		})
	}
}

func TestMode2DoHResolverForwardsCNAMEAndEDNSDO(t *testing.T) {
	for _, tc := range []struct {
		name  string
		qtype uint16
		want  string
	}{
		{name: "CNAME to A", qtype: 1, want: "203.0.113.10"},
		{name: "CNAME to AAAA", qtype: 28, want: "2001:db8::10"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			receivedQuery := make(chan []byte, 1)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method != http.MethodPost {
					t.Errorf("DoH method=%q, want POST", req.Method)
				}
				if got := req.Header.Get("Content-Type"); got != "application/dns-message" {
					t.Errorf("DoH Content-Type=%q", got)
				}
				if got := req.Header.Get("Accept"); got != "application/dns-message" {
					t.Errorf("DoH Accept=%q", got)
				}
				body, err := io.ReadAll(req.Body)
				if err != nil {
					t.Errorf("read DoH request: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				receivedQuery <- append([]byte(nil), body...)
				response := mode2AppendResponseOPT(mode2CNAMEAddressResponse(body, tc.qtype, 900, 600))
				w.Header().Set("Content-Type", "application/dns-message")
				_, _ = w.Write(response)
			}))
			defer server.Close()

			snapshot := &Snapshot{
				cfg: Config{
					DNSMode: "resolver",
					Cache: CacheConfig{
						Enabled: true, MinTTL: 0, MaxTTL: 300, MaxEntries: 10, MaxBytes: 4096,
					},
					DNSQueryTimeoutSeconds: 3,
					DoHTimeoutSeconds:      3,
				},
				resolverGeneration: 92,
				resolverUpstreams: []*ResolverRuntime{
					{
						cfg: ResolverUpstream{ID: "doh-test", Type: "doh"},
						upstream: &UpstreamRuntime{
							cfg:    Upstream{ID: "doh-test", URL: server.URL},
							client: server.Client(),
						},
					},
				},
			}
			runtime := &Runtime{cache: map[string]cacheItem{}}
			runtime.snapshot.Store(snapshot)

			query := mode2QueryWithEDNSDO("alias.example", tc.qtype)
			response := runtime.resolverDNSResponse(query, snapshot)
			if dnsRCode(response) != 0 {
				t.Fatalf("DoH resolver response rcode=%d, want NOERROR", dnsRCode(response))
			}
			select {
			case forwarded := <-receivedQuery:
				if !bytes.Equal(forwarded, query) {
					t.Fatal("DoH query was modified; EDNS0/DO/COOKIE and DNS question must be forwarded unchanged")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("DoH resolver did not receive the DNS query")
			}

			answers, err := dnsRRsInSection(response, 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(answers) != 2 || answers[0].typeCode != 5 || answers[1].typeCode != tc.qtype {
				t.Fatalf("expected CNAME plus terminal type %d, got %+v", tc.qtype, answers)
			}
			cnameTarget, cnameEnd, err := decodeName(response, answers[0].rdata)
			if err != nil || cnameEnd != answers[0].end || cnameTarget != "target.example" {
				t.Fatalf("CNAME target=%q end=%d err=%v, want target.example", cnameTarget, cnameEnd, err)
			}
			if got := net.IP(response[answers[1].rdata:answers[1].end]).String(); got != tc.want {
				t.Fatalf("terminal address=%q, want %q", got, tc.want)
			}

			opt := extractEDNSOPT(response)
			if len(opt) != 19 || binary.BigEndian.Uint16(opt[3:5]) != 1400 ||
				binary.BigEndian.Uint16(opt[7:9]) != 0x8000 ||
				binary.BigEndian.Uint16(opt[11:13]) != 10 ||
				!bytes.Equal(opt[15:19], []byte{0x11, 0x22, 0x33, 0x44}) {
				t.Fatalf("DoH upstream OPT/DO/COOKIE was not preserved: %v", opt)
			}
			if binary.BigEndian.Uint16(response[2:4])&0x0020 != 0 {
				t.Fatal("DoH test upstream response did not set AD; plugin must not add a false AD bit")
			}
		})
	}
}

func startMode2TestTCPResolver(t *testing.T, handler func([]byte) []byte) (string, *atomic.Int32) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	count := &atomic.Int32{}
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				var length [2]byte
				if _, readErr := io.ReadFull(conn, length[:]); readErr != nil {
					return
				}
				n := int(binary.BigEndian.Uint16(length[:]))
				if n < 12 || n > maxDNSMessage {
					return
				}
				query := make([]byte, n)
				if _, readErr := io.ReadFull(conn, query); readErr != nil {
					return
				}
				count.Add(1)
				response := handler(query)
				if len(response) < 12 || len(response) > maxDNSMessage {
					return
				}
				binary.BigEndian.PutUint16(length[:], uint16(len(response)))
				frame := append(length[:], response...)
				for len(frame) > 0 {
					written, writeErr := conn.Write(frame)
					if writeErr != nil || written == 0 {
						return
					}
					frame = frame[written:]
				}
			}(conn)
		}
	}()
	return listener.Addr().String(), count
}

func TestMode2TCPResolverForwardsCNAMEAddressAndEDNSDO(t *testing.T) {
	for _, tc := range []struct {
		name  string
		qtype uint16
		want  string
	}{
		{name: "CNAME to A", qtype: 1, want: "203.0.113.10"},
		{name: "CNAME to AAAA", qtype: 28, want: "2001:db8::10"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			receivedQuery := make(chan []byte, 1)
			address, requestCount := startMode2TestTCPResolver(t, func(query []byte) []byte {
				receivedQuery <- append([]byte(nil), query...)
				return mode2AppendResponseOPT(mode2CNAMEAddressResponse(query, tc.qtype, 900, 600))
			})
			snapshot := &Snapshot{
				cfg: Config{
					DNSMode: "resolver",
					Cache: CacheConfig{
						Enabled: true, MinTTL: 0, MaxTTL: 300, MaxEntries: 10, MaxBytes: 4096,
					},
					DNSQueryTimeoutSeconds: 3,
				},
				resolverGeneration: 93,
				resolverUpstreams: []*ResolverRuntime{
					{cfg: ResolverUpstream{ID: "tcp-test", Type: "tcp"}, address: address},
				},
			}
			runtime := &Runtime{cache: map[string]cacheItem{}}
			runtime.snapshot.Store(snapshot)
			query := mode2QueryWithEDNSDO("alias.example", tc.qtype)
			response := runtime.resolverDNSResponse(query, snapshot)
			if dnsRCode(response) != 0 || requestCount.Load() != 1 {
				t.Fatalf("response rcode=%d, TCP upstream requests=%d; want NOERROR and one request", dnsRCode(response), requestCount.Load())
			}

			select {
			case forwarded := <-receivedQuery:
				if !bytes.Equal(forwarded, query) {
					t.Fatal("TCP resolver query was modified; EDNS0/DO/COOKIE must be forwarded unchanged")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("TCP resolver did not receive the DNS query")
			}

			answers, err := dnsRRsInSection(response, 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(answers) != 2 || answers[0].typeCode != 5 || answers[1].typeCode != tc.qtype {
				t.Fatalf("expected CNAME plus terminal type %d, got %+v", tc.qtype, answers)
			}
			cnameTarget, cnameEnd, err := decodeName(response, answers[0].rdata)
			if err != nil || cnameEnd != answers[0].end || cnameTarget != "target.example" {
				t.Fatalf("CNAME target=%q end=%d err=%v, want target.example", cnameTarget, cnameEnd, err)
			}
			if got := net.IP(response[answers[1].rdata:answers[1].end]).String(); got != tc.want {
				t.Fatalf("terminal address=%q, want %q", got, tc.want)
			}
			opt := extractEDNSOPT(response)
			if len(opt) != 19 || binary.BigEndian.Uint16(opt[3:5]) != 1400 ||
				binary.BigEndian.Uint16(opt[7:9]) != 0x8000 ||
				!bytes.Equal(opt[15:19], []byte{0x11, 0x22, 0x33, 0x44}) {
				t.Fatalf("TCP upstream OPT/DO/COOKIE was not preserved: %v", opt)
			}
		})
	}
}

func TestMode2SystemResolverQueryRejectsPluginListenerLoop(t *testing.T) {
	resolvConf := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(resolvConf, []byte("nameserver 127.0.0.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	resolver := &systemDNSResolver{
		resolvConfPath:    resolvConf,
		listenerAddresses: []string{"127.0.0.1:53"},
	}
	_, err := resolver.query(context.Background(), makeDNSQuery("loop.example", 1))
	if err == nil || !strings.Contains(err.Error(), "refusing a DNS loop") {
		t.Fatalf("system resolver error=%v, want plugin listener DNS-loop refusal", err)
	}
}

func TestMode2ResolverCooldownSkipsKnownFailedUpstream(t *testing.T) {
	closed, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	unusedAddress := closed.LocalAddr().String()
	_ = closed.Close()
	goodAddress, goodCount := startMode2TestUDPResolver(t, func(query []byte) []byte {
		return testAResponse(query, 30)
	})
	now := time.Now()
	runtime := &Runtime{upstreamCooldown: map[string]time.Time{"offline": now.Add(upstreamFailureCooldown)}}
	snapshot := &Snapshot{
		cfg: Config{DNSQueryTimeoutSeconds: 3, DoHTimeoutSeconds: 3},
		resolverUpstreams: []*ResolverRuntime{
			{cfg: ResolverUpstream{ID: "offline", Type: "udp"}, address: unusedAddress},
			{cfg: ResolverUpstream{ID: "good", Type: "udp"}, address: goodAddress},
		},
	}
	response, selected, err := runtime.queryResolverUpstreams(context.Background(), snapshot, makeDNSQuery("mode2.example", 1))
	if err != nil {
		t.Fatal(err)
	}
	if selected != "good" || dnsRCode(response) != 0 || goodCount.Load() != 1 {
		t.Fatalf("selected=%q rcode=%d good calls=%d", selected, dnsRCode(response), goodCount.Load())
	}
}

func TestMode2ResolverReturnsStaleAnswerWhenAllUpstreamsFail(t *testing.T) {
	var failUpstream atomic.Bool
	address, requestCount := startMode2TestUDPResolver(t, func(query []byte) []byte {
		if failUpstream.Load() {
			return nil // Simulate an upstream timeout after the initial successful response.
		}
		return testAResponse(query, 60)
	})
	query := makeDNSQuery("mode2-stale.example", 1)
	snapshot := &Snapshot{
		cfg: Config{
			DNSMode: "resolver",
			Cache: CacheConfig{
				Enabled: true, MinTTL: 0, MaxTTL: 300, StaleTTL: 1800,
				MaxEntries: 10, MaxBytes: 4096,
			},
			DNSQueryTimeoutSeconds: 1,
		},
		resolverGeneration: 1800,
		resolverUpstreams: []*ResolverRuntime{
			{cfg: ResolverUpstream{ID: "primary", Type: "udp"}, address: address},
		},
	}
	runtime := &Runtime{cache: make(map[string]cacheItem)}
	runtime.snapshot.Store(snapshot)

	fresh := runtime.resolverDNSResponse(query, snapshot)
	if dnsRCode(fresh) != 0 || dnsAnswerCount(fresh) != 1 {
		t.Fatalf("initial response: rcode=%d answers=%d, want successful A answer", dnsRCode(fresh), dnsAnswerCount(fresh))
	}
	key := "mode2:1800:" + cacheKey(query)
	runtime.cacheMu.Lock()
	item, ok := runtime.cache[key]
	if !ok {
		runtime.cacheMu.Unlock()
		t.Fatal("successful resolver answer was not cached")
	}
	item.expires = time.Now().Add(-time.Second)
	runtime.cache[key] = item
	runtime.cacheMu.Unlock()

	failUpstream.Store(true)
	stale := runtime.resolverDNSResponse(query, snapshot)
	if dnsRCode(stale) != 0 || dnsAnswerCount(stale) != 1 {
		t.Fatalf("stale response: rcode=%d answers=%d, want cached successful A answer", dnsRCode(stale), dnsAnswerCount(stale))
	}
	if got := binary.BigEndian.Uint16(stale[:2]); got != packetID(query) {
		t.Fatalf("response ID=%#x, want %#x", got, packetID(query))
	}
	positions, err := rrTTLPositions(stale)
	if err != nil || len(positions) == 0 {
		t.Fatalf("failed to inspect stale TTLs: positions=%v err=%v", positions, err)
	}
	for _, offset := range positions {
		if got := binary.BigEndian.Uint32(stale[offset : offset+4]); got != 1 {
			t.Fatalf("stale TTL=%d, want 1", got)
		}
	}
	if got := runtime.resilience.staleCacheHits.Load(); got != 1 {
		t.Fatalf("stale cache hits=%d, want 1", got)
	}
	if got := requestCount.Load(); got != 2 {
		t.Fatalf("upstream requests=%d, want initial success plus one failed refresh", got)
	}
}
