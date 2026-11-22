package main

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---- helpers -------------------------------------------------------------

type scriptedDNS struct {
	conn *net.UDPConn
	hits atomic.Int64
}

func startScriptedDNS(t *testing.T, rcodeFor func(name string) uint16) *scriptedDNS {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	server := &scriptedDNS{conn: conn}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			server.hits.Add(1)
			query := append([]byte(nil), buf[:n]...)
			name, _, end, parseErr := parseQuestion(query)
			if parseErr != nil {
				continue
			}
			response := append([]byte(nil), query[:end]...)
			binary.BigEndian.PutUint16(response[2:4], 0x8180|rcodeFor(name))
			binary.BigEndian.PutUint16(response[4:6], 1)
			for i := 6; i < 12; i += 2 {
				binary.BigEndian.PutUint16(response[i:i+2], 0)
			}
			_, _ = conn.WriteToUDP(response, addr)
		}
	}()
	t.Cleanup(func() { _ = conn.Close() })
	return server
}

func answerRecords(count int, withOPT bool) []byte {
	query := makeDNSQuery("example.com", 1)
	_, _, end, _ := parseQuestion(query)
	response := append([]byte(nil), query[:end]...)
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[4:6], 1)
	binary.BigEndian.PutUint16(response[6:8], uint16(count))
	if withOPT {
		binary.BigEndian.PutUint16(response[10:12], 1)
	}
	for i := 0; i < count; i++ {
		response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, byte(i>>8), byte(i))
	}
	if withOPT {
		response = append(response, 0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0)
	}
	return response
}

// walk returns the AN/AR counts and whether the sections consume the packet exactly.
func walk(p []byte) (an, ar int, exact bool) {
	_, end, err := decodeName(p, 12)
	if err != nil {
		return
	}
	offset := end + 4
	counts := []int{int(binary.BigEndian.Uint16(p[6:8])), int(binary.BigEndian.Uint16(p[8:10])), int(binary.BigEndian.Uint16(p[10:12]))}
	for section, count := range counts {
		for i := 0; i < count; i++ {
			_, nameEnd, err := decodeName(p, offset)
			if err != nil || nameEnd+10 > len(p) {
				return
			}
			offset = nameEnd + 10 + int(binary.BigEndian.Uint16(p[nameEnd+8:nameEnd+10]))
			if section == 0 {
				an++
			}
			if section == 2 {
				ar++
			}
		}
	}
	return an, ar, offset == len(p)
}

// ---- N1: SERVFAIL for one name must not trigger upstream cooldown --------

func TestRegressionSoftFailureDoesNotStartCooldown(t *testing.T) {
	primary := startScriptedDNS(t, func(name string) uint16 {
		if name == "bad.example" {
			return 2
		}
		return 0
	})
	secondary := startScriptedDNS(t, func(string) uint16 { return 0 })
	runtime := &Runtime{}
	snapshot := &Snapshot{cfg: Config{DNSQueryTimeoutSeconds: 3}, resolverUpstreams: []*ResolverRuntime{
		{cfg: ResolverUpstream{ID: "primary", Type: "udp"}, address: primary.conn.LocalAddr().String()},
		{cfg: ResolverUpstream{ID: "secondary", Type: "udp"}, address: secondary.conn.LocalAddr().String()},
	}}
	ask := func(name string) string {
		_, id, err := runtime.queryResolverUpstreams(context.Background(), snapshot, makeDNSQuery(name, 1))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return id
	}
	if id := ask("bad.example"); id != "secondary" {
		t.Fatalf("bad.example must fall through to the secondary for this query, got %s", id)
	}
	for _, name := range []string{"good1.example", "good2.example", "good3.example"} {
		if id := ask(name); id != "primary" {
			t.Fatalf("%s served by %s: one SERVFAIL must not demote the primary", name, id)
		}
	}
	if len(runtime.upstreamCooldown) != 0 {
		t.Fatalf("cooldown map must stay empty after soft failures: %v", runtime.upstreamCooldown)
	}
}

// ---- N2: quick retry after a withdrawn selection --------------------------

func TestRegressionActiveDoHRetryDelayBackoff(t *testing.T) {
	want := []time.Duration{15 * time.Second, 30 * time.Second, 60 * time.Second, 120 * time.Second, 240 * time.Second,
		activeDoHProbeInterval, activeDoHProbeInterval}
	for i, expected := range want {
		if got := activeDoHRetryDelay(i + 1); got != expected {
			t.Fatalf("failure %d: delay %s, want %s", i+1, got, expected)
		}
	}
	if activeDoHRetryDelay(1000) != activeDoHProbeInterval {
		t.Fatal("delay must stay capped at the regular probe interval")
	}
}

// ---- N3: honest error for non-public-only endpoints -----------------------

func TestRegressionNonPublicOnlyEndpointReportsReason(t *testing.T) {
	resolver := &bootstrapResolver{host: "doh.corp.internal", resolvers: []string{"10.0.0.2"}, refreshFor: time.Hour,
		lookup: func(context.Context, string, string) ([]net.IP, error) { return []net.IP{net.ParseIP("10.0.0.5")}, nil }}
	ips, err := resolver.addresses(context.Background(), false)
	if len(ips) != 0 || err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Fatalf("ips=%v err=%v", ips, err)
	}
}

// ---- N4: never answer responses, NOTIMP for other opcodes -----------------

func TestRegressionHandleDNSDropsResponsesAndRejectsOpcodes(t *testing.T) {
	runtime := &Runtime{dnsSem: make(chan struct{}, 4)}
	runtime.snapshot.Store(&Snapshot{cfg: Config{DNSMode: "resolver", DNSQueryTimeoutSeconds: 1}})
	query := makeDNSQuery("example.com", 1)
	flags := binary.BigEndian.Uint16(query[2:4])

	asResponse := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(asResponse[2:4], flags|0x8000)
	if out := runtime.handleDNS(asResponse); len(out) != 0 {
		t.Fatalf("a QR=1 packet must be dropped, got %d bytes", len(out))
	}
	update := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(update[2:4], (flags&^0x7800)|(5<<11))
	if out := runtime.handleDNS(update); dnsRCode(out) != 4 {
		t.Fatalf("opcode UPDATE must return NOTIMP(4), rcode=%d", dnsRCode(out))
	}
}

func TestRegressionUDPNeverSendsDatagramForResponsePackets(t *testing.T) {
	runtime := &Runtime{dnsSem: make(chan struct{}, 4)}
	runtime.snapshot.Store(&Snapshot{cfg: Config{DNSMode: "resolver", DNSQueryTimeoutSeconds: 1, DNSMaxConcurrent: 4}})
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runtime.serveUDP(ctx, conn)
	client, _ := net.DialUDP("udp", nil, conn.LocalAddr().(*net.UDPAddr))
	defer client.Close()

	query := makeDNSQuery("example.com", 1)
	binary.BigEndian.PutUint16(query[2:4], binary.BigEndian.Uint16(query[2:4])|0x8000)
	_, _ = client.Write(query)
	_ = client.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	buf := make([]byte, 512)
	if n, err := client.Read(buf); err == nil {
		t.Fatalf("received %d bytes in reply to a QR=1 packet", n)
	}
	// a normal query must still be answered (SERVFAIL: no resolvers configured)
	_, _ = client.Write(makeDNSQuery("example.com", 1))
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := client.Read(buf)
	if err != nil || n < 12 || dnsRCode(buf[:n]) != 2 {
		t.Fatalf("normal query: n=%d err=%v", n, err)
	}
}

// ---- N5: OPT survives truncation -------------------------------------------

func TestRegressionTruncationKeepsOPT(t *testing.T) {
	full := answerRecords(100, true)
	out := truncateDNSResponse(full, 512)
	an, ar, exact := walk(out)
	if len(out) > 512 || !dnsTruncated(out) || !exact || ar != 1 || an == 0 || an >= 100 {
		t.Fatalf("len=%d TC=%v exact=%v AN=%d AR=%d", len(out), dnsTruncated(out), exact, an, ar)
	}
	untouched := truncateDNSResponse(full, 4096)
	if _, ar, exact := walk(untouched); dnsTruncated(untouched) || !exact || ar != 1 {
		t.Fatal("a response that fits must be returned unchanged")
	}
	noOPT := truncateDNSResponse(answerRecords(100, false), 512)
	if _, ar, exact := walk(noOPT); !exact || ar != 0 || !dnsTruncated(noOPT) {
		t.Fatal("no OPT must be invented when the original had none")
	}
}

// ---- item 17: loop protection on the legacy system-DNS path -----------------

func TestRegressionLegacySystemDNSKnowsListenerAddresses(t *testing.T) {
	cfg := defaultConfig()
	cfg.Upstreams = cfg.Upstreams[:1]
	cfg.Groups[0].Upstreams = []string{cfg.Upstreams[0].ID}
	snapshot, err := buildSnapshot(cfg, map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	system := snapshot.upstreams[cfg.Upstreams[0].ID].systemDNS
	if system == nil || len(system.listenerAddresses) == 0 {
		t.Fatalf("legacy system DNS runtime has no listener addresses: %+v", system)
	}
}
// ---- N6: mode-2 resolver cooldown survives a configuration reload --------

func TestRegressionMode2CooldownSurvivesReload(t *testing.T) {
	const resolverID = "mode2-primary"
	now := time.Now()
	first := &Snapshot{resolverUpstreams: []*ResolverRuntime{
		{cfg: ResolverUpstream{ID: resolverID, Type: "udp"}},
	}}
	runtime := &Runtime{}
	runtime.initHealth(first)
	runtime.markUpstreamFailure(resolverID, now)
	until := now.Add(upstreamFailureCooldown)

	reloaded := &Snapshot{resolverUpstreams: []*ResolverRuntime{
		{cfg: ResolverUpstream{ID: resolverID, Type: "udp"}},
	}}
	runtime.initHealth(reloaded)
	if got, ok := runtime.upstreamCooldown[resolverID]; !ok || !got.Equal(until) {
		t.Fatalf("mode-2 cooldown after reload = %v, present=%v; want %v", got, ok, until)
	}

	// A resolver removed from the new configuration must no longer retain state.
	runtime.initHealth(&Snapshot{})
	if _, ok := runtime.upstreamCooldown[resolverID]; ok {
		t.Fatal("removed mode-2 resolver cooldown was not pruned")
	}
}
