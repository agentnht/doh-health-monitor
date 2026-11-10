package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func testAResponse(q []byte, ttl uint32) []byte {
	_, _, end, err := parseQuestion(q)
	if err != nil {
		panic(err)
	}
	p := make([]byte, 12)
	binary.BigEndian.PutUint16(p[:2], packetID(q))
	binary.BigEndian.PutUint16(p[2:4], 0x8180)
	binary.BigEndian.PutUint16(p[4:6], 1)
	binary.BigEndian.PutUint16(p[6:8], 1)
	p = append(p, q[12:end]...)
	p = append(p, 0xc0, 0x0c) // owner name pointer to question
	p = append(p, 0, 1, 0, 1) // A, IN
	var ttlb [4]byte
	binary.BigEndian.PutUint32(ttlb[:], ttl)
	p = append(p, ttlb[:]...)
	p = append(p, 0, 4, 203, 0, 113, 10)
	return p
}

func TestDNSQueryAndAResponse(t *testing.T) {
	q := makeDNSQuery("www.example.com", 1)
	name, typ, _, err := parseQuestion(q)
	if err != nil {
		t.Fatal(err)
	}
	if name != "www.example.com" || typ != 1 {
		t.Fatalf("unexpected question: %s type=%d", name, typ)
	}
	resp := testAResponse(q, 60)
	ips, err := parseARecords(resp)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "203.0.113.10" {
		t.Fatalf("unexpected A records: %#v", ips)
	}
}

func TestCacheTTLAndTransactionID(t *testing.T) {
	q := makeDNSQuery("cache.example", 1)
	resp := testAResponse(q, 90)
	c := CacheConfig{Enabled: true, MinTTL: 1, MaxTTL: 120, NegativeTTL: 10, MaxEntries: 10, MaxBytes: 4096}
	r := &Runtime{cache: map[string]cacheItem{}}
	key := cacheKey(q)
	r.cachePut(key, resp, c)
	otherID := uint16(0x1234)
	got, ok := r.cacheGet(key, otherID)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if packetID(got) != otherID {
		t.Fatalf("cache ID not rewritten: %x", packetID(got))
	}
	pos, err := rrTTLPositions(got)
	if err != nil || len(pos) != 1 {
		t.Fatalf("TTL positions: %v %v", pos, err)
	}
	if binary.BigEndian.Uint32(got[pos[0]:pos[0]+4]) > 90 {
		t.Fatal("TTL increased")
	}
}

func TestTimevalNanoseconds(t *testing.T) {
	got := timevalNanoseconds(syscall.Timeval{Sec: 2, Usec: 250000})
	if want := uint64(2250000000); got != want {
		t.Fatalf("nanoseconds=%d, want %d", got, want)
	}
	if got := timevalNanoseconds(syscall.Timeval{Sec: -1, Usec: 0}); got != 0 {
		t.Fatalf("negative timeval should return 0, got %d", got)
	}
}

func TestDefaultConfigValid(t *testing.T) {
	c := defaultConfig()
	if err := validateConfig(c); err != nil {
		t.Fatal(err)
	}
	if c.Health.IntervalSeconds != 25*60 {
		t.Fatalf("health interval=%d, want 1500 seconds", c.Health.IntervalSeconds)
	}
	if c.Health.SuccessThreshold != 1 {
		t.Fatalf("success threshold=%d, want one successful check", c.Health.SuccessThreshold)
	}
	if c.Health.FailureThreshold != 3 {
		t.Fatalf("failure threshold=%d, want three consecutive failures", c.Health.FailureThreshold)
	}
}


func TestCacheRejectsZeroEntryLimitWhenEnabled(t *testing.T) {
	c := defaultConfig()
	c.Cache.MaxEntries = 0
	if err := validateConfig(c); err == nil {
		t.Fatal("enabled cache with max_entries=0 must be rejected")
	}
}

func TestCacheFIFOAndByteLimit(t *testing.T) {
	c := CacheConfig{Enabled: true, MinTTL: 1, MaxTTL: 120, NegativeTTL: 10, MaxEntries: 50, MaxBytes: 1024}
	r := &Runtime{cache: map[string]cacheItem{}}
	var oldestKey string
	var oldestID uint16
	var newestKey string
	var newestID uint16
	for i := 0; i < 30; i++ {
		q := makeDNSQuery(fmt.Sprintf("item%02d.example", i), 1)
		if i == 0 {
			oldestKey, oldestID = cacheKey(q), packetID(q)
		}
		if i == 29 {
			newestKey, newestID = cacheKey(q), packetID(q)
		}
		r.cachePut(cacheKey(q), testAResponse(q, 60), c)
	}
	entries, used := r.cacheStats()
	if entries > c.MaxEntries || used > c.MaxBytes {
		t.Fatalf("cache limits exceeded: entries=%d bytes=%d", entries, used)
	}
	if entries >= 30 {
		t.Fatalf("entries=%d, want some FIFO eviction under 1 KiB budget", entries)
	}
	if _, ok := r.cacheGet(oldestKey, oldestID); ok {
		t.Fatal("oldest entry should have been evicted")
	}
	if _, ok := r.cacheGet(newestKey, newestID); !ok {
		t.Fatal("newest cache entry should remain")
	}
}

func TestInitHealthPrunesRemovedUpstreams(t *testing.T) {
	s := &Snapshot{
		groups: map[string]Group{"google": {ID: "google", Upstreams: []string{"current"}}},
		upstreams: map[string]*UpstreamRuntime{"current": {}},
	}
	r := &Runtime{
		health: map[string]map[string]HealthEntry{
			"google": {"current": {State: "up"}, "removed": {State: "down"}},
			"old-group": {"stale": {State: "down"}},
		},
		active: map[string]string{"google": "current", "old-group": "stale"},
		lastGemini: map[string]time.Time{"current": time.Now(), "removed": time.Now()},
	}
	r.initHealth(s)
	if _, ok := r.health["google"]["removed"]; ok {
		t.Fatal("removed upstream health entry was not pruned")
	}
	if _, ok := r.health["old-group"]; ok {
		t.Fatal("removed group health state was not pruned")
	}
	if _, ok := r.lastGemini["removed"]; ok {
		t.Fatal("removed upstream Gemini timestamp was not pruned")
	}
	if r.active["google"] != "current" {
		t.Fatalf("active=%q, want current", r.active["google"])
	}
}

func TestStaleHealthResultIgnoredAfterReload(t *testing.T) {
	s := &Snapshot{groups: map[string]Group{
		"google": {ID: "google", Upstreams: []string{"current"}},
	}}
	r := &Runtime{health: map[string]map[string]HealthEntry{
		"google": {"current": {State: "up"}},
	}}
	r.snapshot.Store(s)
	r.updateHealth("google", "removed", true, time.Millisecond, "", 200, "", nil, HealthConfig{
		SuccessThreshold: 1, FailureThreshold: 3,
	})
	if _, ok := r.health["google"]["removed"]; ok {
		t.Fatal("stale health result recreated a removed upstream")
	}
}

func TestOneSuccessIsEnoughToQualifyUpstream(t *testing.T) {
	r := &Runtime{health: map[string]map[string]HealthEntry{}}
	r.updateHealth("google", "u1", true, time.Millisecond, "", 200, "", nil, HealthConfig{
		SuccessThreshold: 1, FailureThreshold: 3,
	})
	if got := r.health["google"]["u1"].State; got != "up" {
		t.Fatalf("state=%q, want up after one successful check", got)
	}
}

func TestPinnedHTTPClientKeepsTLSVerificationAndBoundsIdleConnections(t *testing.T) {
	client := newPinnedHTTPClient("192.0.2.1", "resolver.example", time.Second)
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected an HTTP transport")
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("TLS certificate verification must remain enabled")
	}
	if tr.TLSClientConfig.MinVersion < 0x0303 {
		t.Fatalf("TLS minimum=%d, want TLS 1.2 or newer", tr.TLSClientConfig.MinVersion)
	}
	if tr.MaxIdleConnsPerHost != 1 || tr.IdleConnTimeout <= 0 {
		t.Fatalf("idle transport limits missing: per-host=%d timeout=%s", tr.MaxIdleConnsPerHost, tr.IdleConnTimeout)
	}
	client.CloseIdleConnections()
}

func TestUDPWorkerPoolBoundsQueueUnderLoad(t *testing.T) {
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		q, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		time.Sleep(20 * time.Millisecond)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(testAResponse(q, 60))
	}))
	defer upstreamServer.Close()

	upstream := &UpstreamRuntime{
		cfg: Upstream{ID: "slow", URL: upstreamServer.URL},
		client: upstreamServer.Client(),
	}
	s := &Snapshot{
		cfg: Config{DNSMaxConcurrent: 1, DNSQueryTimeoutSeconds: 3, Cache: CacheConfig{Enabled: false}},
		groups: map[string]Group{"google": {ID: "google", Upstreams: []string{"slow"}}},
		upstreams: map[string]*UpstreamRuntime{"slow": upstream},
	}
	r := &Runtime{
		dnsSem: make(chan struct{}, 1),
		health: map[string]map[string]HealthEntry{},
		active: map[string]string{"google": "slow"},
		cache: map[string]cacheItem{},
	}
	r.snapshot.Store(s)

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.serveUDP(ctx, serverConn)
		close(done)
	}()
	clientConn, err := net.DialUDP("udp", nil, serverConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		cancel()
		_ = serverConn.Close()
		t.Fatal(err)
	}
	defer clientConn.Close()

	for i := 0; i < 400; i++ {
		q := makeDNSQuery(fmt.Sprintf("load-%03d.example", i), 1)
		binary.BigEndian.PutUint16(q[:2], uint16(i+1))
		if _, err := clientConn.Write(q); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for r.udpDropped.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if dropped := r.udpDropped.Load(); dropped == 0 {
		t.Fatal("expected bounded UDP queue to drop excess burst packets")
	}
	if active := r.activeUDP.Load(); active > 1 {
		t.Fatalf("active UDP workers=%d, want at most 1 from config", active)
	}
	if queued := r.udpQueueDepth.Load(); queued > udpQueueCapacity {
		t.Fatalf("UDP queue depth=%d, capacity=%d", queued, udpQueueCapacity)
	}

	cancel()
	_ = serverConn.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("UDP server did not stop after cancellation")
	}
}

func TestTCPConnectionLimitUnderLoad(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &Runtime{}
	done := make(chan struct{})
	go func() {
		r.serveTCP(ctx, ln)
		close(done)
	}()

	connections := make([]net.Conn, 0, maxTCPConnections+16)
	defer func() {
		cancel()
		_ = ln.Close()
		for _, conn := range connections {
			_ = conn.Close()
		}
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("TCP server did not stop after cancellation")
		}
	}()

	for i := 0; i < maxTCPConnections+16; i++ {
		conn, dialErr := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
		if dialErr != nil {
			t.Fatalf("dial connection %d: %v", i+1, dialErr)
		}
		connections = append(connections, conn)
	}
	deadline := time.Now().Add(2 * time.Second)
	for r.tcpRejected.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if active := r.activeTCP.Load(); active > maxTCPConnections {
		t.Fatalf("active TCP connections=%d, limit=%d", active, maxTCPConnections)
	}
	if rejected := r.tcpRejected.Load(); rejected == 0 {
		t.Fatal("expected excess TCP connections to be rejected")
	}
}

func BenchmarkCacheHit(b *testing.B) {
	q := makeDNSQuery("benchmark.example", 1)
	resp := testAResponse(q, 60)
	cfg := CacheConfig{Enabled: true, MinTTL: 1, MaxTTL: 120, NegativeTTL: 10, MaxEntries: 1000, MaxBytes: 1 << 20}
	r := &Runtime{cache: map[string]cacheItem{}}
	key := cacheKey(q)
	r.cachePut(key, resp, cfg)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.cacheGet(key, uint16(i))
	}
}

func TestHTTPProbeBodyLimitUsesTwoMiBAndRejectsOversize(t *testing.T) {
	large := bytes.Repeat([]byte("x"), 900<<10)
	got, err := readHTTPProbeBody(bytes.NewReader(large))
	if err != nil {
		t.Fatalf("900 KiB Gemini HTML rejected: %v", err)
	}
	if len(got) != len(large) {
		t.Fatalf("read %d bytes, want %d", len(got), len(large))
	}

	tooLarge := bytes.Repeat([]byte("x"), maxHTTPBody+1)
	if _, err := readHTTPProbeBody(bytes.NewReader(tooLarge)); err == nil {
		t.Fatal("expected response larger than 2 MiB to be rejected")
	}
}

func TestGeminiRedirectValidation(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		location string
		want     bool
	}{
		{"consent redirect", http.StatusFound, "https://consent.google.com/save", true},
		{"sign-in redirect", http.StatusTemporaryRedirect, "https://accounts.google.com/signin", true},
		{"same-host redirect", http.StatusMovedPermanently, "https://gemini.google.com/app", true},
		{"external redirect", http.StatusFound, "https://example.org/", false},
		{"sorry redirect", http.StatusFound, "https://www.google.com/sorry/index", false},
		{"missing location", http.StatusFound, "", false},
		{"not a redirect", http.StatusOK, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{StatusCode: tt.status, Header: make(http.Header)}
			if tt.location != "" {
				resp.Header.Set("Location", tt.location)
			}
			if got := geminiRedirectAllowed(resp); got != tt.want {
				t.Fatalf("geminiRedirectAllowed()=%t, want %t", got, tt.want)
			}
		})
	}
}

func TestGeminiRegionBlockDetection(t *testing.T) {
	blocked := [][]byte{
		[]byte("Gemini is not available in your country"),
		[]byte("<html>Service not supported in your location</html>"),
		[]byte("Error code 1060"),
	}
	for _, body := range blocked {
		if !geminiRegionBlocked(body) {
			t.Errorf("expected regional restriction to be detected in %q", body)
		}
	}
	allowed := [][]byte{
		[]byte("<html><title>Gemini</title><body>Welcome</body></html>"),
		[]byte("This service is temporarily unavailable"),
		[]byte("Please sign in to continue"),
	}
	for _, body := range allowed {
		if geminiRegionBlocked(body) {
			t.Errorf("unexpected regional restriction detected in %q", body)
		}
	}
}

func TestDefaultConfigUsesSystemDNSFirstAndDoHProviders(t *testing.T) {
	want := []string{
		systemDNSUpstreamID,
		"eu.geohide.ru",
		"doh.dagami.ru",
		"dns.comss.one",
		"dns.bezmezhau.com",
		"dns.zapret.moe",
	}
	c := defaultConfig()
	got := make([]string, 0, len(c.Upstreams))
	for _, u := range c.Upstreams {
		got = append(got, u.ID)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("default upstreams = %v, want %v", got, want)
	}
	if c.Upstreams[0].Type != "system" {
		t.Fatalf("first upstream type = %q, want system", c.Upstreams[0].Type)
	}
	if len(c.Groups) != 1 || c.Groups[0].ID != "google" {
		t.Fatalf("default config groups = %+v, want only google", c.Groups)
	}
	google := c.Groups[0]
	for _, upstream := range google.Upstreams {
		if !containsString(want, upstream) {
			t.Errorf("unexpected Google upstream %q", upstream)
		}
	}
	if strings.Join(google.Upstreams, ",") != strings.Join(want, ",") {
		t.Errorf("Google upstreams = %v, want %v", google.Upstreams, want)
	}
	if len(google.Checks) != 25 {
		t.Fatalf("Google checks = %d, want 25", len(google.Checks))
	}
	var geminiCheck, accountsCheck *Check
	for i := range google.Checks {
		switch google.Checks[i].Domain {
		case "gemini.google.com":
			geminiCheck = &google.Checks[i]
		case "accounts.google.com":
			accountsCheck = &google.Checks[i]
		}
	}
	if geminiCheck == nil || geminiCheck.HTTPURL != "https://gemini.google.com/" || !geminiCheck.Required {
		t.Errorf("Gemini check = %+v; want required HTTP check for Gemini homepage", geminiCheck)
	}
	if accountsCheck == nil || accountsCheck.HTTPURL != "https://accounts.google.com/.well-known/openid-configuration" || !accountsCheck.Required || !accountsCheck.VerifyOIDC {
		t.Errorf("Accounts check = %+v; want required OIDC discovery check", accountsCheck)
	}
}

func TestNormalizeConfigAddsSystemDNSFirstToLegacyConfig(t *testing.T) {
	c := defaultConfig()
	filtered := c.Upstreams[:0]
	for _, upstream := range c.Upstreams {
		if upstream.ID != systemDNSUpstreamID {
			filtered = append(filtered, upstream)
		}
	}
	c.Upstreams = filtered
	group := c.Groups[0]
	group.Upstreams = group.Upstreams[1:]
	c.Groups[0] = group

	normalized, err := normalizeConfigGroups(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(normalized.Upstreams) != len(c.Upstreams)+1 {
		t.Fatalf("upstream count = %d, want %d", len(normalized.Upstreams), len(c.Upstreams)+1)
	}
	if normalized.Upstreams[0].ID != systemDNSUpstreamID || normalized.Upstreams[0].Type != "system" {
		t.Fatalf("first normalized upstream = %+v, want system DNS", normalized.Upstreams[0])
	}
	if normalized.Groups[0].Upstreams[0] != systemDNSUpstreamID {
		t.Fatalf("first group upstream = %q, want %q", normalized.Groups[0].Upstreams[0], systemDNSUpstreamID)
	}
}

func TestNormalizeConfigMovesExistingSystemDNSFirst(t *testing.T) {
	c := defaultConfig()
	c.Upstreams[0], c.Upstreams[1] = c.Upstreams[1], c.Upstreams[0]
	c.Groups[0].Upstreams[0], c.Groups[0].Upstreams[1] = c.Groups[0].Upstreams[1], c.Groups[0].Upstreams[0]

	normalized, err := normalizeConfigGroups(c)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.Upstreams[0].ID != systemDNSUpstreamID || normalized.Groups[0].Upstreams[0] != systemDNSUpstreamID {
		t.Fatalf("system DNS was not moved to first priority: upstreams=%v group=%v", normalized.Upstreams, normalized.Groups[0].Upstreams)
	}
}

func TestBuildSnapshotIncludesSystemDNSWithoutDoHURL(t *testing.T) {
	c := defaultConfig()
	urls := map[string]string{}
	for _, id := range []string{"eu.geohide.ru", "doh.dagami.ru", "dns.comss.one", "dns.bezmezhau.com", "dns.zapret.moe"} {
		urls[id] = "https://" + id + "/dns-query"
	}
	snapshot, err := buildSnapshot(c, urls)
	if err != nil {
		t.Fatal(err)
	}
	system := snapshot.upstreams[systemDNSUpstreamID]
	if system == nil || system.systemDNS == nil {
		t.Fatal("system DNS runtime was not created")
	}
	if system.client != nil || system.bootstrap != nil {
		t.Fatal("system DNS must not use a DoH HTTP client or bootstrap resolver")
	}
	for _, id := range []string{"eu.geohide.ru", "doh.dagami.ru", "dns.comss.one", "dns.bezmezhau.com", "dns.zapret.moe"} {
		if u := snapshot.upstreams[id]; u == nil || u.client == nil || u.bootstrap == nil {
			t.Errorf("DoH runtime %s was not built", id)
		}
	}
}

func TestBuildSnapshotRejectsDoHURLForSystemDNS(t *testing.T) {
	c := defaultConfig()
	urls := map[string]string{systemDNSUpstreamID: "https://system-dns/dns-query"}
	if _, err := buildSnapshot(c, urls); err == nil {
		t.Fatal("expected system DNS URL in doh-servers.txt to be rejected")
	}
}

func TestParseSystemDNSServersPreservesOrderAndDeduplicates(t *testing.T) {
	got := parseSystemDNSServers("# resolv.conf\nnameserver 8.8.8.8\nnameserver 2001:4860:4860::8888\nnameserver 8.8.8.8 # duplicate\nsearch example.test\n")
	want := []string{"8.8.8.8", "2001:4860:4860::8888"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("system DNS servers = %v, want %v", got, want)
	}
}

func TestReadSystemDNSServersRejectsEmptyResolverList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte("search example.test\nnameserver not-an-ip\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSystemDNSServers(path); err == nil {
		t.Fatal("expected invalid resolver file to be rejected")
	}
}

func TestExchangeSystemDNSUDP(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, maxDNSMessage)
		n, addr, readErr := server.ReadFromUDP(buf)
		if readErr != nil {
			done <- readErr
			return
		}
		_, writeErr := server.WriteToUDP(testAResponse(buf[:n], 45), addr)
		done <- writeErr
	}()

	query := makeDNSQuery("system.example", 1)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	response, err := exchangeSystemDNS(ctx, server.LocalAddr().String(), query)
	if err != nil {
		t.Fatal(err)
	}
	if dnsRCode(response) != 0 || dnsAnswerCount(response) != 1 {
		t.Fatalf("unexpected system DNS response: rcode=%d answers=%d", dnsRCode(response), dnsAnswerCount(response))
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestExchangeSystemDNSTCPFallbackWhenUDPTruncated(t *testing.T) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	port := tcpListener.Addr().(*net.TCPAddr).Port
	udpServer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer udpServer.Close()

	udpDone := make(chan error, 1)
	go func() {
		buf := make([]byte, maxDNSMessage)
		n, addr, readErr := udpServer.ReadFromUDP(buf)
		if readErr != nil {
			udpDone <- readErr
			return
		}
		truncated := testAResponse(buf[:n], 45)
		flags := binary.BigEndian.Uint16(truncated[2:4]) | 0x0200
		binary.BigEndian.PutUint16(truncated[2:4], flags)
		_, writeErr := udpServer.WriteToUDP(truncated, addr)
		udpDone <- writeErr
	}()

	tcpDone := make(chan error, 1)
	go func() {
		conn, acceptErr := tcpListener.Accept()
		if acceptErr != nil {
			tcpDone <- acceptErr
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		var header [2]byte
		if _, readErr := io.ReadFull(conn, header[:]); readErr != nil {
			tcpDone <- readErr
			return
		}
		length := int(binary.BigEndian.Uint16(header[:]))
		query := make([]byte, length)
		if _, readErr := io.ReadFull(conn, query); readErr != nil {
			tcpDone <- readErr
			return
		}
		response := testAResponse(query, 45)
		frame := make([]byte, len(response)+2)
		binary.BigEndian.PutUint16(frame[:2], uint16(len(response)))
		copy(frame[2:], response)
		_, writeErr := conn.Write(frame)
		tcpDone <- writeErr
	}()

	query := makeDNSQuery("large-system-response.example", 1)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	response, err := exchangeSystemDNS(ctx, net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), query)
	if err != nil {
		t.Fatal(err)
	}
	if dnsTruncated(response) || dnsAnswerCount(response) != 1 {
		t.Fatalf("TCP fallback response is still truncated or empty: truncated=%t answers=%d", dnsTruncated(response), dnsAnswerCount(response))
	}
	if err := <-udpDone; err != nil {
		t.Fatal(err)
	}
	if err := <-tcpDone; err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeConfigKeepsOnlyGoogleProfile(t *testing.T) {
	c := defaultConfig()
	google := c.Groups[0]
	c.Groups = append([]Group{{ID: "default", Upstreams: append([]string(nil), google.Upstreams...)}}, google)
	normalized, err := normalizeConfigGroups(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(normalized.Groups) != 1 || normalized.Groups[0].ID != "google" {
		t.Fatalf("normalized groups = %+v, want only google", normalized.Groups)
	}
}

func TestDNSGatewaySendsArbitraryQNAMEThroughGoogleProfile(t *testing.T) {
	var gotName string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Error(err)
			return
		}
		gotName, _, _, err = parseQuestion(body)
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(testAResponse(body, 45))
	}))
	defer srv.Close()

	query := makeDNSQuery("completely-unrelated.example", 1)
	upstream := &UpstreamRuntime{
		cfg: Upstream{ID: "selected-google-doh", URL: srv.URL},
		client: srv.Client(),
	}
	snapshot := &Snapshot{
		groups: map[string]Group{
			"google": {ID: "google", Upstreams: []string{"selected-google-doh"}},
		},
		upstreams: map[string]*UpstreamRuntime{"selected-google-doh": upstream},
	}
	rt := &Runtime{
		active: map[string]string{"google": "selected-google-doh"},
	}
	rt.snapshot.Store(snapshot)

	response, selected, err := rt.query(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	if selected != "selected-google-doh" {
		t.Fatalf("selected upstream = %q", selected)
	}
	if gotName != "completely-unrelated.example" {
		t.Fatalf("DoH received QNAME %q; want arbitrary QNAME unchanged", gotName)
	}
	if dnsRCode(response) != 0 || dnsAnswerCount(response) != 1 {
		t.Fatalf("unexpected DNS response rcode=%d answers=%d", dnsRCode(response), dnsAnswerCount(response))
	}
}

func intsToStrings(values []int) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = fmt.Sprint(value)
	}
	return out
}

func TestLoadDoHListCreatesProxyProviderDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "doh-servers.txt")
	urls, err := loadDoHList(path, true)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"eu.geohide.ru", "doh.dagami.ru", "dns.comss.one", "dns.bezmezhau.com", "dns.zapret.moe"}
	if len(urls) != len(want) {
		t.Fatalf("default DoH URL count = %d, want %d: %#v", len(urls), len(want), urls)
	}
	for _, host := range want {
		if urls[host] == "" {
			t.Errorf("default DoH URL missing %s", host)
		}
	}
	for _, excluded := range []string{"free.shecan.ir", "dns.google", "cloudflare-dns.com", "dns.quad9.net"} {
		if _, ok := urls[excluded]; ok {
			t.Errorf("excluded non-default provider %s is present", excluded)
		}
	}
}

func TestDefaultConfigUsesAutomaticBootstrap(t *testing.T) {
	c := defaultConfig()
	if len(c.BootstrapResolvers) == 0 {
		t.Fatal("expected independent bootstrap DNS resolvers")
	}
	for _, raw := range c.BootstrapResolvers {
		if net.ParseIP(raw) == nil {
			t.Fatalf("invalid bootstrap resolver IP %q", raw)
		}
	}
	for _, upstream := range c.Upstreams {
		if len(upstream.BootstrapIPs) != 0 {
			t.Errorf("upstream %s should use automatic bootstrap by default", upstream.ID)
		}
	}
	if err := validateConfig(c); err != nil {
		t.Fatalf("automatic-bootstrap default config invalid: %v", err)
	}
}

func TestLegacyBootstrapIPsRemainValidAsFallback(t *testing.T) {
	c := defaultConfig()
	c.Upstreams[0].BootstrapIPs = []string{"203.0.113.53"}
	if err := validateConfig(c); err != nil {
		t.Fatalf("legacy bootstrap_ips fallback rejected: %v", err)
	}
}

func TestLoadConfigCreatesAutomaticBootstrapDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	c, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.BootstrapResolvers) == 0 {
		t.Fatal("generated config has no bootstrap_resolvers")
	}
	for _, upstream := range c.Upstreams {
		if len(upstream.BootstrapIPs) != 0 {
			t.Errorf("generated upstream %s unexpectedly has static bootstrap_ips", upstream.ID)
		}
	}
}

func TestBootstrapSelectsFastestDoHIP(t *testing.T) {
	b := &bootstrapResolver{
		host: "doh.example",
		endpoint: "https://doh.example/dns-query",
		probe: func(ctx context.Context, endpoint, ip string, timeout time.Duration) (time.Duration, error) {
			switch ip {
			case "192.0.2.10":
				return 45 * time.Millisecond, nil
			case "192.0.2.20":
				return 8 * time.Millisecond, nil
			case "192.0.2.30":
				return 0, errors.New("unreachable")
			default:
				return 0, errors.New("unexpected test IP")
			}
		},
	}
	got, latency, err := b.fastestIP(context.Background(), []string{"192.0.2.10", "192.0.2.20", "192.0.2.30"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got != "192.0.2.20" {
		t.Fatalf("fastest IP = %s, want 192.0.2.20", got)
	}
	if latency != 8*time.Millisecond {
		t.Fatalf("fastest latency = %s, want 8ms", latency)
	}
}

func TestBootstrapFastestIPDetailedReportsEveryCandidate(t *testing.T) {
	b := &bootstrapResolver{
		host: "doh.example",
		endpoint: "https://doh.example/dns-query",
		probe: func(ctx context.Context, endpoint, ip string, timeout time.Duration) (time.Duration, error) {
			switch ip {
			case "192.0.2.10":
				return 45 * time.Millisecond, nil
			case "192.0.2.20":
				return 8 * time.Millisecond, nil
			case "192.0.2.30":
				return 3 * time.Millisecond, errors.New("TLS handshake failed")
			default:
				return 0, errors.New("unexpected test IP")
			}
		},
	}

	got, latency, results, err := b.fastestIPDetailed(context.Background(),
		[]string{"192.0.2.10", "192.0.2.20", "192.0.2.30"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got != "192.0.2.20" || latency != 8*time.Millisecond {
		t.Fatalf("winner = %s at %s, want 192.0.2.20 at 8ms", got, latency)
	}
	if len(results) != 3 {
		t.Fatalf("got %d probe results, want 3", len(results))
	}
	if results[0].IP != "192.0.2.10" || results[0].Result != "ok" || results[0].ResponseMS != 45 {
		t.Errorf("unexpected first probe result: %+v", results[0])
	}
	if results[1].IP != "192.0.2.20" || results[1].Result != "ok" || results[1].ResponseMS != 8 {
		t.Errorf("unexpected second probe result: %+v", results[1])
	}
	if results[2].IP != "192.0.2.30" || results[2].Result != "error" || !strings.Contains(results[2].Error, "TLS handshake failed") {
		t.Errorf("unexpected third probe result: %+v", results[2])
	}
}

func TestBootstrapFallbackSourceIsReportedDuringRetryCooldown(t *testing.T) {
	b := &bootstrapResolver{
		host:        "doh.example",
		endpoint:    "https://doh.example/dns-query",
		fallback:    []string{"192.0.2.77"},
		lastAttempt: time.Now(),
		refreshFor:  6 * time.Hour,
		probe: func(ctx context.Context, endpoint, ip string, timeout time.Duration) (time.Duration, error) {
			if ip != "192.0.2.77" {
				return 0, fmt.Errorf("unexpected probe IP %s", ip)
			}
			return 9 * time.Millisecond, nil
		},
	}

	ip, err := b.bestIP(context.Background(), false, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if ip != "192.0.2.77" {
		t.Fatalf("selected IP = %s, want configured fallback", ip)
	}
	status := b.status()
	if status.CandidateSource != "configured_fallback" {
		t.Errorf("candidate source = %q, want configured_fallback", status.CandidateSource)
	}
	if len(status.LastProbe) != 1 || status.LastProbe[0].Source != "configured_fallback" {
		t.Errorf("fallback probe source is not reported correctly: %+v", status.LastProbe)
	}
}

func TestBootstrapStatusReturnsDiagnosticSnapshot(t *testing.T) {
	probes := []DoHIPProbeStatus{
		{IP: "192.0.2.10", Source: "dns", Result: "ok", ResponseMS: 12},
	}
	b := &bootstrapResolver{
		host: "doh.example",
		ips: []string{"192.0.2.10", "2001:db8::10"},
		resolvedBy: "1.1.1.1",
		refreshed: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC),
		selectedIP: "192.0.2.10",
		selectedTil: time.Date(2026, 11, 10, 18, 0, 0, 0, time.UTC),
		lastCandidates: []string{"192.0.2.10", "2001:db8::10"},
		lastCandidateSource: "dns",
		lastProbeAt: time.Date(2026, 11, 10, 12, 1, 0, 0, time.UTC),
		lastProbe: probes,
	}
	status := b.status()
	if status.Hostname != "doh.example" || status.ResolvedBy != "1.1.1.1" || status.SelectedIP != "192.0.2.10" {
		t.Fatalf("unexpected bootstrap status: %+v", status)
	}
	if len(status.ResolvedIPs) != 2 || len(status.CandidateIPs) != 2 || len(status.LastProbe) != 1 {
		t.Fatalf("diagnostic lists not preserved: %+v", status)
	}
	status.ResolvedIPs[0] = "changed"
	status.LastProbe[0].IP = "changed"
	if b.ips[0] != "192.0.2.10" || b.lastProbe[0].IP != "192.0.2.10" {
		t.Fatal("status snapshot must not alias internal slices")
	}
}

func TestBootstrapFastestIPReportsAllFailures(t *testing.T) {
	b := &bootstrapResolver{
		host: "doh.example",
		endpoint: "https://doh.example/dns-query",
		probe: func(ctx context.Context, endpoint, ip string, timeout time.Duration) (time.Duration, error) {
			return 0, errors.New("probe failed")
		},
	}
	if _, _, err := b.fastestIP(context.Background(), []string{"192.0.2.1", "192.0.2.2"}, time.Second); err == nil {
		t.Fatal("expected all probes to fail")
	}
}

func TestDNSResponseTTLParse(t *testing.T) {
	q := makeDNSQuery("ttl.example", 1)
	resp := testAResponse(q, 120)
	ttl, ok := minResponseTTL(resp)
	if !ok || ttl != 120 {
		t.Fatalf("ttl=%d ok=%v", ttl, ok)
	}
	decrementTTLs(resp, 30)
	ttl, ok = minResponseTTL(resp)
	if !ok || ttl != 90 {
		t.Fatalf("decremented ttl=%d ok=%v", ttl, ok)
	}
	_ = time.Second
}

func TestRFC8484DoHRoundTrip(t *testing.T) {
	q := makeDNSQuery("wire.example", 1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method=%s", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/dns-message" {
			t.Errorf("content-type=%q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(testAResponse(body, 30))
	}))
	defer srv.Close()
	u := &UpstreamRuntime{cfg: Upstream{ID: "test", URL: srv.URL}, client: srv.Client()}
	got, err := sendDoH(context.Background(), u, q)
	if err != nil {
		t.Fatal(err)
	}
	if packetID(got) != packetID(q) {
		t.Fatal("transaction ID changed")
	}
	ips, err := parseARecords(got)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "203.0.113.10" {
		t.Fatalf("unexpected response: %#v", ips)
	}
}

func TestDoHListOneURLPerLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "doh-servers.txt")
	content := "# proxy providers\nhttps://eu.geohide.ru/dns-query\n\nhttps://doh.dagami.ru/dns-query\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	urls, err := loadDoHList(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if urls["eu.geohide.ru"] != "https://eu.geohide.ru/dns-query" {
		t.Fatalf("GeoHide URL: %q", urls["eu.geohide.ru"])
	}
	if urls["doh.dagami.ru"] != "https://doh.dagami.ru/dns-query" {
		t.Fatalf("Dagami URL: %q", urls["doh.dagami.ru"])
	}
}

func TestBuildSnapshotRequiresBootstrapEntryForDohHost(t *testing.T) {
	c := defaultConfig()
	if _, err := buildSnapshot(c, map[string]string{"unknown.example": "https://unknown.example/dns-query"}); err == nil {
		t.Fatal("expected unknown host to be rejected")
	}
}

func TestVerifyOIDCIssuerExactMatch(t *testing.T) {
	discovery := "https://accounts.example/.well-known/openid-configuration"
	valid := []byte(`{"issuer":"https://accounts.example"}`)
	if err := verifyOIDCIssuer(valid, discovery); err != nil {
		t.Fatalf("valid issuer rejected: %v", err)
	}
	cases := []struct {
		name string
		body []byte
		url  string
	}{
		{name: "wrong issuer host", body: []byte(`{"issuer":"https://evil.example"}`), url: discovery},
		{name: "issuer path mismatch", body: []byte(`{"issuer":"https://accounts.example/other"}`), url: discovery},
		{name: "userinfo", body: valid, url: "https://user@accounts.example/.well-known/openid-configuration"},
		{name: "query", body: valid, url: discovery + "?x=1"},
		{name: "http", body: valid, url: "http://accounts.example/.well-known/openid-configuration"},
		{name: "wrong discovery path", body: valid, url: "https://accounts.example/config"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := verifyOIDCIssuer(tc.body, tc.url); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestReadGeminiAPIKeySecurity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gemini_api_key")
	if err := os.WriteFile(path, []byte("test-key"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readGeminiAPIKey(dir, "gemini_api_key")
	if err != nil || string(got) != "test-key" {
		t.Fatalf("read key: %q, %v", got, err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readGeminiAPIKey(dir, "gemini_api_key"); err == nil {
		t.Fatal("expected unsafe permissions to be rejected")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, make([]byte, (8<<10)+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readGeminiAPIKey(dir, "gemini_api_key"); err == nil {
		t.Fatal("expected oversized key file to be rejected")
	}
	if _, err := readGeminiAPIKey(dir, "../outside"); err == nil {
		t.Fatal("expected path traversal to be rejected")
	}
}

func TestPublishHealthStateClearsUnavailableUpstream(t *testing.T) {
	s := &Snapshot{groups: map[string]Group{"google": {ID: "google", Upstreams: []string{"u1"}}}}
	r := &Runtime{
		health: map[string]map[string]HealthEntry{"google": {"u1": {State: "down"}}},
		active: map[string]string{"google": "u1"},
	}
	r.snapshot.Store(s)
	r.publishHealthState()
	if got := r.active["google"]; got != "" {
		t.Fatalf("active upstream = %q, want cleared", got)
	}
}

func TestRemoveSocketIfSame(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	unixLn := ln.(*net.UnixListener)
	unixLn.SetUnlinkOnClose(false)
	expected, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if err := removeSocketIfSame(path, expected); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("socket path still exists or cannot be checked: %v", err)
	}
}

func TestRemoveSocketIfSameRefusesReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	unixLn := ln.(*net.UnixListener)
	unixLn.SetUnlinkOnClose(false)
	expected, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("do not remove"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := removeSocketIfSame(path, expected); err == nil {
		t.Fatal("expected replacement path to be rejected")
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "do not remove" {
		t.Fatalf("replacement file was changed: data=%q err=%v", b, err)
	}
}


func TestLocalHostsOptionalAndFamilySpecificAnswers(t *testing.T) {
	if got, matched := localHostsResponse(makeDNSQuery("local.example", 1), "local.example", 1, nil); matched || got != nil {
		t.Fatal("empty local_hosts must not intercept DNS")
	}
	hosts := map[string]LocalHost{
		"local.example": {IPv4: []string{"192.0.2.10"}, IPv6: []string{"2001:db8::10"}},
		"v4-only.example": {IPv4: []string{"192.0.2.20"}},
	}
	for _, tc := range []struct {
		name string
		qtype uint16
		wantAnswers uint16
		wantAuthority uint16
	}{
		{"local.example", 1, 1, 0},
		{"local.example", 28, 1, 0},
		{"v4-only.example", 1, 1, 0},
		{"v4-only.example", 28, 0, 1},
		{"local.example", 64, 0, 1},
		{"local.example", 65, 0, 1},
	} {
		t.Run(tc.name+"/"+fmt.Sprint(tc.qtype), func(t *testing.T) {
			q := makeDNSQuery(tc.name, tc.qtype)
			// Ask for authenticated data; locally synthesized answers must never assert AD.
			binary.BigEndian.PutUint16(q[2:4], 0x0130)
			got, matched := localHostsResponse(q, tc.name, tc.qtype, hosts)
			if !matched { t.Fatal("expected local_hosts match") }
			if dnsRCode(got) != 0 { t.Fatalf("rcode=%d", dnsRCode(got)) }
			if binary.BigEndian.Uint16(got[2:4])&0x0020 != 0 { t.Fatal("AD flag must be clear") }
			if binary.BigEndian.Uint16(got[6:8]) != tc.wantAnswers { t.Fatalf("answers=%d", binary.BigEndian.Uint16(got[6:8])) }
			if binary.BigEndian.Uint16(got[8:10]) != tc.wantAuthority { t.Fatalf("authority=%d", binary.BigEndian.Uint16(got[8:10])) }
			positions, err := rrTTLPositions(got)
			if err != nil { t.Fatal(err) }
			if len(positions) == 0 { t.Fatal("expected answer or SOA TTL") }
			for _, pos := range positions {
				if ttl := binary.BigEndian.Uint32(got[pos:pos+4]); ttl != localHostsTTL { t.Fatalf("TTL=%d, want %d", ttl, localHostsTTL) }
			}
		})
	}
}

func TestLocalHostsDoesNotInterceptOtherTypesOrNames(t *testing.T) {
	hosts := map[string]LocalHost{"local.example": {IPv4: []string{"192.0.2.1"}}}
	for _, tc := range []struct{name string; qtype uint16}{
		{"local.example", 16}, // TXT continues through DoH
		{"other.example", 1},
	} {
		if _, matched := localHostsResponse(makeDNSQuery(tc.name, tc.qtype), tc.name, tc.qtype, hosts); matched {
			t.Fatalf("unexpected local interception for %s type %d", tc.name, tc.qtype)
		}
	}
}

func TestLocalHostsConfigValidation(t *testing.T) {
	c := defaultConfig()
	c.LocalHosts = map[string]LocalHost{"LOCAL.example.": {IPv4: []string{"192.0.2.1"}, IPv6: []string{"2001:db8::1"}}}
	if err := validateConfig(c); err != nil { t.Fatalf("valid local_hosts rejected: %v", err) }
	c.LocalHosts = map[string]LocalHost{"bad.example": {IPv4: []string{"2001:db8::1"}}}
	if err := validateConfig(c); err == nil { t.Fatal("expected IPv4 family validation error") }
	c.LocalHosts = map[string]LocalHost{"bad..example": {IPv4: []string{"192.0.2.1"}}}
	if err := validateConfig(c); err == nil { t.Fatal("expected hostname validation error") }
}


func TestLocalHostsPreservesEDNSOPTAndDoesNotOverrideNonIN(t *testing.T) {
	hosts := map[string]LocalHost{"local.example": {IPv4: []string{"192.0.2.1"}}}
	q := makeDNSQuery("local.example", 1)
	q = append(q, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0) // OPT, UDP payload 1232, empty options
	binary.BigEndian.PutUint16(q[10:12], 1)
	got, matched := localHostsResponse(q, "local.example", 1, hosts)
	if !matched { t.Fatal("expected local host match") }
	if binary.BigEndian.Uint16(got[10:12]) != 1 { t.Fatalf("additional count=%d, want 1", binary.BigEndian.Uint16(got[10:12])) }
	if !bytes.Contains(got, []byte{0, 0, 41, 4, 208}) { t.Fatal("EDNS OPT record was not echoed") }

	nonIN := makeDNSQuery("local.example", 1)
	nonIN[len(nonIN)-2] = 0
	nonIN[len(nonIN)-1] = 3
	if _, matched := localHostsResponse(nonIN, "local.example", 1, hosts); matched {
		t.Fatal("non-IN query must not be intercepted")
	}
}

func TestLocalHostsRejectsDuplicateNormalizedNames(t *testing.T) {
	c := defaultConfig()
	c.LocalHosts = map[string]LocalHost{
		"LOCAL.example": {IPv4: []string{"192.0.2.1"}},
		"local.example.": {IPv4: []string{"192.0.2.2"}},
	}
	if err := validateConfig(c); err == nil {
		t.Fatal("expected duplicate normalized hostname to be rejected")
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values { if value == want { return true } }
	return false
}
