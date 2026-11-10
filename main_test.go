package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	c := CacheConfig{Enabled: true, MinTTL: 1, MaxTTL: 120, NegativeTTL: 10, MaxEntries: 10}
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

func TestDomainGroupLongestSuffixAndFakeDNS(t *testing.T) {
	c := defaultConfig()
	s, err := buildSnapshot(c, defaultDoHURLs())
	if err != nil {
		t.Fatal(err)
	}
	r := &Runtime{}
	cases := map[string]string{
		"gemini.google.com":       "google",
		"youtubei.googleapis.com": "youtube",
		"www.netflix.com":         "netflix",
		"chatgpt.com":             "openai",
		"ordinary.example":        "default",
	}
	for host, want := range cases {
		if got := r.groupFor(host, s); got != want {
			t.Errorf("groupFor(%s)=%s, want %s", host, got, want)
		}
	}
	for _, id := range []string{"google", "netflix", "openai", "youtube"} {
		if !s.groups[id].FakeDNS {
			t.Errorf("group %s should have FakeDNS enabled in example", id)
		}
	}
}

func TestDefaultConfigValid(t *testing.T) {
	if err := validateConfig(defaultConfig()); err != nil {
		t.Fatal(err)
	}
}

func TestErrorResponse(t *testing.T) {
	q := makeDNSQuery("bad.example", 1)
	r := servfailResponse(q)
	if dnsRCode(r) != 2 {
		t.Fatalf("rcode=%d, want SERVFAIL", dnsRCode(r))
	}
	if binary.BigEndian.Uint16(r[2:4])&0x8000 == 0 {
		t.Fatal("response bit not set")
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
	content := "# primary\nhttps://dns.google/dns-query\n\nhttps://cloudflare-dns.com/dns-query\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	urls, err := loadDoHList(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if urls["dns.google"] != "https://dns.google/dns-query" {
		t.Fatalf("google URL: %q", urls["dns.google"])
	}
	if urls["cloudflare-dns.com"] != "https://cloudflare-dns.com/dns-query" {
		t.Fatalf("cloudflare URL: %q", urls["cloudflare-dns.com"])
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
	s := &Snapshot{groups: map[string]Group{"default": {ID: "default", Upstreams: []string{"u1"}}}}
	r := &Runtime{
		health: map[string]map[string]HealthEntry{"default": {"u1": {State: "down"}}},
		active: map[string]string{"default": "u1"},
	}
	r.snapshot.Store(s)
	r.publishHealthState()
	if got := r.active["default"]; got != "" {
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
