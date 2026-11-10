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

func TestDefaultConfigUsesProxyDNSProvidersOnly(t *testing.T) {
	want := []string{
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
	for _, g := range c.Groups {
		if strings.Join(g.Upstreams, ",") != strings.Join(want, ",") {
			t.Errorf("group %s upstreams = %v, want %v", g.ID, g.Upstreams, want)
		}
	}
	google := c.Groups[1]
	if google.Checks[0].HTTPURL != "https://gemini.google.com/robots.txt" {
		t.Errorf("Gemini check URL = %q", google.Checks[0].HTTPURL)
	}
	if google.Checks[2].Domain != "connectivitycheck.gstatic.com" ||
		google.Checks[2].HTTPURL != "https://connectivitycheck.gstatic.com/generate_204" ||
		strings.Join(intsToStrings(google.Checks[2].ExpectedStatus), ",") != "204" {
		t.Errorf("Google connectivity check is not using the known-good 204 endpoint: %+v", google.Checks[2])
	}
	wantGoogleChecks := []string{
		"gemini.google.com", "accounts.google.com",
		"aistudio.google.com", "alkalimakersuite-pa.clients6.google.com", "apis.google.com",
		"www.googletagmanager.com", "waa-pa.clients6.google.com", "console.cloud.google.com",
		"people-pa.clients6.google.com", "ln3.googleusercontent.com", "www.google-analytics.com",
		"content-autofill.googleapis.com", "play.google.com", "ssl.gstatic.com", "www.googleapis.com",
	}
	gotGoogleChecks := make([]string, 0, len(google.Checks))
	for _, check := range google.Checks { gotGoogleChecks = append(gotGoogleChecks, check.Domain) }
	if strings.Join(gotGoogleChecks, ",") != strings.Join(wantGoogleChecks, ",") {
		t.Errorf("Google checks = %v, want %v", gotGoogleChecks, wantGoogleChecks)
	}
	if !containsString(google.Domains, "google-analytics.com") {
		t.Errorf("Google group domains must include google-analytics.com")
	}
	for _, g := range c.Groups {
		switch g.ID {
		case "openai":
			if g.Checks[0].HTTPURL != "https://chatgpt.com/robots.txt" {
				t.Errorf("OpenAI check URL = %q", g.Checks[0].HTTPURL)
			}
		case "youtube":
			if g.Checks[0].HTTPURL != "https://www.youtube.com/robots.txt" {
				t.Errorf("YouTube check URL = %q", g.Checks[0].HTTPURL)
			}
		}
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
