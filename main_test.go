package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lucx-doh-health-monitor/internal/autohosts"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func testProtoVarint(value uint64) []byte {
	var out []byte
	for value >= 0x80 {
		out = append(out, byte(value)|0x80)
		value >>= 7
	}
	return append(out, byte(value))
}

func testProtoBytesField(field int, value []byte) []byte {
	out := testProtoVarint(uint64(field<<3 | 2))
	out = append(out, testProtoVarint(uint64(len(value)))...)
	return append(out, value...)
}

func testProtoVarintField(field int, value uint64) []byte {
	out := testProtoVarint(uint64(field << 3))
	return append(out, testProtoVarint(value)...)
}

func testGeositeData(domains ...string) []byte {
	category := testProtoBytesField(1, []byte("TEST"))
	for _, name := range domains {
		domain := testProtoVarintField(1, 2) // Domain suffix rule.
		domain = append(domain, testProtoBytesField(2, []byte(name))...)
		category = append(category, testProtoBytesField(2, domain)...)
	}
	return testProtoBytesField(1, category)
}

func newTestGeositeIndex(t *testing.T, domains ...string) *geositeIndex {
	t.Helper()
	data := testGeositeData(domains...)
	path := filepath.Join(t.TempDir(), "geosite.dat")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	index, err := newGeositeIndex(path, []string{"TEST"})
	if err != nil {
		t.Fatal(err)
	}
	return index
}

func startTestAutoHostsRecorder(t *testing.T, runtime *Runtime, domains ...string) {
	t.Helper()
	runtime.geo = newTestGeositeIndex(t, domains...)
	runtime.autoHostsQueryQueue = make(chan *autoHostsQueryJob, 32)
	runtime.autoHostsQueued = make(map[string]*autoHostsQueryJob)
	ctx, cancel := context.WithCancel(context.Background())
	go runtime.runAutoHostsQueryRecorder(ctx)
	t.Cleanup(cancel)
}

func newTestVPSResolveUpstream(t *testing.T, handler http.HandlerFunc) *UpstreamRuntime {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	return &UpstreamRuntime{
		cfg:    Upstream{ID: "vps-resolve", URL: server.URL},
		client: server.Client(),
	}
}

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

func TestGeositeIndexRetainsLastKnownGoodMatcherOnReloadFailure(t *testing.T) {
	index := newTestGeositeIndex(t, "example.com")
	if !index.MatchAny("www.example.com") {
		t.Fatal("initial matcher did not match expected domain")
	}
	original, err := os.ReadFile(index.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(index.path, []byte{0xff, 0x00}, 0600); err != nil {
		t.Fatal(err)
	}
	if err := index.Reload([]string{"TEST"}); err == nil {
		t.Fatal("expected invalid geosite.dat reload to fail")
	}
	if !index.MatchAny("www.example.com") {
		t.Fatal("failed reload replaced the last known-good matcher")
	}
	status := index.Status()
	if !status.Loaded || status.LastError == "" {
		t.Fatalf("failed reload status is incomplete: %+v", status)
	}
	if len(status.LoadedCategories) != 1 || status.LoadedCategories[0] != "TEST" {
		t.Fatalf("loaded categories changed after failed reload: %+v", status.LoadedCategories)
	}
	if err := os.WriteFile(index.path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := index.Reload([]string{"TEST"}); err != nil {
		t.Fatalf("valid geosite.dat reload failed: %v", err)
	}
	status = index.Status()
	if status.LastError != "" || !status.Loaded {
		t.Fatalf("successful reload did not clear error: %+v", status)
	}
}

func TestGeositeAtomicReplacementDetectedByContentHash(t *testing.T) {
	index := newTestGeositeIndex(t, "old.example")
	oldInfo, err := os.Stat(index.path)
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(filepath.Dir(index.path), "geosite.next")
	data := testGeositeData("new.example") // Same byte length as old.example.
	if err := os.WriteFile(replacement, data, 0600); err != nil {
		t.Fatal(err)
	}
	if int64(len(data)) != oldInfo.Size() {
		t.Fatalf("fixture sizes differ: old=%d new=%d", oldInfo.Size(), len(data))
	}
	if err := os.Chtimes(replacement, oldInfo.ModTime(), oldInfo.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, index.path); err != nil {
		t.Fatal(err)
	}
	if err := index.reloadIfChanged(); err != nil {
		t.Fatalf("reload after atomic rename: %v", err)
	}
	if index.MatchAny("www.old.example") || !index.MatchAny("www.new.example") {
		t.Fatal("content-hash reload did not atomically switch to the replacement matcher")
	}
	if got := index.Status().FileSHA256; got == "" {
		t.Fatal("status does not expose loaded content digest")
	}
}

func TestGeositeTemporaryUnavailableRetainsMatcherAndRecovers(t *testing.T) {
	index := newTestGeositeIndex(t, "old.example")
	parked := index.path + ".parked"
	if err := os.Rename(index.path, parked); err != nil {
		t.Fatal(err)
	}
	if err := index.reloadIfChanged(); err == nil {
		t.Fatal("expected missing geosite.dat to report an error")
	}
	if !index.MatchAny("old.example") {
		t.Fatal("temporary file unavailability discarded the last known-good matcher")
	}
	if err := os.Rename(parked, index.path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(parked, testGeositeData("new.example"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(parked, index.path); err != nil {
		t.Fatal(err)
	}
	if err := index.reloadIfChanged(); err != nil {
		t.Fatalf("recovery reload failed: %v", err)
	}
	if index.MatchAny("old.example") || !index.MatchAny("new.example") {
		t.Fatal("recovered matcher was not applied")
	}
	if status := index.Status(); status.LastError != "" {
		t.Fatalf("successful recovery left error: %s", status.LastError)
	}
}

func TestGeositePeriodicReloadAppliesReplacementWithoutListenerRestart(t *testing.T) {
	index := newTestGeositeIndex(t, "old.example")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		index.runWithInterval(ctx, 5*time.Millisecond)
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()
	replacement := index.path + ".next"
	if err := os.WriteFile(replacement, testGeositeData("new.example"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, index.path); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if index.MatchAny("new.example") && !index.MatchAny("old.example") {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("periodic Geosite reload did not apply the replacement")
}

func TestGeositeConcurrentReadersObserveCompleteMatchers(t *testing.T) {
	index := newTestGeositeIndex(t, "old.example")
	var readers sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				matcher := index.matcher.Load()
				if matcher == nil {
					t.Error("reader observed nil matcher")
					return
				}
				oldMatch := matcher.MatchAny("old.example")
				newMatch := matcher.MatchAny("new.example")
				if oldMatch == newMatch {
					t.Errorf("reader observed incomplete matcher state: old=%t new=%t", oldMatch, newMatch)
					return
				}
			}
		}()
	}
	for i := 0; i < 20; i++ {
		domain := "new.example"
		if i%2 == 1 {
			domain = "old.example"
		}
		tmp := index.path + ".next"
		if err := os.WriteFile(tmp, testGeositeData(domain), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, index.path); err != nil {
			t.Fatal(err)
		}
		if err := index.reloadIfChanged(); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	readers.Wait()
}

func TestGeositeIndexLoadsConfiguredRealAsset(t *testing.T) {
	path := strings.TrimSpace(os.Getenv("LUCX_TEST_GEOSITE_DAT"))
	if path == "" {
		t.Skip("set LUCX_TEST_GEOSITE_DAT to exercise a production geosite.dat asset")
	}
	categories := strings.Split(os.Getenv("LUCX_TEST_GEOSITE_CATEGORIES"), ",")
	if strings.TrimSpace(os.Getenv("LUCX_TEST_GEOSITE_CATEGORIES")) == "" {
		categories = []string{"CN"}
	}
	index, err := newGeositeIndex(path, categories)
	if err != nil {
		t.Fatalf("load real geosite.dat: %v", err)
	}
	if !index.Status().Loaded || index.Status().FileSHA256 == "" {
		t.Fatalf("real geosite.dat was not recorded as loaded: %+v", index.Status())
	}
}

func TestGeositeDataPathUsesDefaultAndConfiguredOverride(t *testing.T) {
	dataDir := filepath.Join(string(filepath.Separator), "usr", "local", "x-ui", "bin", "plugins", "doh-health-monitor", "data")
	if got, want := geositeDataPath(dataDir), filepath.Join(string(filepath.Separator), "usr", "local", "x-ui", "bin", "geosite.dat"); got != want {
		t.Fatalf("default geosite path=%q, want %q", got, want)
	}
	if got, want := geositeDataPath(dataDir, "/opt/xray-assets/geosite.dat"), filepath.Join(string(filepath.Separator), "opt", "xray-assets", "geosite.dat"); got != want {
		t.Fatalf("override geosite path=%q, want %q", got, want)
	}
}

func TestValidateConfigRejectsRelativeGeositePath(t *testing.T) {
	cfg := defaultConfig()
	cfg.GeositePath = "assets/geosite.dat"
	if err := validateConfig(cfg); err == nil {
		t.Fatal("relative geosite_path must be rejected")
	}
}

func TestValidateDNSResponseMatchesFullQuestion(t *testing.T) {
	query := makeDNSQuery("www.example.com", 1)
	response := testAResponse(query, 60)
	if err := validateDNSResponse(query, response, "test"); err != nil {
		t.Fatalf("valid response rejected: %v", err)
	}
	t.Run("qclass mismatch", func(t *testing.T) {
		bad := append([]byte(nil), response...)
		_, _, end, err := parseQuestion(bad)
		if err != nil {
			t.Fatal(err)
		}
		binary.BigEndian.PutUint16(bad[end-2:end], 3)
		if err := validateDNSResponse(query, bad, "test"); err == nil {
			t.Fatal("expected QCLASS mismatch to be rejected")
		}
	})
	t.Run("qtype mismatch", func(t *testing.T) {
		bad := append([]byte(nil), response...)
		_, _, end, err := parseQuestion(bad)
		if err != nil {
			t.Fatal(err)
		}
		binary.BigEndian.PutUint16(bad[end-4:end-2], 28)
		if err := validateDNSResponse(query, bad, "test"); err == nil {
			t.Fatal("expected QTYPE mismatch to be rejected")
		}
	})
	t.Run("qname mismatch", func(t *testing.T) {
		other := makeDNSQuery("other.example.com", 1)
		bad := testAResponse(other, 60)
		binary.BigEndian.PutUint16(bad[:2], packetID(query))
		if err := validateDNSResponse(query, bad, "test"); err == nil {
			t.Fatal("expected QNAME mismatch to be rejected")
		}
	})
	t.Run("opcode mismatch", func(t *testing.T) {
		bad := append([]byte(nil), response...)
		flags := binary.BigEndian.Uint16(bad[2:4])
		binary.BigEndian.PutUint16(bad[2:4], (flags&^0x7800)|0x0800)
		if err := validateDNSResponse(query, bad, "test"); err == nil {
			t.Fatal("expected opcode mismatch to be rejected")
		}
	})
}

func TestUpstreamCooldownSkipsFailedEndpointsAndRecovers(t *testing.T) {
	now := time.Now()
	r := &Runtime{upstreamCooldown: map[string]time.Time{"bad": now.Add(upstreamFailureCooldown)}}
	got := r.upstreamsToAttempt([]string{"bad", "healthy"}, now)
	if strings.Join(got, ",") != "healthy" {
		t.Fatalf("attempt order = %v, want only healthy upstream", got)
	}
	got = r.upstreamsToAttempt([]string{"bad", "healthy"}, now.Add(upstreamFailureCooldown+time.Second))
	if strings.Join(got, ",") != "bad,healthy" {
		t.Fatalf("expired cooldown attempt order = %v, want [bad healthy]", got)
	}
}

func TestUpstreamCooldownProbesOnlyEarliestWhenAllCooling(t *testing.T) {
	now := time.Now()
	r := &Runtime{upstreamCooldown: map[string]time.Time{"later": now.Add(20 * time.Second), "first": now.Add(5 * time.Second)}}
	got := r.upstreamsToAttempt([]string{"later", "first"}, now)
	if len(got) != 1 || got[0] != "first" {
		t.Fatalf("attempt order = %v, want earliest-expiring upstream only", got)
	}
}

func TestSelectAlternateIPExcludesFailedAddress(t *testing.T) {
	now := time.Now()
	b := &bootstrapResolver{
		host: "doh.example", endpoint: "https://doh.example/dns-query",
		ips:       []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"},
		refreshed: now, refreshFor: time.Hour, selectedIP: "192.0.2.1",
		probe: func(_ context.Context, _ string, ip string, _ time.Duration) (time.Duration, error) {
			switch ip {
			case "192.0.2.2":
				return 30 * time.Millisecond, nil
			case "192.0.2.3":
				return 10 * time.Millisecond, nil
			default:
				return 0, errors.New("unexpected candidate")
			}
		},
	}
	got, err := b.selectAlternateIP(context.Background(), "192.0.2.1", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got != "192.0.2.3" {
		t.Fatalf("alternate IP = %s, want 192.0.2.3", got)
	}
	if b.status().SelectedIP != got {
		t.Fatalf("selected IP = %s, want %s", b.status().SelectedIP, got)
	}
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

func TestConfigCanDisableSystemDNSWithoutNormalizerReaddingIt(t *testing.T) {
	cfg := defaultConfig()
	upstreams := make([]Upstream, 0, len(cfg.Upstreams)-1)
	for _, upstream := range cfg.Upstreams {
		if upstream.ID != systemDNSUpstreamID {
			upstreams = append(upstreams, upstream)
		}
	}
	cfg.Upstreams = upstreams
	groupUpstreams := make([]string, 0, len(cfg.Groups[0].Upstreams)-1)
	for _, id := range cfg.Groups[0].Upstreams {
		if id != systemDNSUpstreamID {
			groupUpstreams = append(groupUpstreams, id)
		}
	}
	cfg.Groups[0].Upstreams = groupUpstreams

	normalized, err := normalizeConfigGroups(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, upstream := range normalized.Upstreams {
		if upstream.ID == systemDNSUpstreamID {
			t.Fatal("normalizer re-added disabled system-dns")
		}
	}
	for _, id := range normalized.Groups[0].Upstreams {
		if id == systemDNSUpstreamID {
			t.Fatal("normalizer re-added system-dns to the group")
		}
	}
	if err := validateConfig(normalized); err != nil {
		t.Fatalf("configuration without system DNS should validate: %v", err)
	}
	urls := map[string]string{}
	for _, upstream := range normalized.Upstreams {
		urls[upstream.ID] = "https://resolver.example/dns-query"
	}
	snapshot, err := buildSnapshot(normalized, urls)
	if err != nil {
		t.Fatalf("build snapshot without system DNS: %v", err)
	}
	if _, exists := snapshot.upstreams[systemDNSUpstreamID]; exists {
		t.Fatal("snapshot recreated disabled system-dns")
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
	if c.Health.FailureThreshold != 1 {
		t.Fatalf("failure threshold=%d, want one failed check", c.Health.FailureThreshold)
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
		groups:    map[string]Group{"google": {ID: "google", Upstreams: []string{"current"}}},
		upstreams: map[string]*UpstreamRuntime{"current": {}},
	}
	r := &Runtime{
		health: map[string]map[string]HealthEntry{
			"google":    {"current": {State: "up"}, "removed": {State: "down"}},
			"old-group": {"stale": {State: "down"}},
		},
		active:     map[string]string{"google": "current", "old-group": "stale"},
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
	upstreamServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		q, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		time.Sleep(20 * time.Millisecond)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(testAResponse(q, 60))
	}))
	upstreamServer.EnableHTTP2 = true
	upstreamServer.StartTLS()
	defer upstreamServer.Close()

	vpsResolve := &UpstreamRuntime{
		cfg:    Upstream{ID: "vps-resolve", URL: upstreamServer.URL},
		client: upstreamServer.Client(),
	}
	s := &Snapshot{
		cfg: Config{
			DNSMaxConcurrent:       1,
			DNSQueryTimeoutSeconds: 3,
			DoHTimeoutSeconds:      3,
			Cache:                  CacheConfig{Enabled: false},
		},
	}
	r := &Runtime{
		dnsSem:     make(chan struct{}, 1),
		cache:      map[string]cacheItem{},
		vpsResolve: vpsResolve,
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
	const maxObservedQueueDepth = udpQueueCapacity + 1
	if queued := r.udpQueueDepth.Load(); queued > maxObservedQueueDepth {
		t.Fatalf("UDP pending+dispatch depth=%d, maximum=%d (queue=%d, workers=1)", queued, maxObservedQueueDepth, udpQueueCapacity)
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
		"geohide-eu",
		"dagami",
		"comss-one",
		"bezmezhau",
		"zapret",
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

func TestNormalizeConfigDoesNotReAddDisabledSystemDNS(t *testing.T) {
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
	if len(normalized.Upstreams) != len(c.Upstreams) {
		t.Fatalf("upstream count = %d, want unchanged count %d", len(normalized.Upstreams), len(c.Upstreams))
	}
	for _, upstream := range normalized.Upstreams {
		if upstream.ID == systemDNSUpstreamID {
			t.Fatal("normalizer re-added disabled system-dns")
		}
	}
	for _, id := range normalized.Groups[0].Upstreams {
		if id == systemDNSUpstreamID {
			t.Fatal("normalizer re-added disabled system-dns to the Google group")
		}
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
	urls := map[string]string{
		"geohide-eu": "https://eu.geohide.ru/dns-query",
		"dagami":     "https://dns.dagami.ru/dns-query",
		"comss-one":  "https://dns.comss.one/dns-query",
		"bezmezhau":  "https://dns.bezmezhau.com/dns-query",
		"zapret":     "https://dns.zapret.moe/dns-query",
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
	for _, id := range []string{"geohide-eu", "dagami", "comss-one", "bezmezhau", "zapret"} {
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

func TestGeositeMissUsesDedicatedQuad9OverHTTP2(t *testing.T) {
	var gotName string
	var protocolMajor int
	upstream := newTestVPSResolveUpstream(t, func(w http.ResponseWriter, req *http.Request) {
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
		protocolMajor = req.ProtoMajor
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(testAResponse(body, 45))
	})
	rt := &Runtime{
		vpsResolve: upstream,
		dnsSem:     make(chan struct{}, 1),
		geo:        newTestGeositeIndex(t, "chatgpt.com"),
	}
	rt.snapshot.Store(&Snapshot{cfg: Config{
		DNSQueryTimeoutSeconds: 3,
		DoHTimeoutSeconds:      3,
		Cache:                  CacheConfig{Enabled: false},
	}})
	query := makeDNSQuery("completely-unrelated.example", 1)
	response := rt.handleDNS(query)
	if dnsRCode(response) != 0 || dnsAnswerCount(response) != 1 {
		t.Fatalf("Geosite MISS Quad9 response rcode=%d answers=%d", dnsRCode(response), dnsAnswerCount(response))
	}
	if gotName != "completely-unrelated.example" {
		t.Fatalf("vps-resolve received QNAME %q; want original QNAME", gotName)
	}
	if protocolMajor != 2 {
		t.Fatalf("vps-resolve negotiated HTTP/%d; want HTTP/2", protocolMajor)
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
	want := []string{"geohide-eu", "dagami", "comss-one", "bezmezhau", "zapret"}
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
	var doh *Upstream
	for i := range c.Upstreams {
		if c.Upstreams[i].Type != "system" {
			doh = &c.Upstreams[i]
			break
		}
	}
	if doh == nil {
		t.Fatal("default config has no DoH upstream")
	}
	doh.BootstrapIPs = []string{"203.0.113.53"}
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
		host:     "doh.example",
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
		host:     "doh.example",
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
		host:                "doh.example",
		ips:                 []string{"192.0.2.10", "2001:db8::10"},
		resolvedBy:          "1.1.1.1",
		refreshed:           time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC),
		selectedIP:          "192.0.2.10",
		selectedTil:         time.Date(2026, 11, 10, 18, 0, 0, 0, time.UTC),
		lastCandidates:      []string{"192.0.2.10", "2001:db8::10"},
		lastCandidateSource: "dns",
		lastProbeAt:         time.Date(2026, 11, 10, 12, 1, 0, 0, time.UTC),
		lastProbe:           probes,
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
		host:     "doh.example",
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
	content := "# id;url\ngeohide-eu;https://eu.geohide.ru/dns-query\n\ndagami;https://dns.dagami.ru/dns-query\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	urls, err := loadDoHList(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if urls["geohide-eu"] != "https://eu.geohide.ru/dns-query" {
		t.Fatalf("GeoHide URL: %q", urls["geohide-eu"])
	}
	if urls["dagami"] != "https://dns.dagami.ru/dns-query" {
		t.Fatalf("Dagami URL: %q", urls["dagami"])
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
		"local.example":   {IPv4: []string{"192.0.2.10"}, IPv6: []string{"2001:db8::10"}},
		"v4-only.example": {IPv4: []string{"192.0.2.20"}},
	}
	for _, tc := range []struct {
		name          string
		qtype         uint16
		wantAnswers   uint16
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
			if !matched {
				t.Fatal("expected local_hosts match")
			}
			if dnsRCode(got) != 0 {
				t.Fatalf("rcode=%d", dnsRCode(got))
			}
			if binary.BigEndian.Uint16(got[2:4])&0x0020 != 0 {
				t.Fatal("AD flag must be clear")
			}
			if binary.BigEndian.Uint16(got[6:8]) != tc.wantAnswers {
				t.Fatalf("answers=%d", binary.BigEndian.Uint16(got[6:8]))
			}
			if binary.BigEndian.Uint16(got[8:10]) != tc.wantAuthority {
				t.Fatalf("authority=%d", binary.BigEndian.Uint16(got[8:10]))
			}
			positions, err := rrTTLPositions(got)
			if err != nil {
				t.Fatal(err)
			}
			if len(positions) == 0 {
				t.Fatal("expected answer or SOA TTL")
			}
			for _, pos := range positions {
				if ttl := binary.BigEndian.Uint32(got[pos : pos+4]); ttl != localHostsTTL {
					t.Fatalf("TTL=%d, want %d", ttl, localHostsTTL)
				}
			}
		})
	}
}

func TestLocalHostsDoesNotInterceptOtherTypesOrNames(t *testing.T) {
	hosts := map[string]LocalHost{"local.example": {IPv4: []string{"192.0.2.1"}}}
	for _, tc := range []struct {
		name  string
		qtype uint16
	}{
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
	if err := validateConfig(c); err != nil {
		t.Fatalf("valid local_hosts rejected: %v", err)
	}
	c.LocalHosts = map[string]LocalHost{"bad.example": {IPv4: []string{"2001:db8::1"}}}
	if err := validateConfig(c); err == nil {
		t.Fatal("expected IPv4 family validation error")
	}
	c.LocalHosts = map[string]LocalHost{"bad..example": {IPv4: []string{"192.0.2.1"}}}
	if err := validateConfig(c); err == nil {
		t.Fatal("expected hostname validation error")
	}
}

func TestLocalHostsPreservesEDNSOPTAndDoesNotOverrideNonIN(t *testing.T) {
	hosts := map[string]LocalHost{"local.example": {IPv4: []string{"192.0.2.1"}}}
	q := makeDNSQuery("local.example", 1)
	q = append(q, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0) // OPT, UDP payload 1232, empty options
	binary.BigEndian.PutUint16(q[10:12], 1)
	got, matched := localHostsResponse(q, "local.example", 1, hosts)
	if !matched {
		t.Fatal("expected local host match")
	}
	if binary.BigEndian.Uint16(got[10:12]) != 1 {
		t.Fatalf("additional count=%d, want 1", binary.BigEndian.Uint16(got[10:12]))
	}
	if !bytes.Contains(got, []byte{0, 0, 41, 4, 208}) {
		t.Fatal("EDNS OPT record was not echoed")
	}

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
		"LOCAL.example":  {IPv4: []string{"192.0.2.1"}},
		"local.example.": {IPv4: []string{"192.0.2.2"}},
	}
	if err := validateConfig(c); err == nil {
		t.Fatal("expected duplicate normalized hostname to be rejected")
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestSetIntegrationFlagPreservesConfigAndToggles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	original := []byte("{\"dns_listen_udp\":\"127.0.0.1:5355\",\"custom\":{\"keep\":true}}\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := setIntegrationFlag(path, true); err != nil {
		t.Fatalf("set integration=true: %v", err)
	}
	read := func() map[string]any {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		if err := json.Unmarshal(data, &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	config := read()
	if config["integration"] != true {
		t.Fatalf("integration flag=%v, want true", config["integration"])
	}
	if config["dns_listen_udp"] != "127.0.0.1:5355" {
		t.Fatalf("unrelated config key changed: %#v", config)
	}
	if nested := config["custom"].(map[string]any); nested["keep"] != true {
		t.Fatalf("unknown nested config key changed: %#v", nested)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("config permissions=%#o, want 0600", info.Mode().Perm())
	}
	if err := setIntegrationFlag(path, false); err != nil {
		t.Fatalf("set integration=false: %v", err)
	}
	config = read()
	if config["integration"] != false {
		t.Fatalf("integration flag=%v, want false", config["integration"])
	}
}

func TestAutoHostsDNSAnswersUseActiveEndpointAndFamilyNODATA(t *testing.T) {
	now := time.Now().UTC()
	manager, err := autohosts.New(filepath.Join(t.TempDir(), "auto-hosts.json"))
	if err != nil {
		t.Fatal(err)
	}
	endpoint := autohosts.Endpoint{ServerID: "edge", URL: "https://dns.example/dns-query", Hostname: "dns.example", IPv4: []string{"8.8.8.8"}, UpdatedAt: now}
	if err := manager.ApplyCycle("edge", endpoint, []autohosts.ProbeResult{{Domain: "chatgpt.com", Success: true, CheckedAt: now}}, now); err != nil {
		t.Fatal(err)
	}
	if err := manager.SetEnabled(true); err != nil {
		t.Fatal(err)
	}

	aQuery := makeDNSQuery("chatgpt.com", 1)
	aResponse, matched := autoHostsResponse(aQuery, "chatgpt.com", 1, manager)
	if !matched {
		t.Fatal("expected Auto Hosts A match")
	}
	aRecords, err := parseARecords(aResponse)
	if err != nil {
		t.Fatal(err)
	}
	if len(aRecords) != 1 || aRecords[0] != "8.8.8.8" {
		t.Fatalf("Auto Hosts must return active DoH endpoint IP, got %v", aRecords)
	}

	aaaaResponse, matched := autoHostsResponse(makeDNSQuery("chatgpt.com", 28), "chatgpt.com", 28, manager)
	if !matched {
		t.Fatal("IPv4-only endpoint must still match AAAA and return NODATA")
	}
	if binary.BigEndian.Uint16(aaaaResponse[6:8]) != 0 || binary.BigEndian.Uint16(aaaaResponse[8:10]) != 1 {
		t.Fatalf("expected NODATA with local SOA, answer=%d authority=%d", binary.BigEndian.Uint16(aaaaResponse[6:8]), binary.BigEndian.Uint16(aaaaResponse[8:10]))
	}
	httpsResponse, matched := autoHostsResponse(makeDNSQuery("chatgpt.com", 65), "chatgpt.com", 65, manager)
	if !matched || binary.BigEndian.Uint16(httpsResponse[6:8]) != 0 {
		t.Fatal("HTTPS query must be locally answered with NODATA for Auto Hosts domain")
	}
}

func TestManualLocalHostsTakePriorityOverAutoHosts(t *testing.T) {
	now := time.Now().UTC()
	manager, err := autohosts.New(filepath.Join(t.TempDir(), "auto-hosts.json"))
	if err != nil {
		t.Fatal(err)
	}
	endpoint := autohosts.Endpoint{ServerID: "edge", URL: "https://dns.example/dns-query", Hostname: "dns.example", IPv4: []string{"8.8.8.8"}}
	if err := manager.ApplyCycle("edge", endpoint, []autohosts.ProbeResult{{Domain: "chatgpt.com", Success: true, CheckedAt: now}}, now); err != nil {
		t.Fatal(err)
	}
	if err := manager.SetEnabled(true); err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{autoHosts: manager, dnsSem: make(chan struct{}, 1)}
	startTestAutoHostsRecorder(t, runtime, "chatgpt.com")
	runtime.snapshot.Store(&Snapshot{localHosts: map[string]LocalHost{"chatgpt.com": {IPv4: []string{"1.2.3.4"}}}})
	response := runtime.handleDNS(makeDNSQuery("chatgpt.com", 1))
	ips, err := parseARecords(response)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "1.2.3.4" {
		t.Fatalf("manual local_hosts must win over Auto Hosts, got %v", ips)
	}
}

func TestAutoHostsHTTPSettingsAndStatusHandlers(t *testing.T) {
	manager, err := autohosts.New(filepath.Join(t.TempDir(), "auto-hosts.json"))
	if err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{autoHosts: manager}
	request := httptest.NewRequest(http.MethodPost, "/autohosts/config", strings.NewReader("{\"enabled\":true,\"emergency_off\":true}"))
	response := httptest.NewRecorder()
	runtime.handleAutoHostsConfig(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("config handler returned %d: %s", response.Code, response.Body.String())
	}
	if !manager.State().Config.Enabled || !manager.State().Config.EmergencyOff {
		t.Fatal("settings were not applied")
	}
	statusRequest := httptest.NewRequest(http.MethodGet, "/autohosts/status", nil)
	statusResponse := httptest.NewRecorder()
	runtime.handleAutoHostsStatus(statusResponse, statusRequest)
	if statusResponse.Code != http.StatusOK {
		t.Fatalf("status handler returned %d", statusResponse.Code)
	}
	var state autohosts.State
	if err := json.Unmarshal(statusResponse.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if !state.Config.Enabled || !state.Config.EmergencyOff {
		t.Fatal("status response omitted persisted settings")
	}
}

func TestAutoHostsDryRunHandlerDoesNotMutateStateOnUnavailableEndpoints(t *testing.T) {
	manager, err := autohosts.New(filepath.Join(t.TempDir(), "auto-hosts.json"))
	if err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{autoHosts: manager}
	runtime.snapshot.Store(&Snapshot{upstreams: map[string]*UpstreamRuntime{}, groups: map[string]Group{}})
	runtime.autoController = newAutoHostsController(runtime, manager)
	before := manager.State()
	request := httptest.NewRequest(http.MethodPost, "/autohosts/dry-run", strings.NewReader("{}"))
	response := httptest.NewRecorder()
	runtime.handleAutoHostsDryRun(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected unavailable endpoint result, got %d", response.Code)
	}
	after := manager.State()
	if before.ActiveServer != after.ActiveServer || len(before.Domains) != len(after.Domains) || before.UpdatedAt != after.UpdatedAt {
		t.Fatal("failed Dry Run mutated Auto Hosts persistent state")
	}
}

func TestHandleDNSAutoHostsEndToEndAndEmergencyBypass(t *testing.T) {
	now := time.Now().UTC()
	manager, err := autohosts.New(filepath.Join(t.TempDir(), "auto-hosts.json"))
	if err != nil {
		t.Fatal(err)
	}
	endpoint := autohosts.Endpoint{ServerID: "edge", URL: "https://dns.example/dns-query", Hostname: "dns.example", IPv4: []string{"8.8.4.4"}, UpdatedAt: now}
	if err := manager.ApplyCycle("edge", endpoint, []autohosts.ProbeResult{{Domain: "chatgpt.com", Success: true, CheckedAt: now}}, now); err != nil {
		t.Fatal(err)
	}
	enabled := true
	if err := manager.SetEnabled(enabled); err != nil {
		t.Fatal(err)
	}
	if ips, _, matched := manager.Snapshot().Lookup("chatgpt.com", 1, time.Now()); !matched || len(ips) != 1 {
		t.Fatalf("test setup did not publish Auto Hosts record: enabled=%v emergency=%v active=%s domains=%+v endpoint=%+v lookup=%v", manager.State().Config.Enabled, manager.State().Config.EmergencyOff, manager.State().ActiveServer, manager.State().Domains, manager.State().Endpoints, ips)
	}
	var fallbackCalls atomic.Int32
	var fallbackName string
	fallback := newTestVPSResolveUpstream(t, func(w http.ResponseWriter, req *http.Request) {
		fallbackCalls.Add(1)
		body, readErr := io.ReadAll(req.Body)
		if readErr != nil {
			t.Error(readErr)
			return
		}
		fallbackName, _, _, err = parseQuestion(body)
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(testAResponse(body, 30))
	})
	runtime := &Runtime{autoHosts: manager, vpsResolve: fallback, dnsSem: make(chan struct{}, 1)}
	runtime.snapshot.Store(&Snapshot{cfg: Config{
		Cache:                  CacheConfig{Enabled: false},
		DNSQueryTimeoutSeconds: 3,
		DoHTimeoutSeconds:      3,
	}, localHosts: map[string]LocalHost{}, upstreams: map[string]*UpstreamRuntime{}, groups: map[string]Group{}})
	startTestAutoHostsRecorder(t, runtime, "chatgpt.com")

	a := runtime.handleDNS(makeDNSQuery("CHATGPT.COM", 1))
	ips, err := parseARecords(a)
	if err != nil || len(ips) != 1 || ips[0] != "8.8.4.4" {
		t.Fatalf("Auto Hosts A answer = %v, err=%v", ips, err)
	}
	if fallbackCalls.Load() != 0 {
		t.Fatal("Geosite HIT with a fresh Auto Hosts endpoint unexpectedly queried Quad9")
	}
	aaaa := runtime.handleDNS(makeDNSQuery("chatgpt.com", 28))
	if dnsRCode(aaaa) != 0 || binary.BigEndian.Uint16(aaaa[6:8]) != 0 {
		t.Fatalf("AAAA without endpoint IPv6 must be NODATA: %x", aaaa)
	}
	off := true
	if err := manager.SetEmergencyOff(off); err != nil {
		t.Fatal(err)
	}
	bypassed := runtime.handleDNS(makeDNSQuery("chatgpt.com", 1))
	fallbackIPs, fallbackErr := parseARecords(bypassed)
	if fallbackErr != nil || len(fallbackIPs) != 1 || fallbackIPs[0] != "203.0.113.10" {
		t.Fatalf("Emergency OFF must bypass Auto Hosts and use Quad9: answer=%v err=%v rcode=%d", fallbackIPs, fallbackErr, dnsRCode(bypassed))
	}
	if fallbackCalls.Load() != 1 || fallbackName != "chatgpt.com" {
		t.Fatalf("Emergency OFF Quad9 calls=%d qname=%q", fallbackCalls.Load(), fallbackName)
	}
}

func TestDNSGeositeHitRecordsUserDomainAndMapsActiveEndpoint(t *testing.T) {
	now := time.Now().UTC()
	manager, err := autohosts.New(filepath.Join(t.TempDir(), "auto-hosts.json"))
	if err != nil {
		t.Fatal(err)
	}
	endpoint := autohosts.Endpoint{
		ServerID: "edge", URL: "https://dns.example/dns-query", Hostname: "dns.example",
		IPv4: []string{"8.8.4.4"}, UpdatedAt: now,
	}
	probes := []autohosts.ProbeResult{{Domain: "chatgpt.com", Success: true, CheckedAt: now}}
	if err := manager.ApplyCycle("edge", endpoint, probes, now); err != nil {
		t.Fatal(err)
	}
	if err := manager.SetEnabled(true); err != nil {
		t.Fatal(err)
	}

	runtime := &Runtime{autoHosts: manager, dnsSem: make(chan struct{}, 1)}
	startTestAutoHostsRecorder(t, runtime, "protected.example")
	runtime.snapshot.Store(&Snapshot{
		cfg:        Config{Cache: CacheConfig{Enabled: false}},
		localHosts: map[string]LocalHost{},
		upstreams:  map[string]*UpstreamRuntime{},
		groups:     map[string]Group{},
	})

	response := runtime.handleDNS(makeDNSQuery("protected.example", 1))
	ips, err := parseARecords(response)
	if err != nil || len(ips) != 1 || ips[0] != "8.8.4.4" {
		t.Fatalf("Geosite endpoint A response=%v err=%v", ips, err)
	}
	record, ok := manager.State().Domains["protected.example"]
	if !ok || record.Source != "query" || record.LastSeen.IsZero() {
		t.Fatalf("user QNAME was not persisted with query lifecycle metadata: %+v", record)
	}
}

func TestHandleDNSManualLocalHostsOverrideAutoHosts(t *testing.T) {
	now := time.Now().UTC()
	manager, err := autohosts.New(filepath.Join(t.TempDir(), "auto-hosts.json"))
	if err != nil {
		t.Fatal(err)
	}
	endpoint := autohosts.Endpoint{ServerID: "edge", URL: "https://dns.example/dns-query", Hostname: "dns.example", IPv4: []string{"8.8.4.4"}, UpdatedAt: now}
	if err := manager.ApplyFullCycle("edge", []autohosts.Endpoint{endpoint}, []autohosts.ProbeResult{{ServerID: "edge", Domain: "chatgpt.com", Success: true, CheckedAt: now}}, now); err != nil {
		t.Fatal(err)
	}
	enabled := true
	if err := manager.SetEnabled(enabled); err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{autoHosts: manager, dnsSem: make(chan struct{}, 1)}
	runtime.snapshot.Store(&Snapshot{cfg: Config{}, localHosts: map[string]LocalHost{"chatgpt.com": {IPv4: []string{"203.0.113.9"}}}, upstreams: map[string]*UpstreamRuntime{}, groups: map[string]Group{}})
	response := runtime.handleDNS(makeDNSQuery("chatgpt.com", 1))
	ips, err := parseARecords(response)
	if err != nil || len(ips) != 1 || ips[0] != "203.0.113.9" {
		t.Fatalf("manual local_hosts did not win priority: %v err=%v", ips, err)
	}
}

func newAutoHostsDNSRuntimeForTransportTest(t *testing.T) *Runtime {
	t.Helper()
	now := time.Now().UTC()
	manager, err := autohosts.New(filepath.Join(t.TempDir(), "auto-hosts.json"))
	if err != nil {
		t.Fatal(err)
	}
	endpoint := autohosts.Endpoint{ServerID: "edge", URL: "https://dns.example/dns-query", Hostname: "dns.example", IPv4: []string{"8.8.4.4"}, UpdatedAt: now}
	if err := manager.ApplyCycle("edge", endpoint, []autohosts.ProbeResult{{Domain: "chatgpt.com", Success: true, CheckedAt: now}}, now); err != nil {
		t.Fatal(err)
	}
	enabled := true
	if err := manager.Configure(&enabled, nil, nil); err != nil {
		t.Fatal(err)
	}
	r := &Runtime{autoHosts: manager, dnsSem: make(chan struct{}, 2)}
	startTestAutoHostsRecorder(t, r, "chatgpt.com")
	r.snapshot.Store(&Snapshot{cfg: Config{DNSMaxConcurrent: 2}, localHosts: map[string]LocalHost{}, upstreams: map[string]*UpstreamRuntime{}, groups: map[string]Group{}})
	return r
}

func TestAutoHostsDNSOverUDPTransport(t *testing.T) {
	r := newAutoHostsDNSRuntimeForTransportTest(t)
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.serveUDP(ctx, server) }()
	client, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		cancel()
		_ = server.Close()
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = client.Write(makeDNSQuery("chatgpt.com", 1)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	ips, err := parseARecords(buf[:n])
	if err != nil || len(ips) != 1 || ips[0] != "8.8.4.4" {
		t.Fatalf("UDP Auto Hosts response=%v err=%v", ips, err)
	}
	cancel()
	_ = server.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("UDP server did not stop")
	}
}

func TestAutoHostsDNSOverTCPTransport(t *testing.T) {
	r := newAutoHostsDNSRuntimeForTransportTest(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.serveTCP(ctx, listener) }()
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		cancel()
		_ = listener.Close()
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	query := makeDNSQuery("chatgpt.com", 1)
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
	copy(frame[2:], query)
	if _, err = conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	var length [2]byte
	if _, err = io.ReadFull(conn, length[:]); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err = io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	ips, err := parseARecords(response)
	if err != nil || len(ips) != 1 || ips[0] != "8.8.4.4" {
		t.Fatalf("TCP Auto Hosts response=%v err=%v", ips, err)
	}
	cancel()
	_ = listener.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("TCP server did not stop")
	}
}

func TestAutoHostsConfigHotReloadTriggersBackgroundController(t *testing.T) {
	manager, err := autohosts.New(filepath.Join(t.TempDir(), "auto-hosts.json"))
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	if err := manager.Configure(&enabled, nil, nil); err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{autoHosts: manager}
	runtime.autoController = newAutoHostsController(runtime, manager)
	runtime.triggerAutoHostsConfigReload()
	select {
	case <-runtime.autoController.trigger:
	default:
		t.Fatal("hot reload did not trigger an immediate Auto Hosts controller cycle")
	}
	emergencyOff := true
	if err := manager.Configure(nil, &emergencyOff, nil); err != nil {
		t.Fatal(err)
	}
	runtime.triggerAutoHostsConfigReload()
	select {
	case <-runtime.autoController.trigger:
		t.Fatal("hot reload must not reactivate Auto Hosts while Emergency OFF is enabled")
	default:
	}
}

func TestRRCacheTTLDoesNotTreatOPTFlagsAsTTL(t *testing.T) {
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[2:4], 0x8180)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	binary.BigEndian.PutUint16(packet[6:8], 1)
	binary.BigEndian.PutUint16(packet[10:12], 1)
	packet = append(packet, 1, 'a', 0, 0, 1, 0, 1)
	packet = append(packet, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 192, 0, 2, 1)
	packet = append(packet, 0, 0, 41, 0x10, 0, 0, 0, 0x80, 0, 0, 0)

	ttl, ok := minResponseTTL(packet)
	if !ok || ttl != 120 {
		t.Fatalf("minResponseTTL = %d, %v; want 120, true", ttl, ok)
	}
	cache := &Runtime{cache: map[string]cacheItem{}}
	cache.cachePut("edns-key", packet, CacheConfig{Enabled: true, MinTTL: 1, MaxTTL: 300, NegativeTTL: 30, MaxEntries: 8, MaxBytes: 4096})
	if _, ok := cache.cacheGet("edns-key", packetID(packet)); !ok {
		t.Fatal("response containing OPT was not cached")
	}
	positions, err := rrTTLPositions(packet)
	if err != nil || len(positions) != 1 {
		t.Fatalf("rrTTLPositions = %v, %v; want one real RR TTL", positions, err)
	}
	decrementTTLs(packet, 5)
	if got := binary.BigEndian.Uint32(packet[positions[0] : positions[0]+4]); got != 115 {
		t.Fatalf("answer TTL = %d; want 115", got)
	}
	if got := binary.BigEndian.Uint32(packet[len(packet)-6 : len(packet)-2]); got != 0x8000 {
		t.Fatalf("OPT flags = %#x; want DO bit %#x", got, uint32(0x8000))
	}
}

func TestErrorResponseKeepsQuestionConsistentWithQDCount(t *testing.T) {
	query := makeDNSQuery("example.com", 1)
	for _, code := range []uint16{1, 2} {
		response := errorResponse(query, code)
		if got := binary.BigEndian.Uint16(response[4:6]); got != 1 {
			t.Fatalf("QDCOUNT = %d; want 1", got)
		}
		if len(response) != len(query) {
			t.Fatalf("response length = %d; want question length %d", len(response), len(query))
		}
		if binary.BigEndian.Uint16(response[6:12]) != 0 {
			t.Fatal("error response retained RR counts")
		}
		if got := dnsRCode(response); got != int(code) {
			t.Fatalf("rcode = %d; want %d", got, code)
		}
	}
	malformed := make([]byte, 16)
	binary.BigEndian.PutUint16(malformed[4:6], 1)
	malformed[12] = 0xc0
	malformed[13] = 0xff
	response := formerrResponse(malformed)
	if len(response) != 12 || binary.BigEndian.Uint16(response[4:6]) != 0 {
		t.Fatalf("malformed error response must be header-only: len=%d qd=%d", len(response), binary.BigEndian.Uint16(response[4:6]))
	}
}

func TestTruncateDNSUDPResponseSetsTCAndKeepsWholeRecords(t *testing.T) {
	query := makeDNSQuery("example.com", 1)
	response := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[6:8], 1)
	rdata := make([]byte, 900)
	rdata[0] = 192
	rdata[1] = 0
	rdata[2] = 2
	rdata[3] = 1
	response = append(response, 0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 60, byte(len(rdata)>>8), byte(len(rdata)))
	response = append(response, rdata...)
	got := truncateDNSUDPResponse(response, 512)
	if len(got) > 512 {
		t.Fatalf("truncated response length = %d; max 512", len(got))
	}
	if !dnsTruncated(got) {
		t.Fatal("truncated response is missing TC flag")
	}
	if binary.BigEndian.Uint16(got[4:6]) != 1 {
		t.Fatal("truncated response lost its question")
	}
	if binary.BigEndian.Uint16(got[6:8]) != 0 {
		t.Fatal("partial answer RR was retained")
	}
}

func TestCachePutCachesNOERRORNODATA(t *testing.T) {
	query := makeDNSQuery("nodata.example", 1)
	response := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	runtime := &Runtime{cache: map[string]cacheItem{}}
	config := CacheConfig{Enabled: true, MinTTL: 1, MaxTTL: 300, NegativeTTL: 45, MaxEntries: 8, MaxBytes: 4096}
	runtime.cachePut("nodata", response, config)
	if _, ok := runtime.cacheGet("nodata", packetID(query)); !ok {
		t.Fatal("NOERROR/NODATA response was not cached with NegativeTTL")
	}
}

func TestCacheDoCoalescesConcurrentMisses(t *testing.T) {
	runtime := &Runtime{cache: map[string]cacheItem{}}
	query := makeDNSQuery("singleflight.example", 1)
	response := testAResponse(query, 60)
	config := CacheConfig{Enabled: true, MinTTL: 1, MaxTTL: 120, NegativeTTL: 30, MaxEntries: 8, MaxBytes: 4096}
	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	const workers = 16
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id uint16) {
			defer wg.Done()
			_, err := runtime.cacheDo("singleflight", id, func() ([]byte, error) {
				if calls.Add(1) == 1 {
					close(started)
				}
				<-release
				runtime.cachePut("singleflight", response, config)
				return response, nil
			})
			if err != nil {
				t.Errorf("cacheDo: %v", err)
			}
		}(uint16(i + 1))
	}
	<-started
	close(release)
	wg.Wait()
	if got := calls.Load(); got != 1 {
		t.Fatalf("upstream resolver invoked %d times; want exactly once", got)
	}
}

func TestCNAMEChainIntoAutoHostsFailsClosed(t *testing.T) {
	now := time.Now().UTC()
	manager, err := autohosts.New(filepath.Join(t.TempDir(), "auto-hosts.json"))
	if err != nil {
		t.Fatal(err)
	}
	endpoint := autohosts.Endpoint{ServerID: "edge", URL: "https://dns.example/dns-query", Hostname: "dns.example", IPv4: []string{"8.8.8.8"}, UpdatedAt: now}
	if err := manager.ApplyCycle("edge", endpoint, []autohosts.ProbeResult{{Domain: "chatgpt.com", Success: true, CheckedAt: now}}, now); err != nil {
		t.Fatal(err)
	}
	if err := manager.SetEnabled(true); err != nil {
		t.Fatal(err)
	}
	query := makeDNSQuery("alias.example", 1)
	response := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[6:8], 1)
	binary.BigEndian.PutUint16(response[10:12], 1)
	target := appendDNSName(nil, "chatgpt.com")
	response = append(response, 0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60, byte(len(target)>>8), byte(len(target)))
	response = append(response, target...)
	response = append(response, appendDNSName(nil, "chatgpt.com")...)
	response = append(response, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 7)
	for _, qtype := range []uint16{1, 5, 28, 64, 65, 255} {
		if !cnameChainTargetsAutoHosts(response, "alias.example", qtype, manager) {
			t.Fatalf("CNAME into Auto Hosts must be blocked for QTYPE %d", qtype)
		}
	}

	// A Geosite-selected target is protected before it has been persisted.
	selectedTarget := "protected.example"
	geoResponse := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(geoResponse[2:4], 0x8180)
	binary.BigEndian.PutUint16(geoResponse[6:8], 1)
	binary.BigEndian.PutUint16(geoResponse[10:12], 1)
	targetName := appendDNSName(nil, selectedTarget)
	geoResponse = append(geoResponse, 0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60, byte(len(targetName)>>8), byte(len(targetName)))
	geoResponse = append(geoResponse, targetName...)
	geoResponse = append(geoResponse, appendDNSName(nil, selectedTarget)...)
	geoResponse = append(geoResponse, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 7)
	geo := newTestGeositeIndex(t, selectedTarget)
	for _, qtype := range []uint16{1, 5, 28, 64, 65, 255} {
		if !cnameChainTargetsAutoHosts(geoResponse, "alias.example", qtype, manager, geo) {
			t.Fatalf("CNAME into selected Geosite category must be blocked for QTYPE %d", qtype)
		}
	}
	// Exercise the real DNS cache-hit path: the response must be replaced by
	// SERVFAIL rather than returning the protected target's real address.
	runtime := &Runtime{
		autoHosts: manager,
		dnsSem:    make(chan struct{}, 1),
		cache:     make(map[string]cacheItem),
	}
	runtime.snapshot.Store(&Snapshot{
		cfg:        Config{Cache: CacheConfig{Enabled: true, MinTTL: 1, MaxTTL: 120, NegativeTTL: 30, MaxEntries: 8, MaxBytes: 4096}},
		localHosts: map[string]LocalHost{},
		upstreams:  map[string]*UpstreamRuntime{},
		groups:     map[string]Group{},
	})
	runtime.cachePut(cacheKey(query), response, runtime.currentSnapshot().cfg.Cache)
	got := runtime.handleDNS(query)
	if dnsRCode(got) != 2 {
		t.Fatalf("CNAME into Auto Hosts must fail closed, got RCODE=%d", dnsRCode(got))
	}
}

func TestNegativeSOATTLUsesRFC2308Minimum(t *testing.T) {
	query := makeDNSQuery("negative.example", 1)
	response := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(response[2:4], 0x8183)
	binary.BigEndian.PutUint16(response[8:10], 1)
	soa := appendDNSName(nil, "ns.example")
	soa = append(soa, appendDNSName(nil, "hostmaster.example")...)
	for _, v := range []uint32{1, 2, 3, 4, 60} {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v)
		soa = append(soa, b[:]...)
	}
	response = append(response, 0xc0, 0x0c, 0, 6, 0, 1, 0, 0, 2, 88, byte(len(soa)>>8), byte(len(soa)))
	response = append(response, soa...)
	ttl, ok := negativeSOATTL(response)
	if !ok || ttl != 60 {
		t.Fatalf("negative SOA TTL = %d, %v; want min(600, 60)", ttl, ok)
	}
}

func TestLocalDNSReplyDoesNotReflectEDNSClientOptions(t *testing.T) {
	query := makeDNSQuery("local.example", 1)
	query = append(query, 0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 8, 0, 10, 0, 4, 1, 2, 3, 4)
	binary.BigEndian.PutUint16(query[10:12], 1)
	response, matched := localHostsResponse(query, "local.example", 1, map[string]LocalHost{"local.example": {IPv4: []string{"192.0.2.1"}}})
	if !matched {
		t.Fatal("expected local-host response")
	}
	if bytes.Contains(response, []byte{0, 10, 0, 4, 1, 2, 3, 4}) {
		t.Fatal("server response reflected client COOKIE option")
	}
	if !bytes.Contains(response, []byte{0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 0}) {
		t.Fatal("response OPT must retain UDP size and DO bit but contain no options")
	}
}

func TestGeminiConfigValidationRejectsUnsafeValues(t *testing.T) {
	base := defaultConfig()
	base.GeminiAPI.Enabled = true
	base.GeminiAPI.GroupID = "google"
	base.GeminiAPI.KeyFile = "gemini_api_key"
	base.GeminiAPI.IntervalSeconds = 1800
	base.GeminiAPI.Model = "gemini-3.8-flash"
	base.GeminiAPI.Prompt = "Reply with exactly OK."
	base.GeminiAPI.MaxOutputTokens = 64
	if err := validateConfig(base); err != nil {
		t.Fatalf("valid Gemini config rejected: %v", err)
	}
	cases := []struct {
		name string
		edit func(*GeminiAPIConfig)
	}{
		{"negative token budget", func(c *GeminiAPIConfig) { c.MaxOutputTokens = -5 }},
		{"excessive token budget", func(c *GeminiAPIConfig) { c.MaxOutputTokens = 1_000_000 }},
		{"empty prompt", func(c *GeminiAPIConfig) { c.Prompt = "  " }},
		{"oversized prompt", func(c *GeminiAPIConfig) { c.Prompt = strings.Repeat("x", 4097) }},
		{"path-like model", func(c *GeminiAPIConfig) { c.Model = "a/b?x=1" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.edit(&cfg.GeminiAPI)
			if err := validateConfig(cfg); err == nil {
				t.Fatal("invalid Gemini configuration was accepted")
			}
		})
	}
}

func TestGeminiHTTPFailuresDoNotMarkUpstreamUnhealthy(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 429, 500, 503} {
		if !geminiFailureIsShared(GeminiHTTPError{Status: status}) {
			t.Errorf("HTTP %d should be classified as a shared Gemini API failure", status)
		}
	}
	if geminiFailureIsShared(errors.New("dial tcp: connection refused")) {
		t.Fatal("upstream-specific transport failure must remain attributable to the upstream")
	}
}

func TestConfigSourceReloadIntervalUsesConfiguredValue(t *testing.T) {
	if got := configSourceReloadInterval(&Snapshot{cfg: Config{ReloadSecs: 7}}); got != 7*time.Second {
		t.Fatalf("reload interval=%s, want 7s", got)
	}
	if got := configSourceReloadInterval(&Snapshot{cfg: Config{ReloadSecs: 0}}); got != configSourcePollInterval {
		t.Fatalf("invalid config reload interval=%s, want fallback %s", got, configSourcePollInterval)
	}
}

func newReloadTestRuntime(t *testing.T) *Runtime {
	t.Helper()
	dir := t.TempDir()
	if err := initializeConfigSourceFiles(dir); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.json")
	dohPath := filepath.Join(dir, "doh-servers.txt")
	checksPath := filepath.Join(dir, "tst-domen.txt")
	cfg := defaultConfig()
	sources, err := readConfigSources(dohPath, checksPath)
	if err != nil {
		t.Fatal(err)
	}
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
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.configHash = sha256.Sum256(data)
	if info, err := os.Stat(configPath); err == nil {
		snapshot.configMod = info.ModTime()
	}
	runtime := &Runtime{
		configPath: configPath, dohPath: dohPath, checksPath: checksPath,
		sourceHashes:       sources.Checksums,
		healthCheckTrigger: make(chan struct{}, 1),
		health:             map[string]map[string]HealthEntry{}, active: map[string]string{},
		lastGemini: map[string]time.Time{}, cache: map[string]cacheItem{},
	}
	runtime.snapshot.Store(snapshot)
	return runtime
}

func TestReloadOnceDetectsConfigContentWithOlderMtime(t *testing.T) {
	runtime := newReloadTestRuntime(t)
	cfg := runtime.currentSnapshot().cfg
	cfg.DNSQueryTimeoutSeconds++
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtime.configPath, append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(runtime.configPath, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	runtime.reloadOnce()
	if got := runtime.currentSnapshot().cfg.DNSQueryTimeoutSeconds; got != cfg.DNSQueryTimeoutSeconds {
		t.Fatalf("applied DNS timeout=%d, want %d despite older mtime", got, cfg.DNSQueryTimeoutSeconds)
	}
}

func TestReloadOnceAppliesValidSourcesWhenConfigJSONIsBroken(t *testing.T) {
	runtime := newReloadTestRuntime(t)
	if err := os.WriteFile(runtime.configPath, []byte("{broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtime.checksPath, []byte("example.net;A;1;;;0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	runtime.reloadOnce()
	snapshot := runtime.currentSnapshot()
	if len(snapshot.cfg.Groups) != 1 || len(snapshot.cfg.Groups[0].Checks) != 1 || snapshot.cfg.Groups[0].Checks[0].Domain != "example.net" {
		t.Fatalf("valid source edit was blocked by broken config.json: %+v", snapshot.cfg.Groups)
	}
	if _, err := loadConfigNoCreate(runtime.configPath); err != nil {
		t.Fatalf("regenerated config.json is still invalid: %v", err)
	}
	runtime.statusMu.RLock()
	lastError := runtime.lastError
	runtime.statusMu.RUnlock()
	if lastError != "" {
		t.Fatalf("successful reload left LastError=%q", lastError)
	}
}

func TestReloadLoopUsesConfiguredInterval(t *testing.T) {
	runtime := newReloadTestRuntime(t)
	cfg := runtime.currentSnapshot().cfg
	cfg.ReloadSecs = 1
	if err := writeConfigAtomic(runtime.configPath, cfg); err != nil {
		t.Fatal(err)
	}
	configData, err := os.ReadFile(runtime.configPath)
	if err != nil {
		t.Fatal(err)
	}
	initial := *runtime.currentSnapshot()
	initial.cfg = cfg
	initial.configHash = sha256.Sum256(configData)
	runtime.snapshot.Store(&initial)
	if err := os.WriteFile(runtime.checksPath, []byte("loop.example;A;1;;;0\n"), 0600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runtime.reloadLoop(ctx)
		close(done)
	}()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		snapshot := runtime.currentSnapshot()
		if len(snapshot.cfg.Groups) == 1 && len(snapshot.cfg.Groups[0].Checks) == 1 &&
			snapshot.cfg.Groups[0].Checks[0].Domain == "loop.example" {
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("reloadLoop did not stop after context cancellation")
			}
			return
		}
		select {
		case <-done:
			t.Fatal("reloadLoop exited before applying the source change")
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	t.Fatal("reloadLoop did not apply source changes within its configured one-second interval")
}
