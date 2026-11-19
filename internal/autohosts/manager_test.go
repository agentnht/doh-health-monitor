package autohosts

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestLookupEmergencyOffAndFamilySpecificNODATA(t *testing.T) {
	now := time.Now().UTC()
	m, err := New(filepath.Join(t.TempDir(), "auto-hosts.json"))
	if err != nil {
		t.Fatal(err)
	}
	ep := Endpoint{ServerID: "doh-a", URL: "https://dns.example/dns-query", Hostname: "dns.example", IPv4: []string{"192.0.2.10"}, IPv6: []string{"2001:db8::10"}, UpdatedAt: now}
	if err = m.ApplyCycle("doh-a", ep, []ProbeResult{{Domain: "ChatGPT.com.", Success: true, CheckedAt: now}}, now); err != nil {
		t.Fatal(err)
	}
	if err = m.SetEnabled(true); err != nil {
		t.Fatal(err)
	}
	ips, ttl, matched := m.Snapshot().Lookup("chatgpt.com", 1, now.Add(time.Second))
	if !matched || len(ips) != 1 || ips[0] != "192.0.2.10" || ttl <= 0 {
		t.Fatalf("unexpected A lookup: %v %v %v", ips, ttl, matched)
	}
	ips, _, matched = m.Snapshot().Lookup("chatgpt.com", 28, now.Add(time.Second))
	if !matched || len(ips) != 1 || ips[0] != "2001:db8::10" {
		t.Fatalf("unexpected AAAA lookup: %v %v", ips, matched)
	}
	if err = m.SetEmergencyOff(true); err != nil {
		t.Fatal(err)
	}
	if _, _, matched = m.Snapshot().Lookup("chatgpt.com", 1, now.Add(time.Second)); matched {
		t.Fatal("Emergency OFF must bypass Auto Hosts")
	}
	if len(m.State().Domains) != 1 {
		t.Fatal("Emergency OFF must preserve records")
	}
}
func TestIPv4OnlyAAAAIsNODATAAndGraceExpires(t *testing.T) {
	now := time.Now().UTC()
	m, err := New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	ep := Endpoint{ServerID: "v4", URL: "https://dns.example/dns-query", Hostname: "dns.example", IPv4: []string{"192.0.2.53"}, UpdatedAt: now}
	if err = m.ApplyCycle("v4", ep, []ProbeResult{{Domain: "example.com", Success: true, CheckedAt: now}}, now); err != nil {
		t.Fatal(err)
	}
	if err = m.SetEnabled(true); err != nil {
		t.Fatal(err)
	}
	ips, _, matched := m.Snapshot().Lookup("example.com", 28, now.Add(time.Second))
	if !matched || len(ips) != 0 {
		t.Fatalf("expected NODATA, got %v matched=%v", ips, matched)
	}
	if err = m.ApplyCycle("v4", ep, []ProbeResult{{Domain: "example.com", Success: false, CheckedAt: now.Add(time.Minute)}}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, _, matched = m.Snapshot().Lookup("example.com", 1, now.Add(31*time.Minute)); matched {
		t.Fatal("expired record must not be served")
	}
}
func TestPinnedAndDryRunDoNotMutateState(t *testing.T) {
	now := time.Now().UTC()
	m, err := New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	a := Endpoint{ServerID: "a", URL: "https://a.example/dns-query", Hostname: "a.example", IPv4: []string{"192.0.2.1"}, UpdatedAt: now}
	if err = m.ApplyCycle("a", a, nil, now); err != nil {
		t.Fatal(err)
	}
	if err = m.SetPinned("a"); err != nil {
		t.Fatal(err)
	}
	b := Endpoint{ServerID: "b", URL: "https://b.example/dns-query", Hostname: "b.example", IPv4: []string{"192.0.2.2"}, UpdatedAt: now}
	if err = m.ApplyCycle("b", b, nil, now); !errors.Is(err, ErrPinnedServer) {
		t.Fatalf("expected pinned error, got %v", err)
	}
	before := m.State()
	proposed, err := m.DryRun("a", a, []ProbeResult{{Domain: "new.example", Success: true, CheckedAt: now}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := proposed["new.example"]; !ok {
		t.Fatal("dry run omitted successful domain")
	}
	after := m.State()
	if before.ActiveServer != after.ActiveServer || len(after.Domains) != 0 {
		t.Fatal("dry run mutated persistent state")
	}
}
func TestPersistenceAndDomainNormalization(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	m, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	ep := Endpoint{ServerID: "a", URL: "https://dns.example/dns-query", Hostname: "dns.example", IPv4: []string{"192.0.2.1"}}
	if err = m.ApplyCycle("a", ep, []ProbeResult{{Domain: "WWW.Example.com.", Success: true, CheckedAt: now}}, now); err != nil {
		t.Fatal(err)
	}
	reloaded, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reloaded.State().Domains["www.example.com"]; !ok {
		t.Fatal("normalized domain was not persisted")
	}
	if reloaded.Snapshot().ActiveServer != "a" {
		t.Fatal("active server was not restored")
	}
}

func TestFullCyclePersistsAllServerDomainPairsButPublishesOnlyActive(t *testing.T) {
	now := time.Now().UTC()
	m, err := New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	a := Endpoint{ServerID: "a", URL: "https://a.example/dns-query", Hostname: "a.example", IPv4: []string{"192.0.2.1"}}
	b := Endpoint{ServerID: "b", URL: "https://b.example/dns-query", Hostname: "b.example", IPv4: []string{"192.0.2.2"}}
	results := []ProbeResult{
		{ServerID: "a", Domain: "chatgpt.com", Success: true, CheckedAt: now},
		{ServerID: "b", Domain: "chatgpt.com", Success: false, CheckedAt: now, Error: "website unreachable"},
		{ServerID: "b", Domain: "claude.ai", Success: true, CheckedAt: now},
	}
	if err := m.ApplyFullCycle("a", []Endpoint{a, b}, results, now); err != nil {
		t.Fatal(err)
	}
	state := m.State()
	if len(state.ProbeResults) != 3 {
		t.Fatalf("expected all 3 pair results persisted, got %d", len(state.ProbeResults))
	}
	if len(state.Domains) != 1 {
		t.Fatalf("only active-server domain should be published, got %v", state.Domains)
	}
	if _, ok := state.Domains["chatgpt.com"]; !ok {
		t.Fatal("active server's successful domain missing")
	}
	if _, ok := state.Domains["claude.ai"]; ok {
		t.Fatal("inactive server's successful domain must not be published")
	}
	if _, ok := state.Endpoints["b"]; !ok {
		t.Fatal("inactive endpoint missing from state")
	}
}

func TestEndpointFreshnessExpiresIndependentlyFromDomainGrace(t *testing.T) {
	now := time.Now().UTC()
	m, err := New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	ep := Endpoint{ServerID: "edge", URL: "https://dns.example/dns-query", Hostname: "dns.example", IPv4: []string{"8.8.8.8"}, UpdatedAt: now.Add(-25 * time.Hour)}
	if err := m.ApplyCycle("edge", ep, []ProbeResult{{Domain: "chatgpt.com", Success: true, CheckedAt: now}}, now); err != nil {
		t.Fatal(err)
	}
	if err := m.SetEnabled(true); err != nil {
		t.Fatal(err)
	}
	if _, _, matched := m.Snapshot().Lookup("chatgpt.com", 1, now); matched {
		t.Fatal("stale DoH endpoint IP must not be published even while domain grace is valid")
	}
}

func TestConfigurePinsServerAndEmergencyOffAtomically(t *testing.T) {
	m, err := New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	ep := Endpoint{ServerID: "edge", URL: "https://dns.example/dns-query", Hostname: "dns.example", IPv4: []string{"8.8.8.8"}}
	if err := m.ApplyCycle("edge", ep, nil, now); err != nil {
		t.Fatal(err)
	}
	enabled, emergency, pinned := true, true, "edge"
	if err := m.Configure(&enabled, &emergency, &pinned); err != nil {
		t.Fatal(err)
	}
	state := m.State()
	if !state.Config.Enabled || !state.Config.EmergencyOff || state.Config.Mode != "pinned" || state.Config.PinnedServerID != "edge" {
		t.Fatalf("settings were not applied: %+v", state.Config)
	}
	badPin := "missing"
	if err := m.Configure(nil, nil, &badPin); err == nil {
		t.Fatal("expected unknown pinned server to fail")
	}
	after := m.State()
	if after.Config.PinnedServerID != "edge" || !after.Config.EmergencyOff {
		t.Fatal("failed settings update partially mutated state")
	}
	auto := ""
	restore := false
	if err := m.Configure(nil, &restore, &auto); err != nil {
		t.Fatal(err)
	}
	after = m.State()
	if after.Config.Mode != "auto" || after.Config.EmergencyOff {
		t.Fatalf("explicit restore did not apply: %+v", after.Config)
	}
}

func TestRecordPinnedFailurePersistsDegradationWithoutChangingActiveSnapshot(t *testing.T) {
	m, err := New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	ep := Endpoint{ServerID: "edge", URL: "https://dns.example/dns-query", Hostname: "dns.example", IPv4: []string{"8.8.8.8"}}
	if err := m.ApplyCycle("edge", ep, []ProbeResult{{Domain: "chatgpt.com", Success: true, CheckedAt: now}}, now); err != nil {
		t.Fatal(err)
	}
	before := m.State()
	if err := m.RecordProbeFailures("edge", []string{"chatgpt.com", "claude.ai"}, "pinned endpoint DNS resolution failed", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	after := m.State()
	if after.ActiveServer != before.ActiveServer || len(after.Domains) != len(before.Domains) {
		t.Fatal("degradation record changed active DNS domain snapshot")
	}
	failure := after.ProbeResults["edge\x00chatgpt.com"]
	if failure.Success || failure.Error == "" {
		t.Fatalf("pinned degradation not recorded: %+v", failure)
	}
}

func TestEndpointWithoutResolutionTimestampIsNeverPublished(t *testing.T) {
	now := time.Now().UTC()
	m, err := New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	ep := Endpoint{ServerID: "fallback", URL: "https://dns.example/dns-query", Hostname: "dns.example", IPv4: []string{"8.8.8.8"}}
	if err = m.ApplyCycle("fallback", ep, []ProbeResult{{Domain: "chatgpt.com", Success: true, CheckedAt: now}}, now); err != nil {
		t.Fatal(err)
	}
	if err = m.SetEnabled(true); err != nil {
		t.Fatal(err)
	}
	if ips, _, matched := m.Snapshot().Lookup("chatgpt.com", 1, now); matched || len(ips) != 0 {
		t.Fatalf("endpoint without a successful resolution timestamp must not be published: ips=%v matched=%v", ips, matched)
	}
}

func TestConcurrentSnapshotReadsAndAtomicCycles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	m, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	ep := Endpoint{ServerID: "edge", URL: "https://dns.example/dns-query", Hostname: "dns.example", IPv4: []string{"8.8.8.8"}, UpdatedAt: now}
	if err = m.ApplyCycle("edge", ep, []ProbeResult{{Domain: "chatgpt.com", Success: true, CheckedAt: now}}, now); err != nil {
		t.Fatal(err)
	}
	if err = m.SetEnabled(true); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 9)
	for reader := 0; reader < 8; reader++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				snapshot := m.Snapshot()
				if snapshot == nil {
					errs <- errors.New("snapshot unexpectedly nil")
					return
				}
				_, _, _ = snapshot.Lookup("chatgpt.com", 1, time.Now().UTC())
				_ = m.State()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 40; i++ {
			at := now.Add(time.Duration(i) * time.Second)
			next := ep
			next.UpdatedAt = at
			if err := m.ApplyCycle("edge", next, []ProbeResult{{Domain: "chatgpt.com", Success: true, CheckedAt: at}}, at); err != nil {
				errs <- err
				return
			}
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	reloaded, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Snapshot() == nil || reloaded.Snapshot().ActiveServer != "edge" {
		t.Fatal("atomic cycle state was not restored after concurrent reads")
	}
}

func TestPinnedAndEmergencyOffPersistAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	now := time.Now().UTC()
	m, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	ep := Endpoint{ServerID: "edge", URL: "https://dns.example/dns-query", Hostname: "dns.example", IPv4: []string{"8.8.8.8"}, UpdatedAt: now}
	if err = m.ApplyCycle("edge", ep, []ProbeResult{{Domain: "chatgpt.com", Success: true, CheckedAt: now}}, now); err != nil {
		t.Fatal(err)
	}
	enabled, emergency, pinned := true, true, "edge"
	if err = m.Configure(&enabled, &emergency, &pinned); err != nil {
		t.Fatal(err)
	}
	reloaded, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	state := reloaded.State()
	if !state.Config.Enabled || !state.Config.EmergencyOff || state.Config.Mode != "pinned" || state.Config.PinnedServerID != "edge" {
		t.Fatalf("pinned/Emergency OFF settings did not survive restart: %+v", state.Config)
	}
	if _, _, matched := reloaded.Snapshot().Lookup("chatgpt.com", 1, now); matched {
		t.Fatal("Emergency OFF must remain active after restart")
	}
	restore := false
	auto := ""
	if err = reloaded.Configure(nil, &restore, &auto); err != nil {
		t.Fatal(err)
	}
	again, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if again.State().Config.EmergencyOff || again.State().Config.Mode != "auto" {
		t.Fatalf("explicit restore was not persisted: %+v", again.State().Config)
	}
}

func TestQueryDomainsSurviveProbeCyclesAndRefreshLastSeen(t *testing.T) {
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "state.json")
	m, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	ep := Endpoint{ServerID: "edge", URL: "https://dns.example/dns-query", Hostname: "dns.example", IPv4: []string{"8.8.8.8"}, UpdatedAt: now}
	if err := m.ApplyCycle("edge", ep, []ProbeResult{{Domain: "chatgpt.com", Success: true, CheckedAt: now}}, now); err != nil {
		t.Fatal(err)
	}
	if err := m.SetEnabled(true); err != nil {
		t.Fatal(err)
	}
	firstSeen := now.Add(time.Minute)
	if err := m.RecordQuery("service.example", firstSeen); err != nil {
		t.Fatal(err)
	}
	secondSeen := firstSeen.Add(time.Minute)
	if err := m.RecordQuery("service.example.", secondSeen); err != nil {
		t.Fatal(err)
	}
	record := m.State().Domains["service.example"]
	if record.Source != DomainSourceQuery || !record.LastSeen.Equal(secondSeen) || !record.ExpiresAt.Equal(secondSeen.Add(DefaultConfig().GracePeriod)) {
		t.Fatalf("query record was not refreshed: %+v", record)
	}
	next := now.Add(3 * time.Minute)
	ep.UpdatedAt = next
	if err := m.ApplyCycle("edge", ep, []ProbeResult{{Domain: "chatgpt.com", Success: false, CheckedAt: next}}, next); err != nil {
		t.Fatal(err)
	}
	state := m.State()
	if _, ok := state.Domains["service.example"]; !ok {
		t.Fatal("probe cycle removed a user-query domain")
	}
	if _, ok := state.Domains["chatgpt.com"]; !ok {
		t.Fatal("probe failure prematurely removed a control domain inside grace")
	}
	reloaded, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.State().Domains["service.example"]; !got.LastSeen.Equal(secondSeen) {
		t.Fatalf("LastSeen did not survive restart: %+v", got)
	}
}

func TestQueryDomainCapacityAndIndependentGarbageCollection(t *testing.T) {
	now := time.Now().UTC()
	m, err := New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Configure(boolPtr(true), nil, nil); err != nil {
		t.Fatal(err)
	}
	// Reduce the cap through a valid persisted config update.
	m.mu.Lock()
	m.state.Config.MaxDomains = 2
	if err := m.persist(m.state); err != nil {
		m.mu.Unlock()
		t.Fatal(err)
	}
	m.publish()
	m.mu.Unlock()
	if err := m.RecordQuery("one.example", now); err != nil {
		t.Fatal(err)
	}
	if err := m.RecordQuery("two.example", now); err != nil {
		t.Fatal(err)
	}
	if err := m.RecordQuery("three.example", now); err == nil {
		t.Fatal("expected capacity error")
	}
	if err := m.PruneExpired(now.Add(DefaultConfig().GracePeriod + time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(m.State().Domains) != 0 {
		t.Fatalf("expired domains remain after GC: %+v", m.State().Domains)
	}
}

func boolPtr(v bool) *bool { return &v }

func TestGeositeCategoriesPersistNormalized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	m, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetGeositeCategories([]string{" category-ads-all ", "TEST", "test"}); err != nil {
		t.Fatal(err)
	}
	want := []string{"CATEGORY-ADS-ALL", "TEST"}
	got := m.State().Config.GeositeCategories
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("categories not normalized: %#v", got)
	}
	reloaded, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	got = reloaded.State().Config.GeositeCategories
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("categories did not persist: %#v", got)
	}
}

func TestSetGeositeCategoriesRejectsInvalidName(t *testing.T) {
	m, err := New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetGeositeCategories([]string{"bad category"}); err == nil {
		t.Fatal("expected invalid category error")
	}
	if len(m.State().Config.GeositeCategories) != 0 {
		t.Fatal("invalid category update partially mutated state")
	}
}

func TestEndpointForQueryMapsUnrecordedGeositeDomain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	m, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	ep := Endpoint{ServerID: "edge", URL: "https://dns.example/dns-query", Hostname: "dns.example", IPv4: []string{"8.8.8.8"}, IPv6: []string{"2001:4860:4860::8888"}, UpdatedAt: now}
	if err := m.ApplyCycle("edge", ep, nil, now); err != nil {
		t.Fatal(err)
	}
	if err := m.SetEnabled(true); err != nil {
		t.Fatal(err)
	}
	s := m.Snapshot()
	if !s.CanRecordQuery("new-geosite-domain.example") {
		t.Fatal("unrecorded geosite QNAME should fit into Auto Hosts")
	}
	ips, ttl, ok := s.EndpointForQuery(1, now.Add(time.Second))
	if !ok || len(ips) != 1 || ips[0] != "8.8.8.8" || ttl <= 0 {
		t.Fatalf("unexpected endpoint mapping: ips=%v ttl=%v ok=%v", ips, ttl, ok)
	}
	if _, _, ok := s.EndpointForQuery(28, now.Add(time.Second)); !ok {
		t.Fatal("AAAA query should be eligible for endpoint mapping")
	}
	if _, _, ok := s.EndpointForQuery(16, now.Add(time.Second)); ok {
		t.Fatal("TXT query must not be endpoint-mapped")
	}
}

func TestPruneExpiredPublishesCleanupDiagnostics(t *testing.T) {
	now := time.Now().UTC()
	m, err := New(filepath.Join(t.TempDir(), "auto-hosts.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetEnabled(true); err != nil {
		t.Fatal(err)
	}
	if err := m.RecordQuery("stale.example", now); err != nil {
		t.Fatal(err)
	}
	if err := m.PruneExpired(now.Add(31 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.State().Domains["stale.example"]; ok {
		t.Fatal("expired query domain was not pruned")
	}
	status := m.CleanupStatus()
	if status.LastRun.IsZero() || status.LastDeleted != 1 || status.LastError != "" {
		t.Fatalf("unexpected cleanup diagnostics: %+v", status)
	}
}
