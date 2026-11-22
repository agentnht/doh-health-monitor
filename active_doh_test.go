package main

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"lucx-doh-health-monitor/internal/activedoh"
)

func activeDoHTestFixture() (*Runtime, *Snapshot) {
	now := time.Now()
	bootstrap := &bootstrapResolver{
		host:       "resolver.example.test",
		ips:        []string{"10.0.0.1", "1.1.1.1", "2001:4860:4860::8888"},
		refreshed:  now,
		refreshFor: time.Hour,
	}
	upstream := &UpstreamRuntime{
		cfg:       Upstream{ID: "primary", URL: "https://resolver.example.test/dns-query"},
		bootstrap: bootstrap,
	}
	snapshot := &Snapshot{
		activeDoHGeneration: 7,
		upstreams:           map[string]*UpstreamRuntime{"primary": upstream},
	}
	runtime := &Runtime{
		activeDoHSelector: activedoh.NewSelector(activedoh.DefaultPolicy()),
		cache:             make(map[string]cacheItem),
	}
	runtime.snapshot.Store(snapshot)
	return runtime, snapshot
}

func TestActiveDoHLoopBackoffAndRecoveryCadence(t *testing.T) {
	// Simulate five consecutive failed selection cycles, recovery, and one
	// subsequent failure. The last failure must restart at the 15s base delay.
	outcomes := []bool{false, false, false, false, false, true, false}
	var cycle int
	var waits []time.Duration
	var logs bytes.Buffer

	selectCycle := func(context.Context) bool {
		if cycle >= len(outcomes) {
			t.Fatal("selection loop ran more cycles than the controlled outage")
		}
		result := outcomes[cycle]
		cycle++
		return result
	}
	wait := func(_ context.Context, delay time.Duration, _ <-chan struct{}) bool {
		waits = append(waits, delay)
		return len(waits) < len(outcomes)
	}
	logf := func(level, format string, args ...any) {
		_, _ = fmt.Fprintf(&logs, "%s ", level)
		_, _ = fmt.Fprintf(&logs, format, args...)
		_ = logs.WriteByte('\n')
	}

	runActiveDoHLoop(context.Background(), nil, selectCycle, wait, logf)

	want := []time.Duration{
		15 * time.Second,
		30 * time.Second,
		60 * time.Second,
		120 * time.Second,
		240 * time.Second,
		activeDoHProbeInterval, // healthy selection restores the normal cadence
		15 * time.Second,       // a later failure starts a fresh backoff sequence
	}
	if cycle != len(outcomes) || len(waits) != len(want) {
		t.Fatalf("cycles=%d waits=%v, want %d cycles and %d waits", cycle, waits, len(outcomes), len(want))
	}
	for i := range want {
		if waits[i] != want[i] {
			t.Errorf("wait[%d]=%s, want %s", i, waits[i], want[i])
		}
	}

	logOutput := logs.String()
	for i, delay := range want {
		if i == 5 {
			continue // the recovery message records the regular cadence instead
		}
		if !strings.Contains(logOutput, fmt.Sprintf("retry scheduled failures=%d delay=%s", map[int]int{0: 1, 1: 2, 2: 3, 3: 4, 4: 5, 6: 1}[i], delay)) {
			t.Errorf("retry log does not contain delay %s: %s", delay, logOutput)
		}
	}
	if !strings.Contains(logOutput, "selection recovered; regular probe cadence restored interval=5m0s") {
		t.Fatalf("recovery log did not announce normal cadence: %s", logOutput)
	}
}

func TestWaitForActiveDoHHandlesTimerTriggerAndCancellation(t *testing.T) {
	if !waitForActiveDoH(context.Background(), time.Millisecond, nil) {
		t.Fatal("timer expiry should schedule the next selection cycle")
	}

	trigger := make(chan struct{}, 1)
	trigger <- struct{}{}
	if !waitForActiveDoH(context.Background(), time.Hour, trigger) {
		t.Fatal("an explicit trigger should schedule the next selection cycle")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if waitForActiveDoH(ctx, time.Hour, nil) {
		t.Fatal("context cancellation should stop the ActiveDoH loop")
	}
}

func TestActiveDoHLoopStopsWhenContextIsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	(&Runtime{}).activeDoHLoop(ctx)
}

func TestActiveDoHCandidatesFilterAndSortConfiguredUpstreams(t *testing.T) {
	now := time.Now()
	makeBootstrap := func(host string, ips []string) *bootstrapResolver {
		return &bootstrapResolver{
			host: host, ips: ips, refreshed: now, refreshFor: time.Hour,
		}
	}
	snapshot := &Snapshot{upstreams: map[string]*UpstreamRuntime{
		"z-good": {
			cfg:       Upstream{ID: "z-good", URL: "https://z.example.test/dns-query"},
			bootstrap: makeBootstrap("z.example.test", []string{"10.0.0.1", "1.1.1.1", "2001:4860:4860::8888"}),
		},
		"a-private": {
			cfg:       Upstream{ID: "a-private", URL: "https://private.example.test/dns-query"},
			bootstrap: makeBootstrap("private.example.test", []string{"10.0.0.2"}),
		},
		"no-bootstrap": {
			cfg: Upstream{ID: "no-bootstrap", URL: "https://missing.example.test/dns-query"},
		},
		"system-dns": {
			cfg:       Upstream{ID: "system-dns", URL: "https://system.example.test/dns-query"},
			bootstrap: makeBootstrap("system.example.test", []string{"1.1.1.1"}),
			systemDNS: &systemDNSResolver{},
		},
		"blank-url": {
			cfg:       Upstream{ID: "blank-url"},
			bootstrap: makeBootstrap("blank.example.test", []string{"1.1.1.1"}),
		},
		"nil-runtime": nil,
	}}

	candidates := (&Runtime{}).activeDoHCandidates(context.Background(), snapshot)
	if len(candidates) != 1 {
		t.Fatalf("got %d candidates, want only z-good: %+v", len(candidates), candidates)
	}
	got := candidates[0]
	if got.ServerID != "z-good" || got.Hostname != "z.example.test" {
		t.Fatalf("unexpected candidate identity: %+v", got)
	}
	if len(got.IPv4) != 1 || got.IPv4[0] != "1.1.1.1" {
		t.Fatalf("IPv4 candidates=%v, want only public 1.1.1.1", got.IPv4)
	}
	if len(got.IPv6) != 1 || got.IPv6[0] != "2001:4860:4860::8888" {
		t.Fatalf("IPv6 candidates=%v, want public Google IPv6 address", got.IPv6)
	}
}

func TestActiveDoHChecksSelectOnlyConfiguredControlDomains(t *testing.T) {
	control := activedoh.ControlDomains()[0]
	snapshot := &Snapshot{groups: map[string]Group{
		"z-later": {Checks: []Check{
			{Domain: control, HTTPURL: "https://later.example.test/"},
		}},
		"a-first": {Checks: []Check{
			{Domain: "  "},
			{Domain: "unrelated.example.test", HTTPURL: "https://unrelated.example.test/"},
			{Domain: " " + strings.ToUpper(control) + ". ", HTTPURL: "https://first.example.test/", Required: true},
		}},
	}}
	checks := activeDoHChecks(snapshot)
	if len(checks) != 1 {
		t.Fatalf("got %d control checks, want one: %+v", len(checks), checks)
	}
	if got := checks[control]; got.HTTPURL != "https://first.example.test/" || !got.Required {
		t.Fatalf("the first normalized control-domain check was not retained: %+v", got)
	}
}

func TestRunActiveDoHSelectionUnavailableAndCanceledStates(t *testing.T) {
	if !(&Runtime{}).runActiveDoHSelectionWithProbe(context.Background(), nil) {
		t.Fatal("a disabled selector should be treated as a skipped cycle")
	}

	runtime := &Runtime{activeDoHSelector: activedoh.NewSelector(activedoh.DefaultPolicy())}
	if !runtime.runActiveDoHSelectionWithProbe(context.Background(), nil) {
		t.Fatal("a missing snapshot should be treated as a skipped cycle")
	}

	snapshot := &Snapshot{activeDoHGeneration: 1, upstreams: map[string]*UpstreamRuntime{}}
	runtime.snapshot.Store(snapshot)
	if runtime.runActiveDoHSelectionWithProbe(context.Background(), nil) {
		t.Fatal("an empty candidate set must withdraw the selection and request a retry")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runtime.snapshot.Store(&Snapshot{activeDoHGeneration: 2, upstreams: map[string]*UpstreamRuntime{}})
	if !runtime.runActiveDoHSelectionWithProbe(ctx, nil) {
		t.Fatal("a cancelled selection cycle should be discarded, not counted as an outage")
	}
}

func TestRunActiveDoHSelectionWithProbeSelectsHealthyCandidate(t *testing.T) {
	runtime, _ := activeDoHTestFixture()
	probeCalls := 0
	probe := func(_ context.Context, job activeDoHProbeJob, now time.Time) activedoh.ProbeResult {
		probeCalls++
		return activedoh.ProbeResult{
			ServerID: job.serverID, Domain: job.domain, Success: true, CheckedAt: now,
		}
	}
	if !runtime.runActiveDoHSelectionWithProbe(context.Background(), probe) {
		t.Fatal("all successful control probes should produce a healthy selection")
	}
	if want := len(activedoh.ControlDomains()); probeCalls != want {
		t.Fatalf("probe calls=%d, want one for each of %d control domains", probeCalls, want)
	}
	selection, ok := runtime.activeDoHSelector.Current(time.Now())
	if !ok || selection.Candidate.ServerID != "primary" || selection.Score != len(activedoh.ControlDomains()) {
		t.Fatalf("unexpected active selection: %+v, present=%t", selection, ok)
	}
}

func TestRunActiveDoHSelectionWithProbeWithdrawsDuringOutage(t *testing.T) {
	runtime, _ := activeDoHTestFixture()
	probe := func(_ context.Context, job activeDoHProbeJob, now time.Time) activedoh.ProbeResult {
		return activedoh.ProbeResult{
			ServerID: job.serverID, Domain: job.domain, CheckedAt: now, Error: "simulated outage",
		}
	}
	if runtime.runActiveDoHSelectionWithProbe(context.Background(), probe) {
		t.Fatal("a candidate that failed every control probe must not be selected")
	}
	if _, ok := runtime.activeDoHSelector.Current(time.Now()); ok {
		t.Fatal("outage simulation left an active endpoint selected")
	}
}

func TestRunActiveDoHSelectionDiscardsChangedConfiguration(t *testing.T) {
	runtime, snapshot := activeDoHTestFixture()
	probe := func(_ context.Context, job activeDoHProbeJob, now time.Time) activedoh.ProbeResult {
		changed := *snapshot
		changed.activeDoHGeneration++
		runtime.snapshot.Store(&changed)
		return activedoh.ProbeResult{
			ServerID: job.serverID, Domain: job.domain, Success: true, CheckedAt: now,
		}
	}
	if !runtime.runActiveDoHSelectionWithProbe(context.Background(), probe) {
		t.Fatal("a selection cycle invalidated by reload should be discarded")
	}
	if _, ok := runtime.activeDoHSelector.Current(time.Now()); ok {
		t.Fatal("a selection from a stale configuration generation must not be published")
	}
}

func TestActiveDoHCandidatesRejectMalformedAndNonPublicAddresses(t *testing.T) {
	now := time.Now()
	snapshot := &Snapshot{upstreams: map[string]*UpstreamRuntime{
		"private": {
			cfg:       Upstream{ID: "private", URL: "https://private.example.test/dns-query"},
			bootstrap: &bootstrapResolver{host: "private.example.test", ips: []string{"10.0.0.1"}, refreshed: now, refreshFor: time.Hour},
		},
		"invalid-ip": {
			cfg:       Upstream{ID: "invalid-ip", URL: "https://invalid.example.test/dns-query"},
			bootstrap: &bootstrapResolver{host: "invalid.example.test", ips: []string{"not-an-ip"}, refreshed: now, refreshFor: time.Hour},
		},
	}}
	if got := (&Runtime{}).activeDoHCandidates(context.Background(), snapshot); len(got) != 0 {
		t.Fatalf("private or malformed bootstrap addresses must not become candidates: %+v", got)
	}
}
