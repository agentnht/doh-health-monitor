package activedoh

import (
	"fmt"
	"testing"
	"time"
)

func candidate(id, ip string, resolvedAt time.Time) Candidate {
	return Candidate{
		ServerID:   id,
		URL:        "https://" + id + ".example/dns-query",
		Hostname:   id + ".example",
		IPv4:       []string{ip},
		ResolvedAt: resolvedAt,
	}
}

func results(id string, successes int, now time.Time) []ProbeResult {
	domains := ControlDomains()
	out := make([]ProbeResult, 0, len(domains))
	for i, domain := range domains {
		out = append(out, ProbeResult{
			ServerID:  id,
			Domain:    domain,
			Success:   i < successes,
			CheckedAt: now,
		})
	}
	return out
}

func TestControlDomainsAreStableAndCopied(t *testing.T) {
	first := ControlDomains()
	want := []string{
		"chatgpt.com",
		"claude.ai",
		"gemini.google.com",
		"elevenlabs.io",
		"grok.com",
		"www.perplexity.ai",
		"aistudio.google.com",
	}
	if len(first) != len(want) {
		t.Fatalf("got %d control domains, want %d", len(first), len(want))
	}
	for i := range want {
		if first[i] != want[i] {
			t.Fatalf("control domain %d = %q, want %q", i, first[i], want[i])
		}
	}
	first[0] = "mutated.example"
	if ControlDomains()[0] != "chatgpt.com" {
		t.Fatal("caller mutated package control-domain set")
	}
}

func TestInitialSelectionChoosesBestHealthyCandidate(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	s := NewSelector(DefaultPolicy())
	candidates := []Candidate{
		candidate("second", "192.0.2.2", now),
		candidate("first", "192.0.2.1", now),
	}
	probes := append(results("second", 3, now), results("first", 6, now)...)

	selected, ok := s.Select(candidates, probes, now)
	if !ok {
		t.Fatal("expected a selected endpoint")
	}
	if selected.Candidate.ServerID != "first" || selected.Score != 6 || selected.CheckCount != 7 {
		t.Fatalf("unexpected selection: %+v", selected)
	}
	if selected.Generation != 1 {
		t.Fatalf("generation = %d, want 1", selected.Generation)
	}
}

func TestNoHealthyCandidateDoesNotSelectConfiguredFirst(t *testing.T) {
	now := time.Now().UTC()
	s := NewSelector(DefaultPolicy())
	candidates := []Candidate{
		candidate("first", "192.0.2.1", now),
		candidate("second", "192.0.2.2", now),
	}
	probes := append(results("first", 0, now), results("second", 0, now)...)
	if selected, ok := s.Select(candidates, probes, now); ok {
		t.Fatalf("unexpected selection with all checks failed: %+v", selected)
	}
	if _, ok := s.Current(now); ok {
		t.Fatal("selector retained an endpoint after an empty initial cycle")
	}
}

func TestSelectorPrefersCurrentOnEqualScore(t *testing.T) {
	now := time.Now().UTC()
	s := NewSelector(DefaultPolicy())
	a := candidate("a", "192.0.2.1", now)
	b := candidate("b", "192.0.2.2", now)
	if _, ok := s.Select([]Candidate{a}, results("a", 4, now), now); !ok {
		t.Fatal("failed to select initial candidate")
	}

	next := now.Add(11 * time.Minute)
	probes := append(results("a", 5, next), results("b", 5, next)...)
	selected, ok := s.Select([]Candidate{a, b}, probes, next)
	if !ok || selected.Candidate.ServerID != "a" {
		t.Fatalf("tie must retain current server, got %+v ok=%t", selected, ok)
	}
}

func TestSelectorSwitchesAfterRepeatedImprovementAndHold(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	s := NewSelector(DefaultPolicy())
	a := candidate("a", "192.0.2.1", now)
	b := candidate("b", "192.0.2.2", now)
	if _, ok := s.Select([]Candidate{a, b}, results("a", 5, now), now); !ok {
		t.Fatal("failed to select initial candidate")
	}

	first := now.Add(11 * time.Minute)
	probes := append(results("a", 5, first), results("b", 6, first)...)
	selected, ok := s.Select([]Candidate{a, b}, probes, first)
	if !ok || selected.Candidate.ServerID != "a" {
		t.Fatalf("first improvement cycle should not switch, got %+v", selected)
	}

	second := first.Add(time.Minute)
	probes = append(results("a", 5, second), results("b", 6, second)...)
	selected, ok = s.Select([]Candidate{a, b}, probes, second)
	if !ok || selected.Candidate.ServerID != "b" {
		t.Fatalf("second improvement cycle should switch, got %+v", selected)
	}
	if selected.Generation != 2 {
		t.Fatalf("generation = %d, want 2", selected.Generation)
	}
}

func TestEndpointAddressChangeIncrementsGeneration(t *testing.T) {
	now := time.Now().UTC()
	s := NewSelector(DefaultPolicy())
	a := candidate("a", "192.0.2.1", now)
	selected, ok := s.Select([]Candidate{a}, results("a", 5, now), now)
	if !ok || selected.Generation != 1 {
		t.Fatalf("unexpected initial selection: %+v", selected)
	}

	updated := candidate("a", "192.0.2.3", now.Add(time.Minute))
	selected, ok = s.Select([]Candidate{updated}, results("a", 5, now.Add(time.Minute)), now.Add(time.Minute))
	if !ok || selected.Generation != 2 || selected.Candidate.IPv4[0] != "192.0.2.3" {
		t.Fatalf("address change was not published: %+v", selected)
	}
}

func TestEndpointFreshnessAtExactLimitIsExpired(t *testing.T) {
	now := time.Now().UTC()
	s := NewSelector(DefaultPolicy())
	exactlyExpired := candidate("expired", "192.0.2.1", now.Add(-DefaultEndpointMaxAge))
	if selected, ok := s.Select([]Candidate{exactlyExpired}, results("expired", 7, now), now); ok {
		t.Fatalf("endpoint at exact max age must be expired: %+v", selected)
	}
}

func TestStaleBootstrapEndpointIsRejected(t *testing.T) {
	now := time.Now().UTC()
	s := NewSelector(DefaultPolicy())
	stale := candidate("old", "192.0.2.1", now.Add(-DefaultEndpointMaxAge-time.Second))
	if selected, ok := s.Select([]Candidate{stale}, results("old", 7, now), now); ok {
		t.Fatalf("stale endpoint selected: %+v", selected)
	}
}

func TestZeroScoreImmediatelyFailsOverToHealthyCandidate(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	policy := DefaultPolicy()
	policy.MinimumHold = 10 * time.Minute
	policy.SwitchCooldown = 10 * time.Minute
	s := NewSelector(policy)
	a := candidate("a", "192.0.2.1", now)
	b := candidate("b", "192.0.2.2", now)
	if _, ok := s.Select([]Candidate{a, b}, results("a", 7, now), now); !ok {
		t.Fatal("failed to select initial endpoint")
	}
	failureAt := now.Add(5 * time.Minute)
	selected, ok := s.Select([]Candidate{a, b},
		append(results("a", 0, failureAt), results("b", 8, failureAt)...), failureAt)
	if !ok || selected.Candidate.ServerID != "b" || !selected.SelectedAt.Equal(failureAt) {
		t.Fatalf("zero-score endpoint must fail over in the first failed probe cycle: %+v ok=%t", selected, ok)
	}
}

func TestZeroScoreWithoutHealthyAlternativeWithdrawsImmediately(t *testing.T) {
	now := time.Date(2026, 11, 21, 13, 0, 0, 0, time.UTC)
	s := NewSelector(DefaultPolicy())
	a := candidate("a", "192.0.2.1", now)
	if _, ok := s.Select([]Candidate{a}, results("a", 7, now), now); !ok {
		t.Fatal("failed to select initial endpoint")
	}
	failureAt := now.Add(5 * time.Minute)
	if selected, ok := s.Select([]Candidate{a}, results("a", 0, failureAt), failureAt); ok {
		t.Fatalf("zero-score endpoint must be withdrawn immediately: %+v", selected)
	}
	if _, ok := s.Current(failureAt); ok {
		t.Fatal("selector retained zero-score endpoint")
	}
}

func TestDuplicateAndUnknownProbeResultsDoNotInflateScore(t *testing.T) {
	now := time.Now().UTC()
	s := NewSelector(DefaultPolicy())
	a := candidate("a", "192.0.2.1", now)
	probes := []ProbeResult{
		{ServerID: "a", Domain: "CHATGPT.COM.", Success: true, CheckedAt: now},
		{ServerID: "a", Domain: "chatgpt.com", Success: true, CheckedAt: now.Add(time.Second)},
		{ServerID: "a", Domain: "not-in-control-set.example", Success: true, CheckedAt: now},
	}
	selected, ok := s.Select([]Candidate{a}, probes, now)
	if !ok {
		t.Fatal("expected one successful control-domain probe to be sufficient")
	}
	if selected.Score != 1 {
		t.Fatalf("score = %d, want 1", selected.Score)
	}
}

func TestCandidateRejectsInvalidURLHostnameAndIP(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name      string
		candidate Candidate
	}{
		{"url host mismatch", Candidate{ServerID: "a", URL: "https://other.example/dns-query", Hostname: "a.example", IPv4: []string{"192.0.2.1"}, ResolvedAt: now}},
		{"non https", Candidate{ServerID: "a", URL: "http://a.example/dns-query", Hostname: "a.example", IPv4: []string{"192.0.2.1"}, ResolvedAt: now}},
		{"invalid IP", Candidate{ServerID: "a", URL: "https://a.example/dns-query", Hostname: "a.example", IPv4: []string{"not-an-ip"}, ResolvedAt: now}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewSelector(DefaultPolicy())
			if selected, ok := s.Select([]Candidate{tc.candidate}, results("a", 7, now), now); ok {
				t.Fatalf("invalid candidate selected: %+v", selected)
			}
		})
	}
}

func TestSelectionCopiesCandidateAddresses(t *testing.T) {
	now := time.Now().UTC()
	s := NewSelector(DefaultPolicy())
	a := candidate("a", "192.0.2.1", now)
	selected, ok := s.Select([]Candidate{a}, results("a", 7, now), now)
	if !ok {
		t.Fatal("selection failed")
	}
	selected.Candidate.IPv4[0] = "203.0.113.9"
	current, ok := s.Current(now)
	if !ok {
		t.Fatal("current selection unavailable")
	}
	if current.Candidate.IPv4[0] != "192.0.2.1" {
		t.Fatal("caller mutated selector's internal address list")
	}
}

func TestControlDomainScoreDoesNotExceedSeven(t *testing.T) {
	now := time.Now().UTC()
	probes := results("a", 7, now)
	for i := 0; i < 20; i++ {
		probes = append(probes, ProbeResult{
			ServerID:  "a",
			Domain:    fmt.Sprintf("extra-%d.example", i),
			Success:   true,
			CheckedAt: now,
		})
	}
	s := NewSelector(DefaultPolicy())
	selected, ok := s.Select([]Candidate{candidate("a", "192.0.2.1", now)}, probes, now)
	if !ok || selected.Score != 7 {
		t.Fatalf("score = %+v, want seven control checks", selected)
	}
}

func TestConfigGenerationChangeInvalidatesActiveSelection(t *testing.T) {
	now := time.Now().UTC()
	s := NewSelector(DefaultPolicy())

	firstCandidate := candidate("a", "192.0.2.1", now)
	firstCandidate.ConfigGeneration = 41
	first, ok := s.Select([]Candidate{firstCandidate}, results("a", 7, now), now)
	if !ok || first.Generation != 1 {
		t.Fatalf("unexpected initial selection: %+v", first)
	}

	updatedCandidate := candidate("a", "192.0.2.1", now.Add(time.Second))
	updatedCandidate.ConfigGeneration = 42
	updated, ok := s.Select([]Candidate{updatedCandidate}, results("a", 7, now.Add(time.Second)), now.Add(time.Second))
	if !ok {
		t.Fatal("selection should remain available after config reload")
	}
	if updated.Generation != 2 || updated.Candidate.ConfigGeneration != 42 {
		t.Fatalf("config generation change was not published: %+v", updated)
	}
}

func setSuccessfulProbeDuration(values []ProbeResult, duration time.Duration) []ProbeResult {
	for i := range values {
		if values[i].Success {
			values[i].Duration = duration
		}
	}
	return values
}

func TestInitialSelectionUsesLowestEWMAForEqualHealthScore(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	s := NewSelector(DefaultPolicy())
	a := candidate("a", "192.0.2.1", now)
	b := candidate("b", "192.0.2.2", now)
	probes := append(
		setSuccessfulProbeDuration(results("a", 5, now), 120*time.Millisecond),
		setSuccessfulProbeDuration(results("b", 5, now), 40*time.Millisecond)...,
	)
	selected, ok := s.Select([]Candidate{a, b}, probes, now)
	if !ok || selected.Candidate.ServerID != "b" {
		t.Fatalf("expected lower-latency equal-score candidate b, got %+v ok=%t", selected, ok)
	}
	if got := s.latencyEWMA["b"]; got != 40*time.Millisecond {
		t.Fatalf("initial EWMA = %s, want 40ms", got)
	}
}

func TestLatencyOnlySwitchRequiresRepeatedImprovementAndAntiFlapGates(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	s := NewSelector(DefaultPolicy())
	a := candidate("a", "192.0.2.1", now)
	b := candidate("b", "192.0.2.2", now)
	// Equal initial RTTs preserve deterministic configured ordering (A first).
	initial := append(
		setSuccessfulProbeDuration(results("a", 5, now), 100*time.Millisecond),
		setSuccessfulProbeDuration(results("b", 5, now), 100*time.Millisecond)...,
	)
	selected, ok := s.Select([]Candidate{a, b}, initial, now)
	if !ok || selected.Candidate.ServerID != "a" {
		t.Fatalf("expected initial A selection, got %+v ok=%t", selected, ok)
	}

	first := now.Add(11 * time.Minute)
	probes := append(
		setSuccessfulProbeDuration(results("a", 5, first), 300*time.Millisecond),
		setSuccessfulProbeDuration(results("b", 5, first), 10*time.Millisecond)...,
	)
	selected, ok = s.Select([]Candidate{a, b}, probes, first)
	if !ok || selected.Candidate.ServerID != "a" {
		t.Fatalf("one latency improvement cycle must not switch, got %+v", selected)
	}

	second := first.Add(time.Minute)
	probes = append(
		setSuccessfulProbeDuration(results("a", 5, second), 300*time.Millisecond),
		setSuccessfulProbeDuration(results("b", 5, second), 10*time.Millisecond)...,
	)
	selected, ok = s.Select([]Candidate{a, b}, probes, second)
	if !ok || selected.Candidate.ServerID != "b" {
		t.Fatalf("second sustained latency improvement should switch to B, got %+v", selected)
	}
}

func TestLatencyEWMAIgnoresFailedAndUnknownProbes(t *testing.T) {
	now := time.Now().UTC()
	s := NewSelector(DefaultPolicy())
	probes := []ProbeResult{
		{ServerID: "a", Domain: "chatgpt.com", Success: true, CheckedAt: now, Duration: 100 * time.Millisecond},
		{ServerID: "a", Domain: "claude.ai", Success: false, CheckedAt: now, Duration: 900 * time.Millisecond},
		{ServerID: "a", Domain: "unknown.example", Success: true, CheckedAt: now, Duration: time.Millisecond},
	}
	s.mu.Lock()
	s.updateLatencyEWMA(probes)
	s.mu.Unlock()
	if got := s.latencyEWMA["a"]; got != 100*time.Millisecond {
		t.Fatalf("EWMA = %s, want 100ms from successful known probe only", got)
	}
}

func TestLatencyOnlySwitchIgnoresInsignificantAdvantage(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	s := NewSelector(DefaultPolicy())
	a := candidate("a", "192.0.2.1", now)
	b := candidate("b", "192.0.2.2", now)
	initial := append(
		setSuccessfulProbeDuration(results("a", 5, now), 100*time.Millisecond),
		setSuccessfulProbeDuration(results("b", 5, now), 100*time.Millisecond)...,
	)
	if selected, ok := s.Select([]Candidate{a, b}, initial, now); !ok || selected.Candidate.ServerID != "a" {
		t.Fatalf("expected deterministic initial A selection, got %+v", selected)
	}
	for cycle := 1; cycle <= 3; cycle++ {
		at := now.Add(time.Duration(10+cycle) * time.Minute)
		probes := append(
			setSuccessfulProbeDuration(results("a", 5, at), 100*time.Millisecond),
			setSuccessfulProbeDuration(results("b", 5, at), 95*time.Millisecond)...,
		)
		selected, ok := s.Select([]Candidate{a, b}, probes, at)
		if !ok || selected.Candidate.ServerID != "a" {
			t.Fatalf("sub-10%% latency advantage must not cause a switch, got %+v", selected)
		}
	}
}

func TestLatencyPreferredRequiresRelativeAndAbsoluteImprovement(t *testing.T) {
	if latencyPreferred(950*time.Millisecond, time.Second) {
		t.Fatal("50ms improvement should not pass 100ms absolute threshold")
	}
	if latencyPreferred(800*time.Millisecond, time.Second) {
		t.Fatal("200ms improvement should not pass 25% relative threshold")
	}
	if !latencyPreferred(700*time.Millisecond, time.Second) {
		t.Fatal("300ms improvement should pass both thresholds")
	}
	if latencyPreferred(100*time.Millisecond, 150*time.Millisecond) {
		t.Fatal("50ms gain must not pass the 100ms absolute threshold")
	}
	if !latencyPreferred(350*time.Millisecond, 500*time.Millisecond) {
		t.Fatal("150ms gain at 500ms should pass both thresholds")
	}
}
