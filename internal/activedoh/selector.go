package activedoh

import (
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	DefaultEndpointMaxAge = 6 * time.Hour
	DefaultMinimumHold    = 10 * time.Minute
	DefaultSwitchCooldown = 10 * time.Minute
	DefaultFailureCycles  = 2
)

var controlDomains = [...]string{
	"chatgpt.com",
	"claude.ai",
	"gemini.google.com",
	"elevenlabs.io",
	"grok.com",
	"www.perplexity.ai",
	"notebooklm.google.com",
	"aistudio.google.com",
}

// ControlDomains returns the fixed health-check set used to select one active DoH endpoint.
func ControlDomains() []string {
	return append([]string(nil), controlDomains[:]...)
}

type Candidate struct {
	ServerID         string
	URL              string
	Hostname         string
	IPv4             []string
	IPv6             []string
	ResolvedAt       time.Time
	ConfigGeneration uint64
}

type ProbeResult struct {
	ServerID  string
	Domain    string
	Success   bool
	CheckedAt time.Time
	Duration  time.Duration
	Error     string
}

type Policy struct {
	EndpointMaxAge time.Duration
	MinimumHold    time.Duration
	SwitchCooldown time.Duration
	FailureCycles  int
}

func DefaultPolicy() Policy {
	return Policy{
		EndpointMaxAge: DefaultEndpointMaxAge,
		MinimumHold:    DefaultMinimumHold,
		SwitchCooldown: DefaultSwitchCooldown,
		FailureCycles:  DefaultFailureCycles,
	}
}

func normalizePolicy(p Policy) Policy {
	d := DefaultPolicy()
	if p.EndpointMaxAge <= 0 {
		p.EndpointMaxAge = d.EndpointMaxAge
	}
	if p.MinimumHold <= 0 {
		p.MinimumHold = d.MinimumHold
	}
	if p.SwitchCooldown <= 0 {
		p.SwitchCooldown = d.SwitchCooldown
	}
	if p.FailureCycles <= 0 {
		p.FailureCycles = d.FailureCycles
	}
	return p
}

type Selection struct {
	Candidate Candidate
	Generation uint64
	SelectedAt time.Time
	FreshUntil time.Time
	Score      int
	CheckCount int
}

// Selector applies deterministic scoring and anti-flap policy to one active DoH candidate.
// It is deliberately independent of Auto Hosts persistence and DNS request handling.
type Selector struct {
	mu sync.Mutex

	policy Policy

	current *Selection
	generation uint64

	activeSince time.Time
	lastSwitch time.Time
	activeFailures int
	betterCandidate string
	betterCandidateStreak int
}

func NewSelector(policy Policy) *Selector {
	return &Selector{policy: normalizePolicy(policy)}
}

// Select applies one completed probe cycle. A false result means no fresh, healthy endpoint
// is currently selected; callers must not answer mode-1 queries with an old cached endpoint.
func (s *Selector) Select(candidates []Candidate, results []ProbeResult, now time.Time) (Selection, bool) {
	if s == nil {
		return Selection{}, false
	}
	now = now.UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	eligible := make(map[string]Candidate, len(candidates))
	for _, raw := range candidates {
		candidate, ok := normalizeCandidate(raw, now, s.policy.EndpointMaxAge)
		if !ok {
			continue
		}
		if _, exists := eligible[candidate.ServerID]; exists {
			continue
		}
		eligible[candidate.ServerID] = candidate
	}

	scores := scoreResults(results)
	candidateIDs := make([]string, 0, len(eligible))
	for id := range eligible {
		candidateIDs = append(candidateIDs, id)
	}
	sort.Strings(candidateIDs)

	bestID, bestScore := "", 0
	for _, id := range candidateIDs {
		score := scores[id]
		if score > bestScore {
			bestID, bestScore = id, score
		}
	}

	currentID := ""
	currentEligible := false
	currentScore := 0
	if s.current != nil {
		currentID = s.current.Candidate.ServerID
		_, currentEligible = eligible[currentID]
		currentScore = scores[currentID]
	}

	// No currently selected endpoint (or its bootstrap data is stale): select the best
	// healthy candidate immediately. Do not pick the first configured server as a fallback.
	if s.current == nil || !currentEligible {
		if bestID == "" || bestScore == 0 {
			s.clearCurrent()
			return Selection{}, false
		}
		return s.setCurrent(eligible[bestID], bestScore, len(controlDomains), now), true
	}

	currentCandidate := eligible[currentID]
	if currentScore == 0 {
		s.activeFailures++
	} else {
		s.activeFailures = 0
	}

	// No candidate passed any probe. Keep the current selection for the configured
	// failure grace cycles, then withdraw it rather than silently choosing an unhealthy server.
	if bestID == "" || bestScore == 0 {
		s.betterCandidate = ""
		s.betterCandidateStreak = 0
		if s.activeFailures >= s.policy.FailureCycles {
			s.clearCurrent()
			return Selection{}, false
		}
		return s.refreshCurrent(currentCandidate, currentScore, len(controlDomains), now), true
	}

	// Ties retain the current endpoint. This also makes selection stable across map iteration
	// order and config reloads.
	if bestID == currentID || bestScore <= currentScore {
		s.betterCandidate = ""
		s.betterCandidateStreak = 0
		return s.refreshCurrent(currentCandidate, currentScore, len(controlDomains), now), true
	}

	if s.betterCandidate == bestID {
		s.betterCandidateStreak++
	} else {
		s.betterCandidate = bestID
		s.betterCandidateStreak = 1
	}

	repeatedFailure := currentScore == 0 && s.activeFailures >= s.policy.FailureCycles
	repeatedImprovement := s.betterCandidateStreak >= 2
	if repeatedFailure || (repeatedImprovement && s.canSwitch(now)) {
		return s.setCurrent(eligible[bestID], bestScore, len(controlDomains), now), true
	}

	return s.refreshCurrent(currentCandidate, currentScore, len(controlDomains), now), true
}

// Current returns a copy of the current selection only while its bootstrap-derived
// endpoint freshness is still valid.
func (s *Selector) Current(now time.Time) (Selection, bool) {
	if s == nil {
		return Selection{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == nil || !now.Before(s.current.FreshUntil) {
		return Selection{}, false
	}
	return cloneSelection(*s.current), true
}

// Generation is increased whenever the active endpoint identity or address set changes,
// and when an active selection is withdrawn. Cache keys for mode 1 must include this value.
func (s *Selector) Generation() uint64 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.generation
}

func (s *Selector) canSwitch(now time.Time) bool {
	holdElapsed := !s.activeSince.IsZero() && now.Sub(s.activeSince) >= s.policy.MinimumHold
	cooldownElapsed := s.lastSwitch.IsZero() || now.Sub(s.lastSwitch) >= s.policy.SwitchCooldown
	return holdElapsed && cooldownElapsed
}

func (s *Selector) setCurrent(candidate Candidate, score, checkCount int, now time.Time) Selection {
	freshUntil := candidate.ResolvedAt.Add(s.policy.EndpointMaxAge)
	changed := s.current == nil || !sameEndpoint(s.current.Candidate, candidate)
	if changed {
		s.generation++
		s.activeSince = now
		s.lastSwitch = now
		s.activeFailures = 0
		s.betterCandidate = ""
		s.betterCandidateStreak = 0
	}
	selectedAt := now
	if !changed && s.current != nil {
		selectedAt = s.current.SelectedAt
	}
	selection := Selection{
		Candidate: cloneCandidate(candidate),
		Generation: s.generation,
		SelectedAt: selectedAt,
		FreshUntil: freshUntil,
		Score: score,
		CheckCount: checkCount,
	}
	s.current = &selection
	return cloneSelection(selection)
}

func (s *Selector) refreshCurrent(candidate Candidate, score, checkCount int, now time.Time) Selection {
	if s.current == nil {
		return s.setCurrent(candidate, score, checkCount, now)
	}
	// Candidate addresses may refresh while the server ID remains active. In that case
	// setCurrent increments generation so stale mode-1 cache entries cannot survive.
	return s.setCurrent(candidate, score, checkCount, now)
}

func (s *Selector) clearCurrent() {
	if s.current != nil {
		s.generation++
	}
	s.current = nil
	s.activeSince = time.Time{}
	s.lastSwitch = time.Time{}
	s.activeFailures = 0
	s.betterCandidate = ""
	s.betterCandidateStreak = 0
}

func normalizeCandidate(raw Candidate, now time.Time, maxAge time.Duration) (Candidate, bool) {
	c := cloneCandidate(raw)
	c.ServerID = strings.TrimSpace(c.ServerID)
	c.URL = strings.TrimSpace(c.URL)
	c.Hostname = normalizeHostname(c.Hostname)
	if c.ServerID == "" || len(c.ServerID) > 128 || c.URL == "" || c.Hostname == "" ||
		c.ResolvedAt.IsZero() || c.ResolvedAt.After(now) || !now.Before(c.ResolvedAt.Add(maxAge)) {
		return Candidate{}, false
	}
	u, err := url.Parse(c.URL)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Hostname() == "" || u.User != nil ||
		!strings.EqualFold(normalizeHostname(u.Hostname()), c.Hostname) {
		return Candidate{}, false
	}
	c.IPv4 = normalizeIPs(c.IPv4, true)
	c.IPv6 = normalizeIPs(c.IPv6, false)
	if len(c.IPv4)+len(c.IPv6) == 0 {
		return Candidate{}, false
	}
	c.ResolvedAt = c.ResolvedAt.UTC()
	return c, true
}

func normalizeIPs(values []string, wantIPv4 bool) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, raw := range values {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil {
			continue
		}
		var normalized string
		if wantIPv4 {
			if v4 := ip.To4(); v4 != nil {
				normalized = v4.String()
			}
		} else if ip.To4() == nil {
			if v6 := ip.To16(); v6 != nil {
				normalized = v6.String()
			}
		}
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out
}

func normalizeHostname(raw string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
}

func scoreResults(results []ProbeResult) map[string]int {
	latest := make(map[string]map[string]ProbeResult)
	for _, result := range results {
		id := strings.TrimSpace(result.ServerID)
		domain := normalizeHostname(result.Domain)
		if id == "" || !isControlDomain(domain) {
			continue
		}
		byDomain := latest[id]
		if byDomain == nil {
			byDomain = make(map[string]ProbeResult)
			latest[id] = byDomain
		}
		previous, exists := byDomain[domain]
		if exists && previous.CheckedAt.After(result.CheckedAt) {
			continue
		}
		byDomain[domain] = result
	}

	scores := make(map[string]int, len(latest))
	for id, byDomain := range latest {
		for _, result := range byDomain {
			if result.Success {
				scores[id]++
			}
		}
	}
	return scores
}

func isControlDomain(domain string) bool {
	for _, known := range controlDomains {
		if domain == known {
			return true
		}
	}
	return false
}

func sameEndpoint(a, b Candidate) bool {
	if a.ConfigGeneration != b.ConfigGeneration ||
		a.ServerID != b.ServerID || a.URL != b.URL || normalizeHostname(a.Hostname) != normalizeHostname(b.Hostname) {
		return false
	}
	if len(a.IPv4) != len(b.IPv4) || len(a.IPv6) != len(b.IPv6) {
		return false
	}
	a4, b4 := normalizeIPs(a.IPv4, true), normalizeIPs(b.IPv4, true)
	a6, b6 := normalizeIPs(a.IPv6, false), normalizeIPs(b.IPv6, false)
	if len(a4) != len(b4) || len(a6) != len(b6) {
		return false
	}
	for i := range a4 {
		if a4[i] != b4[i] {
			return false
		}
	}
	for i := range a6 {
		if a6[i] != b6[i] {
			return false
		}
	}
	return true
}

func cloneCandidate(c Candidate) Candidate {
	c.IPv4 = append([]string(nil), c.IPv4...)
	c.IPv6 = append([]string(nil), c.IPv6...)
	return c
}

func cloneSelection(s Selection) Selection {
	s.Candidate = cloneCandidate(s.Candidate)
	return s
}
