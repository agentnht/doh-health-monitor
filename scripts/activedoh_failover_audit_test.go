package activedoh

import (
	"testing"
	"time"
)

func TestAuditFailoverLatency(t *testing.T) {
	s := NewSelector(DefaultPolicy())
	t0 := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	cand := func(id, host string) Candidate {
		return Candidate{ServerID: id, URL: "https://" + host + "/dns-query", Hostname: host, IPv4: []string{"8.8.8.8"}, ResolvedAt: t0}
	}
	cands := []Candidate{cand("a", "a.example"), cand("b", "b.example")}
	res := func(now time.Time, aOK, bOK bool) []ProbeResult {
		var out []ProbeResult
		for _, d := range ControlDomains() {
			out = append(out, ProbeResult{ServerID: "a", Domain: d, Success: aOK, CheckedAt: now})
			out = append(out, ProbeResult{ServerID: "b", Domain: d, Success: bOK, CheckedAt: now})
		}
		return out
	}
	now := t0
	sel, _ := s.Select(cands, res(now, true, true), now)
	t.Logf("t=0: selected %s", sel.Candidate.ServerID)
	// endpoint "a" dies right after; probe cycles every 5 min (activeDoHProbeInterval)
	for i := 1; i <= 6; i++ {
		now = t0.Add(time.Duration(i) * 5 * time.Minute)
		sel, ok := s.Select(cands, res(now, false, true), now)
		t.Logf("cycle %d (t=+%dmin): a=0/8 b=8/8 -> selected=%s ok=%v", i, i*5, sel.Candidate.ServerID, ok)
		if sel.Candidate.ServerID == "b" {
			break
		}
	}
}
