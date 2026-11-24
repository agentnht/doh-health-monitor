package main

import (
	"time"
)

const activeDoHStaleResponseBudget = 1800 * time.Millisecond
const activeDoHFailureRecheckInterval = 2 * time.Second
const maxActiveDoHFailureRechecks = 4096

// activeDoHFailureRecheck suppresses repeated upstream attempts briefly after
// a request has already fallen back to stale data. Entries are bounded and
// keyed by the configuration-scoped stale cache key.
func (r *Runtime) staleRecheckSuppressed(key string, now time.Time) bool {
	r.staleRecheckMu.Lock()
	defer r.staleRecheckMu.Unlock()
	deadline, ok := r.staleRechecks[key]
	if !ok {
		return false
	}
	if !now.Before(deadline) {
		delete(r.staleRechecks, key)
		return false
	}
	return true
}

func (r *Runtime) markStaleRecheck(key string, now time.Time) {
	r.staleRecheckMu.Lock()
	defer r.staleRecheckMu.Unlock()
	if r.staleRechecks == nil {
		r.staleRechecks = make(map[string]time.Time)
	}
	if len(r.staleRechecks) >= maxActiveDoHFailureRechecks {
		for existing, deadline := range r.staleRechecks {
			if !now.Before(deadline) {
				delete(r.staleRechecks, existing)
			}
		}
	}
	if len(r.staleRechecks) >= maxActiveDoHFailureRechecks {
		// Keep memory bounded under high-cardinality traffic. Evict one expired
		// or arbitrary old key rather than allowing unbounded growth.
		for existing := range r.staleRechecks {
			delete(r.staleRechecks, existing)
			break
		}
	}
	r.staleRechecks[key] = now.Add(activeDoHFailureRecheckInterval)
}

type dnsAttemptResult struct {
	response []byte
	err      error
}

// awaitDNSWithStaleBudget lets an already-expired cache entry satisfy a
// request within the client-facing budget. If no stale answer is eligible when
// the timer fires, the caller continues waiting for the real upstream result.
func awaitDNSWithStaleBudget(
	result <-chan dnsAttemptResult,
	budget time.Duration,
	stale func() ([]byte, bool),
) ([]byte, error, bool) {
	if budget <= 0 || stale == nil {
		completed := <-result
		return completed.response, completed.err, false
	}
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case completed := <-result:
		return completed.response, completed.err, false
	case <-timer.C:
		if response, ok := stale(); ok {
			return response, nil, true
		}
		completed := <-result
		return completed.response, completed.err, false
	}
}
