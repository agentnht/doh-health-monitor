package main

import (
	"testing"
	"time"
)

func TestAwaitActiveDoHUsesStaleWithinBudget(t *testing.T) {
	result := make(chan activeDoHAttemptResult, 1)
	go func() {
		time.Sleep(30 * time.Millisecond)
		result <- activeDoHAttemptResult{response: []byte("upstream")}
	}()
	started := time.Now()
	got, err, stale := awaitActiveDoHWithStaleBudget(result, 5*time.Millisecond, func() ([]byte, bool) {
		return []byte("stale"), true
	})
	if err != nil || !stale || string(got) != "stale" {
		t.Fatalf("got=%q err=%v stale=%v, want stale response", got, err, stale)
	}
	if elapsed := time.Since(started); elapsed > 25*time.Millisecond {
		t.Fatalf("stale response took %s; expected bounded return", elapsed)
	}
}

func TestAwaitActiveDoHFallsThroughWhenStaleUnavailable(t *testing.T) {
	result := make(chan activeDoHAttemptResult, 1)
	result <- activeDoHAttemptResult{response: []byte("upstream")}
	got, err, stale := awaitActiveDoHWithStaleBudget(result, time.Millisecond, func() ([]byte, bool) {
		return nil, false
	})
	if err != nil || stale || string(got) != "upstream" {
		t.Fatalf("got=%q err=%v stale=%v, want upstream response", got, err, stale)
	}
}

func TestStaleRecheckSuppressionExpiresAndStaysBounded(t *testing.T) {
	r := &Runtime{}
	now := time.Now()
	r.markStaleRecheck("one", now)
	if !r.staleRecheckSuppressed("one", now.Add(time.Second)) {
		t.Fatal("expected recheck suppression before deadline")
	}
	if r.staleRecheckSuppressed("one", now.Add(3*time.Second)) {
		t.Fatal("suppression should expire")
	}
	for i := 0; i < maxActiveDoHFailureRechecks+10; i++ {
		r.markStaleRecheck(string(rune(i+1)), now)
	}
	if len(r.staleRechecks) > maxActiveDoHFailureRechecks {
		t.Fatalf("recheck map grew to %d entries", len(r.staleRechecks))
	}
}
