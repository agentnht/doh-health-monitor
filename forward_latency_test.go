package main

import (
	"testing"
	"time"
)

func TestForwardLatencyHistogramReportsBoundedPercentiles(t *testing.T) {
	r := &Runtime{}
	for _, sample := range []time.Duration{
		20 * time.Millisecond,
		40 * time.Millisecond,
		90 * time.Millisecond,
		150 * time.Millisecond,
		300 * time.Millisecond,
		900 * time.Millisecond,
		2 * time.Second,
		5 * time.Second,
	} {
		r.recordDoHForwardLatency(sample)
	}
	if got := r.forwardLatencyPercentile(50); got != 200 {
		t.Fatalf("p50 bucket=%dms, want 200ms", got)
	}
	if got := r.forwardLatencyPercentile(95); got != 6400 {
		t.Fatalf("p95 bucket=%dms, want 6400ms overflow bucket", got)
	}
	if got := r.forwardLatencySampleCount(); got != 8 {
		t.Fatalf("sample count=%d, want 8", got)
	}
}

func TestForwardLatencyHistogramEmptyAndOutOfRangePercentiles(t *testing.T) {
	r := &Runtime{}
	if got := r.forwardLatencyPercentile(95); got != 0 {
		t.Fatalf("empty p95=%d, want 0", got)
	}
	r.recordDoHForwardLatency(75 * time.Millisecond)
	if got := r.forwardLatencyPercentile(0); got != 100 {
		t.Fatalf("p0 bucket=%d, want first rank's 100ms bucket", got)
	}
}
