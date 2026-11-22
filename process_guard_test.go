package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProcessGuardPreventsDuplicateAndRemovesPID(t *testing.T) {
	dir := t.TempDir()
	first, err := acquireProcessGuard(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.WritePID(); err != nil {
		t.Fatal(err)
	}

	pidPath := filepath.Join(dir, "doh-health-monitor.pid")
	pid, err := readDaemonPID(pidPath)
	if err != nil {
		t.Fatal(err)
	}
	if pid != os.Getpid() {
		t.Fatalf("PID file=%d, want current process %d", pid, os.Getpid())
	}

	if second, err := acquireProcessGuard(dir); err == nil {
		second.Release()
		t.Fatal("second daemon instance acquired the process lock")
	} else if !strings.Contains(err.Error(), "already running") {
		t.Fatalf("duplicate-instance error=%v", err)
	}

	first.Release()
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Fatalf("PID file still exists after clean release: %v", err)
	}

	second, err := acquireProcessGuard(dir)
	if err != nil {
		t.Fatalf("lock was not released: %v", err)
	}
	defer second.Release()
	if err := second.WritePID(); err != nil {
		t.Fatal(err)
	}
}

func TestProcessGuardReplacesStalePID(t *testing.T) {
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "doh-health-monitor.pid")
	if err := os.WriteFile(pidPath, []byte("99999999\n"), 0600); err != nil {
		t.Fatal(err)
	}

	guard, err := acquireProcessGuard(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Release()
	if err := guard.WritePID(); err != nil {
		t.Fatal(err)
	}
	pid, err := readDaemonPID(pidPath)
	if err != nil {
		t.Fatal(err)
	}
	if pid != os.Getpid() {
		t.Fatalf("stale PID was not replaced: got %d, want %d", pid, os.Getpid())
	}
}
