package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// processGuard keeps the daemon single-instance across panel and systemd
// launchers. The lock file intentionally remains in the data directory:
// unlinking a locked file can create an inode race between concurrent starts.
type processGuard struct {
	lockFile *os.File
	pidPath  string
	pid      int
}

func acquireProcessGuard(dataDir string) (*processGuard, error) {
	lockPath := filepath.Join(dataDir, "doh-health-monitor.lock")
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open daemon lock: %w", err)
	}
	if err := lockFile.Chmod(0600); err != nil {
		_ = lockFile.Close()
		return nil, fmt.Errorf("secure daemon lock: %w", err)
	}
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lockFile.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			pidPath := filepath.Join(dataDir, "doh-health-monitor.pid")
			pid, _ := readDaemonPID(pidPath)
			if pid > 0 {
				return nil, fmt.Errorf("another doh-health-monitor instance is already running (PID %d)", pid)
			}
			return nil, errors.New("another doh-health-monitor instance is already starting or running")
		}
		return nil, fmt.Errorf("acquire daemon lock: %w", err)
	}

	return &processGuard{
		lockFile: lockFile,
		pidPath:  filepath.Join(dataDir, "doh-health-monitor.pid"),
	}, nil
}

func readDaemonPID(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid < 1 {
		return 0, fmt.Errorf("invalid PID file %s", path)
	}
	return pid, nil
}

// WritePID publishes the PID only after all daemon listeners have been bound.
// A temporary file plus rename prevents readers from observing a partial PID.
func (g *processGuard) WritePID() error {
	if g == nil || g.lockFile == nil {
		return errors.New("daemon process lock is not held")
	}
	if g.pid != 0 {
		return nil
	}

	tmp, err := os.CreateTemp(filepath.Dir(g.pidPath), ".doh-health-monitor.pid-*")
	if err != nil {
		return fmt.Errorf("create PID file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("secure PID file: %w", err)
	}
	if _, err := fmt.Fprintf(tmp, "%d\n", os.Getpid()); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write PID file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync PID file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close PID file: %w", err)
	}
	if err := os.Rename(tmpPath, g.pidPath); err != nil {
		return fmt.Errorf("publish PID file: %w", err)
	}
	g.pid = os.Getpid()
	return nil
}

// Release removes only this process's PID file and releases the advisory lock.
// After SIGKILL the PID file may remain stale; the next lock owner safely
// replaces it because the kernel lock, not the PID text, controls ownership.
func (g *processGuard) Release() {
	if g == nil || g.lockFile == nil {
		return
	}
	if g.pid != 0 {
		if pid, err := readDaemonPID(g.pidPath); err == nil && pid == g.pid {
			if err := os.Remove(g.pidPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				logLine("WARN", "PID file cleanup failed path=%s: %v", g.pidPath, err)
			}
		}
	}
	_ = syscall.Flock(int(g.lockFile.Fd()), syscall.LOCK_UN)
	_ = g.lockFile.Close()
	g.lockFile = nil
}
