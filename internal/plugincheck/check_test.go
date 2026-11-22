package plugincheck

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func writeTestExecutable(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func testToolOptions(t *testing.T, listenerPID int) Options {
	t.Helper()
	binDir := t.TempDir()
	systemctl := writeTestExecutable(t, binDir, "systemctl", `#!/bin/sh
case "$1:$2" in
  show:--property=LoadState) printf 'loaded\n' ;;
  show:--property=MainPID) printf '%s\n' "$PLUGIN_TEST_MAIN_PID" ;;
  is-active:--quiet) exit 0 ;;
  *) exit 2 ;;
esac
`)
	ss := writeTestExecutable(t, binDir, "ss", `#!/bin/sh
printf 'LISTEN 0 128 127.0.0.1:5355 0.0.0.0:* users:(("doh-health-monitor",pid=%s,fd=3))\n' "$PLUGIN_TEST_LISTENER_PID"
`)
	t.Setenv("PLUGIN_TEST_MAIN_PID", strconv.Itoa(listenerPID))
	t.Setenv("PLUGIN_TEST_LISTENER_PID", strconv.Itoa(listenerPID))
	opts := DefaultOptions()
	opts.Service = "test.service"
	opts.systemctlPath = systemctl
	opts.ssPath = ss
	return opts
}

func TestCheckPluginHealthRequiresListenersOwnedByServiceMainPID(t *testing.T) {
	const servicePID = 12345
	opts := testToolOptions(t, servicePID)

	requests := 0
	status := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet || r.URL.Path != "/healthz" {
			t.Errorf("health request=%s %s, want GET /healthz", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	}))
	defer status.Close()
	opts.StatusURL = status.URL + "/healthz"

	if err := checkPluginHealth(opts, nil); err != nil {
		t.Fatalf("read-only plugin check failed: %v", err)
	}
	if requests != 1 {
		t.Fatalf("status API requests=%d, want 1", requests)
	}
}

func TestCheckPluginHealthRejectsListenerOwnedByAnotherProcess(t *testing.T) {
	opts := testToolOptions(t, 12345)
	t.Setenv("PLUGIN_TEST_LISTENER_PID", "54321")

	statusRequests := 0
	status := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		statusRequests++
		_, _ = w.Write([]byte("ok\n"))
	}))
	defer status.Close()
	opts.StatusURL = status.URL + "/healthz"

	err := checkPluginHealth(opts, nil)
	if err == nil || !strings.Contains(err.Error(), "not owned by service MainPID") {
		t.Fatalf("foreign listener PID should fail ownership check, got %v", err)
	}
	if statusRequests != 0 {
		t.Fatalf("health endpoint was queried before socket ownership was proven: %d requests", statusRequests)
	}
}

func TestCheckPluginHealthRejectsMissingSocketOwner(t *testing.T) {
	opts := testToolOptions(t, 12345)
	opts.ssPath = writeTestExecutable(t, t.TempDir(), "ss", "#!/bin/sh\nprintf 'LISTEN 0 128 127.0.0.1:5355 0.0.0.0:*\\n'\n")
	if err := checkPluginHealth(opts, nil); err == nil {
		t.Fatal("listener without ss process ownership metadata must fail")
	}
}

func TestListenerOwnedByPID(t *testing.T) {
	tests := []struct {
		name string
		line string
		want bool
	}{
		{"ipv4 service PID", `LISTEN 0 128 127.0.0.1:5355 0.0.0.0:* users:(("plugin",pid=42,fd=3))`, true},
		{"ipv6 service PID", `UNCONN 0 0 [::1]:5355 [::]:* users:(("plugin",pid=42,fd=4))`, true},
		{"foreign PID", `LISTEN 0 128 127.0.0.1:5355 0.0.0.0:* users:(("other",pid=43,fd=3))`, false},
		{"non-loopback", `LISTEN 0 128 0.0.0.0:5355 0.0.0.0:* users:(("plugin",pid=42,fd=3))`, false},
		{"wrong port", `LISTEN 0 128 127.0.0.1:5356 0.0.0.0:* users:(("plugin",pid=42,fd=3))`, false},
		{"no process metadata", `LISTEN 0 128 127.0.0.1:5355 0.0.0.0:*`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := listenerOwnedByPID(tt.line, 5355, 42); got != tt.want {
				t.Fatalf("listenerOwnedByPID()=%t, want %t", got, tt.want)
			}
		})
	}
}

func TestExecutablePathRequiresAbsoluteExecutable(t *testing.T) {
	path := writeTestExecutable(t, t.TempDir(), "tool", "#!/bin/sh\nexit 0\n")
	if _, err := executablePath("ss", "relative/tool"); err == nil {
		t.Fatal("relative override path must be rejected")
	}
	got, err := executablePath("ss", path)
	if err != nil {
		t.Fatal(err)
	}
	if got != path {
		t.Fatalf("executable path=%q, want %q", got, path)
	}
	if _, err := executablePath("ss", filepath.Join(filepath.Dir(path), "missing")); err == nil {
		t.Fatal("missing executable path must be rejected")
	}
}

func TestCheckPluginHealthRejectsNonLoopbackStatusURL(t *testing.T) {
	opts := DefaultOptions()
	opts.StatusURL = "http://192.0.2.10:18765/healthz"
	if err := checkPluginHealth(opts, nil); err == nil {
		t.Fatal("non-loopback status URL must be rejected")
	}
}

func TestCheckPluginHealthRejectsDetailedStatusURL(t *testing.T) {
	opts := DefaultOptions()
	opts.StatusURL = "http://127.0.0.1:18765/status"
	if err := checkPluginHealth(opts, nil); err == nil {
		t.Fatal("detailed /status endpoint must not be used as unauthenticated health probe")
	}
}
