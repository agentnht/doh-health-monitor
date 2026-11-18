package dohintegration

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckPluginHealthUsesReadOnlyLocalProbes(t *testing.T) {
	binDir := t.TempDir()
	systemctl := filepath.Join(binDir, "systemctl")
	systemctlScript := "#!/bin/sh\ncase \"$1\" in\n  show) printf 'loaded\\n' ;;\n  is-active) exit 0 ;;\n  *) exit 2 ;;\nesac\n"
	if err := os.WriteFile(systemctl, []byte(systemctlScript), 0700); err != nil {
		t.Fatal(err)
	}
	ss := filepath.Join(binDir, "ss")
	ssScript := "#!/bin/sh\nprintf 'LISTEN 0 128 127.0.0.1:5355 0.0.0.0:*\\nUNCONN 0 0 127.0.0.1:5355 0.0.0.0:*\\n'\n"
	if err := os.WriteFile(ss, []byte(ssScript), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	dataDir := t.TempDir()
	const apiToken = "0123456789abcdefghijklmnopqrstuvwxyzABCDE"
	if err := os.WriteFile(filepath.Join(dataDir, "auto-hosts-api.token"), []byte(apiToken+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LUCX_PLUGIN_DATA", dataDir)

	requests := 0
	status := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet {
			t.Errorf("status method=%s, want GET", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+apiToken {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"version\":\"test\"}"))
	}))
	defer status.Close()

	opts := DefaultOptions()
	opts.Service = "test.service"
	opts.StatusURL = status.URL
	if err := checkPluginHealth(opts, nil); err != nil {
		t.Fatalf("read-only plugin check failed: %v", err)
	}
	if requests != 1 {
		t.Fatalf("status API requests=%d, want 1", requests)
	}
}

func TestCheckPluginHealthRejectsNonLoopbackStatusURL(t *testing.T) {
	opts := DefaultOptions()
	opts.StatusURL = "http://192.0.2.10:18765/status"
	if err := checkPluginHealth(opts, nil); err == nil {
		t.Fatal("non-loopback status URL must be rejected")
	}
}
