package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeConfigWithoutStaleTTL(t *testing.T, path string, explicitZero bool) {
	t.Helper()
	data, err := json.Marshal(defaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	var cache map[string]json.RawMessage
	if err := json.Unmarshal(root["cache"], &cache); err != nil {
		t.Fatal(err)
	}
	if explicitZero {
		cache["stale_ttl_seconds"] = json.RawMessage("0")
	} else {
		delete(cache, "stale_ttl_seconds")
	}
	root["cache"], err = json.Marshal(cache)
	if err != nil {
		t.Fatal(err)
	}
	data, err = json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestStaleTTLDefaultAppliesToStartupAndHotReload(t *testing.T) {
	for _, load := range []struct {
		name string
		fn   func(string) (Config, error)
	}{
		{name: "startup", fn: loadConfig},
		{name: "hot_reload", fn: loadConfigNoCreate},
	} {
		t.Run(load.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			writeConfigWithoutStaleTTL(t, path, false)
			cfg, err := load.fn(path)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Cache.StaleTTL != 3600 {
				t.Fatalf("missing stale_ttl_seconds loaded as %d, want 3600", cfg.Cache.StaleTTL)
			}
			writeConfigWithoutStaleTTL(t, path, true)
			cfg, err = load.fn(path)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Cache.StaleTTL != 0 {
				t.Fatalf("explicit stale_ttl_seconds=0 loaded as %d, want 0", cfg.Cache.StaleTTL)
			}
		})
	}
}
