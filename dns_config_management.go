package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// dnsConfigWriteMu serializes CLI, Web UI and daemon-generated config updates.
var dnsConfigWriteMu sync.Mutex

// writeConfigWithBackup is shared by CLI and Web UI for all config.json writes.
func writeConfigWithBackup(path string, cfg Config) error {
	original, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read current config.json for backup: %w", err)
	}
	backupPath := path + ".bak"
	if backupInfo, err := os.Lstat(backupPath); err == nil && backupInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing to replace a symlink at config.json.bak")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect config backup: %w", err)
	}
	if err := writeAtomicFile(backupPath, original, 0600); err != nil {
		return fmt.Errorf("create config.json.bak: %w", err)
	}
	if err := writeConfigAtomic(path, cfg); err != nil {
		return fmt.Errorf("atomic config.json replacement failed (backup retained): %w", err)
	}
	return nil
}

// saveDNSModeConfig is the single write path used by the CLI and Web UI.
// It validates the complete resulting config before creating a backup or
// replacing config.json. The daemon applies the atomic replacement by hot reload.
func saveDNSModeConfig(dataDir, mode string, resolvers []ResolverUpstream) (Config, error) {
	dnsConfigWriteMu.Lock()
	defer dnsConfigWriteMu.Unlock()
	root, err := filepath.Abs(strings.TrimSpace(dataDir))
	if err != nil || strings.TrimSpace(dataDir) == "" {
		return Config{}, errors.New("plugin data directory is not configured")
	}
	info, err := os.Lstat(root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return Config{}, errors.New("plugin data directory must be an existing real directory")
	}
	path := filepath.Join(root, "config.json")
	fi, err := os.Lstat(path)
	if err != nil {
		return Config{}, fmt.Errorf("inspect config.json: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() || fi.Size() > webUIAdminMaxFile {
		return Config{}, errors.New("config.json must be a regular non-symlink file within the size limit")
	}
	cfg, err := loadConfigNoCreate(path)
	if err != nil {
		return Config{}, fmt.Errorf("existing config.json is invalid: %w", err)
	}
	mode = strings.TrimSpace(mode)
	if mode != "endpoint_ip" && mode != "resolver" {
		return Config{}, errors.New("dns_mode must be endpoint_ip or resolver")
	}
	cfg.DNSMode = mode
	if resolvers != nil {
		cfg.ResolverUpstreams = append([]ResolverUpstream(nil), resolvers...)
	}
	cfg = normalizeDNSConfig(cfg)
	cfg = normalizeCacheConfig(cfg)
	if err := validateConfig(cfg); err != nil {
		return Config{}, fmt.Errorf("DNS configuration validation failed: %w", err)
	}
	if err := writeConfigWithBackup(path, cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func runDNSConfigCLI(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: doh-health-monitor config")
	}
	dataDir := strings.TrimSpace(os.Getenv("LUCX_PLUGIN_DATA"))
	if dataDir == "" {
		return errors.New("LUCX_PLUGIN_DATA is required")
	}
	path := filepath.Join(dataDir, "config.json")
	cfg, err := loadConfigNoCreate(path)
	if err != nil {
		return fmt.Errorf("load config.json: %w", err)
	}
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Текущий DNS mode: %s\n", cfg.DNSMode)
	fmt.Println("Выберите режим:")
	fmt.Println("  1) endpoint_ip (режим по умолчанию)")
	fmt.Println("  2) resolver")
	fmt.Print("Новый режим [1/2, Enter — отмена]: ")
	choice, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read mode selection: %w", err)
	}
	switch strings.TrimSpace(choice) {
	case "":
		fmt.Println("Изменения отменены.")
		return nil
	case "1":
		cfg.DNSMode = "endpoint_ip"
	case "2":
		cfg.DNSMode = "resolver"
	default:
		return errors.New("выберите 1, 2 или Enter для отмены")
	}

	var resolvers []ResolverUpstream
	if cfg.DNSMode == "resolver" {
		encoded, _ := json.Marshal(cfg.ResolverUpstreams)
		fmt.Println("Текущий resolver_upstreams (JSON, одна строка):")
		fmt.Println(string(encoded))
		fmt.Println("Вставьте новый JSON-массив одной строкой или нажмите Enter, чтобы оставить текущий порядок и параметры.")
		fmt.Print("resolver_upstreams JSON [Enter — оставить]: ")
		line, readErr := reader.ReadString('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return fmt.Errorf("read resolver_upstreams: %w", readErr)
		}
		if strings.TrimSpace(line) != "" {
			if err := json.Unmarshal([]byte(line), &resolvers); err != nil {
				return fmt.Errorf("invalid resolver_upstreams JSON: %w", err)
			}
		} else {
			resolvers = cfg.ResolverUpstreams
		}
	}
	fmt.Printf("Будет сохранено: dns_mode=%s, resolver_upstreams=%d. Продолжить? [y/N]: ", cfg.DNSMode, func() int { if resolvers != nil { return len(resolvers) }; return len(cfg.ResolverUpstreams) }())
	confirm, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read confirmation: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(confirm), "y") && !strings.EqualFold(strings.TrimSpace(confirm), "yes") {
		fmt.Println("Изменения отменены.")
		return nil
	}
	if resolvers == nil {
		resolvers = cfg.ResolverUpstreams
	}
	saved, err := saveDNSModeConfig(dataDir, cfg.DNSMode, resolvers)
	if err != nil {
		return err
	}
	fmt.Printf("[OK] Сохранено: dns_mode=%s, resolver_upstreams=%d\n", saved.DNSMode, len(saved.ResolverUpstreams))
	fmt.Println("Создан config.json.bak. Демон применит изменения автоматически в течение 30 секунд.")
	fmt.Println("Проверьте /status: last_reload обновится, last_error должен быть пустым.")
	return nil
}
