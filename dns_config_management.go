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
	"syscall"
)

// dnsConfigWriteMu serializes CLI, Web UI and daemon-generated config updates.
var dnsConfigWriteMu sync.Mutex

// acquireDNSConfigFileLock coordinates independent daemon, CLI and Web UI
// processes. The lock file is stable and is never renamed with config.json.
func acquireDNSConfigFileLock(dataDir string) (func(), error) {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return nil, errors.New("plugin data directory is not configured")
	}
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, fmt.Errorf("resolve plugin data directory: %w", err)
	}
	root, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("resolve plugin data directory: %w", err)
	}
	info, err := os.Lstat(root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("plugin data directory must be an existing real directory")
	}
	lockPath := filepath.Join(root, "config.json.lock")
	fd, err := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("open config lock file: %w", err)
	}
	file := os.NewFile(uintptr(fd), lockPath)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("open config lock file failed")
	}
	fileInfo, err := file.Stat()
	if err != nil || !fileInfo.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.New("config lock path must be a regular non-symlink file")
	}
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("secure config lock file: %w", err)
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock config file: %w", err)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			_ = syscall.Flock(fd, syscall.LOCK_UN)
			_ = file.Close()
		})
	}, nil
}

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

// prepareConfigForRuntime applies the same source-file generation and snapshot
// construction as the daemon before a management write is allowed.
func prepareConfigForRuntime(dataDir string, cfg Config) (Config, error) {
	dohPath, _, err := webUIDataFile(dataDir, "doh-servers.txt", webUIAdminMaxFile)
	if err != nil {
		return Config{}, fmt.Errorf("read DoH source for runtime validation: %w", err)
	}
	checksPath, _, err := webUIDataFile(dataDir, "tst-domen.txt", webUIAdminMaxFile)
	if err != nil {
		return Config{}, fmt.Errorf("read health-check source for runtime validation: %w", err)
	}
	sources, err := readConfigSources(dohPath, checksPath)
	if err != nil {
		return Config{}, fmt.Errorf("configuration sources are invalid: %w", err)
	}
	cfg, err = applyConfigSources(cfg, sources)
	if err != nil {
		return Config{}, fmt.Errorf("generated config validation failed: %w", err)
	}
	if _, err := buildSnapshot(cfg, sources.DoHURLs); err != nil {
		return Config{}, fmt.Errorf("runtime snapshot validation failed: %w", err)
	}
	return cfg, nil
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
	releaseFileLock, err := acquireDNSConfigFileLock(root)
	if err != nil {
		return Config{}, err
	}
	defer releaseFileLock()
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
	cfg, err = prepareConfigForRuntime(root, cfg)
	if err != nil {
		return Config{}, err
	}
	if err := writeConfigWithBackup(path, cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func parseResolverUpstreamsJSON(raw string) ([]ResolverUpstream, error) {
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var resolvers []ResolverUpstream
	if err := decoder.Decode(&resolvers); err != nil {
		return nil, fmt.Errorf("invalid resolver_upstreams JSON: %w", err)
	}
	if resolvers == nil {
		return nil, errors.New("resolver_upstreams must be a JSON array, not null")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("resolver_upstreams must contain exactly one JSON value")
	}
	return resolvers, nil
}

func runDNSConfigCLI(args []string) error {
	return runDNSConfigCLIWithIO(args, os.Getenv("LUCX_PLUGIN_DATA"), bufio.NewReader(os.Stdin), os.Stdout)
}

func runDNSConfigCLIWithIO(args []string, dataDir string, reader *bufio.Reader, out io.Writer) error {
	if len(args) != 0 {
		return errors.New("usage: doh-health-monitor config")
	}
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return errors.New("LUCX_PLUGIN_DATA is required")
	}
	path := filepath.Join(dataDir, "config.json")
	cfg, err := loadConfigNoCreate(path)
	if err != nil {
		return fmt.Errorf("load config.json: %w", err)
	}
	if reader == nil || out == nil {
		return errors.New("CLI input and output streams are required")
	}
	fmt.Fprintf(out, "Текущий DNS mode: %s\n", cfg.DNSMode)
	fmt.Fprintln(out, "Выберите режим:")
	fmt.Fprintln(out, "  1) endpoint_ip (режим по умолчанию)")
	fmt.Fprintln(out, "  2) resolver")
	fmt.Fprint(out, "Новый режим [1/2, Enter — отмена]: ")
	choice, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read mode selection: %w", err)
	}
	switch strings.TrimSpace(choice) {
	case "":
		fmt.Fprintln(out, "Изменения отменены.")
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
		fmt.Fprintln(out, "Текущий resolver_upstreams (JSON, одна строка):")
		fmt.Fprintln(out, string(encoded))
		fmt.Fprintln(out, "Вставьте новый JSON-массив одной строкой или нажмите Enter, чтобы оставить текущий порядок и параметры.")
		fmt.Fprint(out, "resolver_upstreams JSON [Enter — оставить]: ")
		line, readErr := reader.ReadString('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return fmt.Errorf("read resolver_upstreams: %w", readErr)
		}
		if strings.TrimSpace(line) != "" {
			parsed, err := parseResolverUpstreamsJSON(line)
			if err != nil {
				return err
			}
			resolvers = parsed
		} else {
			resolvers = cfg.ResolverUpstreams
		}
	}
	resolverCount := len(cfg.ResolverUpstreams)
	if resolvers != nil {
		resolverCount = len(resolvers)
	}
	fmt.Fprintf(out, "Будет сохранено: dns_mode=%s, resolver_upstreams=%d. Продолжить? [y/N]: ", cfg.DNSMode, resolverCount)
	confirm, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read confirmation: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(confirm), "y") && !strings.EqualFold(strings.TrimSpace(confirm), "yes") {
		fmt.Fprintln(out, "Изменения отменены.")
		return nil
	}
	if resolvers == nil {
		resolvers = cfg.ResolverUpstreams
	}
	saved, err := saveDNSModeConfig(dataDir, cfg.DNSMode, resolvers)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "[OK] Сохранено: dns_mode=%s, resolver_upstreams=%d\n", saved.DNSMode, len(saved.ResolverUpstreams))
	fmt.Fprintln(out, "Создан config.json.bak. Демон применит изменения автоматически в течение 30 секунд.")
	fmt.Fprintln(out, "Проверьте /status: last_reload обновится, last_error должен быть пустым.")
	return nil
}
