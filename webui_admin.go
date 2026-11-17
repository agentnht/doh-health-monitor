package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"lucx-doh-health-monitor/internal/dohintegration"
)

const (
	webUIAdminMaxBody       = 1 << 20
	webUIAdminMaxFile       = 2 << 20
	webUIAdminMaxRows       = 1000
	webUIAdminMaxDigQueries = 50
	webUIAdminDigWorkers    = 5
	webUIAdminService       = "lucx-plugin-doh-health-monitor"
)

var webUIAdminMu sync.Mutex

type webUIEditableConfig struct {
	DNSListenUDP           string          `json:"dns_listen_udp"`
	DNSListenTCP           string          `json:"dns_listen_tcp"`
	HTTPListen             string          `json:"http_listen"`
	ReloadSecs             int             `json:"reload_interval_seconds"`
	DNSQueryTimeoutSeconds int             `json:"dns_query_timeout_seconds"`
	DoHTimeoutSeconds      int             `json:"doh_timeout_seconds"`
	DNSMaxConcurrent       int             `json:"dns_max_concurrent"`
	Health                 HealthConfig    `json:"health"`
	Cache                  CacheConfig     `json:"cache"`
	BootstrapResolvers     []string        `json:"bootstrap_resolvers"`
	GeminiAPI              GeminiAPIConfig `json:"gemini_api"`
	Integration            bool            `json:"integration"`
}

type webUISourceRow struct {
	Active   bool     `json:"active"`
	Editable bool     `json:"editable"`
	System   bool     `json:"system,omitempty"`
	Fields   []string `json:"fields,omitempty"`
	Raw      string   `json:"raw,omitempty"`
}

type webUISourcesResponse struct {
	DoH    []webUISourceRow `json:"doh"`
	Checks []webUISourceRow `json:"checks"`
}

type webUISourceUpdate struct {
	Kind string           `json:"kind"`
	Rows []webUISourceRow `json:"rows"`
}

type webUISecretRequest struct {
	Key string `json:"key"`
}

type webUIIntegrationRequest struct {
	Action    string `json:"action"`
	Confirmed bool   `json:"confirmed"`
}

type webUITestResult struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	Reason     string `json:"reason,omitempty"`
	Domain     string `json:"domain,omitempty"`
	QType      string `json:"qtype,omitempty"`
	Answer     string `json:"answer,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
}

type webUITestSummary struct {
	Status string            `json:"status"`
	RunAt  time.Time         `json:"run_at"`
	Tests  []webUITestResult `json:"tests"`
	Passed int               `json:"passed"`
	Failed int               `json:"failed"`
}

type webUIOperationLogger struct {
	mu      sync.Mutex
	dataDir string
	lines   []string
}

func (l *webUIOperationLogger) Printf(format string, args ...any) {
	line := redactWebUILogLine(fmt.Sprintf(format, args...))
	l.mu.Lock()
	l.lines = append(l.lines, line)
	if len(l.lines) > 200 {
		l.lines = append([]string(nil), l.lines[len(l.lines)-200:]...)
	}
	l.mu.Unlock()

	if l.dataDir == "" {
		return
	}
	path := filepath.Join(l.dataDir, "webui-operations.log")
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_APPEND|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return
	}
	_ = file.Chmod(0600)
	_, _ = fmt.Fprintf(file, "%s level=INFO %s\n", time.Now().UTC().Format(time.RFC3339), line)
}

func (l *webUIOperationLogger) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

var webUILogSecretPattern = regexp.MustCompile("(?i)(Bearer\\s+|apiToken:\\s*|XUI_API_TOKEN=)([^\\s\\\"'<>]+)")

func redactWebUILogLine(line string) string {
	return webUILogSecretPattern.ReplaceAllString(line, "1[REDACTED]")
}

func webUIDataRoot(dataDir string) (string, error) {
	if strings.TrimSpace(dataDir) == "" {
		return "", errors.New("LUCX_PLUGIN_DATA is not configured for Web UI management")
	}
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return "", errors.New("could not resolve plugin data directory")
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", fmt.Errorf("plugin data directory is unavailable: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("plugin data path must be a real directory")
	}
	root, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", errors.New("could not safely resolve plugin data directory")
	}
	return root, nil
}

func webUIDataFile(dataDir, name string, maxBytes int64) (string, []byte, error) {
	root, err := webUIDataRoot(dataDir)
	if err != nil {
		return "", nil, err
	}
	switch name {
	case "config.json", "doh-servers.txt", "tst-domen.txt":
	default:
		return "", nil, errors.New("unsupported management file")
	}
	path := filepath.Join(root, name)
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return path, nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return path, nil, errors.New("could not open management file")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxBytes {
		return path, nil, errors.New("management file is not a regular file or exceeds the size limit")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil || int64(len(data)) > maxBytes {
		return path, nil, errors.New("could not safely read management file")
	}
	return path, data, nil
}

func writeWebUIJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeWebUIError(w http.ResponseWriter, status int, err error) {
	message := "management request failed"
	if err != nil {
		message = err.Error()
	}
	writeWebUIJSON(w, status, map[string]any{"error": message})
}

func decodeWebUIJSON(r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, webUIAdminMaxBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("invalid request body: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("request body must contain exactly one JSON value")
	}
	return nil
}

func webUIAdminAPI(w http.ResponseWriter, r *http.Request, path, dataDir string) {
	if strings.TrimSpace(dataDir) == "" {
		writeWebUIError(w, http.StatusServiceUnavailable, errors.New("management is unavailable: LUCX_PLUGIN_DATA is not set"))
		return
	}
	switch path {
	case "/api/v1/config":
		switch r.Method {
		case http.MethodGet:
			config, err := readWebUIConfig(dataDir)
			if err != nil {
				writeWebUIError(w, http.StatusInternalServerError, err)
				return
			}
			writeWebUIJSON(w, http.StatusOK, config)
		case http.MethodPost:
			var config webUIEditableConfig
			if err := decodeWebUIJSON(r, &config); err != nil {
				writeWebUIError(w, http.StatusBadRequest, err)
				return
			}
			restartRequired, err := saveWebUIConfig(dataDir, config)
			if err != nil {
				writeWebUIError(w, http.StatusBadRequest, err)
				return
			}
			saved, _ := readWebUIConfig(dataDir)
			writeWebUIJSON(w, http.StatusOK, map[string]any{"ok": true, "restart_required": restartRequired, "config": saved})
		default:
			methodNotAllowed(w, "GET, POST")
		}
	case "/api/v1/config/defaults":
		if r.Method != http.MethodPost {
			methodNotAllowed(w, "POST")
			return
		}
		var request struct {
			Section string `json:"section"`
		}
		if err := decodeWebUIJSON(r, &request); err != nil {
			writeWebUIError(w, http.StatusBadRequest, err)
			return
		}
		restartRequired, err := resetWebUIConfigSection(dataDir, request.Section)
		if err != nil {
			writeWebUIError(w, http.StatusBadRequest, err)
			return
		}
		config, _ := readWebUIConfig(dataDir)
		writeWebUIJSON(w, http.StatusOK, map[string]any{"ok": true, "restart_required": restartRequired, "config": config})
	case "/api/v1/sources":
		switch r.Method {
		case http.MethodGet:
			sources, err := readWebUISources(dataDir)
			if err != nil {
				writeWebUIError(w, http.StatusInternalServerError, err)
				return
			}
			writeWebUIJSON(w, http.StatusOK, sources)
		case http.MethodPost:
			var update webUISourceUpdate
			if err := decodeWebUIJSON(r, &update); err != nil {
				writeWebUIError(w, http.StatusBadRequest, err)
				return
			}
			if err := saveWebUISources(dataDir, update); err != nil {
				writeWebUIError(w, http.StatusBadRequest, err)
				return
			}
			sources, _ := readWebUISources(dataDir)
			writeWebUIJSON(w, http.StatusOK, map[string]any{"ok": true, "sources": sources, "reload_note": "Демон проверит изменения автоматически в течение 30 секунд."})
		default:
			methodNotAllowed(w, "GET, POST")
		}
	case "/api/v1/gemini-key":
		if r.Method != http.MethodPost {
			methodNotAllowed(w, "POST")
			return
		}
		var request webUISecretRequest
		if err := decodeWebUIJSON(r, &request); err != nil {
			writeWebUIError(w, http.StatusBadRequest, err)
			return
		}
		if err := saveWebUIGeminiKey(dataDir, request.Key); err != nil {
			writeWebUIError(w, http.StatusBadRequest, err)
			return
		}
		writeWebUIJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Ключ сохранён в приватный файл с правами 0600. Содержимое не возвращается."})
	case "/api/v1/integration/logs":
		if r.Method != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
		lines, err := readWebUIIntegrationLog(dataDir, 300)
		if err != nil {
			writeWebUIError(w, http.StatusInternalServerError, err)
			return
		}
		writeWebUIJSON(w, http.StatusOK, map[string]any{"lines": lines})
	case "/api/v1/logs":
		if r.Method != http.MethodGet {
			methodNotAllowed(w, "GET")
			return
		}
		lines := 250
		if raw := r.URL.Query().Get("lines"); raw != "" {
			value, err := strconv.Atoi(raw)
			if err != nil || value < 20 || value > 1000 {
				writeWebUIError(w, http.StatusBadRequest, errors.New("lines must be between 20 and 1000"))
				return
			}
			lines = value
		}
		logs, source, err := readWebUILogs(dataDir, lines)
		if err != nil {
			writeWebUIError(w, http.StatusInternalServerError, err)
			return
		}
		writeWebUIJSON(w, http.StatusOK, map[string]any{"source": source, "lines": logs})
	case "/api/v1/tests/run":
		if r.Method != http.MethodPost {
			methodNotAllowed(w, "POST")
			return
		}
		webUIAdminMu.Lock()
		result := runWebUIAdminTests(dataDir)
		webUIAdminMu.Unlock()
		writeWebUIJSON(w, http.StatusOK, result)
	case "/api/v1/integration":
		if r.Method != http.MethodPost {
			methodNotAllowed(w, "POST")
			return
		}
		var request webUIIntegrationRequest
		if err := decodeWebUIJSON(r, &request); err != nil {
			writeWebUIError(w, http.StatusBadRequest, err)
			return
		}
		action := strings.ToLower(strings.TrimSpace(request.Action))
		if action != "integrate" && action != "remove" && action != "check" {
			writeWebUIError(w, http.StatusBadRequest, errors.New("action must be integrate, remove or check"))
			return
		}
		if action != "check" && !request.Confirmed {
			writeWebUIError(w, http.StatusBadRequest, errors.New("operation confirmation is required"))
			return
		}
		webUIAdminMu.Lock()
		logOutput, err := runWebUIIntegration(dataDir, action)
		webUIAdminMu.Unlock()
		if err != nil {
			writeWebUIJSON(w, http.StatusOK, map[string]any{"ok": false, "action": action, "output": logOutput, "error": err.Error()})
			return
		}
		writeWebUIJSON(w, http.StatusOK, map[string]any{"ok": true, "action": action, "output": logOutput})
	default:
		http.NotFound(w, r)
	}
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeWebUIError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
}

func readWebUIConfig(dataDir string) (webUIEditableConfig, error) {
	root, err := webUIDataRoot(dataDir)
	if err != nil {
		return webUIEditableConfig{}, err
	}
	path, _, err := webUIDataFile(dataDir, "config.json", webUIAdminMaxFile)
	if err != nil {
		return webUIEditableConfig{}, err
	}
	config, err := loadConfigNoCreate(path)
	if err != nil {
		return webUIEditableConfig{}, fmt.Errorf("config.json is invalid: %w", err)
	}
	_ = root
	return editableWebUIConfig(config), nil
}

func editableWebUIConfig(config Config) webUIEditableConfig {
	return webUIEditableConfig{
		DNSListenUDP: config.DNSListenUDP, DNSListenTCP: config.DNSListenTCP, HTTPListen: config.HTTPListen,
		ReloadSecs: config.ReloadSecs, DNSQueryTimeoutSeconds: config.DNSQueryTimeoutSeconds,
		DoHTimeoutSeconds: config.DoHTimeoutSeconds, DNSMaxConcurrent: config.DNSMaxConcurrent,
		Health: config.Health, Cache: config.Cache,
		BootstrapResolvers: append([]string(nil), config.BootstrapResolvers...),
		GeminiAPI: config.GeminiAPI, Integration: config.Integration,
	}
}

func saveWebUIConfig(dataDir string, view webUIEditableConfig) (bool, error) {
	webUIAdminMu.Lock()
	defer webUIAdminMu.Unlock()
	root, err := webUIDataRoot(dataDir)
	if err != nil {
		return false, err
	}
	path, _, err := webUIDataFile(dataDir, "config.json", webUIAdminMaxFile)
	if err != nil {
		return false, err
	}
	config, err := loadConfigNoCreate(path)
	if err != nil {
		return false, fmt.Errorf("existing config.json is invalid: %w", err)
	}
	restartRequired := config.DNSListenUDP != view.DNSListenUDP ||
		config.DNSListenTCP != view.DNSListenTCP ||
		config.HTTPListen != view.HTTPListen ||
		config.DNSMaxConcurrent != view.DNSMaxConcurrent
	config.DNSListenUDP = strings.TrimSpace(view.DNSListenUDP)
	config.DNSListenTCP = strings.TrimSpace(view.DNSListenTCP)
	config.HTTPListen = strings.TrimSpace(view.HTTPListen)
	config.ReloadSecs = view.ReloadSecs
	config.DNSQueryTimeoutSeconds = view.DNSQueryTimeoutSeconds
	config.DoHTimeoutSeconds = view.DoHTimeoutSeconds
	config.DNSMaxConcurrent = view.DNSMaxConcurrent
	config.Health = view.Health
	config.Cache = view.Cache
	config.BootstrapResolvers = append([]string(nil), view.BootstrapResolvers...)
	config.GeminiAPI = view.GeminiAPI
	config = normalizeCacheConfig(config)
	if err := validateConfig(config); err != nil {
		return false, fmt.Errorf("config validation failed: %w", err)
	}
	if err := writeConfigAtomic(filepath.Join(root, "config.json"), config); err != nil {
		return false, fmt.Errorf("save config.json: %w", err)
	}
	return restartRequired, nil
}

func resetWebUIConfigSection(dataDir, section string) (bool, error) {
	webUIAdminMu.Lock()
	defer webUIAdminMu.Unlock()
	root, err := webUIDataRoot(dataDir)
	if err != nil {
		return false, err
	}
	path, _, err := webUIDataFile(dataDir, "config.json", webUIAdminMaxFile)
	if err != nil {
		return false, err
	}
	config, err := loadConfigNoCreate(path)
	if err != nil {
		return false, err
	}
	defaults := defaultConfig()
	switch section {
	case "health":
		config.Health = defaults.Health
	case "cache":
		config.Cache = defaults.Cache
	case "bootstrap_resolvers":
		config.BootstrapResolvers = append([]string(nil), defaults.BootstrapResolvers...)
	default:
		return false, errors.New("default section must be health, cache or bootstrap_resolvers")
	}
	if err := validateConfig(normalizeCacheConfig(config)); err != nil {
		return false, fmt.Errorf("default values failed config validation: %w", err)
	}
	if err := writeConfigAtomic(filepath.Join(root, "config.json"), config); err != nil {
		return false, err
	}
	return false, nil
}

func readWebUISources(dataDir string) (webUISourcesResponse, error) {
	_, dohData, err := webUIDataFile(dataDir, "doh-servers.txt", webUIAdminMaxFile)
	if err != nil {
		return webUISourcesResponse{}, err
	}
	_, checksData, err := webUIDataFile(dataDir, "tst-domen.txt", webUIAdminMaxFile)
	if err != nil {
		return webUISourcesResponse{}, err
	}
	return webUISourcesResponse{
		DoH: parseWebUISourceRows(dohData, 2, "id;url"),
		Checks: parseWebUISourceRows(checksData, 6, "domain;qtypes"),
	}, nil
}

func parseWebUISourceRows(data []byte, fieldCount int, header string) []webUISourceRow {
	var rows []webUISourceRow
	for _, original := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(original)
		if trimmed == "" {
			continue
		}
		active := true
		value := trimmed
		if strings.HasPrefix(value, "#") {
			active = false
			value = strings.TrimSpace(strings.TrimPrefix(value, "#"))
			if value == "" || strings.HasPrefix(strings.ToLower(value), strings.ToLower(header)) || !strings.Contains(value, ";") {
				rows = append(rows, webUISourceRow{Active: false, Editable: false, Raw: trimmed})
				continue
			}
		}
		fields := strings.SplitN(value, ";", fieldCount)
		for len(fields) < fieldCount {
			fields = append(fields, "")
		}
		system := fieldCount == 2 && strings.EqualFold(strings.TrimSpace(fields[0]), systemDNSUpstreamID)
		rows = append(rows, webUISourceRow{Active: active, Editable: true, System: system, Fields: fields})
	}
	return rows
}

func saveWebUISources(dataDir string, update webUISourceUpdate) error {
	webUIAdminMu.Lock()
	defer webUIAdminMu.Unlock()
	fieldCount, fileName := 0, ""
	switch update.Kind {
	case "doh":
		fieldCount, fileName = 2, "doh-servers.txt"
	case "checks":
		fieldCount, fileName = 6, "tst-domen.txt"
	default:
		return errors.New("kind must be doh or checks")
	}
	if len(update.Rows) > webUIAdminMaxRows {
		return fmt.Errorf("too many rows; maximum is %d", webUIAdminMaxRows)
	}
	systemRows := 0
	var output strings.Builder
	for index, row := range update.Rows {
		if !row.Editable {
			raw := strings.TrimSpace(row.Raw)
			if row.Active || !strings.HasPrefix(raw, "#") || strings.ContainsAny(raw, "\r\n") || len(raw) > 512 {
				return fmt.Errorf("row %d: only read-only comment rows may use raw text", index+1)
			}
			if update.Kind == "doh" && strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(raw, "#")), systemDNSUpstreamID+";") {
				return fmt.Errorf("row %d: system-dns must remain an editable protected row", index+1)
			}
			output.WriteString(raw)
			output.WriteByte('\n')
			continue
		}
		if len(row.Fields) != fieldCount {
			return fmt.Errorf("row %d: expected %d fields", index+1, fieldCount)
		}
		fields := make([]string, fieldCount)
		for fieldIndex, field := range row.Fields {
			if strings.ContainsAny(field, "\r\n") || strings.Contains(field, ";") || len(field) > 2048 {
				return fmt.Errorf("row %d field %d contains an invalid delimiter or is too long", index+1, fieldIndex+1)
			}
			fields[fieldIndex] = strings.TrimSpace(field)
		}
		line := strings.Join(fields, ";")
		if update.Kind == "doh" {
			isSystemID := strings.EqualFold(fields[0], systemDNSUpstreamID)
			if row.System || isSystemID {
				if !row.System || !isSystemID {
					return fmt.Errorf("row %d: system-dns is a protected system row", index+1)
				}
				systemRows++
				if fields[1] != "" {
					return fmt.Errorf("row %d: system-dns uses /etc/resolv.conf and must not have a DoH URL", index+1)
				}
				fields[0] = systemDNSUpstreamID
				line = strings.Join(fields, ";")
			}
		}
		if !row.Active {
			line = "# " + line
		}
		output.WriteString(line)
		output.WriteByte('\n')
	}
	if update.Kind == "doh" && systemRows != 1 {
		return errors.New("doh-servers.txt must keep exactly one system-dns row; disable it with the checkbox instead of deleting it")
	}
	data := []byte(output.String())
	if update.Kind == "doh" && len(strings.TrimSpace(string(data))) == 0 {
		data = []byte("# id;url — provider ID; HTTPS endpoint\n")
	}
	if update.Kind == "doh" {
		providers, err := parseDoHProviders(data)
		if err != nil {
			return fmt.Errorf("doh-servers.txt validation failed: %w", err)
		}
		if len(providers) == 0 {
			return errors.New("at least one upstream must remain enabled; keep system-dns active or enable a DoH provider")
		}
	} else {
		if _, err := parseHealthChecks(data); err != nil {
			return fmt.Errorf("tst-domen.txt validation failed: %w", err)
		}
	}
	path, _, err := webUIDataFile(dataDir, fileName, webUIAdminMaxFile)
	if err != nil {
		return err
	}
	if err := writeAtomicFile(path, data, 0600); err != nil {
		return fmt.Errorf("save %s: %w", fileName, err)
	}
	return nil
}

func saveWebUIGeminiKey(dataDir, key string) error {
	webUIAdminMu.Lock()
	defer webUIAdminMu.Unlock()
	key = strings.TrimSpace(key)
	if key == "" || len(key) > 8192 || strings.ContainsAny(key, "\r\n\t ") {
		return errors.New("Gemini API key must be a non-empty single-line value of at most 8192 bytes")
	}
	for _, r := range key {
		if r < 0x21 || r > 0x7e {
			return errors.New("Gemini API key contains unsupported characters")
		}
	}
	root, err := webUIDataRoot(dataDir)
	if err != nil {
		return err
	}
	_, _, err = webUIDataFile(dataDir, "config.json", webUIAdminMaxFile)
	if err != nil {
		return err
	}
	config, err := loadConfigNoCreate(filepath.Join(root, "config.json"))
	if err != nil {
		return err
	}
	relative := filepath.Clean(config.GeminiAPI.KeyFile)
	if filepath.IsAbs(relative) || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return errors.New("gemini_api.key_file must stay inside the plugin data directory")
	}
	target := filepath.Join(root, relative)
	parent := filepath.Dir(target)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return errors.New("could not create Gemini key directory")
	}
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return errors.New("could not resolve Gemini key directory")
	}
	relParent, err := filepath.Rel(root, resolvedParent)
	if err != nil || relParent == ".." || strings.HasPrefix(relParent, ".."+string(os.PathSeparator)) {
		return errors.New("Gemini key directory escapes plugin data directory")
	}
	if info, err := os.Lstat(target); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("Gemini key target must be a regular non-symlink file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("could not inspect Gemini key target")
	}
	temp, err := os.CreateTemp(resolvedParent, ".gemini-key-*")
	if err != nil {
		return errors.New("could not create temporary Gemini key file")
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0600); err != nil {
		_ = temp.Close()
		return errors.New("could not secure Gemini key file")
	}
	if _, err := temp.WriteString(key + "\n"); err != nil {
		_ = temp.Close()
		return errors.New("could not write Gemini key file")
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return errors.New("could not sync Gemini key file")
	}
	if err := temp.Close(); err != nil {
		return errors.New("could not close Gemini key file")
	}
	if err := os.Rename(tempName, target); err != nil {
		return errors.New("could not atomically install Gemini key file")
	}
	return nil
}

func readWebUILogs(dataDir string, count int) ([]string, string, error) {
	var all []string
	source := ""
	if journalctl, err := exec.LookPath("journalctl"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		command := exec.CommandContext(ctx, journalctl, "-u", webUIAdminService+".service", "-n", strconv.Itoa(count), "--no-pager", "-o", "short-iso-precise")
		output, commandErr := command.Output()
		cancel()
		if commandErr == nil {
			all = append(all, tailLines(string(output), count)...)
			source = "systemd journal"
		}
	}
	root, rootErr := webUIDataRoot(dataDir)
	if len(all) == 0 && rootErr == nil {
		parentLog := filepath.Join(filepath.Dir(root), "plugin.log")
		if lines, err := readWebUILogFile(parentLog, count); err == nil && len(lines) > 0 {
			all = append(all, lines...)
			source = "plugin.log (integration operations)"
		}
	}
	if len(all) == 0 {
		return []string{"Записи журнала пока недоступны. Проверьте наличие systemd journal или plugin.log."}, "no log source", nil
	}
	if len(all) > count {
		all = all[len(all)-count:]
	}
	for index := range all {
		all[index] = redactWebUILogLine(all[index])
	}
	return all, source, nil
}

func readWebUILogFile(path string, count int) ([]string, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("could not open log file")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 2<<20 {
		return nil, errors.New("log file is invalid or too large")
	}
	data, err := io.ReadAll(io.LimitReader(file, (2<<20)+1))
	if err != nil || len(data) > 2<<20 {
		return nil, errors.New("log file is too large")
	}
	return tailLines(string(data), count), nil
}

func tailLines(value string, count int) []string {
	lines := strings.Split(strings.TrimRight(value, "\r\n"), "\n")
	if len(lines) > count {
		lines = lines[len(lines)-count:]
	}
	for index := range lines {
		lines[index] = strings.TrimRight(lines[index], "\r")
	}
	return lines
}

func webUITest(name string, ok bool, reason string) webUITestResult {
	status := "NotOK"
	if ok {
		status = "OK"
	}
	return webUITestResult{Name: name, Status: status, Reason: reason}
}

func runWebUIAdminTests(dataDir string) webUITestSummary {
	summary := webUITestSummary{Status: "NotOK", RunAt: time.Now().UTC(), Tests: []webUITestResult{}}

	// Keep the legacy integration preflight as the first mandatory check.
	integrationOutput, integrationErr := runWebUIIntegration(dataDir, "check")
	integrationReason := strings.TrimSpace(integrationOutput)
	if integrationErr != nil {
		if integrationReason != "" {
			integrationReason += "\n"
		}
		integrationReason += integrationErr.Error()
	}
	summary.Tests = append(summary.Tests, webUITest("DNS integration preflight", integrationErr == nil, integrationReason))

	configPath, _, fileErr := webUIDataFile(dataDir, "config.json", webUIAdminMaxFile)
	if fileErr != nil {
		summary.Tests = append(summary.Tests, webUITest("Чтение config.json", false, fileErr.Error()))
		return finalizeWebUITests(summary)
	}
	config, configErr := loadConfigNoCreate(configPath)
	if configErr != nil {
		summary.Tests = append(summary.Tests, webUITest("Валидация config.json", false, configErr.Error()))
		return finalizeWebUITests(summary)
	}
	summary.Tests = append(summary.Tests, webUITest("Валидация config.json", true, "Структура и параметры конфигурации корректны"))

	dohPath, _, dohErr := webUIDataFile(dataDir, "doh-servers.txt", webUIAdminMaxFile)
	checksPath, _, checksErr := webUIDataFile(dataDir, "tst-domen.txt", webUIAdminMaxFile)
	if dohErr != nil || checksErr != nil {
		err := dohErr
		if err == nil {
			err = checksErr
		}
		summary.Tests = append(summary.Tests, webUITest("Проверка файлов списков", false, err.Error()))
		return finalizeWebUITests(summary)
	}
	sources, sourceErr := readConfigSources(dohPath, checksPath)
	if sourceErr != nil {
		summary.Tests = append(summary.Tests, webUITest("Проверка файлов списков", false, sourceErr.Error()))
		return finalizeWebUITests(summary)
	}
	summary.Tests = append(summary.Tests, webUITest("Проверка файлов списков", true, fmt.Sprintf("DoH-серверов: %d, DNS-проверок: %d", len(sources.Providers), len(sources.Checks))))

	digResults := runWebUIDigTests(config.DNSListenUDP, sources.Checks)
	summary.Tests = append(summary.Tests, digResults...)
	udpOK := false
	for _, result := range digResults {
		if result.Status == "OK" {
			udpOK = true
			break
		}
	}
	if udpOK {
		summary.Tests = append(summary.Tests, webUITest("UDP DNS listener", true, config.DNSListenUDP+" отвечает на реальные dig-запросы"))
	} else if address, err := localListenAddress(config.DNSListenUDP); err != nil {
		summary.Tests = append(summary.Tests, webUITest("UDP DNS listener", false, err.Error()))
	} else if listener, err := net.ListenPacket("udp", address); err == nil {
		_ = listener.Close()
		summary.Tests = append(summary.Tests, webUITest("UDP DNS listener", true, "Порт свободен и доступен для запуска DNS-демона; активный ответ DNS не получен"))
	} else {
		summary.Tests = append(summary.Tests, webUITest("UDP DNS listener", false, "Порт занят, но ожидаемый DNS-ответ не получен"))
	}

	summary.Tests = append(summary.Tests, testWebUIHTTPListener(config.HTTPListen))
	if config.Integration {
		summary.Tests = append(summary.Tests, runWebUIXrayIntegrationCheck(dataDir))
	} else {
		summary.Tests = append(summary.Tests, webUITest("Xray DNS integration", true, "Интеграция выключена в config.json"))
	}
	return finalizeWebUITests(summary)
}

func finalizeWebUITests(summary webUITestSummary) webUITestSummary {
	summary.Passed, summary.Failed = 0, 0
	for _, test := range summary.Tests {
		if test.Status == "OK" {
			summary.Passed++
		} else {
			summary.Failed++
		}
	}
	if summary.Failed == 0 && len(summary.Tests) > 0 {
		summary.Status = "OK"
	} else {
		summary.Status = "NotOK"
	}
	return summary
}

func localListenAddress(address string) (string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return "", errors.New("listener address must be host:port")
	}
	if host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return "", errors.New("для проверки Web UI допускаются только loopback listener addresses")
		}
	}
	if portNumber, err := strconv.Atoi(port); err != nil || portNumber < 1 || portNumber > 65535 {
		return "", errors.New("listener port is outside 1..65535")
	}
	return net.JoinHostPort(host, port), nil
}

func testWebUIHTTPListener(address string) webUITestResult {
	localAddress, err := localListenAddress(address)
	if err != nil {
		return webUITest("HTTP listener", false, err.Error())
	}
	host, port, _ := net.SplitHostPort(localAddress)
	target := "http://" + net.JoinHostPort(host, port) + "/healthz"
	client := &http.Client{Timeout: 1500 * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, requestErr := client.Get(target)
	if requestErr == nil {
		_ = response.Body.Close()
		if response.StatusCode == http.StatusOK {
			return webUITest("HTTP listener", true, localAddress+" отвечает на /healthz")
		}
	}
	listener, listenErr := net.Listen("tcp", localAddress)
	if listenErr == nil {
		_ = listener.Close()
		return webUITest("HTTP listener", true, "Порт свободен и доступен для запуска HTTP listener; активный endpoint пока не отвечает")
	}
	return webUITest("HTTP listener", false, "Порт занят, но штатный /healthz endpoint недоступен")
}

func runWebUIDigTests(address string, checks []Check) []webUITestResult {
	var queries []struct {
		domain string
		qtype  uint16
	}
	for _, check := range checks {
		for _, qtype := range check.QTypes {
			queries = append(queries, struct {
				domain string
				qtype  uint16
			}{domain: check.Domain, qtype: qtype})
		}
	}
	if len(queries) == 0 {
		return []webUITestResult{webUITest("dig", false, "В tst-domen.txt нет активных DNS-проверок")}
	}
	results := make([]webUITestResult, len(queries))
	executable, err := exec.LookPath("dig")
	if err != nil {
		for index, query := range queries {
			results[index] = webUIDigResult(query.domain, query.qtype, "", 0, errors.New("утилита dig не установлена"))
		}
		return results
	}
	if len(queries) > webUIAdminMaxDigQueries {
		for index, query := range queries[webUIAdminMaxDigQueries:] {
			results[index] = webUIDigResult(query.domain, query.qtype, "", 0, fmt.Errorf("лимит проверки: выполнено не более %d DNS-запросов за один запуск", webUIAdminMaxDigQueries))
		}
		queries = queries[:webUIAdminMaxDigQueries]
	}
	localAddress, addressErr := localListenAddress(address)
	if addressErr != nil {
		for index, query := range queries {
			results[index] = webUIDigResult(query.domain, query.qtype, "", 0, addressErr)
		}
		return results
	}
	host, port, _ := net.SplitHostPort(localAddress)
	type digQuery struct {
		index  int
		domain string
		qtype  uint16
	}
	queue := make(chan digQuery)
	var workers sync.WaitGroup
	for worker := 0; worker < webUIAdminDigWorkers; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for query := range queue {
				start := time.Now()
				name := dnsQTypeName(query.qtype)
				if !validDNSHostname(normalizeDomain(query.domain)) {
					results[query.index] = webUIDigResult(query.domain, query.qtype, "", 0, errors.New("invalid DNS test domain"))
					continue
				}
				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				command := exec.CommandContext(ctx, executable, "+time=2", "+tries=1", "+noall", "+answer", "@"+host, "-p", port, "-q", normalizeDomain(query.domain), name)
				output, commandErr := command.CombinedOutput()
				cancel()
				answer := strings.TrimSpace(string(output))
				if len(answer) > 2048 {
					answer = answer[:2048] + "…"
				}
				results[query.index] = webUIDigResult(query.domain, query.qtype, answer, time.Since(start).Milliseconds(), commandErr)
			}
		}()
	}
	for index, query := range queries {
		queue <- digQuery{index: index, domain: query.domain, qtype: query.qtype}
	}
	close(queue)
	workers.Wait()
	return results
}

func dnsQTypeName(value uint16) string {
	names := map[uint16]string{1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 64: "SVCB", 65: "HTTPS", 257: "CAA"}
	if name, ok := names[value]; ok {
		return name
	}
	return fmt.Sprintf("TYPE%d", value)
}

func webUIDigResult(domain string, qtype uint16, answer string, elapsed int64, commandErr error) webUITestResult {
	name := "dig " + domain + " " + dnsQTypeName(qtype)
	if commandErr != nil {
		reason := "DNS-запрос завершился ошибкой"
		if strings.TrimSpace(answer) != "" {
			reason += ": " + answer
		} else {
			reason += ": " + commandErr.Error()
		}
		return webUITestResult{Name: name, Status: "NotOK", Reason: reason, Domain: domain, QType: dnsQTypeName(qtype), DurationMS: elapsed}
	}
	if answer == "" {
		return webUITestResult{Name: name, Status: "NotOK", Reason: "dig не получил секцию ANSWER", Domain: domain, QType: dnsQTypeName(qtype), DurationMS: elapsed}
	}
	return webUITestResult{Name: name, Status: "OK", Domain: domain, QType: dnsQTypeName(qtype), Answer: answer, DurationMS: elapsed}
}

func runWebUIXrayIntegrationCheck(dataDir string) webUITestResult {
	root, err := webUIDataRoot(dataDir)
	if err != nil {
		return webUITest("Xray DNS integration", false, err.Error())
	}
	script := filepath.Join(filepath.Dir(root), "scripts", "check-dns-integration.sh")
	info, err := os.Lstat(script)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return webUITest("Xray DNS integration", false, "Не найден штатный read-only scripts/check-dns-integration.sh")
	}
	config, err := loadConfigNoCreate(filepath.Join(root, "config.json"))
	if err != nil {
		return webUITest("Xray DNS integration", false, "Не удалось прочитать config.json: "+err.Error())
	}
	udpAddress, err := localListenAddress(config.DNSListenUDP)
	if err != nil {
		return webUITest("Xray DNS integration", false, err.Error())
	}
	_, pluginPort, _ := net.SplitHostPort(udpAddress)
	httpAddress, err := localListenAddress(config.HTTPListen)
	if err != nil {
		return webUITest("Xray DNS integration", false, err.Error())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "bash", script)
	command.Env = append(os.Environ(),
		"LUCX_PLUGIN_DATA="+root,
		"DOH_SKIP_PLUGIN_HEALTH_CHECK=1",
		"DOH_PLUGIN_PORT="+pluginPort,
		"DOH_STATUS_URL=http://"+httpAddress+"/status",
	)
	output, commandErr := command.CombinedOutput()
	text := strings.TrimSpace(string(output))
	if len(text) > 4096 {
		text = text[len(text)-4096:]
	}
	text = redactWebUILogLine(text)
	if ctx.Err() != nil {
		return webUITest("Xray DNS integration", false, "Проверка превысила лимит 35 секунд")
	}
	if commandErr != nil {
		if text == "" {
			text = commandErr.Error()
		}
		return webUITest("Xray DNS integration", false, text)
	}
	if text == "" {
		text = "Read-only диагностика завершилась успешно"
	}
	return webUITest("Xray DNS integration", true, text)
}

func runWebUIIntegration(dataDir, action string) (string, error) {
	if os.Geteuid() != 0 {
		return "", errors.New("операции интеграции Web UI должны выполняться от root")
	}
	if action != "integrate" && action != "remove" && action != "check" {
		return "", errors.New("unsupported integration action")
	}
	root, err := webUIDataRoot(dataDir)
	if err != nil {
		return "", err
	}
	config, err := loadConfigNoCreate(filepath.Join(root, "config.json"))
	if err != nil {
		return "", fmt.Errorf("config.json is invalid: %w", err)
	}
	udpAddress, err := localListenAddress(config.DNSListenUDP)
	if err != nil {
		return "", fmt.Errorf("configured DNS listener: %w", err)
	}
	_, pluginPort, _ := net.SplitHostPort(udpAddress)
	httpAddress, err := localListenAddress(config.HTTPListen)
	if err != nil {
		return "", fmt.Errorf("configured HTTP listener: %w", err)
	}
	statusURL := "http://" + httpAddress + "/status"
	if !dohintegration.IsLocalURL(statusURL) {
		return "", errors.New("configured status endpoint must use loopback")
	}
	logger := &webUIOperationLogger{dataDir: root}
	logger.Printf("INTEGRATION action=%s started", strings.ToUpper(action))
	args := []string{action, "--plugin-port", pluginPort, "--plugin-status-url", statusURL}
	done := make(chan error, 1)
	go func() {
		done <- dohintegration.RunCommand(args, logger)
	}()
	select {
	case err := <-done:
		if err != nil {
			logger.Printf("INTEGRATION action=%s failed: %v", strings.ToUpper(action), err)
			return logger.String(), err
		}
	case <-time.After(45 * time.Second):
		timeoutErr := errors.New("операция интеграции превысила лимит 45 секунд")
		logger.Printf("INTEGRATION action=%s failed: %v", strings.ToUpper(action), timeoutErr)
		return logger.String(), timeoutErr
	}
	if action == "integrate" || action == "remove" {
		if err := setIntegrationFlag(filepath.Join(root, "config.json"), action == "integrate"); err != nil {
			logger.Printf("INTEGRATION action=%s completed but config flag update failed: %v", strings.ToUpper(action), err)
			return logger.String(), fmt.Errorf("операция завершилась, но не удалось обновить integration в config.json: %w", err)
		}
	}
	logger.Printf("INTEGRATION action=%s completed successfully", strings.ToUpper(action))
	return logger.String(), nil
}

func readWebUIIntegrationLog(dataDir string, count int) ([]string, error) {
	root, err := webUIDataRoot(dataDir)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(root, "webui-operations.log")
	lines, err := readWebUILogFile(path, count)
	if errors.Is(err, os.ErrNotExist) {
		return []string{"Операции интеграции/деинтеграции ещё не выполнялись."}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return []string{"Операции интеграции/деинтеграции ещё не выполнялись."}, nil
	}
	for index := range lines {
		lines[index] = redactWebUILogLine(lines[index])
	}
	return lines, nil
}
