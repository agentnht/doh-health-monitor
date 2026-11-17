package main

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"encoding/json"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

//go:embed defaults/doh-servers.txt defaults/tst-domen.txt
var embeddedConfigSources embed.FS

const configSourcePollInterval = 30 * time.Second

type DoHProvider struct {
	ID     string
	URL    string
	System bool
}

type ConfigSourceChecksums struct {
	DoH      string
	Checks   string
	Combined string
}

type ConfigSources struct {
	Providers        []DoHProvider
	Checks           []Check
	DoHURLs          map[string]string
	SystemDNSEnabled bool
	Checksums        ConfigSourceChecksums
}

func initializeConfigSourceFiles(dataDir string) error {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return fmt.Errorf("create plugin data directory: %w", err)
	}
	files := []string{"defaults/doh-servers.txt", "defaults/tst-domen.txt"}
	for _, embeddedPath := range files {
		name := filepath.Base(embeddedPath)
		path := filepath.Join(dataDir, name)
		if _, err := os.Stat(path); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat %s: %w", name, err)
		}
		data, err := fs.ReadFile(embeddedConfigSources, embeddedPath)
		if err != nil {
			return fmt.Errorf("read embedded %s: %w", name, err)
		}
		if err := writeAtomicFile(path, data, 0600); err != nil {
			return fmt.Errorf("create %s from embedded defaults: %w", name, err)
		}
		logLine("INFO", "CONFIG_SOURCE_CREATED file=%s source=embedded_default", name)
	}

	// Older installations stored URL-only entries. Convert them once to the
	// stable ID;URL format without changing endpoints or their order.
	dohPath := filepath.Join(dataDir, "doh-servers.txt")
	raw, err := os.ReadFile(dohPath)
	if err != nil {
		return fmt.Errorf("read doh-servers.txt: %w", err)
	}
	migrated, changed, err := migrateLegacyDoHList(raw)
	if err != nil {
		return fmt.Errorf("migrate legacy doh-servers.txt: %w", err)
	}
	if changed {
		if err := writeAtomicFile(dohPath, migrated, 0600); err != nil {
			return fmt.Errorf("write migrated doh-servers.txt: %w", err)
		}
		logLine("INFO", "CONFIG_SOURCE_MIGRATED file=doh-servers.txt format=id;url")
		raw = migrated
	}
	withSystem, addedSystem, err := ensureSystemDNSDoHEntry(raw)
	if err != nil {
		return fmt.Errorf("ensure system-dns entry in doh-servers.txt: %w", err)
	}
	if addedSystem {
		if err := writeAtomicFile(dohPath, withSystem, 0600); err != nil {
			return fmt.Errorf("write system-dns entry to doh-servers.txt: %w", err)
		}
		logLine("INFO", "CONFIG_SOURCE_MIGRATED file=doh-servers.txt added_system_dns_entry")
	}
	return nil
}

func ensureSystemDNSDoHEntry(data []byte) ([]byte, bool, error) {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	found := 0
	for lineNumber, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "#"))
		}
		fields := strings.SplitN(line, ";", 2)
		if len(fields) == 2 && strings.EqualFold(strings.TrimSpace(fields[0]), systemDNSUpstreamID) {
			found++
			if strings.TrimSpace(fields[1]) != "" {
				return nil, false, fmt.Errorf("line %d: system-dns must not have a DoH URL", lineNumber+1)
			}
		}
	}
	if found > 1 {
		return nil, false, errors.New("doh-servers.txt must contain exactly one system-dns row; duplicate rows found")
	}
	if found == 1 {
		return data, false, nil
	}

	// Older versions always enabled system DNS implicitly. Preserve that
	// behaviour when migrating a list that predates the editable system row.
	insertAt := 0
	for i, raw := range lines {
		lower := strings.ToLower(strings.TrimSpace(raw))
		if strings.HasPrefix(lower, "#") && strings.Contains(lower, "id;url") {
			insertAt = i + 1
			break
		}
	}
	lines = append(lines, "")
	copy(lines[insertAt+1:], lines[insertAt:])
	lines[insertAt] = systemDNSUpstreamID + ";"
	return []byte(strings.Join(lines, "\n")), true, nil
}

func migrateLegacyDoHList(data []byte) ([]byte, bool, error) {
	lines := strings.Split(string(data), "\n")
	var entries []DoHProvider
	hasLegacy := false
	hasNewFormat := false
	for lineNumber, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, ";") {
			hasNewFormat = true
			continue
		}
		hasLegacy = true
		parsed, err := url.Parse(line)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
			return nil, false, fmt.Errorf("line %d: expected an HTTPS DoH URL", lineNumber+1)
		}
		entries = append(entries, DoHProvider{ID: legacyProviderID(parsed.Hostname()), URL: line})
	}
	if !hasLegacy {
		return data, false, nil
	}
	if hasNewFormat {
		return nil, false, errors.New("file mixes legacy URL-only and id;url entries")
	}
	var out strings.Builder
	out.WriteString("# id;url — provider IDs remain stable when endpoint hostnames change\n")
	for _, entry := range entries {
		fmt.Fprintf(&out, "%s;%s\n", entry.ID, entry.URL)
	}
	return []byte(out.String()), true, nil
}

func legacyProviderID(host string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	known := map[string]string{
		"eu.geohide.ru":    "geohide-eu",
		"doh.dagami.ru":    "dagami",
		"dns.dagami.ru":    "dagami",
		"dns.comss.one":    "comss-one",
		"dns.bezmezhau.com": "bezmezhau",
		"dns.zapret.moe":   "zapret",
	}
	if id, ok := known[host]; ok {
		return id
	}
	if !strings.Contains(host, ".") {
		return host
	}
	return "provider-" + strings.ReplaceAll(host, ".", "-")
}

func readConfigSources(dohPath, checksPath string) (ConfigSources, error) {
	dohData, err := os.ReadFile(dohPath)
	if err != nil {
		return ConfigSources{}, fmt.Errorf("read doh-servers.txt: %w", err)
	}
	checksData, err := os.ReadFile(checksPath)
	if err != nil {
		return ConfigSources{}, fmt.Errorf("read tst-domen.txt: %w", err)
	}
	checksums := configSourceChecksums(dohData, checksData)
	providers, err := parseDoHProviders(dohData)
	if err != nil {
		return ConfigSources{Checksums: checksums}, fmt.Errorf("doh-servers.txt: %w", err)
	}
	checks, err := parseHealthChecks(checksData)
	if err != nil {
		return ConfigSources{Checksums: checksums}, fmt.Errorf("tst-domen.txt: %w", err)
	}
	urls := make(map[string]string, len(providers))
	systemDNSEnabled := false
	for _, provider := range providers {
		if provider.System || provider.ID == systemDNSUpstreamID {
			systemDNSEnabled = true
			continue
		}
		urls[provider.ID] = provider.URL
	}
	return ConfigSources{
		Providers: providers, Checks: checks, DoHURLs: urls,
		SystemDNSEnabled: systemDNSEnabled, Checksums: checksums,
	}, nil
}

func configSourceChecksums(dohData, checksData []byte) ConfigSourceChecksums {
	dohHash := sha256.Sum256(dohData)
	checksHash := sha256.Sum256(checksData)
	combinedHash := sha256.Sum256([]byte(hex.EncodeToString(dohHash[:]) + "\n" + hex.EncodeToString(checksHash[:])))
	return ConfigSourceChecksums{
		DoH:      hex.EncodeToString(dohHash[:]),
		Checks:   hex.EncodeToString(checksHash[:]),
		Combined: hex.EncodeToString(combinedHash[:]),
	}
}

func parseDoHProviders(data []byte) ([]DoHProvider, error) {
	if len(data) == 0 {
		return nil, errors.New("file is empty; keep the header comment even when no DoH providers are configured")
	}
	seen := make(map[string]bool)
	var providers []DoHProvider
	for lineNumber, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, ";", 2)
		if len(fields) != 2 {
			return nil, fmt.Errorf("line %d: expected id;https://host/dns-query", lineNumber+1)
		}
		id := strings.TrimSpace(fields[0])
		endpoint := strings.TrimSpace(fields[1])
		if !validProviderID(id) {
			return nil, fmt.Errorf("line %d: invalid provider ID %q", lineNumber+1, id)
		}
		id = strings.ToLower(id)
		if id == systemDNSUpstreamID {
			if endpoint != "" {
				return nil, fmt.Errorf("line %d: system-dns is a system resolver and must not have a DoH URL", lineNumber+1)
			}
			if seen[id] {
				return nil, fmt.Errorf("line %d: duplicate provider ID %q", lineNumber+1, id)
			}
			seen[id] = true
			providers = append(providers, DoHProvider{ID: id, System: true})
			continue
		}
		if seen[id] {
			return nil, fmt.Errorf("line %d: duplicate provider ID %q", lineNumber+1, id)
		}
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" || parsed.Path == "" {
			return nil, fmt.Errorf("line %d: endpoint must be an HTTPS URL with a path and without userinfo or fragment", lineNumber+1)
		}
		if parsed.Port() != "" {
			if _, err := strconv.Atoi(parsed.Port()); err != nil {
				return nil, fmt.Errorf("line %d: invalid endpoint port", lineNumber+1)
			}
		}
		seen[id] = true
		providers = append(providers, DoHProvider{ID: id, URL: endpoint})
	}
	return providers, nil
}

func validProviderID(id string) bool {
	if id == "" || len(id) > 64 || id[0] == '-' || id[0] == '_' || id[0] == '.' {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '-' && r != '_' && r != '.' {
			return false
		}
	}
	return true
}

func parseHealthChecks(data []byte) ([]Check, error) {
	var checks []Check
	seen := make(map[string]bool)
	for lineNumber, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, ";", 6)
		if len(fields) != 6 {
			return nil, fmt.Errorf("line %d: expected domain;qtypes;required;http_url;expected_status;verify_oidc", lineNumber+1)
		}
		domain := normalizeDomain(fields[0])
		if !validDNSHostname(domain) {
			return nil, fmt.Errorf("line %d: invalid domain %q", lineNumber+1, fields[0])
		}
		if seen[domain] {
			return nil, fmt.Errorf("line %d: duplicate domain %q", lineNumber+1, domain)
		}
		qtypes, err := parseHealthQTypes(fields[1])
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber+1, err)
		}
		required, err := parseBinaryFlag(fields[2])
		if err != nil {
			return nil, fmt.Errorf("line %d: required: %w", lineNumber+1, err)
		}
		httpURL := strings.TrimSpace(fields[3])
		expected, err := parseExpectedHTTPStatuses(fields[4])
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber+1, err)
		}
		verifyOIDC, err := parseBinaryFlag(fields[5])
		if err != nil {
			return nil, fmt.Errorf("line %d: verify_oidc: %w", lineNumber+1, err)
		}
		if httpURL == "" {
			if len(expected) != 0 || verifyOIDC {
				return nil, fmt.Errorf("line %d: expected_status and verify_oidc require http_url", lineNumber+1)
			}
		} else {
			parsed, parseErr := url.Parse(httpURL)
			if parseErr != nil || parsed.Scheme != "https" || !strings.EqualFold(parsed.Hostname(), domain) || parsed.User != nil || parsed.Fragment != "" {
				return nil, fmt.Errorf("line %d: http_url must be HTTPS on the same hostname as domain", lineNumber+1)
			}
		}
		if verifyOIDC && !strings.HasSuffix(strings.TrimRight(httpURL, "/"), "/.well-known/openid-configuration") {
			return nil, fmt.Errorf("line %d: verify_oidc requires an OIDC discovery URL", lineNumber+1)
		}
		seen[domain] = true
		checks = append(checks, Check{
			Domain: domain, QTypes: qtypes, Required: required, HTTPURL: httpURL,
			ExpectedStatus: expected, VerifyOIDC: verifyOIDC,
		})
	}
	if len(checks) == 0 {
		return nil, errors.New("no health checks configured")
	}
	return checks, nil
}

func parseBinaryFlag(raw string) (bool, error) {
	switch strings.TrimSpace(raw) {
	case "0":
		return false, nil
	case "1":
		return true, nil
	default:
		return false, fmt.Errorf("expected 0 or 1, got %q", strings.TrimSpace(raw))
	}
}

func parseHealthQTypes(raw string) ([]uint16, error) {
	var out []uint16
	seen := make(map[uint16]bool)
	for _, item := range strings.Split(strings.TrimSpace(raw), ",") {
		name := strings.ToUpper(strings.TrimSpace(item))
		if name == "" {
			return nil, errors.New("qtypes must contain one or more comma-separated DNS types")
		}
		var value uint64
		switch name {
		case "A":
			value = 1
		case "NS":
			value = 2
		case "CNAME":
			value = 5
		case "SOA":
			value = 6
		case "PTR":
			value = 12
		case "MX":
			value = 15
		case "TXT":
			value = 16
		case "AAAA":
			value = 28
		case "SRV":
			value = 33
		case "SVCB":
			value = 64
		case "HTTPS":
			value = 65
		case "CAA":
			value = 257
		default:
			parsed, err := strconv.ParseUint(name, 10, 16)
			if err != nil || parsed == 0 {
				return nil, fmt.Errorf("unsupported DNS qtype %q", item)
			}
			value = parsed
		}
		qt := uint16(value)
		if seen[qt] {
			return nil, fmt.Errorf("duplicate DNS qtype %s", name)
		}
		seen[qt] = true
		out = append(out, qt)
	}
	return out, nil
}

func parseExpectedHTTPStatuses(raw string) ([]int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var out []int
	seen := make(map[int]bool)
	for _, item := range strings.Split(raw, ",") {
		status, err := strconv.Atoi(strings.TrimSpace(item))
		if err != nil || status < 100 || status > 599 {
			return nil, fmt.Errorf("invalid expected HTTP status %q", item)
		}
		if seen[status] {
			return nil, fmt.Errorf("duplicate expected HTTP status %d", status)
		}
		seen[status] = true
		out = append(out, status)
	}
	return out, nil
}

func applyConfigSources(base Config, sources ConfigSources) (Config, error) {
	if len(base.Groups) == 0 {
		return Config{}, errors.New("config.json has no Google group")
	}
	groupIndex := -1
	for i := range base.Groups {
		if base.Groups[i].ID == "google" {
			groupIndex = i
			break
		}
	}
	if groupIndex < 0 {
		return Config{}, errors.New("config.json has no Google group")
	}

	existing := make(map[string]Upstream, len(base.Upstreams))
	var system Upstream
	for _, upstream := range base.Upstreams {
		if upstream.ID == systemDNSUpstreamID {
			system = upstream
			continue
		}
		key := upstream.ID
		if strings.Contains(key, ".") {
			key = legacyProviderID(key)
		}
		existing[key] = upstream
	}
	if system.ID == "" {
		system = Upstream{ID: systemDNSUpstreamID, Name: "System DNS (VPS)", Type: "system"}
	}
	system.Type = "system"
	system.BootstrapIPs = nil

	upstreams := make([]Upstream, 0, len(sources.Providers)+1)
	ordered := make([]string, 0, len(sources.Providers)+1)
	if sources.SystemDNSEnabled {
		upstreams = append(upstreams, system)
		ordered = append(ordered, systemDNSUpstreamID)
	}
	for _, provider := range sources.Providers {
		if provider.System || provider.ID == systemDNSUpstreamID {
			continue
		}
		upstream, ok := existing[provider.ID]
		if !ok {
			upstream = Upstream{ID: provider.ID, Name: provider.ID}
		}
		upstream.ID = provider.ID
		upstream.Type = ""
		upstream.URL = ""
		if strings.TrimSpace(upstream.Name) == "" {
			upstream.Name = provider.ID
		}
		upstreams = append(upstreams, upstream)
		ordered = append(ordered, provider.ID)
	}
	if len(ordered) == 0 {
		return Config{}, errors.New("at least one DoH or system DNS upstream must be enabled")
	}

	base.Upstreams = upstreams
	group := base.Groups[groupIndex]
	group.Upstreams = ordered
	group.Checks = append([]Check(nil), sources.Checks...)
	base.Groups = []Group{group}
	base = normalizeCacheConfig(base)
	if err := validateConfig(base); err != nil {
		return Config{}, fmt.Errorf("generated config validation failed: %w", err)
	}
	return base, nil
}

func writeConfigAtomic(path string, cfg Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode generated config: %w", err)
	}
	return writeAtomicFile(path, append(data, '\n'), 0600)
}

func writeAtomicFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".config-source-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
