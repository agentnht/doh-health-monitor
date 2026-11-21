package main

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"encoding/json"
	"net"
	"sort"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

//go:embed defaults/doh-servers.txt defaults/tst-domen.txt defaults/local-hosts.txt
var embeddedConfigSources embed.FS

const (
	configSourcePollInterval = 30 * time.Second
	localHostsSourceFile     = "local-hosts.txt"
	localHostsSourceHeader   = "# hostname;ipv4[,ipv4...];ipv6[,ipv6...]"
	maxLocalHostEntries      = 1000
	maxLocalHostIPsPerFamily = 16
)

type DoHProvider struct {
	ID     string
	URL    string
	System bool
}

type ConfigSourceChecksums struct {
	DoH      string
	Checks   string
	Hosts    string
	Combined string
}

type ConfigSources struct {
	Providers        []DoHProvider
	Checks           []Check
	LocalHosts       map[string]LocalHost
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
	if err := initializeLocalHostsSourceFile(dataDir); err != nil {
		return fmt.Errorf("initialize %s: %w", localHostsSourceFile, err)
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

func readConfigSources(dohPath, checksPath string, localHostsPaths ...string) (ConfigSources, error) {
	dohData, err := os.ReadFile(dohPath)
	if err != nil {
		return ConfigSources{}, fmt.Errorf("read doh-servers.txt: %w", err)
	}
	checksData, err := os.ReadFile(checksPath)
	if err != nil {
		return ConfigSources{}, fmt.Errorf("read tst-domen.txt: %w", err)
	}
	localHostsPath := filepath.Join(filepath.Dir(dohPath), localHostsSourceFile)
	if len(localHostsPaths) > 0 && strings.TrimSpace(localHostsPaths[0]) != "" {
		localHostsPath = localHostsPaths[0]
	}
	hostsData, err := os.ReadFile(localHostsPath)
	if err != nil {
		return ConfigSources{}, fmt.Errorf("read %s: %w", localHostsSourceFile, err)
	}
	checksums := configSourceChecksums(dohData, checksData, hostsData)
	providers, err := parseDoHProviders(dohData)
	if err != nil {
		return ConfigSources{Checksums: checksums}, fmt.Errorf("doh-servers.txt: %w", err)
	}
	checks, err := parseHealthChecks(checksData)
	if err != nil {
		return ConfigSources{Checksums: checksums}, fmt.Errorf("tst-domen.txt: %w", err)
	}
	localHosts, err := parseLocalHostsFile(hostsData)
	if err != nil {
		return ConfigSources{Checksums: checksums}, fmt.Errorf("%s: %w", localHostsSourceFile, err)
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
		Providers: providers, Checks: checks, LocalHosts: localHosts, DoHURLs: urls,
		SystemDNSEnabled: systemDNSEnabled, Checksums: checksums,
	}, nil
}
func configSourceChecksums(dohData, checksData []byte, localHostsData ...[]byte) ConfigSourceChecksums {
	if len(localHostsData) == 0 {
		localHostsData = [][]byte{[]byte(localHostsSourceHeader + "\n")}
	}
	dohHash := sha256.Sum256(dohData)
	checksHash := sha256.Sum256(checksData)
	hostsHash := sha256.Sum256(localHostsData[0])
	dohHex := hex.EncodeToString(dohHash[:])
	checksHex := hex.EncodeToString(checksHash[:])
	hostsHex := hex.EncodeToString(hostsHash[:])
	combinedHash := sha256.Sum256([]byte(dohHex + "\n" + checksHex + "\n" + hostsHex))
	return ConfigSourceChecksums{DoH: dohHex, Checks: checksHex, Hosts: hostsHex, Combined: hex.EncodeToString(combinedHash[:])}
}

func initializeLocalHostsSourceFile(dataDir string) error {
	path := filepath.Join(dataDir, localHostsSourceFile)
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > webUIAdminMaxFile {
			return errors.New("existing local-hosts.txt must be a regular non-symlink file within the size limit")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	legacyHosts := map[string]LocalHost{}
	configPath := filepath.Join(dataDir, "config.json")
	if info, err := os.Lstat(configPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > webUIAdminMaxFile {
			return errors.New("legacy config.json must be a regular non-symlink file within the size limit")
		}
		data, err := os.ReadFile(configPath)
		if err != nil {
			return fmt.Errorf("read legacy config.json: %w", err)
		}
		var legacy struct {
			LocalHosts map[string]LocalHost `json:"local_hosts"`
		}
		if err := json.Unmarshal(data, &legacy); err != nil {
			return fmt.Errorf("decode legacy local_hosts from config.json: %w", err)
		}
		legacyHosts = legacy.LocalHosts
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect legacy config.json: %w", err)
	}

	var data []byte
	var err error
	if len(legacyHosts) == 0 {
		data, err = fs.ReadFile(embeddedConfigSources, "defaults/local-hosts.txt")
	} else {
		data, err = encodeLocalHostsFile(legacyHosts)
	}
	if err != nil {
		return fmt.Errorf("prepare migrated local hosts: %w", err)
	}
	if _, err := parseLocalHostsFile(data); err != nil {
		return fmt.Errorf("validate migrated local hosts: %w", err)
	}
	if err := writeAtomicFile(path, data, 0600); err != nil {
		return fmt.Errorf("create local-hosts.txt: %w", err)
	}
	if len(legacyHosts) > 0 {
		logLine("INFO", "CONFIG_SOURCE_MIGRATED file=local-hosts.txt entries=%d", len(legacyHosts))
	} else {
		logLine("INFO", "CONFIG_SOURCE_CREATED file=local-hosts.txt source=embedded_default")
	}
	return nil
}

func parseLocalHostsFile(data []byte) (map[string]LocalHost, error) {
	if len(data) > webUIAdminMaxFile {
		return nil, errors.New("file exceeds the size limit")
	}
	result := make(map[string]LocalHost)
	for lineNumber, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ";")
		if len(fields) != 3 {
			return nil, fmt.Errorf("line %d: expected hostname;ipv4[,ipv4...];ipv6[,ipv6...]", lineNumber+1)
		}
		host, entry, err := normalizeLocalHostEntry(fields[0], LocalHost{
			IPv4: splitLocalHostIPs(fields[1]),
			IPv6: splitLocalHostIPs(fields[2]),
		})
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber+1, err)
		}
		if _, exists := result[host]; exists {
			return nil, fmt.Errorf("line %d: duplicate hostname %q", lineNumber+1, host)
		}
		result[host] = entry
		if len(result) > maxLocalHostEntries {
			return nil, fmt.Errorf("more than %d host entries", maxLocalHostEntries)
		}
	}
	return result, nil
}

func splitLocalHostIPs(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	items := strings.Split(raw, ",")
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, strings.TrimSpace(item))
	}
	return out
}

func normalizeLocalHostEntry(rawHost string, entry LocalHost) (string, LocalHost, error) {
	host := normalizeDomain(rawHost)
	if !validDNSHostname(host) {
		return "", LocalHost{}, fmt.Errorf("invalid hostname %q", rawHost)
	}
	if len(entry.IPv4) > maxLocalHostIPsPerFamily || len(entry.IPv6) > maxLocalHostIPsPerFamily {
		return "", LocalHost{}, fmt.Errorf("at most %d IPv4 and %d IPv6 addresses are allowed per hostname", maxLocalHostIPsPerFamily, maxLocalHostIPsPerFamily)
	}
	if len(entry.IPv4)+len(entry.IPv6) == 0 {
		return "", LocalHost{}, errors.New("at least one IPv4 or IPv6 address is required")
	}
	normalized := LocalHost{}
	seen4, seen6 := map[string]bool{}, map[string]bool{}
	for _, raw := range entry.IPv4 {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil || ip.To4() == nil {
			return "", LocalHost{}, fmt.Errorf("invalid IPv4 address %q", raw)
		}
		value := ip.To4().String()
		if seen4[value] {
			return "", LocalHost{}, fmt.Errorf("duplicate IPv4 address %q", value)
		}
		seen4[value] = true
		normalized.IPv4 = append(normalized.IPv4, value)
	}
	for _, raw := range entry.IPv6 {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil || ip.To4() != nil || ip.To16() == nil {
			return "", LocalHost{}, fmt.Errorf("invalid IPv6 address %q", raw)
		}
		value := ip.String()
		if seen6[value] {
			return "", LocalHost{}, fmt.Errorf("duplicate IPv6 address %q", value)
		}
		seen6[value] = true
		normalized.IPv6 = append(normalized.IPv6, value)
	}
	return host, normalized, nil
}

func encodeLocalHostsFile(hosts map[string]LocalHost) ([]byte, error) {
	if len(hosts) > maxLocalHostEntries {
		return nil, fmt.Errorf("more than %d host entries", maxLocalHostEntries)
	}
	keys := make([]string, 0, len(hosts))
	for host := range hosts {
		keys = append(keys, host)
	}
	sort.Strings(keys)
	var out strings.Builder
	out.WriteString(localHostsSourceHeader + "\n")
	seen := make(map[string]bool, len(hosts))
	for _, rawHost := range keys {
		host, entry, err := normalizeLocalHostEntry(rawHost, hosts[rawHost])
		if err != nil {
			return nil, fmt.Errorf("local_hosts %q: %w", rawHost, err)
		}
		if seen[host] {
			return nil, fmt.Errorf("duplicate local_hosts hostname after normalization: %q", rawHost)
		}
		seen[host] = true
		fmt.Fprintf(&out, "%s;%s;%s\n", host, strings.Join(entry.IPv4, ","), strings.Join(entry.IPv6, ","))
	}
	return []byte(out.String()), nil
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
	base.LocalHosts = make(map[string]LocalHost, len(sources.LocalHosts))
	for host, entry := range sources.LocalHosts {
		base.LocalHosts[host] = LocalHost{IPv4: append([]string(nil), entry.IPv4...), IPv6: append([]string(nil), entry.IPv6...)}
	}
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
