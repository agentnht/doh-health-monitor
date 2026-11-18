package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"lucx-doh-health-monitor/internal/autohosts"
	"lucx-doh-health-monitor/internal/dohintegration"
)

const (
	pluginID                  = "doh-health-monitor"
	pluginVersion             = "2.2.1"
	systemDNSUpstreamID       = "system-dns"
	systemResolvConfPath      = "/etc/resolv.conf"
	systemDNSPerServerTimeout = 2 * time.Second
	maxDNSMessage             = 65535
	maxHTTPBody               = 2 << 20
	defaultCacheMaxBytes      = 8 << 20
	maxCacheMaxBytes          = 256 << 20
	maxUDPWorkers             = 64
	udpQueueCapacity          = 128
	maxTCPConnections         = 128
	tcpIdleTimeout            = 30 * time.Second
	tcpWriteTimeout           = 10 * time.Second
)

type Config struct {
	LocalHosts             map[string]LocalHost `json:"local_hosts"`
	DNSListenUDP           string               `json:"dns_listen_udp"`
	DNSListenTCP           string               `json:"dns_listen_tcp"`
	HTTPListen             string               `json:"http_listen"`
	ReloadSecs             int                  `json:"reload_interval_seconds"`
	DNSQueryTimeoutSeconds int                  `json:"dns_query_timeout_seconds"`
	DoHTimeoutSeconds      int                  `json:"doh_timeout_seconds"`
	DNSMaxConcurrent       int                  `json:"dns_max_concurrent"`
	Health                 HealthConfig         `json:"health"`
	Cache                  CacheConfig          `json:"cache"`
	Upstreams              []Upstream           `json:"upstreams"`
	BootstrapResolvers     []string             `json:"bootstrap_resolvers,omitempty"`
	Groups                 []Group              `json:"groups"`
	GeminiAPI              GeminiAPIConfig      `json:"gemini_api"`
	Integration            bool                 `json:"integration"`
}
type LocalHost struct {
	IPv4 []string `json:"ipv4"`
	IPv6 []string `json:"ipv6"`
}
type HealthConfig struct {
	IntervalSeconds  int `json:"interval_seconds"`
	TimeoutSeconds   int `json:"timeout_seconds"`
	FailureThreshold int `json:"failure_threshold"`
	SuccessThreshold int `json:"success_threshold"`
}
type CacheConfig struct {
	Enabled     bool `json:"enabled"`
	MinTTL      int  `json:"min_ttl_seconds"`
	MaxTTL      int  `json:"max_ttl_seconds"`
	NegativeTTL int  `json:"negative_ttl_seconds"`
	MaxEntries  int  `json:"max_entries"`
	MaxBytes    int  `json:"max_bytes"`
}
type Upstream struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Type         string   `json:"type,omitempty"`
	URL          string   `json:"-"`
	BootstrapIPs []string `json:"bootstrap_ips"`
}
type Group struct {
	ID string `json:"id"`
	// Deprecated legacy fields are accepted for config compatibility and ignored.
	FakeDNS   bool     `json:"fake_dns,omitempty"`
	Domains   []string `json:"domains,omitempty"`
	Upstreams []string `json:"upstreams"`
	Checks    []Check  `json:"checks,omitempty"`
}
type Check struct {
	Domain         string   `json:"domain"`
	QTypes         []uint16 `json:"qtypes,omitempty"`
	HTTPURL        string   `json:"http_url,omitempty"`
	Required       bool     `json:"required"`
	ExpectedStatus []int    `json:"expected_status,omitempty"`
	VerifyOIDC     bool     `json:"verify_oidc,omitempty"`
}
type GeminiAPIConfig struct {
	Enabled          bool   `json:"enabled"`
	RequiredForGroup bool   `json:"required_for_group"`
	GroupID          string `json:"group_id"`
	Model            string `json:"model"`
	IntervalSeconds  int    `json:"interval_seconds"`
	KeyFile          string `json:"key_file"`
	Prompt           string `json:"prompt"`
	MaxOutputTokens  int    `json:"max_output_tokens"`
}

type Snapshot struct {
	cfg        Config
	localHosts map[string]LocalHost
	upstreams  map[string]*UpstreamRuntime
	groups     map[string]Group
	loadedAt   time.Time
	configMod  time.Time
	configHash [32]byte
}
type UpstreamRuntime struct {
	cfg       Upstream
	client    *http.Client
	bootstrap *bootstrapResolver
	systemDNS *systemDNSResolver
}

type systemDNSResolver struct {
	resolvConfPath string
}

type bootstrapResolver struct {
	host                string
	endpoint            string
	resolvers           []string
	fallback            []string
	mu                  sync.Mutex
	selectMu            sync.Mutex
	ips                 []string
	resolvedBy          string
	refreshed           time.Time
	lastAttempt         time.Time
	refreshFor          time.Duration
	selectedIP          string
	selectedTil         time.Time
	lastCandidates      []string
	lastCandidateSource string
	lastProbeAt         time.Time
	lastProbe           []DoHIPProbeStatus
	probe               func(context.Context, string, string, time.Duration) (time.Duration, error)
}

type DoHIPProbeStatus struct {
	IP         string `json:"ip"`
	Source     string `json:"source"`
	Result     string `json:"result"`
	ResponseMS int64  `json:"response_ms"`
	Error      string `json:"error,omitempty"`
}

type DoHBootstrapStatus struct {
	Hostname        string             `json:"hostname"`
	ResolvedIPs     []string           `json:"resolved_ips,omitempty"`
	ResolvedBy      string             `json:"resolved_by,omitempty"`
	ResolvedAt      time.Time          `json:"resolved_at,omitempty"`
	CandidateIPs    []string           `json:"candidate_ips,omitempty"`
	CandidateSource string             `json:"candidate_source,omitempty"`
	SelectedIP      string             `json:"selected_ip,omitempty"`
	SelectedUntil   time.Time          `json:"selected_until,omitempty"`
	LastProbeAt     time.Time          `json:"last_probe_at,omitempty"`
	LastProbe       []DoHIPProbeStatus `json:"last_probe,omitempty"`
}

func (b *bootstrapResolver) status() DoHBootstrapStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	return DoHBootstrapStatus{
		Hostname:        b.host,
		ResolvedIPs:     append([]string(nil), b.ips...),
		ResolvedBy:      b.resolvedBy,
		ResolvedAt:      b.refreshed,
		CandidateIPs:    append([]string(nil), b.lastCandidates...),
		CandidateSource: b.lastCandidateSource,
		SelectedIP:      b.selectedIP,
		SelectedUntil:   b.selectedTil,
		LastProbeAt:     b.lastProbeAt,
		LastProbe:       append([]DoHIPProbeStatus(nil), b.lastProbe...),
	}
}

func (b *bootstrapResolver) recordProbeSnapshot(candidates []string, source string, probes []DoHIPProbeStatus) {
	b.mu.Lock()
	b.lastCandidates = append([]string(nil), candidates...)
	b.lastCandidateSource = source
	b.lastProbeAt = time.Now().UTC()
	b.lastProbe = append([]DoHIPProbeStatus(nil), probes...)
	b.mu.Unlock()
}

type ProbeStatus struct {
	Domain      string `json:"domain"`
	Required    bool   `json:"required"`
	DNSOK       bool   `json:"dns_ok"`
	HTTPChecked bool   `json:"http_checked"`
	HTTPOK      bool   `json:"http_ok"`
	HTTPStatus  int    `json:"http_status,omitempty"`
	Error       string `json:"error,omitempty"`
}
type HealthEntry struct {
	State           string        `json:"state"`
	Checks          []ProbeStatus `json:"checks,omitempty"`
	SuccessStreak   int           `json:"success_streak"`
	FailureStreak   int           `json:"failure_streak"`
	LastCheck       time.Time     `json:"last_check,omitempty"`
	CheckDurationMS int64         `json:"check_duration_ms,omitempty"`
	LastError       string        `json:"last_error,omitempty"`
	LastHTTP        int           `json:"last_http_status,omitempty"`
	GeminiState     string        `json:"gemini_api_state,omitempty"`
}
type GroupStatus struct {
	ActiveUpstream string                 `json:"active_upstream"`
	Upstreams      map[string]HealthEntry `json:"upstreams"`
}
type Status struct {
	ID               string                        `json:"id"`
	Version          string                        `json:"version"`
	StartedAt        time.Time                     `json:"started_at"`
	UpdatedAt        time.Time                     `json:"updated_at"`
	DNSUDP           string                        `json:"dns_udp"`
	DNSTCP           string                        `json:"dns_tcp"`
	HTTP             string                        `json:"http"`
	Config           string                        `json:"config"`
	Cache            CacheStatus                   `json:"cache"`
	Groups           map[string]GroupStatus        `json:"groups"`
	DoHBootstrap     map[string]DoHBootstrapStatus `json:"doh_bootstrap,omitempty"`
	SystemDNSServers []string                      `json:"system_dns_servers,omitempty"`
	SystemDNSError   string                        `json:"system_dns_error,omitempty"`
	GeminiAPI        string                        `json:"gemini_api"`
	Queries          uint64                        `json:"queries"`
	CacheHits        uint64                        `json:"cache_hits"`
	Failures         uint64                        `json:"failures"`
	ActiveUDP        int64                         `json:"active_udp"`
	UDPQueueDepth    int64                         `json:"udp_queue_depth"`
	UDPDropped       uint64                        `json:"udp_dropped"`
	ActiveTCP        int64                         `json:"active_tcp"`
	TCPRejected      uint64                        `json:"tcp_rejected"`
	Goroutines       int                           `json:"goroutines"`
	HeapAllocBytes   uint64                        `json:"heap_alloc_bytes"`
	HeapInuseBytes   uint64                        `json:"heap_inuse_bytes"`
	HeapSysBytes     uint64                        `json:"heap_sys_bytes"`
	CPUUserNS        uint64                        `json:"cpu_user_ns"`
	CPUSystemNS      uint64                        `json:"cpu_system_ns"`
	LastReload       time.Time                     `json:"last_reload,omitempty"`
	LastError        string                        `json:"last_error,omitempty"`
}
type CacheStatus struct {
	Enabled    bool `json:"enabled"`
	Entries    int  `json:"entries"`
	MaxEntries int  `json:"max_entries"`
	Bytes      int  `json:"bytes"`
	MaxBytes   int  `json:"max_bytes"`
}
type GeminiHTTPError struct{ Status int }

func (e GeminiHTTPError) Error() string { return fmt.Sprintf("Gemini API HTTP %d", e.Status) }

type Event struct {
	ID     string          `json:"id"`
	Type   string          `json:"type"`
	Source string          `json:"source"`
	Time   json.RawMessage `json:"time"`
	Data   json.RawMessage `json:"data"`
}
type autoHostsQueryJob struct {
	domain string
	done   chan struct{}
	err    error
}

type Runtime struct {
	dnsSem                 chan struct{}
	dataDir                string
	autoHosts              *autohosts.Manager
	geo                    *geositeIndex
	vpsResolve             *UpstreamRuntime
	autoHostsQueryQueue    chan *autoHostsQueryJob
	autoHostsQueueMu       sync.Mutex
	autoHostsQueued        map[string]*autoHostsQueryJob
	autoController         *autoHostsController
	configPath             string
	dohPath                string
	checksPath             string
	sourceHashes           ConfigSourceChecksums
	lastRejectedSourceHash string
	healthCheckTrigger     chan struct{}
	snapshot               atomic.Pointer[Snapshot]
	mu                     sync.RWMutex
	health                 map[string]map[string]HealthEntry
	active                 map[string]string
	upstreamCooldown       map[string]time.Time
	cacheMu                sync.Mutex
	cache                  map[string]cacheItem
	cacheFlights           map[string]*cacheFlight
	cacheOrder             []cacheOrderEntry
	cacheOrderHead         int
	cacheBytes             int
	cacheSeq               uint64
	cacheHits              atomic.Uint64
	activeUDP              atomic.Int64
	udpQueueDepth          atomic.Int64
	udpDropped             atomic.Uint64
	activeTCP              atomic.Int64
	tcpRejected            atomic.Uint64
	queries                atomic.Uint64
	failures               atomic.Uint64
	lastGemini             map[string]time.Time
	statusMu               sync.RWMutex
	lastError              string
	lastReload             time.Time
}

func main() {
	log.SetFlags(0)
	if len(os.Args) > 1 {
		runManagementCommand(os.Args[1:])
		return
	}
	runDaemon()
}

func runManagementCommand(args []string) {
	if len(args) == 0 {
		return
	}
	action := strings.ToLower(strings.TrimSpace(args[0]))
	if action == "web" {
		if len(args) != 2 {
			logLine("ERROR", "WEB_UI does not accept additional arguments")
			os.Exit(2)
		}
		if err := runWebUI(); err != nil {
			logLine("ERROR", "WEB_UI: %v", err)
			os.Exit(1)
		}
		return
	}
	if action == "check" {
		logger := lucxIntegrationLogger{}
		if err := dohintegration.RunCommand(args, logger); err != nil {
			logLine("ERROR", "CHECK: %v", err)
			os.Exit(1)
		}
		return
	}
	if action != "integrate" && action != "remove" {
		logLine("ERROR", "CLI supports integrate, remove, check, and web")
		os.Exit(2)
	}
	dataDir, err := dohintegration.PluginDataDir()
	if err != nil {
		logLine("ERROR", "INTEGRATION data directory: %v", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		logLine("ERROR", "INTEGRATION create data directory failed")
		os.Exit(1)
	}
	configPath := filepath.Join(dataDir, "config.json")
	if _, err := loadConfig(configPath); err != nil {
		logLine("ERROR", "INTEGRATION config is invalid: %v", err)
		os.Exit(1)
	}
	pluginLog, err := os.OpenFile(filepath.Join(filepath.Dir(dataDir), "plugin.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		logLine("ERROR", "INTEGRATION cannot open plugin.log: %v", err)
		os.Exit(1)
	}
	info, err := pluginLog.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = pluginLog.Close()
		logLine("ERROR", "INTEGRATION plugin.log is not a regular file")
		os.Exit(1)
	}
	if err := pluginLog.Chmod(0600); err != nil {
		_ = pluginLog.Close()
		logLine("ERROR", "INTEGRATION cannot secure plugin.log: %v", err)
		os.Exit(1)
	}
	defer pluginLog.Close()
	logger := lucxIntegrationLogger{file: pluginLog}
	logger.Printf("INTEGRATION directive=%s started", strings.ToUpper(action))
	if err := dohintegration.RunCommand(args, logger); err != nil {
		logger.Printf("INTEGRATION directive=%s failed: %v", strings.ToUpper(action), err)
		os.Exit(1)
	}
	enabled := action == "integrate"
	if err := setIntegrationFlag(configPath, enabled); err != nil {
		logger.Printf("INTEGRATION directive=%s succeeded but config flag update failed: %v", strings.ToUpper(action), err)
		os.Exit(1)
	}
	logger.Printf("INTEGRATION directive=%s completed integration=%t", strings.ToUpper(action), enabled)
	return
}

type lucxIntegrationLogger struct{ file *os.File }

func (l lucxIntegrationLogger) Printf(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	logLine("INFO", "%s", message)
	if l.file != nil {
		_, err := fmt.Fprintf(l.file, "%s level=INFO %s\n", time.Now().UTC().Format(time.RFC3339), message)
		if err == nil {
			err = l.file.Sync()
		}
		if err != nil {
			logLine("ERROR", "INTEGRATION log write failed: %v", err)
		}
	}
}

func setIntegrationFlag(path string, enabled bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var config map[string]any
	if err := decoder.Decode(&config); err != nil || config == nil {
		return errors.New("config.json is not a JSON object")
	}
	config["integration"] = enabled
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	encoded = append(encoded, '\n')
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".config.json-*")
	if err != nil {
		return fmt.Errorf("create temporary config: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(encoded); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("replace config atomically: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func fatal(f string, a ...any) { logLine("ERROR", f, a...); os.Exit(1) }
func envOr(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}
func logLine(level, f string, a ...any) {
	log.Printf("%s level=%s %s", time.Now().UTC().Format(time.RFC3339), level, fmt.Sprintf(f, a...))
}
func loadConfig(path string) (Config, error) {
	if _, e := os.Stat(path); errors.Is(e, os.ErrNotExist) {
		b, _ := json.MarshalIndent(defaultConfig(), "", "  ")
		if e = os.WriteFile(path, append(b, '\n'), 0600); e != nil {
			return Config{}, fmt.Errorf("create default config: %w", e)
		}
		logLine("WARN", "CONFIG_TEMPLATE_CREATED path=%s; review Google checks and bootstrap_resolvers", path)
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return Config{}, e
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if e = dec.Decode(&c); e != nil {
		return Config{}, fmt.Errorf("decode config: %w", e)
	}
	c, e = normalizeConfigGroups(c)
	if e != nil {
		return Config{}, e
	}
	c = normalizeCacheConfig(c)
	if e = validateConfig(c); e != nil {
		return Config{}, e
	}
	return c, nil
}
func defaultConfig() Config {
	c := Config{
		DNSListenUDP: "127.0.0.1:5355", DNSListenTCP: "127.0.0.1:5355", HTTPListen: "127.0.0.1:18765", ReloadSecs: 5,
		DNSQueryTimeoutSeconds: 15, DoHTimeoutSeconds: 10, DNSMaxConcurrent: 256,
		Health:             HealthConfig{IntervalSeconds: 25 * 60, TimeoutSeconds: 5, FailureThreshold: 1, SuccessThreshold: 1},
		Cache:              CacheConfig{Enabled: true, MinTTL: 5, MaxTTL: 300, NegativeTTL: 15, MaxEntries: 8192, MaxBytes: defaultCacheMaxBytes},
		LocalHosts:         map[string]LocalHost{},
		BootstrapResolvers: []string{"1.1.1.1", "8.8.8.8"},
		Upstreams: []Upstream{
			{ID: systemDNSUpstreamID, Name: "System DNS (VPS)", Type: "system"},
			{ID: "geohide-eu", Name: "GeoHide EU"},
			{ID: "dagami", Name: "Dagami"},
			{ID: "comss-one", Name: "Comss.one"},
			{ID: "bezmezhau", Name: "Bezmezhau"},
			{ID: "zapret", Name: "Zapret"},
		},
		Groups: []Group{
			{ID: "google", Upstreams: []string{systemDNSUpstreamID, "geohide-eu", "dagami", "comss-one", "bezmezhau", "zapret"}},
		},
		GeminiAPI: GeminiAPIConfig{Enabled: false, RequiredForGroup: false, GroupID: "google", Model: "gemini-3.8-flash", IntervalSeconds: 1800, KeyFile: "gemini_api_key", Prompt: "Reply with exactly OK.", MaxOutputTokens: 8},
	}
	if data, err := embeddedConfigSources.ReadFile("defaults/tst-domen.txt"); err == nil {
		if checks, err := parseHealthChecks(data); err == nil {
			c.Groups[0].Checks = checks
		}
	}
	return c
}
func normalizeConfigGroups(c Config) (Config, error) {
	// Older installations may still have multiple groups. Keep only the Google
	// suitability profile; the DNS gateway never routes by queried domain.
	for _, g := range c.Groups {
		if g.ID == "google" {
			c.Groups = []Group{g}
			return ensureSystemDNSFirst(c)
		}
	}
	return Config{}, errors.New("configuration has no group with id 'google'")
}

func ensureSystemDNSFirst(c Config) (Config, error) {
	var system Upstream
	found := false
	remaining := make([]Upstream, 0, len(c.Upstreams))
	for _, u := range c.Upstreams {
		if u.ID == systemDNSUpstreamID {
			if found {
				return Config{}, fmt.Errorf("duplicate upstream id %q", systemDNSUpstreamID)
			}
			if u.Type != "system" {
				return Config{}, fmt.Errorf("upstream %q is reserved for type system", systemDNSUpstreamID)
			}
			system = u
			found = true
			continue
		}
		remaining = append(remaining, u)
	}
	if !found {
		// The source list controls whether system-dns is enabled. Do not
		// recreate it when a previous reload removed it intentionally.
		c.Upstreams = remaining
		return c, nil
	}
	c.Upstreams = append([]Upstream{system}, remaining...)

	// Keep system DNS first only when the saved group already references it.
	// Membership itself is controlled by doh-servers.txt.
	group := c.Groups[0]
	containsSystem := false
	ordered := make([]string, 0, len(group.Upstreams))
	for _, id := range group.Upstreams {
		if id == systemDNSUpstreamID {
			containsSystem = true
			continue
		}
		ordered = append(ordered, id)
	}
	if containsSystem {
		group.Upstreams = append([]string{systemDNSUpstreamID}, ordered...)
		c.Groups[0] = group
	}
	return c, nil
}

func normalizeCacheConfig(c Config) Config {
	// Older config files predate max_bytes; give them a bounded default.
	if c.Cache.MaxBytes == 0 {
		c.Cache.MaxBytes = defaultCacheMaxBytes
	}
	return c
}

func validateConfig(c Config) error {
	if !validListen(c.DNSListenUDP) || !validListen(c.DNSListenTCP) || !validListen(c.HTTPListen) {
		return errors.New("dns_listen_udp, dns_listen_tcp and http_listen must be host:port")
	}
	if c.ReloadSecs < 1 || c.ReloadSecs > 300 {
		return errors.New("reload_interval_seconds must be 1..300")
	}
	if c.DNSQueryTimeoutSeconds < 1 || c.DNSQueryTimeoutSeconds > 120 || c.DoHTimeoutSeconds < 1 || c.DoHTimeoutSeconds > 60 || c.DNSMaxConcurrent < 1 || c.DNSMaxConcurrent > 4096 {
		return errors.New("dns_query_timeout_seconds, doh_timeout_seconds or dns_max_concurrent out of range")
	}
	if c.Health.IntervalSeconds < 5 || c.Health.IntervalSeconds > 3600 || c.Health.TimeoutSeconds < 1 || c.Health.TimeoutSeconds > 60 || c.Health.FailureThreshold < 1 || c.Health.FailureThreshold > 20 || c.Health.SuccessThreshold < 1 || c.Health.SuccessThreshold > 50 {
		return errors.New("invalid health settings")
	}
	if c.Cache.MinTTL < 0 || c.Cache.MaxTTL < 1 || c.Cache.MaxTTL < c.Cache.MinTTL || c.Cache.NegativeTTL < 0 || c.Cache.MaxEntries < 0 || c.Cache.MaxBytes < 0 {
		return errors.New("invalid cache settings")
	}
	if c.Cache.Enabled && (c.Cache.MaxEntries < 1 || c.Cache.MaxEntries > 100000 || c.Cache.MaxBytes < 1024 || c.Cache.MaxBytes > maxCacheMaxBytes) {
		return fmt.Errorf("enabled cache limits must be max_entries=1..100000 and max_bytes=1024..%d", maxCacheMaxBytes)
	}
	if len(c.Upstreams) == 0 {
		return errors.New("at least one upstream is required")
	}
	resolvers := c.BootstrapResolvers
	if len(resolvers) == 0 {
		resolvers = defaultBootstrapResolvers()
	}
	for _, ip := range resolvers {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("invalid bootstrap resolver IP %q", ip)
		}
	}
	normalizedHosts := map[string]bool{}
	for host, entry := range c.LocalHosts {
		normalized := normalizeDomain(host)
		if normalizedHosts[normalized] {
			return fmt.Errorf("duplicate local_hosts hostname after normalization: %q", host)
		}
		normalizedHosts[normalized] = true
		if !validDNSHostname(normalized) {
			return fmt.Errorf("invalid local_hosts hostname %q", host)
		}
		for _, raw := range entry.IPv4 {
			ip := net.ParseIP(strings.TrimSpace(raw))
			if ip == nil || ip.To4() == nil {
				return fmt.Errorf("local_hosts %s has invalid IPv4 address %q", host, raw)
			}
		}
		for _, raw := range entry.IPv6 {
			ip := net.ParseIP(strings.TrimSpace(raw))
			if ip == nil || ip.To4() != nil || ip.To16() == nil {
				return fmt.Errorf("local_hosts %s has invalid IPv6 address %q", host, raw)
			}
		}
	}
	ids := map[string]bool{}
	systemDNSCount := 0
	for _, u := range c.Upstreams {
		if u.ID == "" || ids[u.ID] {
			return fmt.Errorf("upstream id empty or duplicate: %q", u.ID)
		}
		ids[u.ID] = true
		if strings.ContainsAny(u.ID, "/:@ \t") {
			return fmt.Errorf("upstream id must be a hostname: %s", u.ID)
		}
		switch u.Type {
		case "":
			if u.ID == systemDNSUpstreamID {
				return fmt.Errorf("upstream %q must have type system", systemDNSUpstreamID)
			}
		case "system":
			systemDNSCount++
			if u.ID != systemDNSUpstreamID {
				return fmt.Errorf("system DNS upstream must use id %q", systemDNSUpstreamID)
			}
			if len(u.BootstrapIPs) != 0 {
				return errors.New("system DNS upstream must not define bootstrap_ips")
			}
		case "doh":
			if u.ID == systemDNSUpstreamID {
				return fmt.Errorf("upstream id %q is reserved for system DNS", systemDNSUpstreamID)
			}
		default:
			return fmt.Errorf("unsupported upstream type %q for %s", u.Type, u.ID)
		}
		for _, ip := range u.BootstrapIPs {
			if net.ParseIP(ip) == nil {
				return fmt.Errorf("invalid bootstrap IP %q in %s", ip, u.ID)
			}
		}
	}
	if systemDNSCount > 1 {
		return fmt.Errorf("at most one system DNS upstream is allowed; got %d", systemDNSCount)
	}
	groups := map[string]bool{}
	for _, g := range c.Groups {
		if g.ID == "" || groups[g.ID] {
			return fmt.Errorf("group id empty or duplicate: %q", g.ID)
		}
		groups[g.ID] = true
		if len(g.Upstreams) == 0 {
			return fmt.Errorf("group %s has no upstreams", g.ID)
		}
		for _, u := range g.Upstreams {
			if !ids[u] {
				return fmt.Errorf("group %s references unknown upstream %s", g.ID, u)
			}
		}
		for _, ch := range g.Checks {
			if !validDNSHostname(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(ch.Domain)), ".")) {
				return fmt.Errorf("invalid check domain %q in group %s", ch.Domain, g.ID)
			}
			for _, qt := range ch.QTypes {
				if qt == 0 {
					return fmt.Errorf("invalid qtype 0 in group %s", g.ID)
				}
			}
			if ch.HTTPURL != "" {
				p, e := url.Parse(ch.HTTPURL)
				if e != nil || p.Scheme != "https" || p.Hostname() == "" {
					return fmt.Errorf("check URL must be HTTPS in group %s", g.ID)
				}
			}
		}
	}
	if len(c.Groups) != 1 || !groups["google"] {
		return errors.New("exactly one group with id 'google' is required")
	}
	if c.GeminiAPI.Enabled {
		if filepath.IsAbs(c.GeminiAPI.KeyFile) || strings.HasPrefix(filepath.Clean(c.GeminiAPI.KeyFile), "..") {
			return errors.New("gemini_api.key_file must be a relative path inside LUCX_PLUGIN_DATA")
		}
		if !groups[c.GeminiAPI.GroupID] {
			return errors.New("gemini_api.group_id must reference a configured group")
		}
		if !validGeminiModel(c.GeminiAPI.Model) {
			return errors.New("gemini_api.model must be a model identifier containing only ASCII letters, digits, '.', '_' or '-' (maximum 128 characters)")
		}
		if c.GeminiAPI.KeyFile == "" || c.GeminiAPI.IntervalSeconds < 60 || c.GeminiAPI.IntervalSeconds > 86400 {
			return errors.New("gemini_api requires key_file and interval_seconds in 60..86400")
		}
		if strings.TrimSpace(c.GeminiAPI.Prompt) == "" || len(c.GeminiAPI.Prompt) > 4096 {
			return errors.New("gemini_api.prompt must contain 1..4096 bytes of non-whitespace text")
		}
		if c.GeminiAPI.MaxOutputTokens < 1 || c.GeminiAPI.MaxOutputTokens > 8192 {
			return errors.New("gemini_api.max_output_tokens must be in 1..8192")
		}
	}
	return nil
}
func validGeminiModel(model string) bool {
	if len(model) == 0 || len(model) > 128 {
		return false
	}
	for i, r := range model {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-') {
			return false
		}
		if i == 0 && !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

func validDNSHostname(host string) bool {
	if host == "" || len(host) > 253 || net.ParseIP(host) != nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
				return false
			}
		}
	}
	return true
}
func validListen(s string) bool {
	h, p, e := net.SplitHostPort(s)
	return e == nil && h != "" && p != ""
}
func normalizeDomain(s string) string {
	return strings.Trim(strings.ToLower(strings.TrimSpace(s)), ".")
}
func loadDoHList(path string, create bool) (map[string]string, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) && create {
		defaults, readErr := embeddedConfigSources.ReadFile("defaults/doh-servers.txt")
		if readErr != nil {
			return nil, readErr
		}
		if writeErr := writeAtomicFile(path, defaults, 0600); writeErr != nil {
			return nil, writeErr
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	providers, err := parseDoHProviders(data)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(providers))
	for _, provider := range providers {
		if provider.System || provider.ID == systemDNSUpstreamID {
			continue
		}
		out[provider.ID] = provider.URL
	}
	return out, nil
}

func buildSnapshot(c Config, dohURLs map[string]string) (*Snapshot, error) {
	s := &Snapshot{cfg: c, upstreams: map[string]*UpstreamRuntime{}, groups: map[string]Group{}, localHosts: map[string]LocalHost{}, loadedAt: time.Now().UTC()}
	for host, entry := range c.LocalHosts {
		s.localHosts[normalizeDomain(host)] = entry
	}
	known := map[string]bool{}
	for _, u := range c.Upstreams {
		known[u.ID] = true
	}
	for id := range dohURLs {
		if !known[id] {
			return nil, fmt.Errorf("DoH server %s in doh-servers.txt has no upstream/bootstrap entry in config.json", id)
		}
		for _, configured := range c.Upstreams {
			if configured.ID == id && configured.Type == "system" {
				return nil, fmt.Errorf("system DNS upstream %s must not have a DoH URL", id)
			}
		}
	}
	resolvers := c.BootstrapResolvers
	if len(resolvers) == 0 {
		resolvers = defaultBootstrapResolvers()
	}
	for _, u := range c.Upstreams {
		if u.Type == "system" {
			s.upstreams[u.ID] = &UpstreamRuntime{
				cfg:       u,
				systemDNS: &systemDNSResolver{resolvConfPath: systemResolvConfPath},
			}
			continue
		}
		urlValue, ok := dohURLs[u.ID]
		if !ok {
			continue
		}
		u.URL = urlValue
		client, bootstrap, e := newDoHClient(u, resolvers, time.Duration(c.DoHTimeoutSeconds)*time.Second)
		if e != nil {
			return nil, e
		}
		s.upstreams[u.ID] = &UpstreamRuntime{cfg: u, client: client, bootstrap: bootstrap}
	}
	for _, g := range c.Groups {
		for _, uid := range g.Upstreams {
			if s.upstreams[uid] == nil {
				return nil, fmt.Errorf("group %s references DoH server %s missing from doh-servers.txt", g.ID, uid)
			}
		}
		s.groups[g.ID] = g
	}
	return s, nil
}
func defaultBootstrapResolvers() []string { return []string{"1.1.1.1", "8.8.8.8"} }

func newVPSResolveUpstream(timeout time.Duration) (*UpstreamRuntime, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	cfg := Upstream{ID: "vps-resolve", Name: "Quad9 Secure", Type: "doh", URL: "https://dns.quad9.net/dns-query"}
	client, bootstrap, err := newDoHClient(cfg, defaultBootstrapResolvers(), timeout)
	if err != nil {
		return nil, err
	}
	return &UpstreamRuntime{cfg: cfg, client: client, bootstrap: bootstrap}, nil
}

func newDoHClient(u Upstream, resolvers []string, timeout time.Duration) (*http.Client, *bootstrapResolver, error) {
	pu, err := url.Parse(u.URL)
	if err != nil || pu.Scheme != "https" || pu.Hostname() == "" {
		return nil, nil, fmt.Errorf("invalid DoH URL for %s", u.ID)
	}
	bootstrap := &bootstrapResolver{
		host: pu.Hostname(), endpoint: u.URL, resolvers: append([]string(nil), resolvers...),
		fallback: append([]string(nil), u.BootstrapIPs...), refreshFor: 6 * time.Hour,
	}
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12, ServerName: pu.Hostname()},
		ForceAttemptHTTP2: true, MaxIdleConns: 16, MaxIdleConnsPerHost: 8,
		IdleConnTimeout: 60 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			port := pu.Port()
			if port == "" {
				port = "443"
			}
			ip, err := bootstrap.bestIP(ctx, false, timeout)
			if err != nil {
				return nil, fmt.Errorf("select DoH IP for %s: %w", pu.Hostname(), err)
			}
			conn, dialErr := (&net.Dialer{Timeout: minDuration(timeout, 5*time.Second), KeepAlive: 30 * time.Second}).
				DialContext(ctx, network, net.JoinHostPort(ip, port))
			if dialErr == nil {
				return conn, nil
			}

			alternateIP, alternateErr := bootstrap.selectAlternateIP(ctx, ip, timeout)
			if alternateErr == nil {
				retryConn, retryErr := (&net.Dialer{Timeout: minDuration(timeout, 5*time.Second), KeepAlive: 30 * time.Second}).
					DialContext(ctx, network, net.JoinHostPort(alternateIP, port))
				if retryErr == nil {
					return retryConn, nil
				}
				return nil, fmt.Errorf("selected IP %s failed (%v); alternate IP %s failed: %w", ip, dialErr, alternateIP, retryErr)
			}
			return nil, fmt.Errorf("selected IP %s failed: %v; alternate IP selection failed: %w", ip, dialErr, alternateErr)
		},
	}
	client := &http.Client{
		Transport: tr, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return client, bootstrap, nil
}

func (b *bootstrapResolver) addresses(ctx context.Context, force bool) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !force && len(b.ips) > 0 && time.Since(b.refreshed) < b.refreshFor {
		return append([]string(nil), b.ips...), nil
	}
	if !force && time.Since(b.lastAttempt) < time.Minute {
		if len(b.ips) > 0 {
			return append([]string(nil), b.ips...), nil
		}
		if len(b.fallback) > 0 {
			return append([]string(nil), b.fallback...), nil
		}
	}
	b.lastAttempt = time.Now()
	ips := make([]string, 0, 8)
	seen := map[string]bool{}
	resolvedBy := ""
	var err error
	for _, server := range b.resolvers {
		lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		resolver := &net.Resolver{
			PreferGo: true, StrictErrors: false,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 1500 * time.Millisecond}).DialContext(ctx, network, net.JoinHostPort(server, "53"))
			},
		}
		found, lookupErr := resolver.LookupNetIP(lookupCtx, "ip", b.host)
		cancel()
		if len(found) > 0 {
			for _, ip := range found {
				v := ip.String()
				if net.ParseIP(v) != nil && !seen[v] {
					seen[v] = true
					ips = append(ips, v)
				}
			}
			if len(ips) > 0 {
				err = nil
				resolvedBy = server
				break
			}
		}
		err = lookupErr
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	if len(b.resolvers) == 0 {
		err = errors.New("no bootstrap DNS resolvers configured")
	}
	if len(ips) > 0 {
		b.ips = ips
		b.resolvedBy = resolvedBy
		b.refreshed = time.Now()
		return append([]string(nil), ips...), nil
	}
	if err == nil {
		err = errors.New("DNS lookup returned no A or AAAA records")
	}
	if len(b.ips) > 0 {
		return append([]string(nil), b.ips...), fmt.Errorf("DNS refresh failed; using cached IPs: %w", err)
	}
	if len(b.fallback) > 0 {
		return append([]string(nil), b.fallback...), fmt.Errorf("DNS lookup failed; using configured bootstrap_ips: %w", err)
	}
	return nil, err
}

func (b *bootstrapResolver) bestIP(ctx context.Context, force bool, timeout time.Duration) (string, error) {
	b.selectMu.Lock()
	defer b.selectMu.Unlock()

	b.mu.Lock()
	if !force && b.selectedIP != "" && time.Now().Before(b.selectedTil) {
		ip := b.selectedIP
		b.mu.Unlock()
		return ip, nil
	}
	previousRefresh := b.refreshed
	b.mu.Unlock()

	ips, resolveErr := b.addresses(ctx, force)
	if len(ips) == 0 {
		if resolveErr == nil {
			resolveErr = errors.New("no bootstrap IPs available")
		}
		return "", resolveErr
	}
	b.mu.Lock()
	usingFallback := len(b.ips) == 0 && len(b.fallback) > 0 && (resolveErr != nil || b.refreshed.IsZero())
	source := "dns"
	if usingFallback {
		source = "configured_fallback"
	} else if !b.refreshed.IsZero() && b.refreshed.Equal(previousRefresh) {
		source = "cache"
	}
	b.mu.Unlock()

	allCandidates := append([]string(nil), ips...)
	ip, latency, probes, probeErr := b.fastestIPDetailed(ctx, ips, timeout)
	for i := range probes {
		probes[i].Source = source
	}

	if probeErr != nil && len(b.fallback) > 0 && !usingFallback {
		fallbackIP, fallbackLatency, fallbackProbes, fallbackErr := b.fastestIPDetailed(ctx, b.fallback, timeout)
		for i := range fallbackProbes {
			fallbackProbes[i].Source = "configured_fallback"
		}
		probes = append(probes, fallbackProbes...)
		for _, fallbackCandidate := range b.fallback {
			allCandidates = appendUniqueString(allCandidates, fallbackCandidate)
		}
		if fallbackErr == nil {
			ip, latency, probeErr, usingFallback = fallbackIP, fallbackLatency, nil, true
			source += "+configured_fallback"
		}
	}

	b.recordProbeSnapshot(allCandidates, source, probes)
	for _, result := range probes {
		level := "INFO"
		if result.Result != "ok" {
			level = "WARN"
		}
		logLine(level, "DoH IP probe hostname=%s ip=%s source=%s result=%s response_ms=%d error=%s",
			b.host, result.IP, result.Source, result.Result, result.ResponseMS, safeLog(result.Error))
	}

	if probeErr != nil {
		if resolveErr != nil {
			return "", fmt.Errorf("no responsive DoH address: %v (DNS resolution: %w)", probeErr, resolveErr)
		}
		return "", fmt.Errorf("no responsive DoH address: %w", probeErr)
	}

	b.mu.Lock()
	b.selectedIP = ip
	refreshUntil := b.refreshed.Add(b.refreshFor)
	if !usingFallback && !b.refreshed.IsZero() && time.Now().Before(refreshUntil) {
		b.selectedTil = refreshUntil
	} else {
		// Retry DNS resolution periodically while temporarily relying on cached/fallback IPs.
		b.selectedTil = time.Now().Add(time.Minute)
	}
	selectedUntil := b.selectedTil
	b.mu.Unlock()

	logLine("INFO", "DoH IP selected hostname=%s ip=%s response_ms=%d candidates=%d fallback=%t selected_until=%s",
		b.host, ip, latency.Milliseconds(), len(allCandidates), usingFallback, selectedUntil.UTC().Format(time.RFC3339))
	return ip, nil
}

func (b *bootstrapResolver) selectAlternateIP(ctx context.Context, currentIP string, timeout time.Duration) (string, error) {
	ips, resolveErr := b.addresses(ctx, false)
	candidates := make([]string, 0, len(ips)+len(b.fallback))
	for _, ip := range ips {
		if ip != currentIP {
			candidates = appendUniqueString(candidates, ip)
		}
	}
	for _, ip := range b.fallback {
		if ip != currentIP {
			candidates = appendUniqueString(candidates, ip)
		}
	}
	if len(candidates) == 0 {
		if resolveErr != nil {
			return "", fmt.Errorf("no alternate bootstrap IP available: %w", resolveErr)
		}
		return "", errors.New("no alternate bootstrap IP available")
	}
	ip, _, probes, probeErr := b.fastestIPDetailed(ctx, candidates, timeout)
	b.recordProbeSnapshot(candidates, "alternate", probes)
	if probeErr != nil {
		return "", probeErr
	}
	b.mu.Lock()
	b.selectedIP = ip
	refreshUntil := b.refreshed.Add(b.refreshFor)
	if !b.refreshed.IsZero() && time.Now().Before(refreshUntil) {
		b.selectedTil = refreshUntil
	} else {
		b.selectedTil = time.Now().Add(time.Minute)
	}
	b.mu.Unlock()
	logLine("WARN", "DoH alternate IP selected hostname=%s previous_ip=%s alternate_ip=%s", b.host, currentIP, ip)
	return ip, nil
}

func appendUniqueString(items []string, value string) []string {
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}

func (b *bootstrapResolver) fastestIP(ctx context.Context, ips []string, timeout time.Duration) (string, time.Duration, error) {
	bestIP, bestLatency, _, err := b.fastestIPDetailed(ctx, ips, timeout)
	return bestIP, bestLatency, err
}

func (b *bootstrapResolver) fastestIPDetailed(ctx context.Context, ips []string, timeout time.Duration) (string, time.Duration, []DoHIPProbeStatus, error) {
	type result struct {
		ip      string
		latency time.Duration
		err     error
	}
	probe := b.probe
	if probe == nil {
		probe = probeDoHIP
	}
	results := make(chan result, len(ips))
	for _, candidate := range ips {
		ip := candidate
		go func() {
			probeTimeout := minDuration(timeout, 5*time.Second)
			probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
			defer cancel()
			latency, err := probe(probeCtx, b.endpoint, ip, probeTimeout)
			results <- result{ip: ip, latency: latency, err: err}
		}()
	}

	var bestIP string
	var bestLatency time.Duration
	var failures []string
	probeResults := make([]DoHIPProbeStatus, 0, len(ips))
	for range ips {
		select {
		case <-ctx.Done():
			return "", 0, probeResults, ctx.Err()
		case res := <-results:
			entry := DoHIPProbeStatus{
				IP: res.ip, ResponseMS: res.latency.Milliseconds(), Result: "ok",
			}
			if res.err != nil {
				entry.Result = "error"
				entry.Error = safeLog(res.err.Error())
				failures = append(failures, res.ip+": "+res.err.Error())
			} else if bestIP == "" || res.latency < bestLatency {
				bestIP, bestLatency = res.ip, res.latency
			}
			probeResults = append(probeResults, entry)
		}
	}
	sort.Slice(probeResults, func(i, j int) bool { return probeResults[i].IP < probeResults[j].IP })
	if bestIP == "" {
		return "", 0, probeResults, fmt.Errorf("all DoH IP probes failed: %s", strings.Join(failures, "; "))
	}
	return bestIP, bestLatency, probeResults, nil
}

func probeDoHIP(ctx context.Context, endpoint, ip string, timeout time.Duration) (time.Duration, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		return 0, errors.New("invalid DoH endpoint URL")
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	start := time.Now()
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12, ServerName: parsed.Hostname()},
		ForceAttemptHTTP2: true, DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: minDuration(timeout, 5*time.Second)}).
				DialContext(ctx, network, net.JoinHostPort(ip, port))
		},
	}
	client := &http.Client{
		Transport: transport, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer transport.CloseIdleConnections()

	probe := &UpstreamRuntime{
		cfg:    Upstream{ID: parsed.Hostname(), URL: endpoint},
		client: client,
	}
	if _, err := sendDoH(ctx, probe, makeDNSQuery("example.com", 1)); err != nil {
		return time.Since(start), err
	}
	return time.Since(start), nil
}

func minDuration(a, b time.Duration) time.Duration {
	if a <= 0 || a > b {
		return b
	}
	return a
}

func (r *Runtime) initHealth(s *Snapshot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.health == nil {
		r.health = map[string]map[string]HealthEntry{}
	}
	if r.active == nil {
		r.active = map[string]string{}
	}

	validGroups := make(map[string]map[string]struct{}, len(s.groups))
	validUpstreams := make(map[string]struct{}, len(s.upstreams))
	for uid := range s.upstreams {
		validUpstreams[uid] = struct{}{}
	}
	for gid, g := range s.groups {
		valid := make(map[string]struct{}, len(g.Upstreams))
		for _, uid := range g.Upstreams {
			valid[uid] = struct{}{}
		}
		validGroups[gid] = valid
		if r.health[gid] == nil {
			r.health[gid] = map[string]HealthEntry{}
		}
		for uid := range r.health[gid] {
			if _, ok := valid[uid]; !ok {
				delete(r.health[gid], uid)
			}
		}
		for _, uid := range g.Upstreams {
			if _, ok := r.health[gid][uid]; !ok {
				r.health[gid][uid] = HealthEntry{State: "unknown", GeminiState: "not_checked"}
			}
		}
		if _, ok := valid[r.active[gid]]; !ok {
			if len(g.Upstreams) > 0 {
				r.active[gid] = g.Upstreams[0]
			} else {
				delete(r.active, gid)
			}
		}
	}
	for gid := range r.health {
		if _, ok := validGroups[gid]; !ok {
			delete(r.health, gid)
		}
	}
	for gid := range r.active {
		if _, ok := validGroups[gid]; !ok {
			delete(r.active, gid)
		}
	}
	for groupID := range r.lastGemini {
		if _, ok := validGroups[groupID]; !ok {
			delete(r.lastGemini, groupID)
		}
	}
	if r.upstreamCooldown != nil {
		for uid := range r.upstreamCooldown {
			if _, ok := validUpstreams[uid]; !ok {
				delete(r.upstreamCooldown, uid)
			}
		}
	}
}
func (r *Runtime) currentSnapshot() *Snapshot { return r.snapshot.Load() }
func (r *Runtime) orderedUpstreams(gid string, s *Snapshot) []string {
	g, ok := s.groups[gid]
	if !ok {
		g = s.groups["google"]
	}
	r.mu.RLock()
	active := r.active[gid]
	r.mu.RUnlock()
	out := make([]string, 0, len(g.Upstreams))
	if active != "" {
		for _, id := range g.Upstreams {
			if id == active {
				out = append(out, id)
				break
			}
		}
	}
	for _, id := range g.Upstreams {
		if id != active {
			out = append(out, id)
		}
	}
	return out
}

const upstreamFailureCooldown = 30 * time.Second

func (r *Runtime) upstreamsToAttempt(order []string, now time.Time) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.upstreamCooldown == nil {
		r.upstreamCooldown = make(map[string]time.Time)
	}
	available := make([]string, 0, len(order))
	earliestID := ""
	var earliest time.Time
	for _, uid := range order {
		until, cooling := r.upstreamCooldown[uid]
		if !cooling || !now.Before(until) {
			delete(r.upstreamCooldown, uid)
			available = append(available, uid)
			continue
		}
		if earliestID == "" || until.Before(earliest) {
			earliestID, earliest = uid, until
		}
	}
	if len(available) > 0 {
		return available
	}
	// If every upstream is cooling down, probe only the one whose cooldown
	// expires first to avoid hammering every known-bad endpoint on each query.
	if earliestID != "" {
		return []string{earliestID}
	}
	return append([]string(nil), order...)
}

func (r *Runtime) markUpstreamFailure(uid string, now time.Time) {
	r.mu.Lock()
	if r.upstreamCooldown == nil {
		r.upstreamCooldown = make(map[string]time.Time)
	}
	r.upstreamCooldown[uid] = now.Add(upstreamFailureCooldown)
	r.mu.Unlock()
}

func (r *Runtime) markUpstreamSuccess(uid string) {
	r.mu.Lock()
	delete(r.upstreamCooldown, uid)
	r.mu.Unlock()
}

func (r *Runtime) queryVPSResolve(ctx context.Context, packet []byte) ([]byte, error) {
	if r.vpsResolve == nil {
		return nil, errors.New("vps-resolve Quad9 upstream is unavailable")
	}
	snapshot := r.currentSnapshot()
	if snapshot == nil {
		return nil, errors.New("DNS runtime snapshot is unavailable")
	}
	timeout := minDuration(
		time.Duration(snapshot.cfg.DoHTimeoutSeconds)*time.Second,
		time.Duration(snapshot.cfg.DNSQueryTimeoutSeconds)*time.Second,
	)
	attemptCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	response, err := sendUpstreamDNS(attemptCtx, r.vpsResolve, packet)
	if err != nil {
		r.failures.Add(1)
		return nil, fmt.Errorf("vps-resolve: %w", err)
	}
	return response, nil
}

func (r *Runtime) enqueueAutoHostsQuery(rawDomain string) (*autoHostsQueryJob, bool) {
	if r.autoHosts == nil || r.autoHostsQueryQueue == nil {
		return nil, false
	}
	domain, err := autohosts.NormalizeDomain(rawDomain)
	if err != nil {
		return nil, false
	}
	r.autoHostsQueueMu.Lock()
	defer r.autoHostsQueueMu.Unlock()
	if existing := r.autoHostsQueued[domain]; existing != nil {
		return existing, true
	}
	job := &autoHostsQueryJob{domain: domain, done: make(chan struct{})}
	select {
	case r.autoHostsQueryQueue <- job:
		r.autoHostsQueued[domain] = job
		return job, true
	default:
		return nil, false
	}
}

func (r *Runtime) runAutoHostsQueryRecorder(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-r.autoHostsQueryQueue:
			if job == nil {
				continue
			}
			if r.autoHosts == nil {
				job.err = errors.New("Auto Hosts manager is unavailable")
			} else {
				job.err = r.autoHosts.RecordQuery(job.domain, time.Now().UTC())
			}
			close(job.done)
			r.autoHostsQueueMu.Lock()
			if r.autoHostsQueued[job.domain] == job {
				delete(r.autoHostsQueued, job.domain)
			}
			r.autoHostsQueueMu.Unlock()
			if job.err != nil {
				logLine("WARN", "AUTO_HOSTS query record failed domain=%s: %v", job.domain, job.err)
			}
		}
	}
}

func (r *Runtime) query(ctx context.Context, packet []byte) ([]byte, string, error) {
	name, _, _, err := parseQuestion(packet)
	if err != nil {
		return nil, "", err
	}
	s := r.currentSnapshot()
	// Every DNS question received by this listener uses the single Google-qualified gateway.
	const gid = "google"
	order := r.upstreamsToAttempt(r.orderedUpstreams(gid, s), time.Now())
	var errs []string
	var lastDNSResponse []byte
	var lastDNSUpstream string
	attemptTimeout := minDuration(
		time.Duration(s.cfg.DoHTimeoutSeconds)*time.Second,
		time.Duration(s.cfg.DNSQueryTimeoutSeconds)*time.Second,
	)
	// Keep fallback attempts independent, but cap one client query to four
	// upstreams so a large configuration cannot multiply worst-case latency.
	if len(order) > 4 {
		order = order[:4]
	}
	for _, uid := range order {
		u := s.upstreams[uid]
		if u == nil {
			continue
		}
		attemptCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
		resp, attemptErr := sendUpstreamDNS(attemptCtx, u, packet)
		cancel()
		if attemptErr != nil {
			r.markUpstreamFailure(uid, time.Now())
			errs = append(errs, uid+": "+attemptErr.Error())
			continue
		}
		// A DNS-level SERVFAIL/REFUSED or TC response proves the endpoint
		// answered the request. It is not evidence that the upstream is down
		// and must never put it into the transport-failure cooldown.
		r.markUpstreamSuccess(uid)
		if dnsRCode(resp) == 2 || dnsRCode(resp) == 5 || dnsTruncated(resp) {
			lastDNSResponse, lastDNSUpstream = resp, uid
			continue
		}
		return resp, uid, nil
	}
	if lastDNSResponse != nil {
		return lastDNSResponse, lastDNSUpstream, nil
	}
	r.failures.Add(1)
	return nil, "", fmt.Errorf("all upstreams failed for %s (%s)", name, strings.Join(errs, "; "))
}
func sendUpstreamDNS(ctx context.Context, u *UpstreamRuntime, packet []byte) ([]byte, error) {
	if u != nil && u.systemDNS != nil {
		return u.systemDNS.query(ctx, packet)
	}
	return sendDoH(ctx, u, packet)
}

func sendDoH(ctx context.Context, u *UpstreamRuntime, packet []byte) ([]byte, error) {
	do := func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.cfg.URL, bytes.NewReader(packet))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		return u.client.Do(req)
	}
	resp, e := do()
	if e != nil && u.bootstrap != nil && ctx.Err() == nil {
		currentIP := u.bootstrap.status().SelectedIP
		if alternateIP, alternateErr := u.bootstrap.selectAlternateIP(ctx, currentIP, 3*time.Second); alternateErr == nil {
			u.client.CloseIdleConnections()
			logLine("WARN", "DoH request retry hostname=%s alternate_ip=%s", u.bootstrap.host, alternateIP)
			resp, e = do()
		} else {
			e = fmt.Errorf("DoH request failed: %v; alternate IP retry unavailable: %w", e, alternateErr)
		}
	}
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	if u.cfg.ID == "vps-resolve" && resp.ProtoMajor != 2 {
		return nil, fmt.Errorf("vps-resolve requires HTTP/2, negotiated %s", resp.Proto)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("DoH HTTP %d", resp.StatusCode)
	}
	if ct := strings.ToLower(resp.Header.Get("Content-Type")); !strings.Contains(ct, "application/dns-message") {
		return nil, fmt.Errorf("unexpected DoH content-type %q", ct)
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, maxDNSMessage+1))
	if e != nil {
		return nil, e
	}
	if e = validateDNSResponse(packet, b, "DoH"); e != nil {
		return nil, e
	}
	return b, nil
}
func (r *Runtime) serveUDP(ctx context.Context, c *net.UDPConn) {
	type udpJob struct {
		addr   *net.UDPAddr
		packet []byte
	}
	jobs := make(chan udpJob, udpQueueCapacity)
	workers := maxUDPWorkers
	if snap := r.currentSnapshot(); snap != nil && snap.cfg.DNSMaxConcurrent < workers {
		workers = snap.cfg.DNSMaxConcurrent
	}
	if workers < 1 {
		workers = 1
	}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case job, ok := <-jobs:
					if !ok {
						return
					}
					r.udpQueueDepth.Add(-1)
					r.activeUDP.Add(1)
					resp := r.handleDNS(job.packet)
					r.activeUDP.Add(-1)
					resp = truncateDNSUDPResponse(resp, 4096)
					_, _ = c.WriteToUDP(resp, job.addr)
				}
			}
		}()
	}
	defer func() {
		close(jobs)
		wg.Wait()
		r.udpQueueDepth.Store(0)
	}()

	buf := make([]byte, maxDNSMessage)
	for {
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := c.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			if ctx.Err() != nil {
				return
			}
			logLine("WARN", "DNS UDP read: %v", err)
			continue
		}
		q := append([]byte(nil), buf[:n]...)
		r.udpQueueDepth.Add(1)
		select {
		case jobs <- udpJob{addr: addr, packet: q}:
		case <-ctx.Done():
			r.udpQueueDepth.Add(-1)
			return
		default:
			r.udpQueueDepth.Add(-1)
			r.udpDropped.Add(1)
			_, _ = c.WriteToUDP(servfailResponse(q), addr)
		}
	}
}
func (r *Runtime) serveTCP(ctx context.Context, ln net.Listener) {
	sem := make(chan struct{}, maxTCPConnections)
	var connections sync.Map
	var wg sync.WaitGroup
	defer func() {
		connections.Range(func(key, _ any) bool {
			if conn, ok := key.(net.Conn); ok {
				_ = conn.Close()
			}
			return true
		})
		wg.Wait()
	}()

	for {
		if tl, ok := ln.(*net.TCPListener); ok {
			_ = tl.SetDeadline(time.Now().Add(time.Second))
		}
		conn, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			if ctx.Err() != nil {
				return
			}
			logLine("WARN", "DNS TCP accept: %v", err)
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			_ = conn.Close()
			return
		default:
			r.tcpRejected.Add(1)
			_ = conn.Close()
			continue
		}
		connections.Store(conn, struct{}{})
		r.activeTCP.Add(1)
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer func() {
				r.activeTCP.Add(-1)
				<-sem
				connections.Delete(c)
			}()
			r.handleTCPConn(ctx, c)
		}(conn)
	}
}
func (r *Runtime) handleTCPConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	for {
		if ctx.Err() != nil {
			return
		}
		_ = c.SetReadDeadline(time.Now().Add(tcpIdleTimeout))
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(l[:]))
		if n < 12 || n > maxDNSMessage {
			return
		}
		q := make([]byte, n)
		if _, err := io.ReadFull(c, q); err != nil {
			return
		}
		resp := r.handleDNS(q)
		if len(resp) > maxDNSMessage {
			return
		}
		_ = c.SetWriteDeadline(time.Now().Add(tcpWriteTimeout))
		binary.BigEndian.PutUint16(l[:], uint16(len(resp)))
		if _, err := c.Write(l[:]); err != nil {
			return
		}
		if _, err := c.Write(resp); err != nil {
			return
		}
	}
}
func (r *Runtime) handleDNS(packet []byte) (response []byte) {
	// DNS requests are isolated: an unexpected panic must fail only this
	// request, never take down the daemon's UDP/TCP serving goroutines.
	defer func() {
		if recovered := recover(); recovered != nil {
			r.failures.Add(1)
			logLine("ERROR", "DNS request panic recovered: %v", recovered)
			response = servfailResponse(packet)
		}
	}()
	select {
	case r.dnsSem <- struct{}{}:
		defer func() { <-r.dnsSem }()
	default:
		return servfailResponse(packet)
	}
	r.queries.Add(1)
	name, qtype, _, e := parseQuestion(packet)
	if e != nil {
		return formerrResponse(packet)
	}
	s := r.currentSnapshot()
	if response, matched := localHostsResponse(packet, normalizeDomain(name), qtype, s.localHosts); matched {
		return response
	}
	if r.geo != nil && r.geo.MatchAny(normalizeDomain(name)) && r.autoHosts != nil {
		autoSnapshot := r.autoHosts.Snapshot()
		if autoSnapshot != nil && autoSnapshot.CanRecordQuery(name) {
			job, queued := r.enqueueAutoHostsQuery(name)
			if queued {
				select {
				case <-job.done:
					if job.err == nil {
						if response, matched := autoHostsEndpointResponse(packet, normalizeDomain(name), qtype, r.autoHosts.Snapshot(), time.Now()); matched {
							return response
						}
					}
				case <-time.After(150 * time.Millisecond):
					// Persistence remains off the DNS handler. A slow or failed
					// write falls through to the dedicated Quad9 resolver.
				}
			}
		}
	}
	cacheKey := cacheKey(packet)
	if s.cfg.Cache.Enabled {
		if v, ok := r.cacheGet(cacheKey, packetID(packet)); ok {
			r.cacheHits.Add(1)
			if cnameChainTargetsAutoHosts(v, normalizeDomain(name), qtype, r.autoHosts) {
				return servfailResponse(packet)
			}
			return v
		}
	}
	resolve := func() ([]byte, error) {
		response, queryErr := r.queryVPSResolve(context.Background(), packet)
		if queryErr == nil && cnameChainTargetsAutoHosts(response, normalizeDomain(name), qtype, r.autoHosts) {
			return nil, errors.New("upstream CNAME targets an Auto Hosts protected domain")
		}
		// An in-flight request from the previous snapshot must not repopulate
		// the cache after a reload has invalidated it.
		if queryErr == nil && s.cfg.Cache.Enabled && r.currentSnapshot() == s {
			r.cachePut(cacheKey, response, s.cfg.Cache)
		}
		return response, queryErr
	}
	var resp []byte
	if s.cfg.Cache.Enabled {
		resp, e = r.cacheDo(cacheKey, packetID(packet), resolve)
	} else {
		resp, e = resolve()
	}
	if e != nil {
		return servfailResponse(packet)
	}
	return resp
}

const localHostsTTL uint32 = 60

// localHostsResponse handles only explicitly configured hosts and the A, AAAA,
// SVCB and HTTPS RR types. A nil/empty map leaves normal DoH processing untouched.
func localHostsResponse(query []byte, host string, qtype uint16, hosts map[string]LocalHost) ([]byte, bool) {
	return localHostsResponseWithTTL(query, host, qtype, hosts, localHostsTTL)
}

func localHostsResponseWithTTL(query []byte, host string, qtype uint16, hosts map[string]LocalHost, ttl uint32) ([]byte, bool) {
	entry, ok := hosts[normalizeDomain(host)]
	_, _, questionEnd, questionErr := parseQuestion(query)
	if !ok || questionErr != nil || questionEnd < 2 || binary.BigEndian.Uint16(query[questionEnd-2:questionEnd]) != 1 ||
		(qtype != 1 && qtype != 28 && qtype != 64 && qtype != 65) {
		return nil, false
	}
	_, _, questionEnd, err := parseQuestion(query)
	if err != nil || questionEnd > len(query) {
		return nil, false
	}
	opt := minimalResponseOPT(query)
	flags := binary.BigEndian.Uint16(query[2:4])
	responseFlags := (flags & 0x7900) | 0x8080 // preserve opcode/RD; set QR and RA; AD is deliberately clear
	response := make([]byte, 12)
	copy(response[:2], query[:2])
	binary.BigEndian.PutUint16(response[2:4], responseFlags)
	binary.BigEndian.PutUint16(response[4:6], 1)
	response = append(response, query[12:questionEnd]...)
	answers := 0
	if qtype == 1 {
		for _, raw := range entry.IPv4 {
			ip := net.ParseIP(strings.TrimSpace(raw)).To4()
			if ip == nil {
				continue
			}
			response = appendLocalHostRRWithTTL(response, qtype, ip, ttl)
			answers++
		}
	} else if qtype == 28 {
		for _, raw := range entry.IPv6 {
			ip := net.ParseIP(strings.TrimSpace(raw)).To16()
			if ip == nil || net.ParseIP(strings.TrimSpace(raw)).To4() != nil {
				continue
			}
			response = appendLocalHostRRWithTTL(response, qtype, ip, ttl)
			answers++
		}
	}
	binary.BigEndian.PutUint16(response[6:8], uint16(answers))
	if answers == 0 {
		response = appendLocalHostSOAWithTTL(response, ttl)
		binary.BigEndian.PutUint16(response[8:10], 1)
	}
	if len(opt) > 0 {
		response = append(response, opt...)
		binary.BigEndian.PutUint16(response[10:12], 1)
	}
	return response, true
}

// cnameChainTargetsAutoHosts fails closed when an upstream CNAME chain points
// at a name managed by Auto Hosts. Returning SERVFAIL avoids leaking the real
// target address from either Answer or Additional while preserving exact-name
// Auto Hosts handling for direct queries.
func cnameChainTargetsAutoHosts(response []byte, originalName string, qtype uint16, manager *autohosts.Manager) bool {
	if manager == nil || (qtype != 1 && qtype != 28 && qtype != 64 && qtype != 65) || len(response) < 12 {
		return false
	}
	snapshot := manager.Snapshot()
	if snapshot == nil || !snapshot.Enabled || snapshot.EmergencyOff {
		return false
	}
	off := 12
	qd := int(binary.BigEndian.Uint16(response[4:6]))
	for i := 0; i < qd; i++ {
		n, err := skipName(response, off)
		if err != nil || n+4 > len(response) {
			return false
		}
		off = n + 4
	}
	answerCount := int(binary.BigEndian.Uint16(response[6:8]))
	aliases := make(map[string]string)
	for i := 0; i < answerCount; i++ {
		owner, next, err := decodeName(response, off)
		if err != nil || next+10 > len(response) {
			return false
		}
		typ := binary.BigEndian.Uint16(response[next : next+2])
		rdlen := int(binary.BigEndian.Uint16(response[next+8 : next+10]))
		rdata := next + 10
		end := rdata + rdlen
		if end > len(response) {
			return false
		}
		if typ == 5 {
			target, _, nameErr := decodeName(response, rdata)
			if nameErr == nil {
				aliases[normalizeDomain(owner)] = normalizeDomain(target)
			}
		}
		off = end
	}
	current := normalizeDomain(originalName)
	seen := make(map[string]struct{}, 16)
	for i := 0; i < 16; i++ {
		target, ok := aliases[current]
		if !ok {
			return false
		}
		if _, duplicate := seen[target]; duplicate {
			return false
		}
		seen[target] = struct{}{}
		if _, _, matched := snapshot.Lookup(target, qtype, time.Now()); matched {
			return true
		}
		current = target
	}
	return false
}

func autoHostsEndpointResponse(query []byte, host string, qtype uint16, snapshot *autohosts.Snapshot, now time.Time) ([]byte, bool) {
	ips, ttlDuration, matched := snapshot.EndpointForQuery(qtype, now)
	if !matched {
		return nil, false
	}
	entry := LocalHost{}
	if qtype == 1 {
		entry.IPv4 = ips
	} else if qtype == 28 {
		entry.IPv6 = ips
	}
	ttl := uint32(ttlDuration / time.Second)
	if ttl == 0 {
		ttl = 1
	}
	return localHostsResponseWithTTL(query, host, qtype, map[string]LocalHost{normalizeDomain(host): entry}, ttl)
}

func autoHostsResponse(query []byte, host string, qtype uint16, manager *autohosts.Manager) ([]byte, bool) {
	if manager == nil {
		return nil, false
	}
	snapshot := manager.Snapshot()
	if snapshot == nil {
		return nil, false
	}
	ips, ttlDuration, matched := snapshot.Lookup(host, qtype, time.Now())
	if !matched {
		return nil, false
	}
	entry := LocalHost{}
	if qtype == 1 {
		entry.IPv4 = ips
	} else if qtype == 28 {
		entry.IPv6 = ips
	}
	ttl := uint32(ttlDuration / time.Second)
	if ttl == 0 {
		ttl = 1
	}
	return localHostsResponseWithTTL(query, host, qtype, map[string]LocalHost{normalizeDomain(host): entry}, ttl)
}

func appendLocalHostRR(packet []byte, qtype uint16, ip []byte) []byte {
	return appendLocalHostRRWithTTL(packet, qtype, ip, localHostsTTL)
}

func appendLocalHostRRWithTTL(packet []byte, qtype uint16, ip []byte, ttlValue uint32) []byte {
	packet = append(packet, 0xc0, 0x0c)
	packet = append(packet, byte(qtype>>8), byte(qtype), 0, 1)
	var ttl [4]byte
	binary.BigEndian.PutUint32(ttl[:], ttlValue)
	packet = append(packet, ttl[:]...)
	packet = append(packet, byte(len(ip)>>8), byte(len(ip)))
	return append(packet, ip...)
}

func appendLocalHostSOA(packet []byte) []byte {
	return appendLocalHostSOAWithTTL(packet, localHostsTTL)
}

func appendLocalHostSOAWithTTL(packet []byte, ttlValue uint32) []byte {
	packet = append(packet, 0xc0, 0x0c)
	packet = append(packet, 0, 6, 0, 1)
	var ttl [4]byte
	binary.BigEndian.PutUint32(ttl[:], ttlValue)
	packet = append(packet, ttl[:]...)
	soa := make([]byte, 0, 64)
	soa = appendDNSName(soa, "ns.local-hosts.invalid")
	soa = appendDNSName(soa, "hostmaster.local-hosts.invalid")
	for _, value := range []uint32{1, ttlValue, ttlValue, ttlValue, ttlValue} {
		var raw [4]byte
		binary.BigEndian.PutUint32(raw[:], value)
		soa = append(soa, raw[:]...)
	}
	packet = append(packet, byte(len(soa)>>8), byte(len(soa)))
	return append(packet, soa...)
}

func appendDNSName(packet []byte, name string) []byte {
	for _, label := range strings.Split(name, ".") {
		packet = append(packet, byte(len(label)))
		packet = append(packet, label...)
	}
	return append(packet, 0)
}

// extractEDNSOPT returns the first OPT RR from the additional section, if any.
func extractEDNSOPT(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	off := 12
	qd := int(binary.BigEndian.Uint16(query[4:6]))
	counts := []int{
		int(binary.BigEndian.Uint16(query[6:8])),
		int(binary.BigEndian.Uint16(query[8:10])),
		int(binary.BigEndian.Uint16(query[10:12])),
	}
	for i := 0; i < qd; i++ {
		n, err := skipName(query, off)
		if err != nil || n+4 > len(query) {
			return nil
		}
		off = n + 4
	}
	for section, count := range counts {
		for i := 0; i < count; i++ {
			start := off
			n, err := skipName(query, off)
			if err != nil || n+10 > len(query) {
				return nil
			}
			typ := binary.BigEndian.Uint16(query[n : n+2])
			rdlen := int(binary.BigEndian.Uint16(query[n+8 : n+10]))
			off = n + 10 + rdlen
			if off > len(query) {
				return nil
			}
			if section == 2 && typ == 41 {
				return append([]byte(nil), query[start:off]...)
			}
		}
	}
	return nil
}

func (r *Runtime) monitorLoop(ctx context.Context) {
	for {
		r.runChecks(ctx)
		s := r.currentSnapshot()
		t := time.NewTimer(time.Duration(s.cfg.Health.IntervalSeconds) * time.Second)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-r.healthCheckTrigger:
			if !t.Stop() {
				select {
				case <-t.C:
				default:
				}
			}
		case <-t.C:
		}
	}
}
func (r *Runtime) runChecks(ctx context.Context) {
	s := r.currentSnapshot()
	sem := make(chan struct{}, 12)
	var wg sync.WaitGroup
	for gid, g := range s.groups {
		r.mu.RLock()
		geminiProbeUID := r.active[gid]
		r.mu.RUnlock()
		if geminiProbeUID == "" && len(g.Upstreams) > 0 {
			geminiProbeUID = g.Upstreams[0]
		}
		for _, uid := range g.Upstreams {
			u := s.upstreams[uid]
			if u == nil {
				continue
			}
			wg.Add(1)
			go func(gid string, g Group, uid string, u *UpstreamRuntime) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					return
				}
				start := time.Now()
				ok := true
				lastErr := ""
				httpStatus := 0
				probeResults := make([]ProbeStatus, 0, len(g.Checks))
				for _, ch := range g.Checks {
					pr := ProbeStatus{Domain: ch.Domain, Required: ch.Required}
					qtypes := ch.QTypes
					if len(qtypes) == 0 {
						qtypes = []uint16{1, 28}
					}
					dnsOK := false
					var dnsErr error
					for _, qt := range qtypes {
						cctx, cancel := context.WithTimeout(ctx, time.Duration(s.cfg.Health.TimeoutSeconds)*time.Second)
						resp, _, err := r.queryVia(cctx, u, makeDNSQuery(ch.Domain, qt))
						cancel()
						if err == nil && dnsRCode(resp) == 0 && dnsAnswerCount(resp) > 0 {
							dnsOK = true
							break
						}
						if err != nil {
							dnsErr = err
						} else {
							dnsErr = fmt.Errorf("DNS qtype=%d rcode=%d answers=%d", qt, dnsRCode(resp), dnsAnswerCount(resp))
						}
					}
					pr.DNSOK = dnsOK
					if !dnsOK {
						pr.Error = "DNS: " + fmt.Sprint(dnsErr)
						if ch.Required {
							ok = false
							lastErr = ch.Domain + ": " + pr.Error
						}
						probeResults = append(probeResults, pr)
						continue
					}
					if ch.HTTPURL != "" {
						pr.HTTPChecked = true
						probeCtx, cancel := context.WithTimeout(ctx, time.Duration(s.cfg.Health.TimeoutSeconds)*time.Second)
						hs, he := r.httpProbe(probeCtx, u, ch)
						cancel()
						httpStatus = hs
						pr.HTTPStatus = hs
						pr.HTTPOK = he == nil
						if he != nil {
							pr.Error = "HTTP: " + he.Error()
							if ch.Required {
								ok = false
								lastErr = ch.Domain + ": " + pr.Error
							}
						}
					}
					probeResults = append(probeResults, pr)
				}
				gemState := "disabled"
				if s.cfg.GeminiAPI.Enabled && s.cfg.GeminiAPI.GroupID == gid {
					if uid != geminiProbeUID {
						gemState = "not_selected"
					} else if r.geminiDue(gid, s.cfg.GeminiAPI.IntervalSeconds) {
						apiCtx, cancel := context.WithTimeout(ctx, time.Duration(s.cfg.DoHTimeoutSeconds+5)*time.Second)
						_, ge := r.geminiProbe(apiCtx, u, s.cfg.GeminiAPI)
						cancel()
						if ge != nil {
							gemState = "failed"
							logLine("WARN", "Gemini API group probe failed group=%s upstream=%s error=%s", gid, uid, safeLog(ge.Error()))
							if s.cfg.GeminiAPI.RequiredForGroup && !geminiFailureIsShared(ge) {
								ok = false
								lastErr = "Gemini API transport: " + safeLog(ge.Error())
							}
						} else {
							gemState = "ok"
						}
					} else {
						gemState = "not_due"
					}
				}
				r.updateHealth(gid, uid, ok, time.Since(start), lastErr, httpStatus, gemState, probeResults, s.cfg.Health)
			}(gid, g, uid, u)
		}
	}
	wg.Wait()
	r.publishHealthState()
}

func (r *Runtime) queryVia(ctx context.Context, u *UpstreamRuntime, q []byte) ([]byte, string, error) {
	resp, e := sendUpstreamDNS(ctx, u, q)
	return resp, u.cfg.ID, e
}

func parseSystemDNSServers(contents string) []string {
	servers := make([]string, 0, 2)
	seen := make(map[string]bool)
	for _, raw := range strings.Split(contents, "\n") {
		fields := strings.Fields(raw)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		value := strings.TrimSpace(fields[1])
		host, zone, hasZone := strings.Cut(value, "%")
		ip := net.ParseIP(host)
		if ip == nil {
			continue
		}
		normalized := ip.String()
		if hasZone && zone != "" {
			normalized += "%" + zone
		}
		if !seen[normalized] {
			seen[normalized] = true
			servers = append(servers, normalized)
		}
	}
	return servers
}

func readSystemDNSServers(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read system resolver config %s: %w", path, err)
	}
	servers := parseSystemDNSServers(string(data))
	if len(servers) == 0 {
		return nil, fmt.Errorf("no valid nameserver entries in %s", path)
	}
	return servers, nil
}

func (r *systemDNSResolver) query(ctx context.Context, packet []byte) ([]byte, error) {
	path := r.resolvConfPath
	if path == "" {
		path = systemResolvConfPath
	}
	servers, err := readSystemDNSServers(path)
	if err != nil {
		return nil, err
	}
	var failures []string
	for _, server := range servers {
		perServer := systemDNSPerServerTimeout
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				break
			}
			if perServer > remaining {
				perServer = remaining
			}
		}
		serverCtx, cancel := context.WithTimeout(ctx, perServer)
		response, queryErr := exchangeSystemDNS(serverCtx, net.JoinHostPort(server, "53"), packet)
		cancel()
		if queryErr == nil {
			rcode := dnsRCode(response)
			if rcode != 2 && rcode != 5 {
				return response, nil
			}
			queryErr = fmt.Errorf("system resolver %s returned DNS RCODE %d", server, rcode)
		}
		failures = append(failures, server+": "+queryErr.Error())
		if ctx.Err() != nil {
			break
		}
	}
	if len(failures) == 0 && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(failures) == 0 {
		return nil, errors.New("system DNS has no responsive nameserver")
	}
	return nil, fmt.Errorf("all system DNS resolvers failed: %s", strings.Join(failures, "; "))
}

func exchangeSystemDNS(ctx context.Context, address string, packet []byte) ([]byte, error) {
	if len(packet) < 12 || len(packet) > maxDNSMessage {
		return nil, errors.New("invalid DNS query size for system resolver")
	}
	response, err := exchangeSystemDNSNetwork(ctx, address, "udp", packet)
	if err != nil {
		return nil, err
	}
	if err := validateSystemDNSResponse(packet, response); err != nil {
		return nil, err
	}
	if dnsTruncated(response) {
		response, err = exchangeSystemDNSNetwork(ctx, address, "tcp", packet)
		if err != nil {
			return nil, fmt.Errorf("retry truncated system DNS response over TCP: %w", err)
		}
		if err := validateSystemDNSResponse(packet, response); err != nil {
			return nil, err
		}
		if dnsTruncated(response) {
			return nil, errors.New("system DNS response remains truncated over TCP")
		}
	}
	return response, nil
}

func exchangeSystemDNSNetwork(ctx context.Context, address, network string, packet []byte) ([]byte, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(systemDNSPerServerTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if network == "udp" {
		if _, err := conn.Write(packet); err != nil {
			return nil, err
		}
		buf := make([]byte, maxDNSMessage+1)
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if n > maxDNSMessage {
			return nil, errors.New("system DNS UDP response exceeds maximum DNS message size")
		}
		return append([]byte(nil), buf[:n]...), nil
	}
	if network != "tcp" {
		return nil, fmt.Errorf("unsupported system DNS network %q", network)
	}
	frame := make([]byte, len(packet)+2)
	binary.BigEndian.PutUint16(frame[:2], uint16(len(packet)))
	copy(frame[2:], packet)
	for len(frame) > 0 {
		n, writeErr := conn.Write(frame)
		if writeErr != nil {
			return nil, writeErr
		}
		if n == 0 {
			return nil, io.ErrShortWrite
		}
		frame = frame[n:]
	}
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	responseLen := int(binary.BigEndian.Uint16(header[:]))
	if responseLen < 12 || responseLen > maxDNSMessage {
		return nil, fmt.Errorf("invalid system DNS TCP response size %d", responseLen)
	}
	response := make([]byte, responseLen)
	if _, err := io.ReadFull(conn, response); err != nil {
		return nil, err
	}
	return response, nil
}

func validateDNSResponse(query, response []byte, source string) error {
	if len(query) < 12 {
		return errors.New("original DNS query is too short")
	}
	if len(response) < 12 || len(response) > maxDNSMessage {
		return fmt.Errorf("invalid %s DNS response size", source)
	}
	if binary.BigEndian.Uint16(response[:2]) != packetID(query) {
		return fmt.Errorf("%s DNS response transaction ID does not match query", source)
	}
	queryFlags := binary.BigEndian.Uint16(query[2:4])
	responseFlags := binary.BigEndian.Uint16(response[2:4])
	if responseFlags&0x8000 == 0 {
		return fmt.Errorf("%s DNS returned a packet without QR response flag", source)
	}
	if queryFlags&0x7800 != responseFlags&0x7800 {
		return fmt.Errorf("%s DNS response opcode does not match query", source)
	}
	queryName, queryType, queryEnd, err := parseQuestion(query)
	if err != nil {
		return fmt.Errorf("invalid original DNS query: %w", err)
	}
	responseName, responseType, responseEnd, err := parseQuestion(response)
	if err != nil {
		return fmt.Errorf("invalid %s DNS response question: %w", source, err)
	}
	queryClass := binary.BigEndian.Uint16(query[queryEnd-2 : queryEnd])
	responseClass := binary.BigEndian.Uint16(response[responseEnd-2 : responseEnd])
	if !strings.EqualFold(normalizeDomain(queryName), normalizeDomain(responseName)) ||
		queryType != responseType || queryClass != responseClass {
		return fmt.Errorf("%s DNS response question does not match query", source)
	}
	return nil
}

func validateSystemDNSResponse(query, response []byte) error {
	return validateDNSResponse(query, response, "system")
}

func readHTTPProbeBody(body io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, maxHTTPBody+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxHTTPBody {
		return nil, fmt.Errorf("HTTP probe response exceeds %d bytes", maxHTTPBody)
	}
	return data, nil
}

func geminiRedirectAllowed(resp *http.Response) bool {
	if resp == nil || resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return false
	}
	target, err := resp.Location()
	if err != nil || target.Scheme != "https" || target.User != nil {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(target.Hostname(), "."))
	switch host {
	case "gemini.google.com", "accounts.google.com", "consent.google.com", "google.com", "www.google.com":
	default:
		return false
	}
	path := strings.ToLower(target.EscapedPath())
	return !strings.Contains(path, "sorry") && !strings.Contains(path, "unsupported")
}

func geminiRegionBlocked(body []byte) bool {
	text := strings.ToLower(string(body))
	indicators := []string{
		"not available in your country",
		"not available in your region",
		"not available in your location",
		"not supported in your country",
		"not supported in your region",
		"not supported in your location",
		"isn't available in your country",
		"is not available where you are",
		"error code 1060",
	}
	for _, indicator := range indicators {
		if strings.Contains(text, indicator) {
			return true
		}
	}
	return false
}

func (r *Runtime) httpProbe(ctx context.Context, u *UpstreamRuntime, ch Check) (int, error) {
	pu, e := url.Parse(ch.HTTPURL)
	if e != nil {
		return 0, e
	}
	ips, e := r.resolveA(ctx, u, pu.Hostname())
	if e != nil {
		return 0, e
	}
	if len(ips) == 0 {
		return 0, errors.New("no A records")
	}
	client := newPinnedHTTPClient(ips[0], pu.Hostname(), time.Duration(r.currentSnapshot().cfg.DoHTimeoutSeconds)*time.Second)
	defer client.CloseIdleConnections()
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, ch.HTTPURL, nil)
	if e != nil {
		return 0, e
	}
	req.Header.Set("User-Agent", "LucX-DoH-HealthMonitor/"+pluginVersion)
	resp, e := client.Do(req)
	if e != nil {
		return 0, e
	}
	defer resp.Body.Close()
	body, readErr := readHTTPProbeBody(resp.Body)
	if readErr != nil {
		return resp.StatusCode, fmt.Errorf("read HTTP probe response: %w", readErr)
	}
	isGemini := strings.EqualFold(ch.Domain, "gemini.google.com")
	if isGemini && geminiRegionBlocked(body) {
		return resp.StatusCode, errors.New("Gemini regional restriction detected in response body")
	}
	ok := len(ch.ExpectedStatus) == 0 && resp.StatusCode >= 200 && resp.StatusCode < 400
	for _, s := range ch.ExpectedStatus {
		if s == resp.StatusCode {
			ok = true
		}
	}
	if isGemini {
		// A Google-owned HTTPS redirect can be a normal sign-in or consent flow.
		// Do not follow it with this IP-pinned client; validate and report its target.
		ok = (resp.StatusCode >= 200 && resp.StatusCode < 300) || geminiRedirectAllowed(resp)
		if !ok && resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := ""
			if target, err := resp.Location(); err == nil {
				location = target.String()
			}
			return resp.StatusCode, fmt.Errorf("unexpected Gemini redirect to %q", location)
		}
	}
	if !ok {
		return resp.StatusCode, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}
	if ch.VerifyOIDC {
		if err := verifyOIDCIssuer(body, ch.HTTPURL); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

func verifyOIDCIssuer(body []byte, discoveryURL string) error {
	const suffix = "/.well-known/openid-configuration"
	u, err := url.Parse(discoveryURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !strings.HasSuffix(u.Path, suffix) {
		return errors.New("OIDC discovery URL must be HTTPS and end with /.well-known/openid-configuration")
	}
	expectedIssuer := strings.TrimSuffix(discoveryURL, suffix)
	var doc struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("decode OIDC discovery document: %w", err)
	}
	if doc.Issuer == "" || doc.Issuer != expectedIssuer {
		return fmt.Errorf("OIDC issuer mismatch: got %q, want %q", doc.Issuer, expectedIssuer)
	}
	return nil
}

func newPinnedHTTPClient(ip, host string, timeout time.Duration) *http.Client {
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}, ForceAttemptHTTP2: true, MaxIdleConns: 1, MaxIdleConnsPerHost: 1, IdleConnTimeout: 10 * time.Second, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		_, port, e := net.SplitHostPort(address)
		if e != nil {
			port = "443"
		}
		return (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, net.JoinHostPort(ip, port))
	}}
	return &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func (r *Runtime) resolveA(ctx context.Context, u *UpstreamRuntime, domain string) ([]string, error) {
	resp, _, e := r.queryVia(ctx, u, makeDNSQuery(domain, 1))
	if e != nil {
		return nil, e
	}
	return parseARecords(resp)
}
func (r *Runtime) geminiDue(uid string, interval int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := uid
	if last := r.lastGemini[k]; time.Since(last) < time.Duration(interval)*time.Second {
		return false
	}
	r.lastGemini[k] = time.Now()
	return true
}

func readGeminiAPIKey(dataDir, relativePath string) ([]byte, error) {
	if filepath.IsAbs(relativePath) {
		return nil, errors.New("key file path must be relative to plugin data directory")
	}
	clean := filepath.Clean(relativePath)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return nil, errors.New("key file path escapes plugin data directory")
	}
	root, err := filepath.EvalSymlinks(dataDir)
	if err != nil {
		return nil, fmt.Errorf("resolve plugin data directory: %w", err)
	}
	target := filepath.Join(root, clean)
	parent, err := filepath.EvalSymlinks(filepath.Dir(target))
	if err != nil {
		return nil, fmt.Errorf("resolve key file directory: %w", err)
	}
	relParent, err := filepath.Rel(root, parent)
	if err != nil || relParent == ".." || strings.HasPrefix(relParent, ".."+string(os.PathSeparator)) {
		return nil, errors.New("key file path escapes plugin data directory")
	}
	target = filepath.Join(parent, filepath.Base(target))
	fd, err := syscall.Open(target, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), target)
	if f == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("open key file failed")
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("key file must be a regular file")
	}
	if fi.Mode().Perm()&0077 != 0 {
		return nil, errors.New("key file permissions must not grant group/other access (use 0600 or 0400)")
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != uint32(os.Getuid()) && st.Uid != 0 {
		return nil, errors.New("key file must be owned by the plugin user or root")
	}
	if fi.Size() > 8<<10 {
		return nil, errors.New("key file exceeds 8 KiB")
	}
	b, err := io.ReadAll(io.LimitReader(f, (8<<10)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 8<<10 {
		return nil, errors.New("key file exceeds 8 KiB")
	}
	return b, nil
}

func (r *Runtime) geminiProbe(ctx context.Context, u *UpstreamRuntime, c GeminiAPIConfig) (string, error) {
	b, e := readGeminiAPIKey(r.dataDir, c.KeyFile)
	if e != nil {
		return "", fmt.Errorf("read Gemini API key file: %w", e)
	}
	key := strings.TrimSpace(string(b))
	if key == "" {
		return "", errors.New("Gemini API key is empty")
	}
	host := "generativelanguage.googleapis.com"
	ips, e := r.resolveA(ctx, u, host)
	if e != nil {
		return "", fmt.Errorf("resolve Gemini API: %w", e)
	}
	if len(ips) == 0 {
		return "", errors.New("resolve Gemini API: DNS returned no A records")
	}
	endpoint := "https://" + host + "/v1beta/models/" + url.PathEscape(c.Model) + ":generateContent"
	payload := map[string]any{"contents": []any{map[string]any{"parts": []any{map[string]string{"text": c.Prompt}}}}, "generationConfig": map[string]any{"maxOutputTokens": c.MaxOutputTokens, "temperature": 0}}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode Gemini API request: %w", err)
	}
	timeout := 10 * time.Second
	if snapshot := r.currentSnapshot(); snapshot != nil {
		timeout = time.Duration(snapshot.cfg.DoHTimeoutSeconds) * time.Second
	}
	var lastErr error
	for index, ip := range ips {
		if index >= 4 {
			break
		}
		client := newPinnedHTTPClient(ip, host, timeout)
		req, requestErr := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if requestErr != nil {
			client.CloseIdleConnections()
			return "", requestErr
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-goog-api-key", key)
		resp, requestErr := client.Do(req)
		if requestErr != nil {
			client.CloseIdleConnections()
			lastErr = requestErr
			continue
		}
		rb, readErr := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBody+1))
		_ = resp.Body.Close()
		client.CloseIdleConnections()
		if readErr != nil {
			lastErr = fmt.Errorf("read Gemini API response: %w", readErr)
			continue
		}
		if len(rb) > maxHTTPBody {
			return "", fmt.Errorf("Gemini API response exceeds %d bytes", maxHTTPBody)
		}
		if resp.StatusCode != http.StatusOK {
			return "", GeminiHTTPError{Status: resp.StatusCode}
		}
		var out struct {
			Candidates []struct {
				FinishReason string `json:"finishReason"`
				Content      struct {
					Parts []struct {
						Text string `json:"text"`
					} `json:"parts"`
				} `json:"content"`
			} `json:"candidates"`
		}
		if err := json.Unmarshal(rb, &out); err != nil || len(out.Candidates) == 0 {
			return "", errors.New("Gemini API returned no valid candidate")
		}
		var textParts []string
		finishReason := ""
		for _, candidate := range out.Candidates {
			if finishReason == "" {
				finishReason = candidate.FinishReason
			}
			for _, part := range candidate.Content.Parts {
				if text := strings.TrimSpace(part.Text); text != "" {
					textParts = append(textParts, text)
				}
			}
		}
		if len(textParts) == 0 {
			// This probe checks API reachability and model acceptance, not
			// whether a model emits visible text within a tiny token budget.
			return fmt.Sprintf("candidate accepted without visible text (finishReason=%s)", finishReason), nil
		}
		return strings.Join(textParts, "\n"), nil
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", errors.New("Gemini API has no usable resolved address")
}
func geminiFailureIsShared(err error) bool {
	var he GeminiHTTPError
	if errors.As(err, &he) {
		// An HTTP response proves the selected upstream reached the shared Gemini
		// API. Authentication, quota, model and service errors are common to all
		// upstreams and must never mark every DNS route unhealthy.
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "read gemini api key file") ||
		strings.Contains(msg, "gemini api key is empty") ||
		strings.Contains(msg, "no text candidate") || strings.Contains(msg, "no valid candidate")
}

func (r *Runtime) updateHealth(gid, uid string, ok bool, lat time.Duration, lastErr string, httpStatus int, gemState string, checks []ProbeStatus, h HealthConfig) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// A health cycle may finish after a hot reload. Do not recreate removed
	// groups/upstreams from a snapshot that is no longer current.
	if s := r.currentSnapshot(); s != nil {
		g, exists := s.groups[gid]
		if !exists {
			return
		}
		found := false
		for _, configuredID := range g.Upstreams {
			if configuredID == uid {
				found = true
				break
			}
		}
		if !found {
			return
		}
	}
	if r.health[gid] == nil {
		r.health[gid] = map[string]HealthEntry{}
	}
	e := r.health[gid][uid]
	e.LastCheck = time.Now().UTC()
	e.CheckDurationMS = lat.Milliseconds()
	e.LastHTTP = httpStatus
	e.Checks = checks
	if gemState != "" {
		e.GeminiState = gemState
	}
	if ok {
		e.SuccessStreak++
		e.FailureStreak = 0
		e.LastError = ""
		if e.SuccessStreak >= h.SuccessThreshold || e.State == "unknown" && h.SuccessThreshold == 1 {
			e.State = "up"
		}
	} else {
		e.FailureStreak++
		e.SuccessStreak = 0
		e.LastError = lastErr
		if e.FailureStreak >= h.FailureThreshold {
			e.State = "down"
		}
	}
	r.health[gid][uid] = e
}
func (r *Runtime) publishHealthState() {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.currentSnapshot()
	if s == nil {
		return
	}
	for gid, g := range s.groups {
		chosen := ""
		for _, uid := range g.Upstreams {
			if r.health[gid][uid].State == "up" {
				chosen = uid
				break
			}
		}
		if chosen == "" {
			for _, uid := range g.Upstreams {
				if r.health[gid][uid].State != "down" {
					chosen = uid
					break
				}
			}
		}
		old := r.active[gid]
		if chosen == "" {
			if old != "" {
				delete(r.active, gid)
				logLine("WARN", "DNS upstream selection cleared group=%s old=%s reason=no_usable_upstream", gid, old)
			}
			continue
		}
		if old != chosen {
			r.active[gid] = chosen
			logLine("INFO", "DNS upstream selection changed group=%s old=%s new=%s", gid, old, chosen)
		}
	}
}
func configSourceReloadInterval(snapshot *Snapshot) time.Duration {
	if snapshot == nil || snapshot.cfg.ReloadSecs < 1 || snapshot.cfg.ReloadSecs > 300 {
		return configSourcePollInterval
	}
	return time.Duration(snapshot.cfg.ReloadSecs) * time.Second
}

func (r *Runtime) reloadLoop(ctx context.Context) {
	ticker := time.NewTicker(configSourceReloadInterval(r.currentSnapshot()))
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		r.reloadOnce()
		if snapshot := r.currentSnapshot(); snapshot != nil {
			ticker.Reset(configSourceReloadInterval(snapshot))
		}
	}
}

func (r *Runtime) reloadOnce() {
	old := r.currentSnapshot()
	if old == nil {
		return
	}
	cfi, err := os.Stat(r.configPath)
	if err != nil {
		r.rejectConfigReload("config-stat:"+err.Error(), "CONFIG reload rejected: cannot stat config.json: %v", err)
		return
	}
	configData, err := os.ReadFile(r.configPath)
	if err != nil {
		r.rejectConfigReload("config-read:"+err.Error(), "CONFIG reload rejected: cannot read config.json: %v", err)
		return
	}
	observedConfigHash := sha256.Sum256(configData)
	sources, sourceErr := readConfigSources(r.dohPath, r.checksPath)
	if sourceErr != nil {
		rejectedHash := sources.Checksums.Combined
		if rejectedHash == "" {
			rejectedHash = "source-read-error:" + sourceErr.Error()
		}
		r.rejectConfigReload(rejectedHash, "CONFIG source reload rejected: %v", sourceErr)
		return
	}
	sourcesChanged := sources.Checksums != r.sourceHashes
	configChanged := observedConfigHash != old.configHash
	if !sourcesChanged && !configChanged {
		if r.lastRejectedSourceHash != "" {
			r.lastRejectedSourceHash = ""
			r.setError("")
		}
		return
	}

	cfg, configErr := loadConfigNoCreate(r.configPath)
	if configErr != nil {
		if !sourcesChanged {
			r.rejectConfigReload("config-error:"+fmt.Sprintf("%x", observedConfigHash)+":"+configErr.Error(), "CONFIG reload rejected: %v", configErr)
			return
		}
		// A broken config edit must not prevent independently valid source
		// updates. Keep the last accepted non-source settings and regenerate
		// config.json from that known-good base plus the validated source files.
		cfg = old.cfg
		logLine("WARN", "CONFIG file is invalid; applying validated source changes using the last valid config: %v", configErr)
	}
	if cfg.DNSListenUDP != old.cfg.DNSListenUDP || cfg.DNSListenTCP != old.cfg.DNSListenTCP || cfg.HTTPListen != old.cfg.HTTPListen || cfg.DNSMaxConcurrent != old.cfg.DNSMaxConcurrent {
		r.rejectConfigReload("listener-change:"+fmt.Sprintf("%x", observedConfigHash), "CONFIG listener/dns_max_concurrent change requires plugin restart")
		return
	}
	cfg, err = applyConfigSources(cfg, sources)
	if err != nil {
		r.rejectConfigReload(sources.Checksums.Combined+":generated:"+err.Error(), "CONFIG generation rejected: %v", err)
		return
	}
	ns, err := buildSnapshot(cfg, sources.DoHURLs)
	if err != nil {
		r.rejectConfigReload(sources.Checksums.Combined+":snapshot:"+err.Error(), "CONFIG snapshot rejected: %v", err)
		return
	}
	writeErr := writeConfigAtomic(r.configPath, cfg)
	if writeErr == nil {
		if data, readErr := os.ReadFile(r.configPath); readErr == nil {
			ns.configHash = sha256.Sum256(data)
		}
		if fi, statErr := os.Stat(r.configPath); statErr == nil {
			ns.configMod = fi.ModTime()
		}
	} else {
		// Runtime application is independent from persistence of the generated
		// convenience config. Remember the observed file hash to avoid retrying
		// the same bad write on every poll.
		ns.configHash = observedConfigHash
		ns.configMod = cfi.ModTime()
		logLine("ERROR", "CONFIG generated file write failed; valid snapshot is still being applied: %v", writeErr)
	}
	r.snapshot.Store(ns)
	r.initHealth(ns)
	r.cacheMu.Lock()
	r.cache = map[string]cacheItem{}
	r.cacheOrder = nil
	r.cacheOrderHead = 0
	r.cacheBytes = 0
	r.cacheMu.Unlock()
	r.sourceHashes = sources.Checksums
	r.lastRejectedSourceHash = ""
	r.mu.Lock()
	r.lastReload = time.Now().UTC()
	r.mu.Unlock()
	if writeErr != nil {
		r.setError(fmt.Sprintf("CONFIG generated file write failed: %v", writeErr))
	} else {
		r.setError("")
	}
	select {
	case r.healthCheckTrigger <- struct{}{}:
	default:
	}
	logLine("INFO", "CONFIG reloaded upstreams=%d groups=%d checks=%d sources_sha256=%s", len(cfg.Upstreams), len(cfg.Groups), len(sources.Checks), sources.Checksums.Combined)
	r.triggerAutoHostsConfigReload()
}

func (r *Runtime) triggerAutoHostsConfigReload() {
	if r.autoHosts == nil || r.autoController == nil {
		return
	}
	state := r.autoHosts.State()
	if state.Config.Enabled && !state.Config.EmergencyOff {
		r.autoController.Trigger()
	}
}

func (r *Runtime) rejectConfigReload(key, format string, args ...any) {
	r.setError(fmt.Sprintf(format, args...))
	if key != r.lastRejectedSourceHash {
		logLine("ERROR", format, args...)
		r.lastRejectedSourceHash = key
	}
}

func loadConfigNoCreate(path string) (Config, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return Config{}, e
	}
	var c Config
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return Config{}, e
	}
	c, e = normalizeConfigGroups(c)
	if e != nil {
		return Config{}, e
	}
	c = normalizeCacheConfig(c)
	if e = validateConfig(c); e != nil {
		return Config{}, e
	}
	return c, nil
}
func (r *Runtime) setError(s string) { r.statusMu.Lock(); r.lastError = s; r.statusMu.Unlock() }
func (r *Runtime) handleStatus(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	s := r.currentSnapshot()
	cacheEntries, cacheBytes := r.cacheStats()
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	out := Status{
		ID: envOr("LUCX_PLUGIN_ID", pluginID), Version: envOr("LUCX_PLUGIN_VERSION", pluginVersion),
		StartedAt: startedAt, UpdatedAt: time.Now().UTC(), DNSUDP: s.cfg.DNSListenUDP,
		DNSTCP: s.cfg.DNSListenTCP, HTTP: s.cfg.HTTPListen, Config: r.configPath,
		Cache:  CacheStatus{Enabled: s.cfg.Cache.Enabled, Entries: cacheEntries, MaxEntries: s.cfg.Cache.MaxEntries, Bytes: cacheBytes, MaxBytes: s.cfg.Cache.MaxBytes},
		Groups: map[string]GroupStatus{}, DoHBootstrap: map[string]DoHBootstrapStatus{},
		Queries: r.queries.Load(), CacheHits: r.cacheHits.Load(), Failures: r.failures.Load(),
		ActiveUDP: r.activeUDP.Load(), UDPQueueDepth: r.udpQueueDepth.Load(), UDPDropped: r.udpDropped.Load(),
		ActiveTCP: r.activeTCP.Load(), TCPRejected: r.tcpRejected.Load(), Goroutines: runtime.NumGoroutine(),
		HeapAllocBytes: mem.HeapAlloc, HeapInuseBytes: mem.HeapInuse, HeapSysBytes: mem.HeapSys,
		GeminiAPI: "disabled",
	}
	var cpu syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &cpu); err == nil {
		out.CPUUserNS = timevalNanoseconds(cpu.Utime)
		out.CPUSystemNS = timevalNanoseconds(cpu.Stime)
	}
	r.mu.RLock()
	for gid, g := range s.groups {
		gs := GroupStatus{ActiveUpstream: r.active[gid], Upstreams: map[string]HealthEntry{}}
		for _, uid := range g.Upstreams {
			gs.Upstreams[uid] = r.health[gid][uid]
		}
		out.Groups[gid] = gs
	}
	r.mu.RUnlock()
	for uid, upstream := range s.upstreams {
		if upstream.bootstrap != nil {
			out.DoHBootstrap[uid] = upstream.bootstrap.status()
		}
	}
	if servers, err := readSystemDNSServers(systemResolvConfPath); err != nil {
		out.SystemDNSError = err.Error()
	} else {
		out.SystemDNSServers = servers
	}
	if s.cfg.GeminiAPI.Enabled {
		out.GeminiAPI = "enabled"
	}
	r.mu.RLock()
	out.LastReload = r.lastReload
	r.mu.RUnlock()
	r.statusMu.RLock()
	out.LastError = r.lastError
	r.statusMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

var startedAt = time.Now().UTC()

func timevalNanoseconds(tv syscall.Timeval) uint64 {
	if tv.Sec < 0 || tv.Usec < 0 {
		return 0
	}
	return uint64(tv.Sec)*uint64(time.Second) + uint64(tv.Usec)*uint64(time.Microsecond)
}

func (r *Runtime) handleAutoHostsStatus(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.autoHosts == nil {
		http.Error(w, "Auto Hosts is unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(r.autoHosts.State())
}

func (r *Runtime) handleAutoHostsConfig(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.autoHosts == nil {
		http.Error(w, "Auto Hosts is unavailable", http.StatusServiceUnavailable)
		return
	}
	req.Body = http.MaxBytesReader(w, req.Body, 16<<10)
	var input struct {
		Enabled           *bool     `json:"enabled"`
		EmergencyOff      *bool     `json:"emergency_off"`
		PinnedServerID    *string   `json:"pinned_server_id"`
		GeositeCategories *[]string `json:"geosite_categories"`
	}
	decoder := json.NewDecoder(req.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		http.Error(w, "invalid Auto Hosts settings", http.StatusBadRequest)
		return
	}
	if input.GeositeCategories != nil && r.geo != nil {
		if err := r.geo.ValidateCategories(*input.GeositeCategories); err != nil {
			http.Error(w, "selected Geosite categories are unavailable or invalid", http.StatusBadRequest)
			return
		}
	} else if input.GeositeCategories != nil {
		http.Error(w, "Geosite index is unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := r.autoHosts.ConfigureWithGeosite(input.Enabled, input.EmergencyOff, input.PinnedServerID, input.GeositeCategories); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if input.GeositeCategories != nil && r.geo != nil {
		if err := r.geo.Reload(r.autoHosts.State().Config.GeositeCategories); err != nil {
			logLine("WARN", "GEOSITE categories saved but matcher reload failed: %v", err)
		}
	}
	if state := r.autoHosts.State(); state.Config.Enabled && !state.Config.EmergencyOff && r.autoController != nil {
		r.autoController.Trigger()
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(r.autoHosts.State())
}

func (r *Runtime) handleGeositeCategories(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	result := struct {
		Available  bool     `json:"available"`
		Categories []string `json:"categories"`
		Error      string   `json:"error,omitempty"`
	}{Categories: []string{}}
	if r.geo == nil {
		result.Error = "Geosite index is unavailable"
	} else {
		categories, err := r.geo.Categories()
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Available = true
			result.Categories = categories
		}
	}
	_ = json.NewEncoder(w).Encode(result)
}

func (r *Runtime) handleAutoHostsDryRun(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.autoController == nil {
		http.Error(w, "Auto Hosts controller is unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(req.Context(), 5*time.Minute)
	defer cancel()
	preview, err := r.autoController.dryRunCycle(ctx, time.Now().UTC())
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(preview)
}

func removeStaleSocket(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to remove non-socket event path %q", path)
	}
	conn, dialErr := net.DialTimeout("unix", path, 200*time.Millisecond)
	if dialErr == nil {
		_ = conn.Close()
		return fmt.Errorf("event socket %q is already active", path)
	}
	if !errors.Is(dialErr, syscall.ECONNREFUSED) && !errors.Is(dialErr, syscall.ENOENT) {
		return fmt.Errorf("cannot verify stale event socket %q: %w", path, dialErr)
	}
	current, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !os.SameFile(fi, current) || current.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("event socket path %q changed during stale-socket check", path)
	}
	return os.Remove(path)
}

func removeSocketIfSame(path string, expected os.FileInfo) error {
	if expected == nil || expected.Mode()&os.ModeSocket == 0 {
		return errors.New("expected event socket identity is invalid")
	}
	current, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if current.Mode()&os.ModeSocket == 0 || !os.SameFile(expected, current) {
		return fmt.Errorf("refusing to remove changed event socket path %q", path)
	}
	return os.Remove(path)
}

func startEventSocket(path string) (net.Listener, *http.Server, error) {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, nil, e
	}
	if e := removeStaleSocket(path); e != nil {
		return nil, nil, e
	}
	ln, e := net.Listen("unix", path)
	if e != nil {
		return nil, nil, e
	}
	if e = os.Chmod(path, 0600); e != nil {
		_ = ln.Close()
		return nil, nil, e
	}
	if unixLn, ok := ln.(*net.UnixListener); ok {
		unixLn.SetUnlinkOnClose(false)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/_lucx/events", func(w http.ResponseWriter, r *http.Request) { // Respond quickly; body is deliberately bounded.
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		b, e := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		if e != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var ev Event
		if json.Unmarshal(b, &ev) != nil || ev.Type == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		logLine("INFO", "EVENT received id=%s type=%s source=%s", safeLog(ev.ID), safeLog(ev.Type), safeLog(ev.Source))
		w.WriteHeader(http.StatusNoContent)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second}
	go func() {
		if e := srv.Serve(ln); e != nil && !errors.Is(e, http.ErrServerClosed) {
			logLine("ERROR", "EVENT_SOCKET serve: %v", e)
		}
	}()
	return ln, srv, nil
}
func safeLog(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < ' ' || r == 127 {
			return -1
		}
		return r
	}, s)
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}

// Minimal DNS wire helpers. Queries are forwarded unchanged using RFC 8484.
