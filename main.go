package main

import (
	"bytes"
	"context"
	"crypto/rand"
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
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"lucx-doh-health-monitor/internal/activedoh"
	"lucx-doh-health-monitor/internal/dohintegration"
)

const (
	pluginID      = "doh-health-monitor"
	pluginVersion = "2.3.0"
	systemDNSUpstreamID = "system-dns"
	systemResolvConfPath = "/etc/resolv.conf"
	systemDNSPerServerTimeout = 2 * time.Second
	maxDNSMessage        = 65535
	maxHTTPBody          = 2 << 20
	defaultCacheMaxBytes = 8 << 20
	maxCacheMaxBytes     = 256 << 20
	maxUDPWorkers        = 64
	udpQueueCapacity     = 128
	maxTCPConnections    = 128
	maxResolverUpstreams = 64
	tcpIdleTimeout       = 30 * time.Second
	tcpWriteTimeout      = 10 * time.Second
)

type Config struct {
	LocalHosts             map[string]LocalHost `json:"local_hosts"`
	DNSMode                string               `json:"dns_mode"`
	ResolverUpstreams       []ResolverUpstream   `json:"resolver_upstreams"`
	DNSListenUDP           string          `json:"dns_listen_udp"`
	DNSListenTCP           string          `json:"dns_listen_tcp"`
	HTTPListen             string          `json:"http_listen"`
	ReloadSecs             int             `json:"reload_interval_seconds"`
	DNSQueryTimeoutSeconds int             `json:"dns_query_timeout_seconds"`
	DoHTimeoutSeconds      int             `json:"doh_timeout_seconds"`
	DNSMaxConcurrent       int             `json:"dns_max_concurrent"`
	Health                 HealthConfig    `json:"health"`
	Cache                  CacheConfig     `json:"cache"`
	Upstreams              []Upstream      `json:"upstreams"`
	BootstrapResolvers     []string        `json:"bootstrap_resolvers,omitempty"`
	Groups                 []Group         `json:"groups"`
	GeminiAPI              GeminiAPIConfig `json:"gemini_api"`
	// Integration is retained only to decode older config.json files. It no longer
	// controls Xray configuration or enables panel mutation operations.
	Integration bool `json:"integration"`
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

type ResolverUpstream struct {
	ID           string   `json:"id"`
	Name         string   `json:"name,omitempty"`
	Type         string   `json:"type"`
	Address      string   `json:"address,omitempty"`
	URL          string   `json:"url,omitempty"`
	BootstrapIPs []string `json:"bootstrap_ips,omitempty"`
}

type ResolverRuntime struct {
	cfg       ResolverUpstream
	address   string
	systemDNS *systemDNSResolver
	upstream  *UpstreamRuntime
}
type Group struct {
	ID        string   `json:"id"`
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
	cfg                    Config
	localHosts             map[string]LocalHost
	upstreams              map[string]*UpstreamRuntime
	groups                 map[string]Group
	resolverUpstreams      []*ResolverRuntime
	resolverGeneration     uint64
	activeDoHGeneration    uint64
	loadedAt               time.Time
	configMod              time.Time
}
type UpstreamRuntime struct {
	cfg       Upstream
	client    *http.Client
	bootstrap *bootstrapResolver
	systemDNS *systemDNSResolver
}

type systemDNSResolver struct {
	resolvConfPath   string
	listenerAddresses []string
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
	State            string        `json:"state"`
	Checks           []ProbeStatus `json:"checks,omitempty"`
	SuccessStreak    int           `json:"success_streak"`
	FailureStreak    int           `json:"failure_streak"`
	LastCheck        time.Time     `json:"last_check,omitempty"`
	CheckDurationMS  int64         `json:"check_duration_ms,omitempty"`
	LastError        string        `json:"last_error,omitempty"`
	LastHTTP         int           `json:"last_http_status,omitempty"`
	GeminiState      string        `json:"gemini_api_state,omitempty"`
}
type GroupStatus struct {
	ActiveUpstream string                 `json:"active_upstream"`
	Upstreams      map[string]HealthEntry `json:"upstreams"`
}
type Status struct {
	ID           string                          `json:"id"`
	Version      string                          `json:"version"`
	StartedAt    time.Time                       `json:"started_at"`
	UpdatedAt    time.Time                       `json:"updated_at"`
	DNSUDP       string                          `json:"dns_udp"`
	DNSTCP       string                          `json:"dns_tcp"`
	DNSMode      string                          `json:"dns_mode"`
	HTTP         string                          `json:"http"`
	Config       string                          `json:"config"`
	Cache        CacheStatus                     `json:"cache"`
	Groups       map[string]GroupStatus          `json:"groups"`
	DoHBootstrap       map[string]DoHBootstrapStatus `json:"doh_bootstrap,omitempty"`
	ActiveDoH          *ActiveDoHStatus                 `json:"active_doh,omitempty"`
	SystemDNSServers    []string                      `json:"system_dns_servers,omitempty"`
	SystemDNSError      string                        `json:"system_dns_error,omitempty"`
	GeminiAPI           string                        `json:"gemini_api"`
	Queries      uint64                          `json:"queries"`
	CacheHits      uint64                          `json:"cache_hits"`
	Failures       uint64                          `json:"failures"`
	ActiveUDP      int64                           `json:"active_udp"`
	UDPQueueDepth  int64                           `json:"udp_queue_depth"`
	UDPDropped     uint64                          `json:"udp_dropped"`
	ActiveTCP      int64                           `json:"active_tcp"`
	TCPRejected    uint64                          `json:"tcp_rejected"`
	Goroutines     int                             `json:"goroutines"`
	HeapAllocBytes uint64                          `json:"heap_alloc_bytes"`
	HeapInuseBytes uint64                          `json:"heap_inuse_bytes"`
	HeapSysBytes   uint64                          `json:"heap_sys_bytes"`
	CPUUserNS      uint64                          `json:"cpu_user_ns"`
	CPUSystemNS    uint64                          `json:"cpu_system_ns"`
	LastReload   time.Time                       `json:"last_reload,omitempty"`
	LastError    string                          `json:"last_error,omitempty"`
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
type cacheItem struct {
	packet     []byte
	expires    time.Time
	inserted   time.Time
	size       int
	generation uint64
}
type cacheOrderEntry struct {
	key        string
	generation uint64
}
type Runtime struct {
	dnsSem       chan struct{}
	dataDir      string
	configPath   string
	dohPath      string
	checksPath   string
	sourceHashes ConfigSourceChecksums
	lastRejectedSourceHash string
	healthCheckTrigger chan struct{}
	activeDoHTrigger chan struct{}
	activeDoHSelector *activedoh.Selector
	snapshot     atomic.Pointer[Snapshot]
	mu           sync.RWMutex
	health           map[string]map[string]HealthEntry
	active           map[string]string
	upstreamCooldown map[string]time.Time
	cacheMu        sync.Mutex
	cache          map[string]cacheItem
	cacheOrder     []cacheOrderEntry
	cacheOrderHead int
	cacheBytes     int
	cacheSeq       uint64
	cacheHits      atomic.Uint64
	activeUDP      atomic.Int64
	udpQueueDepth  atomic.Int64
	udpDropped     atomic.Uint64
	activeTCP      atomic.Int64
	tcpRejected    atomic.Uint64
	queries    atomic.Uint64
	failures   atomic.Uint64
	lastGemini map[string]time.Time
	statusMu   sync.RWMutex
	lastError  string
	lastReload time.Time
}

func main() {
	log.SetFlags(0)
	if len(os.Args) > 1 {
		action := strings.ToLower(strings.TrimSpace(os.Args[1]))
		if action == "web" {
			if len(os.Args) != 2 {
				logLine("ERROR", "WEB_UI does not accept additional arguments")
				os.Exit(2)
			}
			if err := runWebUI(); err != nil {
				logLine("ERROR", "WEB_UI: %v", err)
				os.Exit(1)
			}
			return
		}
		if action == "config" {
			if err := runDNSConfigCLI(os.Args[2:]); err != nil {
				logLine("ERROR", "CONFIG: %v", err)
				os.Exit(1)
			}
			return
		}
		if action == "check" {
			logger := lucxReadOnlyCheckLogger{}
			if err := dohintegration.RunCommand(os.Args[1:], logger); err != nil {
				logLine("ERROR", "CHECK: %v", err)
				os.Exit(1)
			}
			return
		}
		logLine("ERROR", "CLI supports only read-only check, web and config; Xray Geosite DNS policy must be configured manually")
		os.Exit(2)
	}
	dataDir := strings.TrimSpace(os.Getenv("LUCX_PLUGIN_DATA"))
	if dataDir == "" {
		fatal("LUCX_PLUGIN_DATA is required")
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		fatal("create data dir: %v", err)
	}
	_ = os.Chmod(dataDir, 0700)
	logLine("INFO", "START id=%s version=%s arch=%s data=%s", envOr("LUCX_PLUGIN_ID", pluginID), envOr("LUCX_PLUGIN_VERSION", pluginVersion), runtime.GOARCH, dataDir)

	configPath := filepath.Join(dataDir, "config.json")
	dohPath := filepath.Join(dataDir, "doh-servers.txt")
	checksPath := filepath.Join(dataDir, "tst-domen.txt")
	localHostsPath := filepath.Join(dataDir, localHostsSourceFile)
	startupConfigUnlock, err := acquireDNSConfigFileLock(dataDir)
	if err != nil {
		fatal("CONFIG file lock failed: %v", err)
	}
	if err := initializeConfigSourceFiles(dataDir); err != nil {
		fatal("CONFIG sources initialization failed: %v", err)
	}
	cfg, err := loadConfig(configPath)
	if err != nil {
		fatal("CONFIG invalid: %v", err)
	}
	sources, err := readConfigSources(dohPath, checksPath, localHostsPath)
	if err != nil {
		fatal("CONFIG sources invalid: %v", err)
	}
	cfg, err = applyConfigSources(cfg, sources)
	if err != nil {
		fatal("CONFIG generation failed: %v", err)
	}
	if err := writeConfigAtomic(configPath, cfg); err != nil {
		fatal("CONFIG generated file write failed: %v", err)
	}
	snap, err := buildSnapshot(cfg, sources.DoHURLs)
	if err != nil {
		fatal("CONFIG invalid: %v", err)
	}
	if fi, e := os.Stat(configPath); e == nil {
		snap.configMod = fi.ModTime()
	}
	rt := &Runtime{
		dataDir: dataDir, configPath: configPath, dohPath: dohPath, checksPath: checksPath,
		sourceHashes: sources.Checksums,
		healthCheckTrigger: make(chan struct{}, 1),
		activeDoHTrigger: make(chan struct{}, 1),
		activeDoHSelector: activedoh.NewSelector(activedoh.DefaultPolicy()),
		health: map[string]map[string]HealthEntry{}, active: map[string]string{},
		cache: map[string]cacheItem{}, lastGemini: map[string]time.Time{},
		dnsSem: make(chan struct{}, cfg.DNSMaxConcurrent),
	}
	rt.snapshot.Store(snap)
	rt.initHealth(snap)
	startupConfigUnlock()
	logLine("INFO", "CONFIG loaded path=%s doh_list=%s checks_list=%s groups=%d upstreams=%d checks=%d dns_udp=%s dns_tcp=%s gemini_api=%t", configPath, dohPath, checksPath, len(cfg.Groups), len(cfg.Upstreams), len(sources.Checks), cfg.DNSListenUDP, cfg.DNSListenTCP, cfg.GeminiAPI.Enabled)

	udpAddr, err := net.ResolveUDPAddr("udp", cfg.DNSListenUDP)
	if err != nil {
		fatal("DNS UDP address: %v", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fatal("DNS UDP listen %s: %v", cfg.DNSListenUDP, err)
	}
	tcpLn, err := net.Listen("tcp", cfg.DNSListenTCP)
	if err != nil {
		_ = udpConn.Close()
		fatal("DNS TCP listen %s: %v", cfg.DNSListenTCP, err)
	}
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	httpMux.HandleFunc("/status", rt.handleStatus)
	httpSrv := &http.Server{Addr: cfg.HTTPListen, Handler: httpMux, ReadHeaderTimeout: 3 * time.Second}
	httpLn, err := net.Listen("tcp", cfg.HTTPListen)
	if err != nil {
		_ = udpConn.Close()
		_ = tcpLn.Close()
		fatal("HTTP listen %s: %v", cfg.HTTPListen, err)
	}

	var socketPath string
	var socketInfo os.FileInfo
	var socketLn net.Listener
	var socketSrv *http.Server
	if p := strings.TrimSpace(os.Getenv("LUCX_PLUGIN_SOCKET")); p != "" {
		socketPath = p
		socketLn, socketSrv, err = startEventSocket(p)
		if err != nil {
			logLine("ERROR", "EVENT_SOCKET start failed: %v", err)
		} else {
			socketInfo, err = os.Lstat(p)
			if err != nil {
				logLine("ERROR", "EVENT_SOCKET identity check failed: %v", err)
			} else {
				logLine("INFO", "EVENT_SOCKET listening path=%s", p)
			}
		}
	} else {
		logLine("WARN", "EVENT_SOCKET not configured")
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(6)
	go func() { defer wg.Done(); rt.serveUDP(ctx, udpConn) }()
	go func() { defer wg.Done(); rt.serveTCP(ctx, tcpLn) }()
	go func() {
		defer wg.Done()
		if e := httpSrv.Serve(httpLn); e != nil && !errors.Is(e, http.ErrServerClosed) {
			logLine("ERROR", "HTTP server: %v", e)
			cancel()
		}
	}()
	go func() { defer wg.Done(); rt.monitorLoop(ctx) }()
	go func() { defer wg.Done(); rt.activeDoHLoop(ctx) }()
	go func() { defer wg.Done(); rt.reloadLoop(ctx) }()
	logLine("INFO", "READY DNS=%s/%s HTTP=%s", cfg.DNSListenUDP, cfg.DNSListenTCP, cfg.HTTPListen)

	sigc := make(chan os.Signal, 2)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	sig := <-sigc
	logLine("INFO", "STOP signal=%s received", sig)
	cancel()
	_ = udpConn.Close()
	_ = tcpLn.Close()
	_ = httpSrv.Shutdown(context.Background())
	if socketSrv != nil {
		_ = socketSrv.Shutdown(context.Background())
	}
	if socketLn != nil {
		_ = socketLn.Close()
	}
	if socketPath != "" && socketInfo != nil {
		if e := removeSocketIfSame(socketPath, socketInfo); e != nil {
			logLine("WARN", "EVENT_SOCKET cleanup skipped: %v", e)
		}
	}
	wg.Wait()
	logLine("INFO", "STOP clean=true")
}


type lucxReadOnlyCheckLogger struct{}

func (lucxReadOnlyCheckLogger) Printf(format string, args ...any) {
	logLine("INFO", "CHECK %s", fmt.Sprintf(format, args...))
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
	if e != nil { return Config{}, e }
	c = normalizeDNSConfig(c)
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
		Health: HealthConfig{IntervalSeconds: 25 * 60, TimeoutSeconds: 5, FailureThreshold: 1, SuccessThreshold: 1},
		Cache:  CacheConfig{Enabled: true, MinTTL: 5, MaxTTL: 300, NegativeTTL: 15, MaxEntries: 8192, MaxBytes: defaultCacheMaxBytes},
		DNSMode: "endpoint_ip",
		ResolverUpstreams: []ResolverUpstream{{ID: "system", Name: "System resolver (OS)", Type: "system"}},
		LocalHosts: map[string]LocalHost{},
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

func normalizeDNSConfig(c Config) Config {
	if strings.TrimSpace(c.DNSMode) == "" {
		c.DNSMode = "endpoint_ip"
	}
	if c.ResolverUpstreams == nil {
		// Configurations created before resolver_upstreams existed inherit the
		// documented default. An explicit empty JSON array remains empty and
		// therefore means that mode 2 has no configured upstream.
		c.ResolverUpstreams = []ResolverUpstream{{ID: "system", Name: "System resolver (OS)", Type: "system"}}
	}
	return c
}

func normalizeResolverAddress(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if ip := net.ParseIP(raw); ip != nil {
		return net.JoinHostPort(ip.String(), "53"), nil
	}
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return "", fmt.Errorf("resolver address must be an IP literal with optional port: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", errors.New("plain DNS resolver address must use an IP literal; use a DoH URL for hostname-based upstreams")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", errors.New("resolver address port must be in 1..65535")
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(portNumber)), nil
}

func validateResolverUpstreams(upstreams []ResolverUpstream) error {
	if len(upstreams) > maxResolverUpstreams {
		return fmt.Errorf("resolver_upstreams supports at most %d entries", maxResolverUpstreams)
	}
	ids := make(map[string]bool, len(upstreams))
	systemCount := 0
	for i, resolver := range upstreams {
		id := strings.TrimSpace(resolver.ID)
		if id == "" || len(id) > 128 || strings.ContainsAny(id, "/:@ \t") || ids[id] {
			return fmt.Errorf("resolver_upstreams[%d] has an empty, invalid or duplicate id %q", i, resolver.ID)
		}
		ids[id] = true
		switch resolver.Type {
		case "system":
			systemCount++
			if systemCount > 1 {
				return errors.New("resolver_upstreams may contain at most one system resolver")
			}
			if resolver.Address != "" || resolver.URL != "" || len(resolver.BootstrapIPs) != 0 {
				return fmt.Errorf("system resolver %q must not define address, url or bootstrap_ips", id)
			}
		case "udp", "tcp":
			if resolver.URL != "" || len(resolver.BootstrapIPs) != 0 {
				return fmt.Errorf("plain DNS resolver %q must not define url or bootstrap_ips", id)
			}
			if _, err := normalizeResolverAddress(resolver.Address); err != nil {
				return fmt.Errorf("resolver %q: %w", id, err)
			}
		case "doh":
			if resolver.Address != "" {
				return fmt.Errorf("DoH resolver %q must use url, not address", id)
			}
			parsed, err := url.Parse(strings.TrimSpace(resolver.URL))
			if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
				return fmt.Errorf("DoH resolver %q must have an HTTPS URL without userinfo or fragment", id)
			}
			for _, rawIP := range resolver.BootstrapIPs {
				if net.ParseIP(strings.TrimSpace(rawIP)) == nil {
					return fmt.Errorf("DoH resolver %q has invalid bootstrap IP %q", id, rawIP)
				}
			}
		default:
			return fmt.Errorf("resolver %q has unsupported type %q", id, resolver.Type)
		}
	}
	return nil
}

func configGeneration(value any) uint64 {
	encoded, err := json.Marshal(value)
	if err != nil {
		return 0
	}
	sum := sha256.Sum256(encoded)
	return binary.BigEndian.Uint64(sum[:8])
}

func normalizeCacheConfig(c Config) Config {
	// Older config files predate max_bytes; give them a bounded default.
	if c.Cache.MaxBytes == 0 {
		c.Cache.MaxBytes = defaultCacheMaxBytes
	}
	return c
}

func validateConfig(c Config) error {
	if c.DNSMode != "endpoint_ip" && c.DNSMode != "resolver" {
		return fmt.Errorf("dns_mode must be endpoint_ip or resolver, got %q", c.DNSMode)
	}
	if c.DNSMode == "resolver" && len(c.ResolverUpstreams) == 0 {
		return errors.New("resolver mode requires at least one resolver_upstreams entry")
	}
	if err := validateResolverUpstreams(c.ResolverUpstreams); err != nil {
		return err
	}
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
			if strings.TrimSpace(ch.Domain) == "" {
				return fmt.Errorf("empty check domain in group %s", g.ID)
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
		if c.GeminiAPI.Model == "" || c.GeminiAPI.KeyFile == "" || c.GeminiAPI.IntervalSeconds < 60 {
			return errors.New("gemini_api requires model, key_file and interval_seconds >= 60")
		}
	}
	return nil
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
	resolverBootstrap := c.BootstrapResolvers
	if len(resolverBootstrap) == 0 {
		resolverBootstrap = defaultBootstrapResolvers()
	}
	for _, configured := range c.ResolverUpstreams {
		runtimeResolver := &ResolverRuntime{cfg: configured}
		switch configured.Type {
		case "system":
			runtimeResolver.systemDNS = &systemDNSResolver{
				resolvConfPath: systemResolvConfPath,
				listenerAddresses: []string{c.DNSListenUDP, c.DNSListenTCP},
			}
		case "udp", "tcp":
			address, err := normalizeResolverAddress(configured.Address)
			if err != nil {
				return nil, fmt.Errorf("resolver %s: %w", configured.ID, err)
			}
			runtimeResolver.address = address
		case "doh":
			upstream := Upstream{
				ID: configured.ID, Name: configured.Name, Type: "doh",
				URL: strings.TrimSpace(configured.URL),
				BootstrapIPs: append([]string(nil), configured.BootstrapIPs...),
			}
			client, bootstrap, err := newDoHClient(upstream, resolverBootstrap, time.Duration(c.DoHTimeoutSeconds)*time.Second)
			if err != nil {
				return nil, fmt.Errorf("build mode-2 DoH resolver %s: %w", configured.ID, err)
			}
			runtimeResolver.upstream = &UpstreamRuntime{cfg: upstream, client: client, bootstrap: bootstrap}
		}
		s.resolverUpstreams = append(s.resolverUpstreams, runtimeResolver)
	}
	s.resolverGeneration = configGeneration(struct {
		Mode string
		Resolvers []ResolverUpstream
		Bootstrap []string
		Cache CacheConfig
		LocalHosts map[string]LocalHost
	}{c.DNSMode, c.ResolverUpstreams, c.BootstrapResolvers, c.Cache, c.LocalHosts})
	s.activeDoHGeneration = configGeneration(struct {
		Mode string
		Upstreams []Upstream
		DoHURLs map[string]string
		Bootstrap []string
		LocalHosts map[string]LocalHost
	}{c.DNSMode, c.Upstreams, dohURLs, c.BootstrapResolvers, c.LocalHosts})
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
				cfg: u,
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
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: pu.Hostname()},
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
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: parsed.Hostname()},
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
		cfg: Upstream{ID: parsed.Hostname(), URL: endpoint},
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
	for uid := range r.lastGemini {
		if _, ok := validUpstreams[uid]; !ok {
			delete(r.lastGemini, uid)
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

func (r *Runtime) query(ctx context.Context, packet []byte) ([]byte, string, error) {
	name, _, _, e := parseQuestion(packet)
	if e != nil {
		return nil, "", e
	}
	s := r.currentSnapshot()
	// Every DNS question received by this listener uses the single Google-qualified gateway.
	const gid = "google"
	order := r.upstreamsToAttempt(r.orderedUpstreams(gid, s), time.Now())
	var errs []string
	for _, uid := range order {
		u := s.upstreams[uid]
		if u == nil {
			continue
		}
		resp, e := sendUpstreamDNS(ctx, u, packet)
		if e == nil {
			if dnsRCode(resp) == 2 || dnsRCode(resp) == 5 {
				e = fmt.Errorf("upstream returned DNS RCODE %d", dnsRCode(resp))
			} else if dnsTruncated(resp) {
				e = errors.New("upstream returned truncated response; TCP retry not available over DoH")
			} else {
				r.markUpstreamSuccess(uid)
				return resp, uid, nil
			}
		}
		r.markUpstreamFailure(uid, time.Now())
		errs = append(errs, uid+": "+e.Error())
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
	r.serveUDPWithHandler(ctx, c, r.handleDNS)
}

// serveUDPWithHandler separates queue/worker scheduling from DNS resolution so
// the bounded-queue behavior can be tested deterministically.
func (r *Runtime) serveUDPWithHandler(ctx context.Context, c *net.UDPConn, handle func([]byte) []byte) {
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
					resp := handle(job.packet)
					r.activeUDP.Add(-1)
					if len(resp) > 4096 {
						resp = resp[:4096]
					}
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
func (r *Runtime) handleDNS(packet []byte) []byte {
	select {
	case r.dnsSem <- struct{}{}:
		defer func() { <-r.dnsSem }()
	default:
		return servfailResponse(packet)
	}
	r.queries.Add(1)
	name, qtype, _, err := parseQuestion(packet)
	if err != nil {
		return formerrResponse(packet)
	}
	s := r.currentSnapshot()
	if s == nil {
		return servfailResponse(packet)
	}
	// Local overrides remain available for A/AAAA. The new Geosite DNS path
	// deliberately does not serve HTTPS/SVCB or other non-address QTYPEs.
	if qtype == 1 || qtype == 28 {
		if response, matched := localHostsResponse(packet, normalizeDomain(name), qtype, s.localHosts); matched {
			return response
		}
	}
	if s.cfg.DNSMode == "resolver" {
		return r.resolverDNSResponse(packet, s)
	}
	return r.activeDoHDNSResponse(packet, s)
}

const localHostsTTL uint32 = 60

// localHostsResponse handles only explicitly configured hosts and the A, AAAA,
// SVCB and HTTPS RR types. A nil/empty map leaves normal DoH processing untouched.
func localHostsResponse(query []byte, host string, qtype uint16, hosts map[string]LocalHost) ([]byte, bool) {
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
	opt := extractEDNSOPT(query)
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
			response = appendLocalHostRR(response, qtype, ip)
			answers++
		}
	} else if qtype == 28 {
		for _, raw := range entry.IPv6 {
			ip := net.ParseIP(strings.TrimSpace(raw)).To16()
			if ip == nil || net.ParseIP(strings.TrimSpace(raw)).To4() != nil {
				continue
			}
			response = appendLocalHostRR(response, qtype, ip)
			answers++
		}
	}
	binary.BigEndian.PutUint16(response[6:8], uint16(answers))
	if answers == 0 {
		response = appendLocalHostSOA(response)
		binary.BigEndian.PutUint16(response[8:10], 1)
	}
	if len(opt) > 0 {
		response = append(response, opt...)
		binary.BigEndian.PutUint16(response[10:12], 1)
	}
	return response, true
}

func appendLocalHostRR(packet []byte, qtype uint16, ip []byte) []byte {
	packet = append(packet, 0xc0, 0x0c) // owner name points to QNAME
	packet = append(packet, byte(qtype>>8), byte(qtype), 0, 1)
	var ttl [4]byte
	binary.BigEndian.PutUint32(ttl[:], localHostsTTL)
	packet = append(packet, ttl[:]...)
	packet = append(packet, byte(len(ip)>>8), byte(len(ip)))
	return append(packet, ip...)
}

func appendLocalHostSOA(packet []byte) []byte {
	packet = append(packet, 0xc0, 0x0c) // SOA owner name
	packet = append(packet, 0, 6, 0, 1)
	var ttl [4]byte
	binary.BigEndian.PutUint32(ttl[:], localHostsTTL)
	packet = append(packet, ttl[:]...)
	soa := make([]byte, 0, 64)
	soa = appendDNSName(soa, "ns.local-hosts.invalid")
	soa = appendDNSName(soa, "hostmaster.local-hosts.invalid")
	for _, value := range []uint32{1, localHostsTTL, localHostsTTL, localHostsTTL, localHostsTTL} {
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
			typ := binary.BigEndian.Uint16(query[n:n+2])
			rdlen := int(binary.BigEndian.Uint16(query[n+8:n+10]))
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

func (r *Runtime) deleteCacheEntryLocked(key string, item cacheItem) {
	if current, ok := r.cache[key]; ok && current.generation == item.generation {
		delete(r.cache, key)
		r.cacheBytes -= current.size
		if r.cacheBytes < 0 {
			r.cacheBytes = 0
		}
	}
}

func (r *Runtime) cacheGet(key string, id uint16) ([]byte, bool) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	v, ok := r.cache[key]
	if !ok {
		return nil, false
	}
	if !time.Now().Before(v.expires) {
		r.deleteCacheEntryLocked(key, v)
		return nil, false
	}
	b := append([]byte(nil), v.packet...)
	binary.BigEndian.PutUint16(b[:2], id)
	decrementTTLs(b, uint32(time.Since(v.inserted).Seconds()))
	return b, true
}

func (r *Runtime) evictOldestCacheLocked() bool {
	for r.cacheOrderHead < len(r.cacheOrder) {
		entry := r.cacheOrder[r.cacheOrderHead]
		r.cacheOrderHead++
		if current, ok := r.cache[entry.key]; ok && current.generation == entry.generation {
			delete(r.cache, entry.key)
			r.cacheBytes -= current.size
			if r.cacheBytes < 0 {
				r.cacheBytes = 0
			}
			return true
		}
	}
	return false
}

func (r *Runtime) compactCacheOrderLocked(maxEntries int) {
	if len(r.cacheOrder) <= 2*maxEntries+1024 {
		return
	}
	compact := make([]cacheOrderEntry, 0, len(r.cache))
	for i := r.cacheOrderHead; i < len(r.cacheOrder); i++ {
		entry := r.cacheOrder[i]
		if current, ok := r.cache[entry.key]; ok && current.generation == entry.generation {
			compact = append(compact, entry)
		}
	}
	r.cacheOrder = compact
	r.cacheOrderHead = 0
}

func (r *Runtime) cachePut(key string, packet []byte, c CacheConfig) {
	if !c.Enabled || c.MaxEntries < 1 || c.MaxBytes < 1024 {
		return
	}
	ttl, ok := minResponseTTL(packet)
	if !ok {
		if dnsRCode(packet) == 3 {
			ttl = uint32(c.NegativeTTL)
		} else {
			return
		}
	}
	if ttl == 0 || (c.MinTTL > 0 && ttl < uint32(c.MinTTL)) {
		return
	}
	if ttl > uint32(c.MaxTTL) {
		ttl = uint32(c.MaxTTL)
	}
	if ttl == 0 {
		return
	}
	const cacheItemOverheadEstimate = 128
	cost := len(key) + len(packet) + cacheItemOverheadEstimate
	if cost > c.MaxBytes {
		return
	}

	now := time.Now()
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	if previous, exists := r.cache[key]; exists {
		delete(r.cache, key)
		r.cacheBytes -= previous.size
	}
	r.cacheSeq++
	item := cacheItem{
		packet: append([]byte(nil), packet...),
		expires: now.Add(time.Duration(ttl) * time.Second),
		inserted: now, size: cost, generation: r.cacheSeq,
	}
	r.cache[key] = item
	r.cacheBytes += cost
	r.cacheOrder = append(r.cacheOrder, cacheOrderEntry{key: key, generation: item.generation})

	for len(r.cache) > c.MaxEntries || r.cacheBytes > c.MaxBytes {
		if !r.evictOldestCacheLocked() {
			break
		}
	}
	r.compactCacheOrderLocked(c.MaxEntries)
}

func cacheKey(p []byte) string {
	b := append([]byte(nil), p...)
	if len(b) >= 2 {
		b[0] = 0
		b[1] = 0
	}
	sum := sha256.Sum256(b)
	return string(sum[:])
}
func packetID(p []byte) uint16 {
	if len(p) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(p[:2])
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
					if r.geminiDue(uid, s.cfg.GeminiAPI.IntervalSeconds) {
						apiCtx, cancel := context.WithTimeout(ctx, time.Duration(s.cfg.DoHTimeoutSeconds+5)*time.Second)
						_, ge := r.geminiProbe(apiCtx, u, s.cfg.GeminiAPI)
						cancel()
						if ge != nil {
							gemState = "failed"
							logLine("WARN", "Gemini API probe failed group=%s upstream=%s error=%s", gid, uid, ge.Error())
							if s.cfg.GeminiAPI.RequiredForGroup && !geminiAuthOrQuotaError(ge) {
								ok = false
								lastErr = "Gemini API: " + ge.Error()
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
		if r.pointsBackToPluginListener(server) {
			failures = append(failures, server+": resolver target matches the plugin DNS listener; refusing a DNS loop")
			continue
		}
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
	req.Header.Set("User-Agent", "LucX-DoH-HealthMonitor/1.4.0")
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
	keyPath := c.KeyFile
	if !filepath.IsAbs(keyPath) {
		keyPath = filepath.Join(r.dataDir, keyPath)
	}
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
	if e != nil || len(ips) == 0 {
		return "", fmt.Errorf("resolve Gemini API: %v", e)
	}
	endpoint := "https://" + host + "/v1beta/models/" + url.PathEscape(c.Model) + ":generateContent"
	payload := map[string]any{"contents": []any{map[string]any{"parts": []any{map[string]string{"text": c.Prompt}}}}, "generationConfig": map[string]any{"maxOutputTokens": c.MaxOutputTokens, "temperature": 0}}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-goog-api-key", key)
	client := newPinnedHTTPClient(ips[0], host, time.Duration(r.currentSnapshot().cfg.DoHTimeoutSeconds)*time.Second)
	defer client.CloseIdleConnections()
	resp, e := client.Do(req)
	if e != nil {
		return "", e
	}
	defer resp.Body.Close()
	rb, readErr := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBody+1))
	if readErr != nil {
		return "", fmt.Errorf("read Gemini API response: %w", readErr)
	}
	if len(rb) > maxHTTPBody {
		return "", fmt.Errorf("Gemini API response exceeds %d bytes", maxHTTPBody)
	}
	if resp.StatusCode != http.StatusOK {
		return "", GeminiHTTPError{Status: resp.StatusCode}
	}
	var out struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if e = json.Unmarshal(rb, &out); e != nil || len(out.Candidates) == 0 || len(out.Candidates[0].Content.Parts) == 0 || strings.TrimSpace(out.Candidates[0].Content.Parts[0].Text) == "" {
		return "", errors.New("Gemini API returned no text candidate")
	}
	return strings.TrimSpace(out.Candidates[0].Content.Parts[0].Text), nil
}
func geminiAuthOrQuotaError(err error) bool {
	var he GeminiHTTPError
	if errors.As(err, &he) {
		return he.Status == 400 || he.Status == 401 || he.Status == 403 || he.Status == 429
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "read gemini api key file") || strings.Contains(msg, "gemini api key is empty")
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
func (r *Runtime) reloadLoop(ctx context.Context) {
	ticker := time.NewTicker(configSourcePollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		// Lock before reading either config.json or its managed source files so
		// a writer cannot race the read/merge/write transaction.
		dnsConfigWriteMu.Lock()
		releaseFileLock, lockErr := acquireDNSConfigFileLock(r.dataDir)
		if lockErr != nil {
			dnsConfigWriteMu.Unlock()
			r.rejectConfigReload("config-lock:"+lockErr.Error(), "CONFIG reload rejected: cannot lock config sources: %v", lockErr)
			continue
		}
		unlockConfigWrite := func() {
			releaseFileLock()
			dnsConfigWriteMu.Unlock()
		}

		old := r.currentSnapshot()
		cfi, err := os.Stat(r.configPath)
		if err != nil {
			unlockConfigWrite()
			r.rejectConfigReload("config-stat:"+err.Error(), "CONFIG reload rejected: cannot stat config.json: %v", err)
			continue
		}
		sources, sourceErr := readConfigSources(r.dohPath, r.checksPath, filepath.Join(r.dataDir, localHostsSourceFile))
		if sourceErr != nil {
			rejectedHash := sources.Checksums.Combined
			if rejectedHash == "" {
				rejectedHash = "source-read-error:" + sourceErr.Error()
			}
			unlockConfigWrite()
			r.rejectConfigReload(rejectedHash, "CONFIG source reload rejected: %v", sourceErr)
			continue
		}
		sourcesChanged := sources.Checksums != r.sourceHashes
		configChanged := cfi.ModTime().After(old.configMod)
		if !sourcesChanged && !configChanged {
			// A source file may be reverted byte-for-byte after a rejected edit.
			if r.lastRejectedSourceHash != "" {
				r.lastRejectedSourceHash = ""
				r.setError("")
			}
			unlockConfigWrite()
			continue
		}

		cfg, err := loadConfigNoCreate(r.configPath)
		if err != nil {
			unlockConfigWrite()
			r.rejectConfigReload("config-error:"+cfi.ModTime().UTC().Format(time.RFC3339Nano)+":"+err.Error(), "CONFIG reload rejected: %v", err)
			continue
		}
		if cfg.DNSListenUDP != old.cfg.DNSListenUDP || cfg.DNSListenTCP != old.cfg.DNSListenTCP || cfg.HTTPListen != old.cfg.HTTPListen || cfg.DNSMaxConcurrent != old.cfg.DNSMaxConcurrent {
			unlockConfigWrite()
			r.rejectConfigReload("listener-change:"+cfi.ModTime().UTC().Format(time.RFC3339Nano), "CONFIG listener/dns_max_concurrent change requires plugin restart")
			continue
		}
		cfg, err = applyConfigSources(cfg, sources)
		if err != nil {
			unlockConfigWrite()
			r.rejectConfigReload(sources.Checksums.Combined+":generated:"+err.Error(), "CONFIG generation rejected: %v", err)
			continue
		}
		ns, err := buildSnapshot(cfg, sources.DoHURLs)
		if err != nil {
			unlockConfigWrite()
			r.rejectConfigReload(sources.Checksums.Combined+":snapshot:"+err.Error(), "CONFIG snapshot rejected: %v", err)
			continue
		}
		if err := writeConfigAtomic(r.configPath, cfg); err != nil {
			unlockConfigWrite()
			r.rejectConfigReload(sources.Checksums.Combined+":write:"+err.Error(), "CONFIG generated file write failed: %v", err)
			continue
		}
		if fi, err := os.Stat(r.configPath); err == nil {
			ns.configMod = fi.ModTime()
		}
		r.snapshot.Store(ns)
		r.initHealth(ns)
		if old.activeDoHGeneration != ns.activeDoHGeneration {
			r.clearActiveDoHCache()
		}
		if old.resolverGeneration != ns.resolverGeneration {
			r.clearResolverCache()
		}
		r.sourceHashes = sources.Checksums
		r.lastRejectedSourceHash = ""
		r.mu.Lock()
		r.lastReload = time.Now().UTC()
		r.mu.Unlock()
		r.setError("")
		unlockConfigWrite()
		// Run health checks immediately against the newly applied source files.
		select {
		case r.healthCheckTrigger <- struct{}{}:
		default:
		}
		select {
		case r.activeDoHTrigger <- struct{}{}:
		default:
		}
		logLine("INFO", "CONFIG reloaded upstreams=%d groups=%d checks=%d local_hosts=%d sources_sha256=%s", len(cfg.Upstreams), len(cfg.Groups), len(sources.Checks), len(sources.LocalHosts), sources.Checksums.Combined)
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
	if e != nil { return Config{}, e }
	c = normalizeDNSConfig(c)
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
		DNSTCP: s.cfg.DNSListenTCP, DNSMode: s.cfg.DNSMode, HTTP: s.cfg.HTTPListen, Config: r.configPath,
		Cache: CacheStatus{Enabled: s.cfg.Cache.Enabled, Entries: cacheEntries, MaxEntries: s.cfg.Cache.MaxEntries, Bytes: cacheBytes, MaxBytes: s.cfg.Cache.MaxBytes},
		Groups: map[string]GroupStatus{}, DoHBootstrap: map[string]DoHBootstrapStatus{},
		ActiveDoH: r.activeDoHStatus(),
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

func (r *Runtime) cacheStats() (int, int) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	return len(r.cache), r.cacheBytes
}
func (r *Runtime) cacheLen() int {
	entries, _ := r.cacheStats()
	return entries
}
func (r *Runtime) serveEvent(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost || req.URL.Path != "/_lucx/events" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	b, e := io.ReadAll(io.LimitReader(req.Body, 64<<10))
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
func parseQuestion(p []byte) (string, uint16, int, error) {
	if len(p) < 12 {
		return "", 0, 0, errors.New("DNS header too short")
	}
	qd := binary.BigEndian.Uint16(p[4:6])
	if qd < 1 {
		return "", 0, 0, errors.New("DNS message has no question")
	}
	name, off, e := decodeName(p, 12)
	if e != nil {
		return "", 0, 0, e
	}
	if off+4 > len(p) {
		return "", 0, 0, errors.New("DNS question truncated")
	}
	return name, binary.BigEndian.Uint16(p[off : off+2]), off + 4, nil
}
func decodeName(p []byte, start int) (string, int, error) {
	labels := []string{}
	off := start
	end := -1
	visited := map[int]bool{}
	for steps := 0; steps < 128; steps++ {
		if off >= len(p) {
			return "", 0, errors.New("DNS name out of range")
		}
		if visited[off] {
			return "", 0, errors.New("DNS compression loop")
		}
		visited[off] = true
		l := int(p[off])
		if l&0xc0 == 0xc0 {
			if off+1 >= len(p) {
				return "", 0, errors.New("DNS pointer truncated")
			}
			ptr := ((l & 0x3f) << 8) | int(p[off+1])
			if ptr >= len(p) {
				return "", 0, errors.New("DNS pointer out of range")
			}
			if end < 0 {
				end = off + 2
			}
			off = ptr
			continue
		}
		off++
		if l == 0 {
			if end < 0 {
				end = off
			}
			return strings.Join(labels, "."), end, nil
		}
		if l&0xc0 != 0 || l > 63 || off+l > len(p) {
			return "", 0, errors.New("invalid DNS label")
		}
		labels = append(labels, string(p[off:off+l]))
		off += l
	}
	return "", 0, errors.New("DNS name too deep")
}
func makeDNSQuery(name string, qtype uint16) []byte {
	p := make([]byte, 12)
	_, _ = rand.Read(p[:2])
	binary.BigEndian.PutUint16(p[2:4], 0x0100)
	binary.BigEndian.PutUint16(p[4:6], 1)
	for _, label := range strings.Split(normalizeDomain(name), ".") {
		if len(label) > 63 {
			continue
		}
		p = append(p, byte(len(label)))
		p = append(p, []byte(label)...)
	}
	p = append(p, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return p
}
func dnsRCode(p []byte) int {
	if len(p) < 4 {
		return -1
	}
	return int(binary.BigEndian.Uint16(p[2:4]) & 0x000f)
}
func dnsTruncated(p []byte) bool { return len(p) >= 4 && (binary.BigEndian.Uint16(p[2:4])&0x0200) != 0 }
func dnsAnswerCount(p []byte) int {
	if len(p) < 8 {
		return 0
	}
	return int(binary.BigEndian.Uint16(p[6:8]))
}
func formerrResponse(q []byte) []byte  { return errorResponse(q, 1) }
func servfailResponse(q []byte) []byte { return errorResponse(q, 2) }
func errorResponse(q []byte, rcode uint16) []byte {
	if len(q) < 12 {
		return []byte{}
	}
	p := append([]byte(nil), q...)
	flags := binary.BigEndian.Uint16(p[2:4])
	flags = (flags | 0x8000) &^ 0x0200
	flags = (flags &^ 0x000f) | rcode
	binary.BigEndian.PutUint16(p[2:4], flags)
	for i := 4; i < 12; i += 2 {
		binary.BigEndian.PutUint16(p[i:i+2], 0)
	}
	return p
}
func parseARecords(p []byte) ([]string, error) {
	if len(p) < 12 {
		return nil, errors.New("short DNS response")
	}
	off := 12
	qd := int(binary.BigEndian.Uint16(p[4:6]))
	an := int(binary.BigEndian.Uint16(p[6:8]))
	ns := int(binary.BigEndian.Uint16(p[8:10]))
	ar := int(binary.BigEndian.Uint16(p[10:12]))
	for i := 0; i < qd; i++ {
		_, n, e := decodeName(p, off)
		if e != nil {
			return nil, e
		}
		off = n + 4
		if off > len(p) {
			return nil, errors.New("truncated question")
		}
	}
	ips := []string{}
	for i := 0; i < an+ns+ar; i++ {
		_, n, e := decodeName(p, off)
		if e != nil {
			return ips, e
		}
		off = n
		if off+10 > len(p) {
			return ips, errors.New("truncated RR")
		}
		typ := binary.BigEndian.Uint16(p[off : off+2])
		rd := int(binary.BigEndian.Uint16(p[off+8 : off+10]))
		off += 10
		if off+rd > len(p) {
			return ips, errors.New("truncated RDATA")
		}
		if i < an && typ == 1 && rd == 4 {
			ips = append(ips, net.IP(p[off:off+4]).String())
		}
		off += rd
	}
	return ips, nil
}
func skipName(p []byte, off int) (int, error) { _, n, e := decodeName(p, off); return n, e }
func rrTTLPositions(p []byte) ([]int, error) {
	if len(p) < 12 {
		return nil, errors.New("short DNS message")
	}
	off := 12
	qd := int(binary.BigEndian.Uint16(p[4:6]))
	counts := []int{int(binary.BigEndian.Uint16(p[6:8])), int(binary.BigEndian.Uint16(p[8:10])), int(binary.BigEndian.Uint16(p[10:12]))}
	for i := 0; i < qd; i++ {
		n, e := skipName(p, off)
		if e != nil {
			return nil, e
		}
		off = n + 4
		if off > len(p) {
			return nil, errors.New("truncated question")
		}
	}
	pos := []int{}
	for _, cnt := range counts {
		for i := 0; i < cnt; i++ {
			n, e := skipName(p, off)
			if e != nil {
				return nil, e
			}
			off = n
			if off+10 > len(p) {
				return nil, errors.New("truncated RR")
			}
			if binary.BigEndian.Uint16(p[off:off+2]) != 41 {
				pos = append(pos, off+4)
			}
			rd := int(binary.BigEndian.Uint16(p[off+8 : off+10]))
			off += 10 + rd
			if off > len(p) {
				return nil, errors.New("truncated RDATA")
			}
		}
	}
	return pos, nil
}
func minResponseTTL(p []byte) (uint32, bool) {
	pos, e := rrTTLPositions(p)
	if e != nil || len(pos) == 0 {
		return 0, false
	}
	var min uint32 = ^uint32(0)
	for _, o := range pos {
		v := binary.BigEndian.Uint32(p[o : o+4])
		if v < min {
			min = v
		}
	}
	return min, true
}
func decrementTTLs(p []byte, elapsed uint32) {
	pos, e := rrTTLPositions(p)
	if e != nil {
		return
	}
	for _, o := range pos {
		v := binary.BigEndian.Uint32(p[o : o+4])
		if v > elapsed {
			v -= elapsed
		} else {
			v = 0
		}
		binary.BigEndian.PutUint32(p[o:o+4], v)
	}
}
