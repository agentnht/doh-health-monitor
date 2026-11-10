package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
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
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	pluginID      = "doh-health-monitor"
	pluginVersion = "1.5.0"
	maxDNSMessage = 65535
	maxHTTPBody   = 2 << 20
)

type Config struct {
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
}
type Upstream struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	URL          string   `json:"-"`
	BootstrapIPs []string `json:"bootstrap_ips"`
}
type Group struct {
	ID        string   `json:"id"`
	FakeDNS   bool     `json:"fake_dns"`
	Domains   []string `json:"domains"`
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
	cfg       Config
	upstreams map[string]*UpstreamRuntime
	groups    map[string]Group
	byDomain  []domainBinding
	loadedAt  time.Time
	configMod time.Time
	dohMod    time.Time
	configSum string
}
type UpstreamRuntime struct {
	cfg       Upstream
	client    *http.Client
	bootstrap *bootstrapResolver
}

type bootstrapResolver struct {
	host        string
	endpoint    string
	resolvers   []string
	fallback    []string
	mu          sync.Mutex
	selectMu    sync.Mutex
	ips         []string
	refreshed   time.Time
	lastAttempt time.Time
	refreshFor  time.Duration
	selectedIP  string
	selectedTil time.Time
	probe       func(context.Context, string, string, time.Duration) (time.Duration, error)
}
type domainBinding struct{ suffix, groupID string }
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
	State         string        `json:"state"`
	Checks        []ProbeStatus `json:"checks,omitempty"`
	SuccessStreak int           `json:"success_streak"`
	FailureStreak int           `json:"failure_streak"`
	LastCheck     time.Time     `json:"last_check,omitempty"`
	LatencyMS     int64         `json:"latency_ms,omitempty"`
	LastError     string        `json:"last_error,omitempty"`
	LastHTTP      int           `json:"last_http_status,omitempty"`
	GeminiState   string        `json:"gemini_api_state,omitempty"`
}
type GroupStatus struct {
	ActiveUpstream string                 `json:"active_upstream"`
	Upstreams      map[string]HealthEntry `json:"upstreams"`
}
type Status struct {
	ID         string                 `json:"id"`
	Version    string                 `json:"version"`
	StartedAt  time.Time              `json:"started_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
	DNSUDP     string                 `json:"dns_udp"`
	DNSTCP     string                 `json:"dns_tcp"`
	HTTP       string                 `json:"http"`
	Config     string                 `json:"config"`
	Cache      CacheStatus            `json:"cache"`
	Groups     map[string]GroupStatus `json:"groups"`
	GeminiAPI  string                 `json:"gemini_api"`
	Queries    uint64                 `json:"queries"`
	CacheHits  uint64                 `json:"cache_hits"`
	Failures   uint64                 `json:"failures"`
	LastReload time.Time              `json:"last_reload,omitempty"`
	LastError  string                 `json:"last_error,omitempty"`
}
type CacheStatus struct {
	Enabled    bool `json:"enabled"`
	Entries    int  `json:"entries"`
	MaxEntries int  `json:"max_entries"`
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
	packet   []byte
	expires  time.Time
	inserted time.Time
}
type Runtime struct {
	dnsSem     chan struct{}
	dataDir    string
	configPath string
	dohPath    string
	snapshot   atomic.Pointer[Snapshot]
	mu         sync.RWMutex
	health     map[string]map[string]HealthEntry
	active     map[string]string
	cacheMu    sync.Mutex
	cache      map[string]cacheItem
	cacheHits  atomic.Uint64
	queries    atomic.Uint64
	failures   atomic.Uint64
	lastGemini map[string]time.Time
	statusMu   sync.RWMutex
	lastError  string
	lastReload time.Time
}

func main() {
	log.SetFlags(0)
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
	cfg, err := loadConfig(configPath)
	if err != nil {
		fatal("CONFIG invalid: %v", err)
	}
	dohURLs, err := loadDoHList(dohPath, true)
	if err != nil {
		fatal("DoH list invalid: %v", err)
	}
	snap, err := buildSnapshot(cfg, dohURLs)
	if err != nil {
		fatal("CONFIG invalid: %v", err)
	}
	if fi, e := os.Stat(configPath); e == nil {
		snap.configMod = fi.ModTime()
	}
	if fi, e := os.Stat(dohPath); e == nil {
		snap.dohMod = fi.ModTime()
	}
	rt := &Runtime{dataDir: dataDir, configPath: configPath, dohPath: dohPath, health: map[string]map[string]HealthEntry{}, active: map[string]string{}, cache: map[string]cacheItem{}, lastGemini: map[string]time.Time{}, dnsSem: make(chan struct{}, cfg.DNSMaxConcurrent)}
	rt.snapshot.Store(snap)
	rt.initHealth(snap)
	logLine("INFO", "CONFIG loaded path=%s doh_list=%s groups=%d upstreams=%d dns_udp=%s dns_tcp=%s gemini_api=%t", configPath, dohPath, len(cfg.Groups), len(cfg.Upstreams), cfg.DNSListenUDP, cfg.DNSListenTCP, cfg.GeminiAPI.Enabled)

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
	wg.Add(5)
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
		logLine("WARN", "CONFIG_TEMPLATE_CREATED path=%s; review domain groups and bootstrap_resolvers", path)
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
	if e = validateConfig(c); e != nil {
		return Config{}, e
	}
	return c, nil
}
func defaultConfig() Config {
	return Config{
		DNSListenUDP: "127.0.0.1:5355", DNSListenTCP: "127.0.0.1:5355", HTTPListen: "127.0.0.1:18765", ReloadSecs: 5,
		DNSQueryTimeoutSeconds: 15, DoHTimeoutSeconds: 10, DNSMaxConcurrent: 256,
		Health: HealthConfig{IntervalSeconds: 45, TimeoutSeconds: 5, FailureThreshold: 3, SuccessThreshold: 5},
		Cache:  CacheConfig{Enabled: true, MinTTL: 5, MaxTTL: 300, NegativeTTL: 15, MaxEntries: 8192},
		BootstrapResolvers: []string{"1.1.1.1", "8.8.8.8"},
		Upstreams: []Upstream{
			{ID: "dns.google", Name: "Google Public DNS"},
			{ID: "cloudflare-dns.com", Name: "Cloudflare"},
			{ID: "dns.quad9.net", Name: "Quad9"},
		},
		Groups: []Group{
			{ID: "default", Domains: []string{}, Upstreams: []string{"dns.google", "cloudflare-dns.com", "dns.quad9.net"}, Checks: []Check{{Domain: "example.com", Required: true}}},
			{ID: "google", FakeDNS: true, Domains: []string{"google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "google.org", "googleadservices.com", "gemini.google.com", "generativelanguage.googleapis.com", "clients6.google.com", "jnn-pa.googleapis.com", "waa-pa.clients6.google.com"}, Upstreams: []string{"dns.google", "cloudflare-dns.com", "dns.quad9.net"}, Checks: []Check{
				{Domain: "gemini.google.com", HTTPURL: "https://gemini.google.com/", Required: true, ExpectedStatus: []int{200, 301, 302, 403}},
				{Domain: "accounts.google.com", HTTPURL: "https://accounts.google.com/.well-known/openid-configuration", Required: true, ExpectedStatus: []int{200}, VerifyOIDC: true},
				{Domain: "www.gstatic.com", HTTPURL: "https://www.gstatic.com/", Required: true, ExpectedStatus: []int{200, 301, 302, 403}},
				{Domain: "ssl.gstatic.com", HTTPURL: "https://ssl.gstatic.com/", Required: false, ExpectedStatus: []int{200, 301, 302, 403}},
				{Domain: "fonts.googleapis.com", HTTPURL: "https://fonts.googleapis.com/css2?family=Roboto", Required: false, ExpectedStatus: []int{200}},
				{Domain: "fonts.gstatic.com", Required: false},
				{Domain: "www.googleapis.com", HTTPURL: "https://www.googleapis.com/", Required: false, ExpectedStatus: []int{200, 301, 302, 403}},
				{Domain: "apis.google.com", Required: false},
				{Domain: "jnn-pa.googleapis.com", Required: false},
				{Domain: "waa-pa.clients6.google.com", Required: false},
			}},
			{ID: "netflix", FakeDNS: true, Domains: []string{"netflix.com", "nflxvideo.net", "nflximg.net", "nflxso.net", "nflxext.com", "netflix.net"}, Upstreams: []string{"cloudflare-dns.com", "dns.google", "dns.quad9.net"}, Checks: []Check{{Domain: "www.netflix.com", HTTPURL: "https://www.netflix.com/", Required: true, ExpectedStatus: []int{200, 301, 302, 403}}}},
			{ID: "openai", FakeDNS: true, Domains: []string{"openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com"}, Upstreams: []string{"cloudflare-dns.com", "dns.google", "dns.quad9.net"}, Checks: []Check{{Domain: "chatgpt.com", HTTPURL: "https://chatgpt.com/", Required: true, ExpectedStatus: []int{200, 301, 302, 403}}}},
			{ID: "youtube", FakeDNS: true, Domains: []string{"youtube.com", "youtubei.googleapis.com", "googlevideo.com", "ytimg.com", "youtu.be", "youtube-nocookie.com"}, Upstreams: []string{"dns.google", "cloudflare-dns.com", "dns.quad9.net"}, Checks: []Check{{Domain: "www.youtube.com", HTTPURL: "https://www.youtube.com/", Required: true, ExpectedStatus: []int{200, 301, 302, 403}}}},
		},
		GeminiAPI: GeminiAPIConfig{Enabled: false, RequiredForGroup: false, GroupID: "google", Model: "gemini-3.8-flash", IntervalSeconds: 1800, KeyFile: "gemini_api_key", Prompt: "Reply with exactly OK.", MaxOutputTokens: 8},
	}
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
	if c.Cache.MinTTL < 0 || c.Cache.MaxTTL < 1 || c.Cache.MaxTTL < c.Cache.MinTTL || c.Cache.NegativeTTL < 0 || c.Cache.MaxEntries < 0 {
		return errors.New("invalid cache settings")
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
	ids := map[string]bool{}
	for _, u := range c.Upstreams {
		if u.ID == "" || ids[u.ID] {
			return fmt.Errorf("upstream id empty or duplicate: %q", u.ID)
		}
		ids[u.ID] = true
		if strings.ContainsAny(u.ID, "/:@ \t") {
			return fmt.Errorf("upstream id must be a hostname: %s", u.ID)
		}
		for _, ip := range u.BootstrapIPs {
			if net.ParseIP(ip) == nil {
				return fmt.Errorf("invalid bootstrap IP %q in %s", ip, u.ID)
			}
		}
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
		for _, d := range g.Domains {
			if normalizeDomain(d) == "" {
				return fmt.Errorf("invalid domain in group %s", g.ID)
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
	if !groups["default"] {
		return errors.New("a group with id 'default' is required")
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
func validListen(s string) bool {
	h, p, e := net.SplitHostPort(s)
	return e == nil && h != "" && p != ""
}
func normalizeDomain(s string) string {
	return strings.Trim(strings.ToLower(strings.TrimSpace(s)), ".")
}
func defaultDoHURLs() map[string]string {
	return map[string]string{
		"dns.google":         "https://dns.google/dns-query",
		"cloudflare-dns.com": "https://cloudflare-dns.com/dns-query",
		"dns.quad9.net":      "https://dns.quad9.net/dns-query",
	}
}
func loadDoHList(path string, create bool) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && create {
		var lines []string
		for _, u := range []string{"https://dns.google/dns-query", "https://cloudflare-dns.com/dns-query", "https://dns.quad9.net/dns-query"} {
			lines = append(lines, u)
		}
		if err = os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
			return nil, err
		}
		b, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for n, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		u, e := url.Parse(line)
		if e != nil || u.Scheme != "https" || u.Hostname() == "" {
			return nil, fmt.Errorf("doh-servers.txt line %d: expected https://host/dns-query", n+1)
		}
		id := strings.ToLower(u.Hostname())
		if _, exists := out[id]; exists {
			return nil, fmt.Errorf("duplicate DoH hostname %s", id)
		}
		out[id] = line
	}
	if len(out) == 0 {
		return nil, errors.New("doh-servers.txt contains no DoH URLs")
	}
	return out, nil
}

func buildSnapshot(c Config, dohURLs map[string]string) (*Snapshot, error) {
	s := &Snapshot{cfg: c, upstreams: map[string]*UpstreamRuntime{}, groups: map[string]Group{}, loadedAt: time.Now().UTC()}
	known := map[string]bool{}
	for _, u := range c.Upstreams {
		known[u.ID] = true
	}
	for id := range dohURLs {
		if !known[id] {
			return nil, fmt.Errorf("DoH server %s in doh-servers.txt has no upstream/bootstrap entry in config.json", id)
		}
	}
	resolvers := c.BootstrapResolvers
	if len(resolvers) == 0 {
		resolvers = defaultBootstrapResolvers()
	}
	for _, u := range c.Upstreams {
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
		for _, d := range g.Domains {
			d = normalizeDomain(d)
			if d != "" {
				s.byDomain = append(s.byDomain, domainBinding{d, g.ID})
			}
		}
	}
	sort.Slice(s.byDomain, func(i, j int) bool { return len(s.byDomain[i].suffix) > len(s.byDomain[j].suffix) })
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

			refreshedIP, refreshErr := bootstrap.bestIP(ctx, true, timeout)
			if refreshErr == nil && refreshedIP != ip {
				retryConn, retryErr := (&net.Dialer{Timeout: minDuration(timeout, 5*time.Second), KeepAlive: 30 * time.Second}).
					DialContext(ctx, network, net.JoinHostPort(refreshedIP, port))
				if retryErr == nil {
					return retryConn, nil
				}
				return nil, fmt.Errorf("selected IP %s failed (%v); refreshed fastest IP %s failed: %w", ip, dialErr, refreshedIP, retryErr)
			}
			if refreshErr != nil {
				return nil, fmt.Errorf("selected IP %s failed: %v; bootstrap refresh failed: %w", ip, dialErr, refreshErr)
			}
			return nil, fmt.Errorf("selected IP %s failed: %w", ip, dialErr)
		},
	}
	client := &http.Client{
		Transport: tr, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return client, bootstrap, nil
}

func defaultBootstrapResolvers() []string { return []string{"1.1.1.1", "8.8.8.8"} }

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
	resolver := &net.Resolver{
		PreferGo: true, StrictErrors: false,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var last error
			for _, server := range b.resolvers {
				conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, net.JoinHostPort(server, "53"))
				if err == nil {
					return conn, nil
				}
				last = err
			}
			if last == nil {
				last = errors.New("no bootstrap DNS resolvers configured")
			}
			return nil, last
		},
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	found, err := resolver.LookupNetIP(lookupCtx, "ip", b.host)
	ips := make([]string, 0, len(found))
	seen := map[string]bool{}
	for _, ip := range found {
		v := ip.String()
		if net.ParseIP(v) != nil && !seen[v] {
			seen[v] = true
			ips = append(ips, v)
		}
	}
	if len(ips) > 0 {
		b.ips = ips
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
	b.mu.Unlock()

	ips, resolveErr := b.addresses(ctx, force)
	if len(ips) == 0 {
		if resolveErr == nil {
			resolveErr = errors.New("no bootstrap IPs available")
		}
		return "", resolveErr
	}
	ip, latency, probeErr := b.fastestIP(ctx, ips, timeout)
	usingFallback := false
	if probeErr != nil && len(b.fallback) > 0 {
		fallbackIP, fallbackLatency, fallbackErr := b.fastestIP(ctx, b.fallback, timeout)
		if fallbackErr == nil {
			ip, latency, probeErr, usingFallback = fallbackIP, fallbackLatency, nil, true
		}
	}
	if probeErr != nil {
		if resolveErr != nil {
			return "", fmt.Errorf("no responsive DoH address: %v (DNS resolution: %w)", probeErr, resolveErr)
		}
		return "", fmt.Errorf("no responsive DoH address: %w", probeErr)
	}

	b.mu.Lock()
	b.selectedIP = ip
	if resolveErr == nil && !usingFallback {
		b.selectedTil = time.Now().Add(b.refreshFor)
	} else {
		// Retry DNS resolution periodically while temporarily relying on cached/fallback IPs.
		b.selectedTil = time.Now().Add(time.Minute)
	}
	b.mu.Unlock()

	logLine("INFO", "DoH IP selected hostname=%s ip=%s response_ms=%d candidates=%d fallback=%t", b.host, ip, latency.Milliseconds(), len(ips), usingFallback)
	return ip, nil
}

func (b *bootstrapResolver) fastestIP(ctx context.Context, ips []string, timeout time.Duration) (string, time.Duration, error) {
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
			probeCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			latency, err := probe(probeCtx, b.endpoint, ip, timeout)
			results <- result{ip: ip, latency: latency, err: err}
		}()
	}

	var bestIP string
	var bestLatency time.Duration
	var failures []string
	for range ips {
		select {
		case <-ctx.Done():
			return "", 0, ctx.Err()
		case res := <-results:
			if res.err != nil {
				failures = append(failures, res.ip+": "+res.err.Error())
				continue
			}
			if bestIP == "" || res.latency < bestLatency {
				bestIP, bestLatency = res.ip, res.latency
			}
		}
	}
	if bestIP == "" {
		return "", 0, fmt.Errorf("all DoH IP probes failed: %s", strings.Join(failures, "; "))
	}
	return bestIP, bestLatency, nil
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
	for gid, g := range s.groups {
		if r.health[gid] == nil {
			r.health[gid] = map[string]HealthEntry{}
		}
		for _, uid := range g.Upstreams {
			if _, ok := r.health[gid][uid]; !ok {
				r.health[gid][uid] = HealthEntry{State: "unknown", GeminiState: "not_checked"}
			}
		}
		if r.active[gid] == "" && len(g.Upstreams) > 0 {
			r.active[gid] = g.Upstreams[0]
		}
	}
}
func (r *Runtime) currentSnapshot() *Snapshot { return r.snapshot.Load() }
func (r *Runtime) groupFor(domain string, s *Snapshot) string {
	domain = normalizeDomain(domain)
	for _, b := range s.byDomain {
		if domain == b.suffix || strings.HasSuffix(domain, "."+b.suffix) {
			return b.groupID
		}
	}
	return "default"
}
func (r *Runtime) orderedUpstreams(gid string, s *Snapshot) []string {
	g, ok := s.groups[gid]
	if !ok {
		g = s.groups["default"]
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
func (r *Runtime) query(ctx context.Context, packet []byte) ([]byte, string, error) {
	name, _, _, e := parseQuestion(packet)
	if e != nil {
		return nil, "", e
	}
	s := r.currentSnapshot()
	gid := r.groupFor(name, s)
	order := r.orderedUpstreams(gid, s)
	var errs []string
	for _, uid := range order {
		u := s.upstreams[uid]
		if u == nil {
			continue
		}
		resp, e := sendDoH(ctx, u, packet)
		if e == nil {
			if dnsRCode(resp) == 2 || dnsRCode(resp) == 5 {
				e = fmt.Errorf("upstream returned DNS RCODE %d", dnsRCode(resp))
			} else if dnsTruncated(resp) {
				e = errors.New("upstream returned truncated response; TCP retry not available over DoH")
			} else {
				return resp, uid, nil
			}
		}
		errs = append(errs, uid+": "+e.Error())
	}
	r.failures.Add(1)
	return nil, "", fmt.Errorf("all upstreams failed for %s (%s)", name, strings.Join(errs, "; "))
}
func sendDoH(ctx context.Context, u *UpstreamRuntime, packet []byte) ([]byte, error) {
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, u.cfg.URL, bytes.NewReader(packet))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, e := u.client.Do(req)
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
	if len(b) < 12 || len(b) > maxDNSMessage {
		return nil, errors.New("invalid DNS response size")
	}
	if _, _, _, e = parseQuestion(b); e != nil {
		return nil, fmt.Errorf("invalid DoH DNS response: %w", e)
	}
	if binary.BigEndian.Uint16(b[2:4])&0x8000 == 0 {
		return nil, errors.New("DoH returned a DNS packet without QR response flag")
	}
	if packetID(b) != packetID(packet) {
		return nil, errors.New("DoH response transaction ID does not match query")
	}
	return b, nil
}
func (r *Runtime) serveUDP(ctx context.Context, c *net.UDPConn) {
	buf := make([]byte, maxDNSMessage)
	for {
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, e := c.ReadFromUDP(buf)
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Timeout() {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}
			if ctx.Err() != nil {
				return
			}
			logLine("WARN", "DNS UDP read: %v", e)
			continue
		}
		q := append([]byte(nil), buf[:n]...)
		go func(a *net.UDPAddr, p []byte) {
			resp := r.handleDNS(p)
			if len(resp) > 4096 {
				resp = resp[:4096]
			}
			_, _ = c.WriteToUDP(resp, a)
		}(addr, q)
	}
}
func (r *Runtime) serveTCP(ctx context.Context, ln net.Listener) {
	for {
		_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
		conn, e := ln.Accept()
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Timeout() {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}
			if ctx.Err() != nil {
				return
			}
			logLine("WARN", "DNS TCP accept: %v", e)
			continue
		}
		go r.handleTCPConn(ctx, conn)
	}
}
func (r *Runtime) handleTCPConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(120 * time.Second))
	for {
		var l [2]byte
		if _, e := io.ReadFull(c, l[:]); e != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(l[:]))
		if n < 12 || n > maxDNSMessage {
			return
		}
		q := make([]byte, n)
		if _, e := io.ReadFull(c, q); e != nil {
			return
		}
		resp := r.handleDNS(q)
		if len(resp) > maxDNSMessage {
			return
		}
		binary.BigEndian.PutUint16(l[:], uint16(len(resp)))
		if _, e := c.Write(l[:]); e != nil {
			return
		}
		if _, e := c.Write(resp); e != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
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
	name, _, _, e := parseQuestion(packet)
	if e != nil {
		return formerrResponse(packet)
	}
	s := r.currentSnapshot()
	cacheKey := cacheKey(packet)
	if s.cfg.Cache.Enabled {
		if v, ok := r.cacheGet(cacheKey, packetID(packet)); ok {
			r.cacheHits.Add(1)
			return v
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.cfg.DNSQueryTimeoutSeconds)*time.Second)
	defer cancel()
	resp, uid, e := r.query(ctx, packet)
	if e != nil {
		return servfailResponse(packet)
	}
	if s.cfg.Cache.Enabled {
		r.cachePut(cacheKey, resp, s.cfg.Cache)
	}
	logLine("DEBUG", "DNS answer domain=%s group=%s upstream=%s", name, r.groupFor(name, s), uid)
	return resp
}
func (r *Runtime) cacheGet(key string, id uint16) ([]byte, bool) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	v, ok := r.cache[key]
	if !ok {
		return nil, false
	}
	if time.Now().After(v.expires) {
		delete(r.cache, key)
		return nil, false
	}
	b := append([]byte(nil), v.packet...)
	binary.BigEndian.PutUint16(b[:2], id)
	decrementTTLs(b, uint32(time.Since(v.inserted).Seconds()))
	return b, true
}
func (r *Runtime) cachePut(key string, packet []byte, c CacheConfig) {
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
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	if c.MaxEntries > 0 && len(r.cache) >= c.MaxEntries {
		for k, v := range r.cache {
			if time.Now().After(v.expires) {
				delete(r.cache, k)
			}
		}
		if len(r.cache) >= c.MaxEntries {
			for k := range r.cache {
				delete(r.cache, k)
				break
			}
		}
	}
	b := append([]byte(nil), packet...)
	r.cache[key] = cacheItem{packet: b, expires: time.Now().Add(time.Duration(ttl) * time.Second), inserted: time.Now()}
}
func cacheKey(p []byte) string {
	b := append([]byte(nil), p...)
	if len(b) >= 2 {
		b[0] = 0
		b[1] = 0
	}
	return hex.EncodeToString(b)
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
	resp, e := sendDoH(ctx, u, q)
	return resp, u.cfg.ID, e
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
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, (256<<10)+1))
	if readErr != nil {
		return resp.StatusCode, fmt.Errorf("read HTTP probe response: %w", readErr)
	}
	if len(body) > 256<<10 {
		return resp.StatusCode, errors.New("HTTP probe response exceeds 256 KiB")
	}
	ok := len(ch.ExpectedStatus) == 0 && resp.StatusCode >= 200 && resp.StatusCode < 400
	for _, s := range ch.ExpectedStatus {
		if s == resp.StatusCode {
			ok = true
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
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}, ForceAttemptHTTP2: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
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
	if r.health[gid] == nil {
		r.health[gid] = map[string]HealthEntry{}
	}
	e := r.health[gid][uid]
	e.LastCheck = time.Now().UTC()
	e.LatencyMS = lat.Milliseconds()
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
	s := r.currentSnapshot()
	r.mu.Lock()
	defer r.mu.Unlock()
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
	for {
		delay := time.Duration(r.currentSnapshot().cfg.ReloadSecs) * time.Second
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		old := r.currentSnapshot()
		cfi, ce := os.Stat(r.configPath)
		dfi, de := os.Stat(r.dohPath)
		if ce != nil || de != nil {
			r.setError("stat configuration files failed")
			continue
		}
		if !cfi.ModTime().After(old.configMod) && !dfi.ModTime().After(old.dohMod) {
			continue
		}
		cfg, e := loadConfigNoCreate(r.configPath)
		if e != nil {
			r.setError("config reload rejected: " + e.Error())
			logLine("ERROR", "CONFIG reload rejected: %v", e)
			continue
		}
		if cfg.DNSListenUDP != old.cfg.DNSListenUDP || cfg.DNSListenTCP != old.cfg.DNSListenTCP || cfg.HTTPListen != old.cfg.HTTPListen || cfg.DNSMaxConcurrent != old.cfg.DNSMaxConcurrent {
			r.setError("listener or dns_max_concurrent changed; restart plugin to apply")
			logLine("WARN", "CONFIG listener/dns_max_concurrent change requires plugin restart")
			continue
		}
		dohURLs, e := loadDoHList(r.dohPath, false)
		if e != nil {
			r.setError("DoH list reload rejected: " + e.Error())
			logLine("ERROR", "DOH list reload rejected: %v", e)
			continue
		}
		ns, e := buildSnapshot(cfg, dohURLs)
		if e != nil {
			r.setError("config reload rejected: " + e.Error())
			logLine("ERROR", "CONFIG reload rejected: %v", e)
			continue
		}
		ns.configMod, ns.dohMod = cfi.ModTime(), dfi.ModTime()
		r.snapshot.Store(ns)
		r.initHealth(ns)
		r.cacheMu.Lock()
		r.cache = map[string]cacheItem{}
		r.cacheMu.Unlock()
		r.mu.Lock()
		r.lastReload = time.Now().UTC()
		r.mu.Unlock()
		r.setError("")
		logLine("INFO", "CONFIG reloaded upstreams=%d groups=%d", len(cfg.Upstreams), len(cfg.Groups))
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
	out := Status{ID: envOr("LUCX_PLUGIN_ID", pluginID), Version: envOr("LUCX_PLUGIN_VERSION", pluginVersion), StartedAt: startedAt, UpdatedAt: time.Now().UTC(), DNSUDP: s.cfg.DNSListenUDP, DNSTCP: s.cfg.DNSListenTCP, HTTP: s.cfg.HTTPListen, Config: r.configPath, Cache: CacheStatus{Enabled: s.cfg.Cache.Enabled, Entries: r.cacheLen(), MaxEntries: s.cfg.Cache.MaxEntries}, Groups: map[string]GroupStatus{}, Queries: r.queries.Load(), CacheHits: r.cacheHits.Load(), Failures: r.failures.Load(), GeminiAPI: "disabled"}
	r.mu.RLock()
	for gid, g := range s.groups {
		gs := GroupStatus{ActiveUpstream: r.active[gid], Upstreams: map[string]HealthEntry{}}
		for _, uid := range g.Upstreams {
			gs.Upstreams[uid] = r.health[gid][uid]
		}
		out.Groups[gid] = gs
	}
	r.mu.RUnlock()
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

func (r *Runtime) cacheLen() int { r.cacheMu.Lock(); defer r.cacheMu.Unlock(); return len(r.cache) }
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
			pos = append(pos, off+4)
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
