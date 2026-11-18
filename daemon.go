package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"lucx-doh-health-monitor/internal/autohosts"
	"lucx-doh-health-monitor/internal/geosite"
)

func runDaemon() {
	dataDir := strings.TrimSpace(os.Getenv("LUCX_PLUGIN_DATA"))
	if dataDir == "" {
		fatal("LUCX_PLUGIN_DATA is required")
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		fatal("create data dir: %v", err)
	}
	_ = os.Chmod(dataDir, 0700)
	autoHostsAPIToken, err := loadOrCreateAutoHostsAPIToken(dataDir)
	if err != nil {
		fatal("AUTO_HOSTS API token initialization failed: %v", err)
	}
	logLine("INFO", "START id=%s version=%s arch=%s data=%s", envOr("LUCX_PLUGIN_ID", pluginID), envOr("LUCX_PLUGIN_VERSION", pluginVersion), runtime.GOARCH, dataDir)

	configPath := filepath.Join(dataDir, "config.json")
	dohPath := filepath.Join(dataDir, "doh-servers.txt")
	checksPath := filepath.Join(dataDir, "tst-domen.txt")
	if err := initializeConfigSourceFiles(dataDir); err != nil {
		fatal("CONFIG sources initialization failed: %v", err)
	}
	cfg, err := loadConfig(configPath)
	if err != nil {
		fatal("CONFIG invalid: %v", err)
	}
	sources, err := readConfigSources(dohPath, checksPath)
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
	if configData, e := os.ReadFile(configPath); e == nil {
		snap.configHash = sha256.Sum256(configData)
	}
	autoHostsManager, err := autohosts.New(filepath.Join(dataDir, "auto-hosts.json"))
	if err != nil {
		fatal("AUTO_HOSTS state initialization failed: %v", err)
	}
	geoIndex, geoErr := newGeositeIndex(geositeDataPath(dataDir, cfg.GeositePath), autoHostsManager.State().Config.GeositeCategories)
	if geoErr != nil {
		logLine("WARN", "GEOSITE initial load failed: %v", geoErr)
	}
	vpsResolve, err := newVPSResolveUpstream(time.Duration(cfg.DoHTimeoutSeconds) * time.Second)
	if err != nil {
		fatal("VPS_RESOLVE Quad9 initialization failed: %v", err)
	}
	rt := &Runtime{
		dataDir: dataDir, autoHosts: autoHostsManager, geo: geoIndex, vpsResolve: vpsResolve,
		autoHostsQueryQueue: make(chan *autoHostsQueryJob, 256), autoHostsQueued: make(map[string]*autoHostsQueryJob),
		configPath: configPath, dohPath: dohPath, checksPath: checksPath,
		sourceHashes:       sources.Checksums,
		healthCheckTrigger: make(chan struct{}, 1),
		health:             map[string]map[string]HealthEntry{}, active: map[string]string{},
		cache: map[string]cacheItem{}, lastGemini: map[string]time.Time{},
		dnsSem: make(chan struct{}, cfg.DNSMaxConcurrent),
	}
	rt.snapshot.Store(snap)
	rt.autoController = newAutoHostsController(rt, autoHostsManager)
	rt.initHealth(snap)
	logLine("INFO", "CONFIG loaded path=%s doh_list=%s checks_list=%s groups=%d upstreams=%d checks=%d dns_udp=%s dns_tcp=%s gemini_api=%t", configPath, dohPath, checksPath, len(cfg.Groups), len(cfg.Upstreams), len(sources.Checks), cfg.DNSListenUDP, cfg.DNSListenTCP, cfg.GeminiAPI.Enabled)

	udpConn, tcpLn, dnsUDPAddress, dnsTCPAddress, err := bindDNSListeners(cfg, dataDir)
	if err != nil {
		fatal("DNS listeners: %v", err)
	}
	rt.dnsUDPAddress = dnsUDPAddress
	rt.dnsTCPAddress = dnsTCPAddress
	logLine("INFO", "DNS_LISTENERS_BOUND mode=%s udp=%s tcp=%s", cfg.DNSPortMode, dnsUDPAddress, dnsTCPAddress)
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	httpMux.HandleFunc("/status", requireAutoHostsAPIToken(autoHostsAPIToken, rt.handleStatus))
	httpMux.HandleFunc("/autohosts/status", requireAutoHostsAPIToken(autoHostsAPIToken, rt.handleAutoHostsStatus))
	httpMux.HandleFunc("/autohosts/config", requireAutoHostsAPIToken(autoHostsAPIToken, rt.handleAutoHostsConfig))
	httpMux.HandleFunc("/autohosts/dry-run", requireAutoHostsAPIToken(autoHostsAPIToken, rt.handleAutoHostsDryRun))
	httpMux.HandleFunc("/geosite/categories", requireAutoHostsAPIToken(autoHostsAPIToken, rt.handleGeositeCategories))
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
	wg.Add(8)
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
	go func() { defer wg.Done(); rt.autoController.run(ctx) }()
	go func() { defer wg.Done(); rt.geo.run(ctx) }()
	go func() { defer wg.Done(); rt.runAutoHostsQueryRecorder(ctx) }()
	logLine("INFO", "READY DNS=%s/%s HTTP=%s", dnsUDPAddress, dnsTCPAddress, cfg.HTTPListen)

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

type geositeIndex struct {
	path             string
	mu               sync.RWMutex
	reloadMu         sync.Mutex
	categories       []string
	loadedCategories []string
	modTime          time.Time
	loadedAt         time.Time
	size             int64
	fileHash         [32]byte
	lastError        string
	matcher          atomic.Pointer[geosite.Matcher]
}

type geositeStatus struct {
	Path             string    `json:"path"`
	Selected         []string  `json:"selected_categories"`
	LoadedCategories []string  `json:"loaded_categories"`
	Loaded           bool      `json:"loaded"`
	LoadedAt         time.Time `json:"loaded_at,omitempty"`
	FileModTime      time.Time `json:"file_mod_time,omitempty"`
	FileSize         int64     `json:"file_size,omitempty"`
	FileSHA256       string    `json:"file_sha256,omitempty"`
	LastError        string    `json:"last_error,omitempty"`
}

func (g *geositeIndex) Status() geositeStatus {
	if g == nil {
		return geositeStatus{LastError: "Geosite index is unavailable"}
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return geositeStatus{
		Path: g.path, Selected: append([]string(nil), g.categories...),
		LoadedCategories: append([]string(nil), g.loadedCategories...),
		Loaded:           g.matcher.Load() != nil, LoadedAt: g.loadedAt,
		FileModTime: g.modTime, FileSize: g.size, FileSHA256: fmt.Sprintf("%x", g.fileHash), LastError: g.lastError,
	}
}

func geositeDataPath(dataDir string, override ...string) string {
	if len(override) > 0 && strings.TrimSpace(override[0]) != "" {
		return filepath.Clean(strings.TrimSpace(override[0]))
	}
	binDir := filepath.Dir(filepath.Dir(filepath.Dir(dataDir)))
	return filepath.Join(binDir, "geosite.dat")
}

func newGeositeIndex(path string, selected []string) (*geositeIndex, error) {
	index := &geositeIndex{path: path}
	if len(selected) == 0 {
		return index, nil
	}
	return index, index.Reload(selected)
}

func (g *geositeIndex) ValidateCategories(selected []string) error {
	if len(selected) == 0 {
		return nil
	}
	if g == nil {
		return errors.New("Geosite index is unavailable")
	}
	_, err := geosite.Load(g.path, selected)
	return err
}

func (g *geositeIndex) Reload(selected []string) error {
	if g == nil {
		return errors.New("Geosite index is unavailable")
	}
	g.reloadMu.Lock()
	defer g.reloadMu.Unlock()

	selected = append([]string(nil), selected...)
	g.mu.Lock()
	g.categories = selected
	g.mu.Unlock()
	if len(selected) == 0 {
		g.matcher.Store(nil)
		g.mu.Lock()
		g.loadedCategories = nil
		g.modTime = time.Time{}
		g.loadedAt = time.Time{}
		g.size = 0
		g.fileHash = [32]byte{}
		g.lastError = ""
		g.mu.Unlock()
		return nil
	}
	data, info, digest, err := readGeositeSnapshot(g.path)
	if err != nil {
		return g.recordReloadError(err)
	}
	return g.publishSnapshot(selected, data, info, digest)
}

func (g *geositeIndex) recordReloadError(err error) error {
	if g != nil && err != nil {
		g.mu.Lock()
		g.lastError = err.Error()
		g.mu.Unlock()
	}
	return err
}

func (g *geositeIndex) Categories() ([]string, error) {
	if g == nil {
		return nil, errors.New("Geosite index is unavailable")
	}
	return geosite.ListCategories(g.path)
}

func (g *geositeIndex) MatchAny(qname string) bool {
	if g == nil {
		return false
	}
	matcher := g.matcher.Load()
	return matcher != nil && matcher.MatchAny(qname)
}

// readGeositeSnapshot reads one stable inode and rejects a path replacement or
// in-place mutation observed during the read. The digest detects replacements
// even when size and mtime are deliberately preserved.
func readGeositeSnapshot(path string) ([]byte, os.FileInfo, [32]byte, error) {
	var zero [32]byte
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, zero, fmt.Errorf("open geosite.dat: %w", err)
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return nil, nil, zero, fmt.Errorf("stat open geosite.dat: %w", err)
	}
	const maxSize = 128 << 20
	if !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > maxSize {
		return nil, nil, zero, errors.New("geosite.dat is not a regular file or exceeds size limit")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxSize+1))
	if err != nil {
		return nil, nil, zero, fmt.Errorf("read geosite.dat: %w", err)
	}
	after, err := file.Stat()
	if err != nil {
		return nil, nil, zero, fmt.Errorf("restat open geosite.dat: %w", err)
	}
	current, err := os.Stat(path)
	if err != nil {
		return nil, nil, zero, fmt.Errorf("restat geosite.dat path: %w", err)
	}
	if !os.SameFile(before, current) || before.Size() != after.Size() ||
		!before.ModTime().Equal(after.ModTime()) || int64(len(data)) != after.Size() {
		return nil, nil, zero, errors.New("geosite.dat changed while it was being read")
	}
	return data, after, sha256.Sum256(data), nil
}

func (g *geositeIndex) publishSnapshot(selected []string, data []byte, info os.FileInfo, digest [32]byte) error {
	matcher, err := geosite.Parse(data, selected)
	if err != nil {
		return g.recordReloadError(err)
	}
	// Publish the fully parsed immutable matcher in one atomic operation.
	g.matcher.Store(matcher)
	g.mu.Lock()
	g.loadedCategories = append([]string(nil), selected...)
	g.modTime = info.ModTime()
	g.loadedAt = time.Now().UTC()
	g.size = info.Size()
	g.fileHash = digest
	g.lastError = ""
	g.mu.Unlock()
	return nil
}

func (g *geositeIndex) reloadIfChanged() error {
	g.mu.RLock()
	selected := append([]string(nil), g.categories...)
	loadedHash := g.fileHash
	loaded := g.matcher.Load() != nil
	g.mu.RUnlock()
	if len(selected) == 0 {
		return nil
	}
	data, info, digest, err := readGeositeSnapshot(g.path)
	if err != nil {
		return g.recordReloadError(err)
	}
	if loaded && digest == loadedHash {
		g.mu.Lock()
		g.lastError = ""
		g.mu.Unlock()
		return nil
	}
	return g.publishSnapshot(selected, data, info, digest)
}

func (g *geositeIndex) run(ctx context.Context) {
	g.runWithInterval(ctx, 30*time.Second)
}

func (g *geositeIndex) runWithInterval(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	lastError := ""
	for {
		if err := g.reloadIfChanged(); err != nil {
			message := err.Error()
			if message != lastError {
				logLine("WARN", "GEOSITE reload failed: %v", err)
				lastError = message
			}
		} else {
			lastError = ""
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
