package main

import (
	"context"
	"crypto/sha256"
	"errors"
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
	geoIndex, geoErr := newGeositeIndex(geositeDataPath(dataDir), autoHostsManager.State().Config.GeositeCategories)
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

type geositeIndex struct {
	path       string
	mu         sync.RWMutex
	reloadMu   sync.Mutex
	categories []string
	modTime    time.Time
	size       int64
	matcher    atomic.Pointer[geosite.Matcher]
}

func geositeDataPath(dataDir string) string {
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
		g.modTime = time.Time{}
		g.size = 0
		g.mu.Unlock()
		return nil
	}

	before, err := os.Stat(g.path)
	if err != nil {
		return err
	}
	matcher, err := geosite.Load(g.path, selected)
	if err != nil {
		return err
	}
	after, err := os.Stat(g.path)
	if err != nil {
		return err
	}
	if !before.ModTime().Equal(after.ModTime()) || before.Size() != after.Size() {
		return errors.New("geosite.dat changed while it was being loaded")
	}

	g.matcher.Store(matcher)
	g.mu.Lock()
	g.modTime = after.ModTime()
	g.size = after.Size()
	g.mu.Unlock()
	return nil
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

func (g *geositeIndex) reloadIfChanged() error {
	g.mu.RLock()
	selected := append([]string(nil), g.categories...)
	modTime, size := g.modTime, g.size
	g.mu.RUnlock()
	if len(selected) == 0 {
		return nil
	}
	info, err := os.Stat(g.path)
	if err != nil {
		return err
	}
	if info.ModTime().Equal(modTime) && info.Size() == size {
		return nil
	}
	return g.Reload(selected)
}

func (g *geositeIndex) run(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
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
