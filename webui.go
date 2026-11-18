package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed webui/*
var webUIAssets embed.FS

const webUISessionCookie = "doh_web_session"

const autoHostsAPITokenFile = "auto-hosts-api.token"

func loadOrCreateAutoHostsAPIToken(dataDir string) (string, error) {
	if strings.TrimSpace(dataDir) == "" {
		return "", errors.New("plugin data directory is required for Auto Hosts API token")
	}
	path := filepath.Join(dataDir, autoHostsAPITokenFile)

	if token, err := readAutoHostsAPIToken(dataDir); err == nil {
		return token, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate Auto Hosts API token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return readAutoHostsAPIToken(dataDir)
	}
	if err != nil {
		return "", err
	}
	if _, err = io.WriteString(file, token+"\n"); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		_ = os.Remove(path)
		return "", err
	}
	if closeErr != nil {
		_ = os.Remove(path)
		return "", closeErr
	}
	return token, nil
}

func readAutoHostsAPIToken(dataDir string) (string, error) {
	if strings.TrimSpace(dataDir) == "" {
		return "", errors.New("plugin data directory is required")
	}
	path := filepath.Join(dataDir, autoHostsAPITokenFile)
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return "", errors.New("Auto Hosts API token file must be regular and mode 0600")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(data))
	if len(token) < 40 || len(token) > 128 {
		return "", errors.New("Auto Hosts API token file has invalid length")
	}
	return token, nil
}

func bearerToken(header string) (string, bool) {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

func requireAutoHostsAPIToken(token string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackWebHost(r.Host) || !isLoopbackRemoteAddr(r.RemoteAddr) || !validWebUIOrigin(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		provided, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok || subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

type webUIProbeStatus struct {
	Domain      string `json:"domain"`
	Required    bool   `json:"required"`
	DNSOK       bool   `json:"dns_ok"`
	HTTPChecked bool   `json:"http_checked"`
	HTTPOK      bool   `json:"http_ok"`
	HTTPStatus  int    `json:"http_status,omitempty"`
}

type webUIUpstreamStatus struct {
	State           string             `json:"state"`
	SuccessStreak   int                `json:"success_streak"`
	FailureStreak   int                `json:"failure_streak"`
	LastCheck       *time.Time         `json:"last_check,omitempty"`
	CheckDurationMS int64              `json:"check_duration_ms,omitempty"`
	LastHTTP        int                `json:"last_http_status,omitempty"`
	Checks          []webUIProbeStatus `json:"checks,omitempty"`
}

type webUIGroupStatus struct {
	ActiveUpstream string                         `json:"active_upstream"`
	Upstreams      map[string]webUIUpstreamStatus `json:"upstreams"`
}

type webUIStatus struct {
	ID            string                      `json:"id"`
	Version       string                      `json:"version"`
	StartedAt     time.Time                   `json:"started_at"`
	UpdatedAt     time.Time                   `json:"updated_at"`
	DNSUDP        string                      `json:"dns_udp"`
	DNSTCP        string                      `json:"dns_tcp"`
	HTTP          string                      `json:"http"`
	Cache         CacheStatus                 `json:"cache"`
	Groups        map[string]webUIGroupStatus `json:"groups"`
	GeminiAPI     string                      `json:"gemini_api"`
	Queries       uint64                      `json:"queries"`
	CacheHits     uint64                      `json:"cache_hits"`
	Failures      uint64                      `json:"failures"`
	ActiveUDP     int64                       `json:"active_udp"`
	UDPQueueDepth int64                       `json:"udp_queue_depth"`
	UDPDropped    uint64                      `json:"udp_dropped"`
	ActiveTCP     int64                       `json:"active_tcp"`
	TCPRejected   uint64                      `json:"tcp_rejected"`
}

func webUIHandler() http.Handler {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "Web UI session initialization failed", http.StatusInternalServerError)
		})
	}
	return newWebUIHandlerWithDataDir("http://127.0.0.1:18765/status", base64.RawURLEncoding.EncodeToString(token), strings.TrimSpace(os.Getenv("LUCX_PLUGIN_DATA")))
}

func newWebUIHandler(statusURL, sessionToken string) http.Handler {
	return newWebUIHandlerWithDataDir(statusURL, sessionToken, strings.TrimSpace(os.Getenv("LUCX_PLUGIN_DATA")))
}

func newWebUIHandlerWithDataDir(statusURL, launchToken, dataDir string) http.Handler {
	cookieBytes := make([]byte, 32)
	if _, err := rand.Read(cookieBytes); err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "Web UI session initialization failed", http.StatusInternalServerError)
		})
	}
	cookieToken := base64.RawURLEncoding.EncodeToString(cookieBytes)
	var launchMu sync.Mutex
	launchUsed := false
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setWebUISecurityHeaders(w)
		if !isLoopbackWebHost(r.Host) {
			http.Error(w, "invalid host", http.StatusForbidden)
			return
		}
		if !validWebUIOrigin(r) {
			http.Error(w, "invalid origin", http.StatusForbidden)
			return
		}

		switch r.URL.Path {
		case "/":
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			// The shell contains no private data; API access requires the session
			// cookie issued by the one-time fragment-token exchange below.
			serveWebUIAsset(w, r, "webui/index.html", "text/html; charset=utf-8")
		case "/session/exchange":
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", "POST")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 2048)
			var input struct {
				Token string `json:"token"`
			}
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				http.Error(w, "invalid launch exchange", http.StatusBadRequest)
				return
			}
			launchMu.Lock()
			valid := !launchUsed && input.Token != "" &&
				subtle.ConstantTimeCompare([]byte(input.Token), []byte(launchToken)) == 1
			if valid {
				launchUsed = true
				launchToken = ""
			}
			launchMu.Unlock()
			if !valid {
				http.Error(w, "launch token expired or already used", http.StatusUnauthorized)
				return
			}
			http.SetCookie(w, &http.Cookie{
				Name: webUISessionCookie, Value: cookieToken, Path: "/",
				HttpOnly: true, SameSite: http.SameSiteStrictMode,
				MaxAge: 3600,
			})
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNoContent)
		case "/app.js":
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			serveWebUIAsset(w, r, "webui/app.js", "text/javascript; charset=utf-8")
		case "/api/v1/status":
			if r.Method != http.MethodGet {
				w.Header().Set("Allow", "GET")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if !webUIRequestAuthorized(r, cookieToken) {
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
			apiToken, tokenErr := readAutoHostsAPIToken(dataDir)
			if tokenErr != nil && strings.TrimSpace(dataDir) != "" {
				http.Error(w, "local status authentication is unavailable", http.StatusServiceUnavailable)
				return
			}
			status, err := fetchWebUIStatus(r.Context(), statusURL, apiToken)
			if err != nil {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(w, "{\"error\":\"daemon_status_unavailable\"}\n")
				return
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(status)
		case "/api/v1/config", "/api/v1/config/defaults", "/api/v1/sources",
			"/api/v1/gemini-key", "/api/v1/logs", "/api/v1/integration/logs",
			"/api/v1/tests/run", "/api/v1/integration":
			if !webUIRequestAuthorized(r, cookieToken) {
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
			webUIAdminAPI(w, r, r.URL.Path, dataDir)
		case "/api/v1/autohosts/status", "/api/v1/autohosts/config", "/api/v1/autohosts/dry-run", "/api/v1/autohosts/geosite-categories":
			if !webUIRequestAuthorized(r, cookieToken) {
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
			proxyWebUIAutoHostsAPI(w, r, statusURL, dataDir)
		default:
			http.NotFound(w, r)
		}
	})
}

func proxyWebUIAutoHostsAPI(w http.ResponseWriter, r *http.Request, statusURL, dataDir string) {
	apiToken, tokenErr := readAutoHostsAPIToken(dataDir)
	if tokenErr != nil {
		http.Error(w, "local Auto Hosts API authentication is unavailable", http.StatusServiceUnavailable)
		return
	}
	parsed, err := url.Parse(statusURL)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Host == "" ||
		parsed.Path != "/status" || parsed.RawQuery != "" || parsed.Fragment != "" || !isLoopbackWebHost(parsed.Host) {
		http.Error(w, "invalid local status URL", http.StatusServiceUnavailable)
		return
	}
	var endpoint string
	switch r.URL.Path {
	case "/api/v1/autohosts/status":
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		endpoint = "/autohosts/status"
	case "/api/v1/autohosts/config":
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		endpoint = "/autohosts/config"
	case "/api/v1/autohosts/dry-run":
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		endpoint = "/autohosts/dry-run"
	case "/api/v1/autohosts/geosite-categories":
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		endpoint = "/geosite/categories"
	default:
		http.NotFound(w, r)
		return
	}
	var body io.Reader
	if r.Body != nil {
		data, readErr := io.ReadAll(io.LimitReader(r.Body, (16<<10)+1))
		if readErr != nil || len(data) > 16<<10 {
			http.Error(w, "request body is invalid or too large", http.StatusBadRequest)
			return
		}
		body = bytes.NewReader(data)
	}
	target := parsed.Scheme + "://" + parsed.Host + endpoint
	ctx := r.Context()
	timeout := 10 * time.Second
	if endpoint == "/autohosts/dry-run" {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, r.Method, target, body)
	if err != nil {
		http.Error(w, "could not create local Auto Hosts request", http.StatusBadGateway)
		return
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	transport := &http.Transport{Proxy: nil}
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer transport.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "local Auto Hosts API is unavailable", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, (2<<20)+1))
	if err != nil || len(data) > 2<<20 {
		http.Error(w, "local Auto Hosts response is invalid or too large", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(data)
}

func webUIRequestAuthorized(r *http.Request, cookieToken string) bool {
	cookie, err := r.Cookie(webUISessionCookie)
	return err == nil && subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(cookieToken)) == 1
}

func setWebUISecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
}

func serveWebUIAsset(w http.ResponseWriter, r *http.Request, name, contentType string) {
	page, err := webUIAssets.ReadFile(name)
	if err != nil {
		http.Error(w, "asset not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(page)
	}
}

func validWebUIOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	if parsed.Scheme != "http" || !isLoopbackWebHost(parsed.Host) {
		return false
	}
	return strings.EqualFold(parsed.Host, r.Host)
}

func isLoopbackRemoteAddr(value string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil {
		host = strings.TrimSpace(value)
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func isLoopbackWebHost(value string) bool {
	host := strings.TrimSpace(value)
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func webUIStatusURLFromConfig() (string, error) {
	dataDir := strings.TrimSpace(os.Getenv("LUCX_PLUGIN_DATA"))
	if dataDir == "" {
		return "", errors.New("LUCX_PLUGIN_DATA is required for Web UI status")
	}
	configPath := filepath.Join(dataDir, "config.json")
	cfg, err := loadConfigNoCreate(configPath)
	if err != nil {
		return "", fmt.Errorf("read plugin config for Web UI status: %w", err)
	}
	host, port, err := net.SplitHostPort(cfg.HTTPListen)
	if err != nil || !isLoopbackWebHost(host) || port == "" {
		return "", errors.New("plugin status listener must use a loopback address")
	}
	return "http://" + net.JoinHostPort(host, port) + "/status", nil
}

func fetchWebUIStatus(ctx context.Context, statusURL string, tokens ...string) (webUIStatus, error) {
	parsed, err := url.Parse(statusURL)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Host == "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "/status" ||
		!isLoopbackWebHost(parsed.Host) {
		return webUIStatus{}, errors.New("invalid local status URL")
	}
	transport := &http.Transport{Proxy: nil}
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	defer transport.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, statusURL, nil)
	if err != nil {
		return webUIStatus{}, err
	}
	req.Header.Set("Accept", "application/json")
	if len(tokens) > 0 && tokens[0] != "" {
		req.Header.Set("Authorization", "Bearer "+tokens[0])
	}
	resp, err := client.Do(req)
	if err != nil {
		return webUIStatus{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return webUIStatus{}, fmt.Errorf("local status endpoint returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return webUIStatus{}, errors.New("local status response is invalid or too large")
	}
	var raw Status
	if err := json.Unmarshal(data, &raw); err != nil {
		return webUIStatus{}, errors.New("local status response is not valid JSON")
	}
	out := webUIStatus{
		ID: raw.ID, Version: raw.Version, StartedAt: raw.StartedAt, UpdatedAt: raw.UpdatedAt,
		DNSUDP: raw.DNSUDP, DNSTCP: raw.DNSTCP, HTTP: raw.HTTP, Cache: raw.Cache,
		Groups: map[string]webUIGroupStatus{}, GeminiAPI: raw.GeminiAPI,
		Queries: raw.Queries, CacheHits: raw.CacheHits, Failures: raw.Failures,
		ActiveUDP: raw.ActiveUDP, UDPQueueDepth: raw.UDPQueueDepth, UDPDropped: raw.UDPDropped,
		ActiveTCP: raw.ActiveTCP, TCPRejected: raw.TCPRejected,
	}
	for groupID, group := range raw.Groups {
		safeGroup := webUIGroupStatus{ActiveUpstream: group.ActiveUpstream, Upstreams: map[string]webUIUpstreamStatus{}}
		for upstreamID, upstream := range group.Upstreams {
			var lastCheck *time.Time
			if !upstream.LastCheck.IsZero() {
				checkedAt := upstream.LastCheck
				lastCheck = &checkedAt
			}
			var safeChecks []webUIProbeStatus
			for _, check := range upstream.Checks {
				safeChecks = append(safeChecks, webUIProbeStatus{
					Domain: check.Domain, Required: check.Required, DNSOK: check.DNSOK,
					HTTPChecked: check.HTTPChecked, HTTPOK: check.HTTPOK, HTTPStatus: check.HTTPStatus,
				})
			}
			safeGroup.Upstreams[upstreamID] = webUIUpstreamStatus{
				State: upstream.State, SuccessStreak: upstream.SuccessStreak, FailureStreak: upstream.FailureStreak,
				LastCheck: lastCheck, CheckDurationMS: upstream.CheckDurationMS, LastHTTP: upstream.LastHTTP, Checks: safeChecks,
			}
		}
		out.Groups[groupID] = safeGroup
	}
	return out, nil
}

func writeWebUILaunchToken(dataDir, token string) error {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dataDir, ".web-ui-launch-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := io.WriteString(tmp, token+"\n"); err != nil {
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
	return os.Rename(name, filepath.Join(dataDir, "web-ui-launch.token"))
}

// runWebUI starts only the temporary management HTTP server. EOF on stdin is
// the supervisor control signal: the SSH menu owns the pipe's write end.
func runWebUI() error {
	statusURL, err := webUIStatusURLFromConfig()
	if err != nil {
		return err
	}
	return runWebUIWithStatusURL(statusURL)
}

func runWebUIWithStatusURL(statusURL string) error {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return fmt.Errorf("create Web UI session token: %w", err)
	}
	sessionToken := base64.RawURLEncoding.EncodeToString(token)
	handler := newWebUIHandlerWithDataDir(statusURL, sessionToken, strings.TrimSpace(os.Getenv("LUCX_PLUGIN_DATA")))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen on Web UI loopback: %w", err)
	}

	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 3 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	serveResult := make(chan error, 1)
	go func() {
		serveResult <- server.Serve(listener)
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	dataDir := strings.TrimSpace(os.Getenv("LUCX_PLUGIN_DATA"))
	if dataDir == "" {
		_ = listener.Close()
		return errors.New("LUCX_PLUGIN_DATA is required for Web UI launch token")
	}
	if err := writeWebUILaunchToken(dataDir, sessionToken); err != nil {
		_ = listener.Close()
		return fmt.Errorf("write Web UI launch token: %w", err)
	}
	if _, err := fmt.Fprintf(os.Stdout, "WEB_UI_READY port=%d\n", port); err != nil {
		_ = listener.Close()
		return fmt.Errorf("write Web UI readiness: %w", err)
	}

	controlClosed := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		close(controlClosed)
	}()

	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)

	select {
	case serveErr := <-serveResult:
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			return fmt.Errorf("Web UI HTTP server stopped: %w", serveErr)
		}
		return nil
	case <-controlClosed:
		logLine("INFO", "WEB_UI supervisor control pipe closed")
	case sig := <-signals:
		logLine("INFO", "WEB_UI shutdown signal=%s", sig)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		_ = server.Close()
		return fmt.Errorf("graceful Web UI shutdown failed: %w", err)
	}
	if serveErr := <-serveResult; serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return fmt.Errorf("Web UI HTTP server stopped: %w", serveErr)
	}
	logLine("INFO", "WEB_UI stopped cleanly")
	return nil
}
