package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

//go:embed webui/index.html
var webUIAssets embed.FS

func webUIHandler() http.Handler {
	page, err := webUIAssets.ReadFile("webui/index.html")
	if err != nil {
		panic("embedded Web UI page is missing: " + err.Error())
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackWebHost(r.Host) {
			http.Error(w, "invalid host", http.StatusForbidden)
			return
		}
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(page)
	})
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

// runWebUI starts only the temporary management HTTP server. EOF on stdin is
// the supervisor control signal: the SSH menu owns the pipe's write end.
func runWebUI() error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen on Web UI loopback: %w", err)
	}

	server := &http.Server{
		Handler:           webUIHandler(),
		ReadHeaderTimeout: 3 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	serveResult := make(chan error, 1)
	go func() {
		serveResult <- server.Serve(listener)
	}()

	port := listener.Addr().(*net.TCPAddr).Port
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
