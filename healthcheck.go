package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const daemonHealthTimeout = 3 * time.Second

func runHealthCheckCLI() error {
	dataDir := strings.TrimSpace(os.Getenv("LUCX_PLUGIN_DATA"))
	if dataDir == "" {
		return fmt.Errorf("LUCX_PLUGIN_DATA is required for healthcheck")
	}
	cfg, err := loadConfigNoCreate(filepath.Join(dataDir, "config.json"))
	if err != nil {
		return fmt.Errorf("read daemon config: %w", err)
	}
	client := &http.Client{
		Timeout: daemonHealthTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if err := probeDaemonHealth(client, cfg.HTTPListen); err != nil {
		return err
	}
	return nil
}

func probeDaemonHealth(client *http.Client, listenAddress string) error {
	host, port, err := net.SplitHostPort(listenAddress)
	if err != nil {
		return fmt.Errorf("invalid HTTP listener address %q: %w", listenAddress, err)
	}
	target := (&url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(host, port),
		Path:   "/healthz",
	}).String()

	ctx, cancel := context.WithTimeout(context.Background(), daemonHealthTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return fmt.Errorf("create health request: %w", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("daemon health endpoint unavailable: %w", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, 16))
	if err != nil {
		return fmt.Errorf("read daemon health response: %w", err)
	}
	if response.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "ok" {
		return fmt.Errorf("daemon health endpoint returned HTTP %d and body %q", response.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}
