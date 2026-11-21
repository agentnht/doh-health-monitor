package plugincheck

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const (
	defaultService   = "lucx-plugin-doh-health-monitor"
	defaultStatusURL = "http://127.0.0.1:18765/healthz"
)

type Error struct {
	Message string
}

func (e *Error) Error() string { return e.Message }

func problem(format string, args ...any) error {
	return &Error{Message: fmt.Sprintf(format, args...)}
}

// Options contains only the local read-only preflight parameters.
type Options struct {
	Timeout            time.Duration
	Service, StatusURL string
	Port               int
}

func DefaultOptions() Options {
	return Options{
		Timeout:   15 * time.Second,
		Service:   defaultService,
		StatusURL: defaultStatusURL,
		Port:      5355,
	}
}

func IsLocalURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Hostname() == "" ||
		u.RawQuery != "" || u.Fragment != "" || u.Path != "/healthz" {
		return false
	}
	if strings.EqualFold(u.Hostname(), "localhost") {
		return true
	}
	ip := net.ParseIP(u.Hostname())
	return ip != nil && ip.IsLoopback()
}

type Logger interface {
	Printf(string, ...any)
}

// checkPluginHealth performs local, read-only checks only. It does not load a
// panel API client, discover panel credentials, mint tokens, or mutate Xray.
func checkPluginHealth(opts Options, logger Logger) error {
	if !regexp.MustCompile("^[A-Za-z0-9_.@-]+$").MatchString(opts.Service) {
		return problem("Invalid DoH Health Monitor systemd service name")
	}
	if !IsLocalURL(opts.StatusURL) {
		return problem("DoH Health Monitor status URL must use localhost/loopback")
	}
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return problem("Required preflight tool systemctl was not found")
	}
	ss, err := exec.LookPath("ss")
	if err != nil {
		return problem("Required preflight tool ss was not found")
	}
	run := func(timeout time.Duration, name string, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Stdin = nil
		out, runErr := cmd.CombinedOutput()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return out, runErr
	}
	load, err := run(5*time.Second, systemctl, "show", "--property=LoadState", "--value", opts.Service)
	if err != nil || strings.TrimSpace(string(load)) != "loaded" {
		return problem("DoH Health Monitor service %q is not installed/loaded; no panel API operation was attempted", opts.Service)
	}
	if _, err := run(5*time.Second, systemctl, "is-active", "--quiet", opts.Service); err != nil {
		return problem("DoH Health Monitor service %q is not active; no panel API operation was attempted", opts.Service)
	}
	if logger != nil {
		logger.Printf("PASS: DoH Health Monitor service %q is installed and active", opts.Service)
	}
	for _, item := range []struct {
		name, flag string
	}{{"TCP", "-ltn"}, {"UDP", "-lun"}} {
		out, err := run(5*time.Second, ss, "-H", item.flag)
		if err != nil || !listenerHasLoopback(string(out), opts.Port) {
			return problem("DoH Health Monitor loopback listener %d/%s is not active; no panel API operation was attempted", opts.Port, item.name)
		}
		if logger != nil {
			logger.Printf("PASS: DoH Health Monitor loopback listener %d/%s is active", opts.Port, item.name)
		}
	}
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequest(http.MethodGet, opts.StatusURL, nil)
	if err != nil {
		return problem("DoH Health Monitor health URL is invalid")
	}
	req.Header.Set("Accept", "text/plain")
	resp, err := client.Do(req)
	if err != nil {
		return problem("DoH Health Monitor health endpoint is unavailable; no panel API operation was attempted")
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 65))
	if err != nil || resp.StatusCode != http.StatusOK || len(data) > 64 || strings.TrimSpace(string(data)) != "ok" {
		return problem("DoH Health Monitor health endpoint is unavailable; no panel API operation was attempted")
	}
	if logger != nil {
		logger.Printf("PASS: DoH Health Monitor minimal /healthz endpoint returns ok")
	}
	return nil
}

func listenerHasLoopback(output string, port int) bool {
	re := regexp.MustCompile(fmt.Sprintf("(127\\.0\\.0\\.1|\\[?::1\\]?):%d(\\s|$)", port))
	for _, line := range strings.Split(output, "\n") {
		if re.MatchString(line) {
			return true
		}
	}
	return false
}
