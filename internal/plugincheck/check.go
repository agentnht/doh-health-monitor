package plugincheck

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	defaultService   = "lucx-plugin-doh-health-monitor"
	defaultStatusURL = "http://127.0.0.1:18765/healthz"
)

var serviceNamePattern = regexp.MustCompile("^[A-Za-z0-9_.@-]+$")
var listenerPIDPattern = regexp.MustCompile(`pid=(\d+)`)

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

	// Executable overrides are deliberately unexported: production callers
	// cannot redirect the privileged preflight to arbitrary commands.
	systemctlPath string
	ssPath        string
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

func executablePath(name, override string) (string, error) {
	if override != "" {
		if !filepath.IsAbs(override) {
			return "", fmt.Errorf("override path is not absolute")
		}
		if err := validateExecutable(override); err != nil {
			return "", err
		}
		return filepath.Clean(override), nil
	}

	candidates := map[string][]string{
		"systemctl": {"/usr/bin/systemctl", "/bin/systemctl"},
		"ss":        {"/usr/bin/ss", "/usr/sbin/ss", "/bin/ss", "/sbin/ss"},
	}
	for _, path := range candidates[name] {
		if err := validateExecutable(path); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("no executable found in standard absolute paths")
}

func validateExecutable(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("path must be absolute")
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("path is not an executable regular file")
	}
	return nil
}

// checkPluginHealth performs local, read-only checks only. It does not load a
// panel API client, discover panel credentials, mint tokens, or mutate Xray.
func checkPluginHealth(opts Options, logger Logger) error {
	if !serviceNamePattern.MatchString(opts.Service) {
		return problem("Invalid DoH Health Monitor systemd service name")
	}
	if !IsLocalURL(opts.StatusURL) {
		return problem("DoH Health Monitor health URL must use localhost/loopback")
	}
	systemctl, err := executablePath("systemctl", opts.systemctlPath)
	if err != nil {
		return problem("Required absolute-path preflight tool systemctl was not found")
	}
	ss, err := executablePath("ss", opts.ssPath)
	if err != nil {
		return problem("Required absolute-path preflight tool ss was not found")
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
	pidOutput, err := run(5*time.Second, systemctl, "show", "--property=MainPID", "--value", opts.Service)
	mainPID, parseErr := strconv.Atoi(strings.TrimSpace(string(pidOutput)))
	if err != nil || parseErr != nil || mainPID <= 1 {
		return problem("DoH Health Monitor service %q has no valid MainPID; no panel API operation was attempted", opts.Service)
	}
	if logger != nil {
		logger.Printf("PASS: DoH Health Monitor service %q is active (MainPID=%d)", opts.Service, mainPID)
	}

	for _, item := range []struct {
		name, flag string
	}{
		{"TCP", "-ltnp"},
		{"UDP", "-lunp"},
	} {
		out, err := run(5*time.Second, ss, "-H", item.flag)
		if err != nil || !listenerOwnedByPID(string(out), opts.Port, mainPID) {
			return problem("DoH Health Monitor loopback %s listener %d is not owned by service MainPID %d; no panel API operation was attempted", item.name, opts.Port, mainPID)
		}
		if logger != nil {
			logger.Printf("PASS: DoH Health Monitor loopback listener %d/%s belongs to MainPID=%d", opts.Port, item.name, mainPID)
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

// listenerOwnedByPID requires both a loopback bind and an ss process owner
// matching systemd's MainPID. A process merely occupying the port is not enough.
func listenerOwnedByPID(output string, port, pid int) bool {
	if port < 1 || port > 65535 || pid <= 1 {
		return false
	}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		// ss -H -ltnp / -lunp: state, recv-q, send-q, local, peer, users...
		if len(fields) < 6 {
			continue
		}
		host, rawPort, err := net.SplitHostPort(fields[3])
		if err != nil {
			continue
		}
		listenerPort, err := strconv.Atoi(rawPort)
		if err != nil || listenerPort != port {
			continue
		}
		ip := net.ParseIP(strings.Trim(host, "[]"))
		if ip == nil || !ip.IsLoopback() {
			continue
		}
		for _, match := range listenerPIDPattern.FindAllStringSubmatch(strings.Join(fields[5:], " "), -1) {
			ownerPID, err := strconv.Atoi(match[1])
			if err == nil && ownerPID == pid {
				return true
			}
		}
	}
	return false
}
