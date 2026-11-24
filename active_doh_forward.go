package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"lucx-doh-health-monitor/internal/activedoh"
)

// sendActiveDoH forwards the original client DNS message to the DoH endpoint
// selected by ActiveDoHSelector. The TCP connection is pinned to a bootstrap
// address while the URL host, HTTP Host and TLS SNI remain the endpoint name.
func sendActiveDoH(ctx context.Context, candidate activedoh.Candidate, packet []byte, timeout time.Duration) ([]byte, error) {
	return sendActiveDoHWithClientFactory(ctx, candidate, packet, timeout,
		func(ip, host string, attemptTimeout time.Duration) *http.Client {
			return newPinnedHTTPClient(ip, host, attemptTimeout)
		})
}

type activeDoHHTTPClientFactory func(ip, host string, timeout time.Duration) *http.Client

// The factory seam keeps endpoint pinning testable without weakening TLS
// verification or adding test-only behavior to the production transport.
func sendActiveDoHWithClientFactory(
	ctx context.Context,
	candidate activedoh.Candidate,
	packet []byte,
	timeout time.Duration,
	newClient activeDoHHTTPClientFactory,
) ([]byte, error) {
	if len(packet) < 12 || len(packet) > maxDNSMessage {
		return nil, errors.New("invalid DNS query size for selected DoH endpoint")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if newClient == nil {
		return nil, errors.New("selected DoH HTTP client factory is unavailable")
	}
	endpoint, err := url.Parse(strings.TrimSpace(candidate.URL))
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil {
		return nil, errors.New("selected DoH endpoint URL is invalid")
	}
	host := strings.TrimSpace(candidate.Hostname)
	if host == "" {
		host = endpoint.Hostname()
	}
	if !strings.EqualFold(strings.TrimSuffix(host, "."), strings.TrimSuffix(endpoint.Hostname(), ".")) {
		return nil, errors.New("selected DoH endpoint hostname does not match its URL")
	}

	ips := make([]string, 0, len(candidate.IPv4)+len(candidate.IPv6))
	for _, raw := range append(append([]string(nil), candidate.IPv4...), candidate.IPv6...) {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if !isPublicDoHIP(ip) {
			continue
		}
		ips = appendUniqueString(ips, ip.String())
	}
	if len(ips) == 0 {
		return nil, errors.New("selected DoH endpoint has no usable bootstrap IP")
	}

	var failures []string
	for _, ip := range ips {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		attemptCtx, cancel := context.WithTimeout(ctx, timeout)
		client := newClient(ip, host, timeout)
		if client == nil {
			cancel()
			failures = append(failures, ip+": HTTP client creation failed")
			continue
		}
		request, requestErr := http.NewRequestWithContext(attemptCtx, http.MethodPost, candidate.URL, bytes.NewReader(packet))
		if requestErr != nil {
			cancel()
			client.CloseIdleConnections()
			return nil, fmt.Errorf("build selected DoH request: %w", requestErr)
		}
		request.Header.Set("Content-Type", "application/dns-message")
		request.Header.Set("Accept", "application/dns-message")
		response, requestErr := client.Do(request)
		if requestErr != nil {
			cancel()
			client.CloseIdleConnections()
			failures = append(failures, ip+": "+sanitizeDoHTransportError(requestErr, candidate.URL).Error())
			continue
		}
		if response.StatusCode != http.StatusOK {
			status := response.StatusCode
			_ = response.Body.Close()
			cancel()
			client.CloseIdleConnections()
			failures = append(failures, fmt.Sprintf("%s: DoH HTTP %d", ip, status))
			continue
		}
		if contentType := strings.ToLower(response.Header.Get("Content-Type")); !strings.Contains(contentType, "application/dns-message") {
			contentType = response.Header.Get("Content-Type")
			_ = response.Body.Close()
			cancel()
			client.CloseIdleConnections()
			failures = append(failures, fmt.Sprintf("%s: unexpected DoH content-type %q", ip, contentType))
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, maxDNSMessage+1))
		_ = response.Body.Close()
		cancel()
		client.CloseIdleConnections()
		if readErr != nil {
			failures = append(failures, ip+": failed to read DoH DNS response")
			continue
		}
		if len(body) < 12 || len(body) > maxDNSMessage {
			failures = append(failures, fmt.Sprintf("%s: invalid DoH DNS response size %d", ip, len(body)))
			continue
		}
		if validateErr := validateDNSResponse(packet, body, "selected DoH"); validateErr != nil {
			failures = append(failures, ip+": "+validateErr.Error())
			continue
		}
		// A structurally valid DNS packet is not necessarily a usable answer.
		// Try another pinned bootstrap address for transient/negative service
		// failures, but keep NXDOMAIN and other authoritative DNS answers intact.
		if qualityErr := activeDoHResponseQualityError(body); qualityErr != nil {
			failures = append(failures, ip+": "+qualityErr.Error())
			continue
		}
		return body, nil
	}
	return nil, fmt.Errorf("all bootstrap IPs for selected DoH endpoint %s failed: %s",
		host, strings.Join(failures, "; "))
}

// activeDoHResponseQualityError rejects DNS responses that should not win an
// upstream attempt. This is deliberately query-scoped: it does not mark the
// selected provider unhealthy or alter ActiveDoHSelector's anti-flap policy.
func activeDoHResponseQualityError(response []byte) error {
	switch dnsRCode(response) {
	case 2:
		return errors.New("DoH upstream returned SERVFAIL")
	case 5:
		return errors.New("DoH upstream returned REFUSED")
	}
	if dnsTruncated(response) {
		return errors.New("DoH upstream returned a truncated DNS response")
	}
	return nil
}
