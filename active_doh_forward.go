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
	"sync/atomic"
	"time"

	"lucx-doh-health-monitor/internal/activedoh"
)

// sendActiveDoH forwards the original client DNS message to the DoH endpoint
// selected by ActiveDoHSelector. The TCP connection is pinned to a bootstrap
// address while the URL host, HTTP Host and TLS SNI remain the endpoint name.
	func sendActiveDoH(ctx context.Context, candidate activedoh.Candidate, packet []byte, timeout time.Duration) ([]byte, error) {
	return sendActiveDoHWithMetrics(ctx, candidate, packet, timeout, nil)
}

func sendActiveDoHWithMetrics(ctx context.Context, candidate activedoh.Candidate, packet []byte, timeout time.Duration, metrics *activeDoHForwardMetrics) ([]byte, error) {
	return sendActiveDoHWithClientFactoryAndMetrics(ctx, candidate, packet, timeout,
		func(ip, host string, attemptTimeout time.Duration) *http.Client {
			return newPinnedHTTPClient(ip, host, attemptTimeout)
		}, metrics)
}

type activeDoHForwardMetrics struct {
	extraAttempts    *atomic.Uint64
	hedgeWins        *atomic.Uint64
	qualityRejections *atomic.Uint64
}

type activeDoHHTTPClientFactory func(ip, host string, timeout time.Duration) *http.Client

const activeDoHHedgeDelay = 250 * time.Millisecond

func sendActiveDoHAttempt(
	ctx context.Context,
	candidate activedoh.Candidate,
	packet []byte,
	ip, host string,
	timeout time.Duration,
	newClient activeDoHHTTPClientFactory,
) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	attemptCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client := newClient(ip, host, timeout)
	if client == nil {
		return nil, errors.New("HTTP client creation failed")
	}
	request, err := http.NewRequestWithContext(attemptCtx, http.MethodPost, candidate.URL, bytes.NewReader(packet))
	if err != nil {
		client.CloseIdleConnections()
		return nil, fmt.Errorf("build selected DoH request: %w", err)
	}
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("Accept", "application/dns-message")
	response, err := client.Do(request)
	if err != nil {
		client.CloseIdleConnections()
		return nil, sanitizeDoHTransportError(err, candidate.URL)
	}
	defer response.Body.Close()
	defer client.CloseIdleConnections()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH HTTP %d", response.StatusCode)
	}
	contentType := strings.ToLower(response.Header.Get("Content-Type"))
	if !strings.Contains(contentType, "application/dns-message") {
		return nil, fmt.Errorf("unexpected DoH content-type %q", response.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxDNSMessage+1))
	if err != nil {
		return nil, errors.New("failed to read DoH DNS response")
	}
	if len(body) < 12 || len(body) > maxDNSMessage {
		return nil, fmt.Errorf("invalid DoH DNS response size %d", len(body))
	}
	if err := validateDNSResponse(packet, body, "selected DoH"); err != nil {
		return nil, err
	}
	if err := activeDoHResponseQualityError(body); err != nil {
		return nil, err
	}
	return body, nil
}

// The factory seam keeps endpoint pinning testable without weakening TLS
// verification or adding test-only behavior to the production transport.
func sendActiveDoHWithClientFactory(
	ctx context.Context,
	candidate activedoh.Candidate,
	packet []byte,
	timeout time.Duration,
	newClient activeDoHHTTPClientFactory,
) ([]byte, error) {
	return sendActiveDoHWithClientFactoryAndMetrics(ctx, candidate, packet, timeout, newClient, nil)
}

func sendActiveDoHWithClientFactoryAndMetrics(
	ctx context.Context,
	candidate activedoh.Candidate,
	packet []byte,
	timeout time.Duration,
	newClient activeDoHHTTPClientFactory,
	metrics *activeDoHForwardMetrics,
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

	// Hedge only within this selected endpoint's pinned bootstrap addresses.
	// The first address gets a head start; if it is slow, another address is
	// tried without waiting for the full request timeout.
	attemptCtx, cancelAttempts := context.WithCancel(ctx)
	defer cancelAttempts()

	type attemptResult struct {
		ip       string
		response []byte
		err      error
		he dged   bool
	}
	results := make(chan attemptResult, len(ips))
	nextIP := 0
	active := 0
	failures := make([]string, 0, len(ips))
	launch := func() {
		attemptIndex := nextIP
		ip := ips[attemptIndex]
		nextIP++
		active++
		if attemptIndex > 0 && metrics != nil && metrics.extraAttempts != nil {
			metrics.extraAttempts.Add(1)
		}
		go func(hedged bool) {
			body, err := sendActiveDoHAttempt(attemptCtx, candidate, packet, ip, host, timeout, newClient)
			results <- attemptResult{ip: ip, response: body, err: err, hedged: hedged}
		}(attemptIndex > 0)
	}
	launch()
	timer := time.NewTimer(activeDoHHedgeDelay)
	defer timer.Stop()

	for active > 0 || nextIP < len(ips) {
		select {
		case result := <-results:
			active--
			if result.err == nil {
				if result.hedged && metrics != nil && metrics.hedgeWins != nil {
					metrics.hedgeWins.Add(1)
				}
				return result.response, nil
			}
			var qualityErr *activeDoHQualityError
			if errors.As(result.err, &qualityErr) && metrics != nil && metrics.qualityRejections != nil {
				metrics.qualityRejections.Add(1)
			}
			failures = append(failures, result.ip+": "+result.err.Error())
			// A failed/low-quality response should not wait for the hedge timer.
			if nextIP < len(ips) {
				launch()
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(activeDoHHedgeDelay)
			}
		case <-timer.C:
			if nextIP < len(ips) {
				launch()
				timer.Reset(activeDoHHedgeDelay)
			}
		}
		if active == 0 && nextIP >= len(ips) {
			break
		}
	}
	return nil, fmt.Errorf("all bootstrap IP attempts for selected DoH endpoint %s failed: %s",
		host, strings.Join(failures, "; "))
}

// activeDoHQualityError identifies a syntactically valid DNS response that is
// not usable as a successful upstream result.
type activeDoHQualityError struct { reason string }

func (e *activeDoHQualityError) Error() string { return e.reason }

// activeDoHResponseQualityError rejects DNS responses that should not win an
// upstream attempt. This is deliberately query-scoped: it does not mark the
// selected provider unhealthy or alter ActiveDoHSelector's anti-flap policy.
func activeDoHResponseQualityError(response []byte) error {
	switch dnsRCode(response) {
	case 2:
		return &activeDoHQualityError{reason: "DoH upstream returned SERVFAIL"}
	case 5:
		return &activeDoHQualityError{reason: "DoH upstream returned REFUSED"}
	}
	if dnsTruncated(response) {
		return &activeDoHQualityError{reason: "DoH upstream returned a truncated DNS response"}
	}
	return nil
}
