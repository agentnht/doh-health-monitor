package main

import (
	"bufio"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestWebUIHandlerServesOnlyLoopbackRoot(t *testing.T) {
	handler := webUIHandler()

	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:19876/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "127.0.0.1:19876"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status=%d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), "DoH Health Monitor") {
		t.Fatal("placeholder page content is missing")
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("Web UI response must not be cached")
	}
	if len(rec.Result().Cookies()) != 1 || rec.Result().Cookies()[0].Name != webUISessionCookie {
		t.Fatal("root page must issue the per-session HttpOnly cookie")
	}
	if !strings.Contains(rec.Body.String(), "/app.js") {
		t.Fatal("dashboard JavaScript asset is missing from the page")
	}
	page := rec.Body.String()
	if got := strings.Count(page, `<section class="panel dashboard-panel">`); got != 1 {
		t.Fatalf("dashboard should have exactly one combined data panel, got %d", got)
	}
	if got := strings.Count(page, `<section class="dashboard-column dashboard-`); got != 2 {
		t.Fatalf("dashboard should have exactly two columns, got %d", got)
	}
	for _, want := range []string{
		`class="dashboard-column dashboard-overview"`,
		`class="dashboard-column dashboard-upstreams"`,
		`class="metric-list"`,
			`<h2>DNS listeners</h2>`,
			`<h2>Запросы и ресурсы</h2>`,
			`<h2>Upstream-группы</h2>`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("dashboard is missing expected layout element %q", want)
		}
	}
	if strings.Index(page, `id="dns-udp"`) > strings.Index(page, `id="dns-tcp"`) {
		t.Fatal("TCP listener must appear below UDP listener")
	}
	if !(strings.Index(page, `<h2>DNS listeners</h2>`) < strings.Index(page, `<h2>Запросы и ресурсы</h2>`) &&
		strings.Index(page, `<h2>Запросы и ресурсы</h2>`) < strings.Index(page, `<h2>Upstream-группы</h2>`)) {
		t.Fatal("dashboard sections must be ordered: DNS listeners, resources, upstream groups")
	}

	if got := strings.Count(page, `aria-expanded="false"`); got != 6 {
		t.Fatalf("all six section buttons must start collapsed, got %d collapsed buttons", got)
	}
	if got := strings.Count(page, `<section class="panel tab-page`); got != 6 {
		t.Fatalf("all section panels must start hidden; got %d", got)
	}
	if strings.Count(page, `class="tab-button"`) != 6 {
		t.Fatal("expected six independent collapsible section buttons")
	}
	for _, want := range []string{
		`data-page="hosts"`,
		`data-page-panel="hosts"`,
		`id="hosts-rows"`,
		`id="hosts-save"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("local hosts editor is missing %q", want)
		}
	}

	badHost := req.Clone(req.Context())
	badHost.Host = "example.org"
	badHost.URL.Path = "/"
	badHostRecorder := httptest.NewRecorder()
	handler.ServeHTTP(badHostRecorder, badHost)
	if badHostRecorder.Code != http.StatusForbidden {
		t.Fatalf("untrusted Host status=%d, want %d", badHostRecorder.Code, http.StatusForbidden)
	}

	badOrigin := req.Clone(req.Context())
	badOrigin.Header.Set("Origin", "http://attacker.example")
	badOriginRecorder := httptest.NewRecorder()
	handler.ServeHTTP(badOriginRecorder, badOrigin)
	if badOriginRecorder.Code != http.StatusForbidden {
		t.Fatalf("untrusted Origin status=%d, want %d", badOriginRecorder.Code, http.StatusForbidden)
	}

	badMethod := req.Clone(req.Context())
	badMethod.Method = http.MethodPost
	methodRecorder := httptest.NewRecorder()
	handler.ServeHTTP(methodRecorder, badMethod)
	if methodRecorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status=%d, want %d", methodRecorder.Code, http.StatusMethodNotAllowed)
	}

	notFound := req.Clone(req.Context())
	notFound.URL.Path = "/api/anything"
	notFoundRecorder := httptest.NewRecorder()
	handler.ServeHTTP(notFoundRecorder, notFound)
	if notFoundRecorder.Code != http.StatusNotFound {
		t.Fatalf("unknown path status=%d, want %d", notFoundRecorder.Code, http.StatusNotFound)
	}
	oldLogs := req.Clone(req.Context())
	oldLogs.URL.Path = "/api/v1/integration/logs"
	oldLogsRecorder := httptest.NewRecorder()
	handler.ServeHTTP(oldLogsRecorder, oldLogs)
	if oldLogsRecorder.Code != http.StatusNotFound {
		t.Fatalf("removed integration log API status=%d, want %d", oldLogsRecorder.Code, http.StatusNotFound)
	}
}

func TestWebUIStatusAPIRequiresSessionAndReturnsSanitizedStatus(t *testing.T) {
	statusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/status" {
			t.Errorf("status request=%s %s, want GET /status", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"doh-health-monitor",
			"version":"test-version",
			"config":"/private/path/config.json",
			"last_error":"SECRET-MUST-NOT-LEAK",
			"queries":17,
			"failures":2,
			"active_doh":{"server_id":"comss-one","url":"https://dns.example/dns-query?token=ACTIVE-DOH-SECRET","hostname":"dns.comss.one","ipv4":["141.133.183.77"],"ipv6":[],"resolved_at":"2026-11-21T04:51:09Z","selected_at":"2026-11-21T08:24:07Z","fresh_until":"2026-11-21T10:51:09Z","generation":2,"score":6,"check_count":8},
			"dns_udp":"127.0.0.1:5355",
			"dns_tcp":"127.0.0.1:5355",
			"dns_mode":"resolver",
			"groups":{"google":{"active_upstream":"system-dns","upstreams":{"system-dns":{
				"state":"up","success_streak":4,"failure_streak":0,
				"last_check":"2026-11-16T10:00:00Z","check_duration_ms":946,"last_http_status":204,
				"last_error":"internal detail",
				"checks":[{"domain":"health.example","required":true,"dns_ok":true,
					"http_checked":true,"http_ok":true,"http_status":204,"error":"PROBE-ERROR-MUST-NOT-LEAK"}]
			}}}}
		}`))
	}))
	defer statusServer.Close()

	handler := newWebUIHandler(statusServer.URL+"/status", "session-test-token")
	apiRequest := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:19876/api/v1/status", nil)
	apiRequest.Host = "127.0.0.1:19876"
	apiRecorder := httptest.NewRecorder()
	handler.ServeHTTP(apiRecorder, apiRequest)
	if apiRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status request=%d, want %d", apiRecorder.Code, http.StatusUnauthorized)
	}

	rootRequest := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:19876/", nil)
	rootRequest.Host = "127.0.0.1:19876"
	rootRecorder := httptest.NewRecorder()
	handler.ServeHTTP(rootRecorder, rootRequest)
	cookies := rootRecorder.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("root page did not issue session cookie")
	}

	apiRequest = httptest.NewRequest(http.MethodGet, "http://127.0.0.1:19876/api/v1/status", nil)
	apiRequest.Host = "127.0.0.1:19876"
	apiRequest.AddCookie(cookies[0])
	apiRequest.Header.Set("Origin", "http://127.0.0.1:19876")
	apiRecorder = httptest.NewRecorder()
	handler.ServeHTTP(apiRecorder, apiRequest)
	if apiRecorder.Code != http.StatusOK {
		t.Fatalf("authenticated status request=%d, body=%s", apiRecorder.Code, apiRecorder.Body.String())
	}
	body := apiRecorder.Body.String()
	if !strings.Contains(body, "test-version") || !strings.Contains(body, "system-dns") || !strings.Contains(body, `"dns_mode":"resolver"`) {
		t.Fatalf("status response is missing expected fields: %s", body)
	}
	for _, want := range []string{
		"\"server_id\":\"comss-one\"", "\"hostname\":\"dns.comss.one\"",
		"\"generation\":2", "\"score\":6", "\"check_count\":8",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("status response is missing ActiveDoH field %s: %s", want, body)
		}
	}
	for _, want := range []string{
		"\"success_streak\":4", "\"failure_streak\":0",
		"\"last_check\":\"2026-11-16T10:00:00Z\"", "\"check_duration_ms\":946",
		"\"domain\":\"health.example\"", "\"dns_ok\":true",
		"\"http_checked\":true", "\"http_ok\":true", "\"http_status\":204",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("status response is missing safe upstream detail %s: %s", want, body)
		}
	}
	for _, forbidden := range []string{
		"private/path", "SECRET-MUST-NOT-LEAK", "internal detail", "PROBE-ERROR-MUST-NOT-LEAK", "ACTIVE-DOH-SECRET",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("status response leaked private or diagnostic field %q: %s", forbidden, body)
		}
	}
	if apiRecorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("status API response must not be cached")
	}
}

func TestFetchWebUIStatusRejectsNonLoopbackURL(t *testing.T) {
	if _, err := fetchWebUIStatus(t.Context(), "http://192.0.2.10:18765/status"); err == nil {
		t.Fatal("non-loopback status URL must be rejected")
	}
}

func TestIsLoopbackWebHost(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "127.0.0.1:19876", "localhost:19876", "[::1]:19876"} {
		if !isLoopbackWebHost(host) {
			t.Errorf("isLoopbackWebHost(%q)=false, want true", host)
		}
	}
	for _, host := range []string{"example.org", "192.0.2.1:19876", "0.0.0.0:80", ""} {
		if isLoopbackWebHost(host) {
			t.Errorf("isLoopbackWebHost(%q)=true, want false", host)
		}
	}
}

func TestRunWebUIStopsWhenSupervisorPipeCloses(t *testing.T) {
	oldStdin, oldStdout := os.Stdin, os.Stdout
	controlRead, controlWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		_ = controlRead.Close()
		_ = controlWrite.Close()
		t.Fatal(err)
	}

	os.Stdin = controlRead
	os.Stdout = readyWrite
	done := make(chan error, 1)
	go func() {
		done <- runWebUIWithStatusURL("http://127.0.0.1:18765/status")
	}()
	finished := false

	cleanup := func() {
		_ = controlWrite.Close()
		if !finished {
			select {
			case <-done:
			case <-time.After(6 * time.Second):
			}
		}
		os.Stdin, os.Stdout = oldStdin, oldStdout
		_ = controlRead.Close()
		_ = readyRead.Close()
		_ = readyWrite.Close()
	}
	defer cleanup()

	type readinessResult struct {
		line string
		err  error
	}
	readiness := make(chan readinessResult, 1)
	go func() {
		line, readErr := bufio.NewReader(readyRead).ReadString('\n')
		readiness <- readinessResult{line: line, err: readErr}
	}()
	var line string
	select {
	case result := <-readiness:
		line = result.line
		if result.err != nil {
			t.Fatalf("read Web UI readiness line: %v", result.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for Web UI readiness line")
	}
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) != 2 || fields[0] != "WEB_UI_READY" || !strings.HasPrefix(fields[1], "port=") {
		t.Fatalf("unexpected readiness protocol: %q", line)
	}
	port, err := strconv.Atoi(strings.TrimPrefix(fields[1], "port="))
	if err != nil || port < 1 || port > 65535 {
		t.Fatalf("invalid readiness port in %q", line)
	}

	response, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
	if err != nil {
		t.Fatalf("request placeholder page: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Web UI status=%d, want %d", response.StatusCode, http.StatusOK)
	}

	if err := controlWrite.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		finished = true
		if err != nil {
			t.Fatalf("Web UI shutdown: %v", err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("Web UI did not stop after supervisor pipe EOF")
	}
}

func TestWebUIAppScriptMakesManagementPagesMutuallyExclusive(t *testing.T) {
	handler := webUIHandler()
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:19876/app.js", nil)
	request.Host = "127.0.0.1:19876"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /app.js status=%d, want %d", recorder.Code, http.StatusOK)
	}
	script := recorder.Body.String()
	for _, want := range []string{
		`panel.hidden = !shouldOpen || panel.dataset.pagePanel !== name`,
		`const shouldOpen = open == null ? !currentlyOpen : Boolean(open)`,
		`button.setAttribute("aria-expanded", String(selected))`,
		`if (kind === "doh" && row.system)`,
		`renderActiveDoH(status.active_doh)`,
		`active.generation`,
		`protectedLabel.textContent = "Защищён"`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("app.js is missing exclusive tab behaviour %q", want)
		}
	}
}
