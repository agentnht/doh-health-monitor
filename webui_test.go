package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestWebUIHandlerServesOnlyLoopbackRoot(t *testing.T) {
	handler := newWebUIHandler("http://127.0.0.1:18765/status", "session-test-token")

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:19876/", nil)
	req.Host = "127.0.0.1:19876"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("initial GET / status=%d, want %d", rec.Code, http.StatusOK)
	}
	exchange := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:19876/session/exchange", strings.NewReader(`{"token":"session-test-token"}`))
	exchange.Host = "127.0.0.1:19876"
	exchange.Header.Set("Content-Type", "application/json")
	exchangeRecorder := httptest.NewRecorder()
	handler.ServeHTTP(exchangeRecorder, exchange)
	cookies := exchangeRecorder.Result().Cookies()
	if exchangeRecorder.Code != http.StatusNoContent || len(cookies) != 1 || cookies[0].Name != webUISessionCookie {
		t.Fatal("valid one-time launch exchange did not issue the HttpOnly session cookie")
	}
	replayRequest := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:19876/session/exchange", strings.NewReader(`{"token":"session-test-token"}`))
	replayRequest.Host = "127.0.0.1:19876"
	replayRequest.Header.Set("Content-Type", "application/json")
	replay := httptest.NewRecorder()
	handler.ServeHTTP(replay, replayRequest)
	if replay.Code != http.StatusUnauthorized {
		t.Fatalf("replayed launch token status=%d, want %d", replay.Code, http.StatusUnauthorized)
	}
	pageRequest := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:19876/", nil)
	pageRequest.Host = "127.0.0.1:19876"
	pageRequest.AddCookie(cookies[0])
	pageRecorder := httptest.NewRecorder()
	handler.ServeHTTP(pageRecorder, pageRequest)
	rec = pageRecorder
	if rec.Code != http.StatusOK {
		t.Fatalf("authenticated GET / status=%d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "DoH Health Monitor") {
		t.Fatal("placeholder page content is missing")
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("Web UI response must not be cached")
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
	if got := strings.Count(page, `<section class="panel tab-page`); got != 7 {
		t.Fatalf("all section panels, including Auto Hosts and both log panels, must start hidden; got %d", got)
	}
	if strings.Count(page, `class="tab-button"`) != 6 {
		t.Fatal("expected six independent collapsible section buttons")
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
			"dns_udp":"127.0.0.1:5355",
			"dns_tcp":"127.0.0.1:5355",
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

	rootRequest := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:19876/session/exchange", strings.NewReader(`{"token":"session-test-token"}`))
	rootRequest.Host = "127.0.0.1:19876"
	rootRequest.Header.Set("Content-Type", "application/json")
	rootRecorder := httptest.NewRecorder()
	handler.ServeHTTP(rootRecorder, rootRequest)
	cookies := rootRecorder.Result().Cookies()
	if rootRecorder.Code != http.StatusNoContent || len(cookies) != 1 {
		t.Fatalf("launch-token exchange failed: status=%d cookies=%d", rootRecorder.Code, len(cookies))
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
	if !strings.Contains(body, "test-version") || !strings.Contains(body, "system-dns") {
		t.Fatalf("status response is missing expected fields: %s", body)
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
		"private/path", "SECRET-MUST-NOT-LEAK", "internal detail", "PROBE-ERROR-MUST-NOT-LEAK",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("status response leaked private or diagnostic field %q: %s", forbidden, body)
		}
	}
	if apiRecorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("status API response must not be cached")
	}
}

func TestAutoHostsMiddlewareRequiresBearerAndLoopbackHost(t *testing.T) {
	handler := requireAutoHostsAPIToken("secret-token", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	for _, tc := range []struct {
		name, host, authorization string
		want                      int
	}{
		{"bare token", "127.0.0.1:18765", "secret-token", http.StatusUnauthorized},
		{"wrong scheme", "127.0.0.1:18765", "Basic secret-token", http.StatusUnauthorized},
		{"bearer", "127.0.0.1:18765", "Bearer secret-token", http.StatusNoContent},
		{"untrusted host", "attacker.example", "Bearer secret-token", http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://"+tc.host+"/status", nil)
			req.Host = tc.host
			req.Header.Set("Authorization", tc.authorization)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status=%d, want %d", rec.Code, tc.want)
			}
		})
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
	oldDataDir := os.Getenv("LUCX_PLUGIN_DATA")
	dataDir := t.TempDir()
	if err := os.Setenv("LUCX_PLUGIN_DATA", dataDir); err != nil {
		t.Fatal(err)
	}
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
		_ = os.Setenv("LUCX_PLUGIN_DATA", oldDataDir)
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

	launchTokenData, err := os.ReadFile(filepath.Join(os.Getenv("LUCX_PLUGIN_DATA"), "web-ui-launch.token"))
	if err != nil {
		t.Fatalf("read private launch token file: %v", err)
	}
	launchToken := strings.TrimSpace(string(launchTokenData))
	if strings.Contains(line, launchToken) || launchToken == "" {
		t.Fatal("launch token must not appear in readiness output")
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	pageResponse, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
	if err != nil {
		t.Fatalf("request Web UI shell: %v", err)
	}
	_ = pageResponse.Body.Close()
	exchangeRequest, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/session/exchange", port), strings.NewReader(`{"token":"`+launchToken+`"}`))
	exchangeRequest.Header.Set("Content-Type", "application/json")
	exchangeResponse, err := client.Do(exchangeRequest)
	if err != nil {
		t.Fatalf("exchange Web UI launch token: %v", err)
	}
	if exchangeResponse.StatusCode != http.StatusNoContent || len(exchangeResponse.Cookies()) != 1 {
		t.Fatalf("exchange response status=%d cookies=%d", exchangeResponse.StatusCode, len(exchangeResponse.Cookies()))
	}
	cookie := exchangeResponse.Cookies()[0]
	_ = exchangeResponse.Body.Close()
	pageRequest, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/", port), nil)
	pageRequest.AddCookie(cookie)
	pageResponse, err = client.Do(pageRequest)
	if err != nil {
		t.Fatalf("request authenticated Web UI page: %v", err)
	}
	_ = pageResponse.Body.Close()
	if pageResponse.StatusCode != http.StatusOK {
		t.Fatalf("authenticated Web UI status=%d, want %d", pageResponse.StatusCode, http.StatusOK)
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
		`protectedLabel.textContent = "Защищён"`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("app.js is missing exclusive tab behaviour %q", want)
		}
	}
}

func TestWebUIAutoHostsProxyOnlyTargetsLoopbackDaemon(t *testing.T) {
	var gotPath, gotMethod, gotBody string
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"ok\":true}"))
	}))
	defer daemon.Close()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/autohosts/config", strings.NewReader("{\"enabled\":true}"))
	response := httptest.NewRecorder()
	dataDir := t.TempDir()
	if _, err := loadOrCreateAutoHostsAPIToken(dataDir); err != nil {
		t.Fatal(err)
	}
	proxyWebUIAutoHostsAPI(response, request, daemon.URL+"/status", dataDir)
	if response.Code != http.StatusOK || gotPath != "/autohosts/config" || gotMethod != http.MethodPost || gotBody != "{\"enabled\":true}" {
		t.Fatalf("unexpected proxy result: status=%d path=%s method=%s body=%s", response.Code, gotPath, gotMethod, gotBody)
	}
	badRequest := httptest.NewRequest(http.MethodGet, "/api/v1/autohosts/status", nil)
	badResponse := httptest.NewRecorder()
	proxyWebUIAutoHostsAPI(badResponse, badRequest, "http://example.com/status", dataDir)
	if badResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("non-loopback status URL was accepted: %d", badResponse.Code)
	}
}

func TestWebUIAutoHostsRoutesRequireSessionAndProxyFullFlow(t *testing.T) {
	var calls []string
	dataDir := t.TempDir()
	apiToken, err := loadOrCreateAutoHostsAPIToken(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("Authorization") != "Bearer "+apiToken {
			t.Errorf("daemon request missing bearer token")
		}
		calls = append(calls, r.Method+" "+r.URL.Path+" "+string(body))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"active_server":"edge"}`))
	}))
	defer daemon.Close()
	handler := newWebUIHandlerWithDataDir(daemon.URL+"/status", "auto-hosts-session", dataDir)
	request := func(method, path, body string, authenticated bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "http://127.0.0.1:19876"+path, strings.NewReader(body))
		req.Host = "127.0.0.1:19876"
		if authenticated {
			req.AddCookie(&http.Cookie{Name: webUISessionCookie, Value: "auto-hosts-session"})
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	for _, tc := range []struct{ method, path, body, want string }{
		{http.MethodGet, "/api/v1/autohosts/status", "", "GET /autohosts/status "},
		{http.MethodPost, "/api/v1/autohosts/config", `{"enabled":true,"pinned_server_id":"edge"}`, "POST /autohosts/config "},
		{http.MethodPost, "/api/v1/autohosts/dry-run", `{}`, "POST /autohosts/dry-run "},
	} {
		unauth := request(tc.method, tc.path, tc.body, false)
		if unauth.Code != http.StatusUnauthorized {
			t.Errorf("unauthenticated %s: status=%d", tc.path, unauth.Code)
		}
		rec := request(tc.method, tc.path, tc.body, true)
		if rec.Code != http.StatusOK {
			t.Errorf("authenticated %s: status=%d body=%s", tc.path, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"active_server":"edge"`) {
			t.Errorf("%s response missing daemon payload: %s", tc.path, rec.Body.String())
		}
	}
	if len(calls) != 3 {
		t.Fatalf("daemon calls=%d, want 3: %v", len(calls), calls)
	}
	if calls[0] != "GET /autohosts/status " || calls[1] != "POST /autohosts/config "+`{"enabled":true,"pinned_server_id":"edge"}` || calls[2] != "POST /autohosts/dry-run {}" {
		t.Fatalf("unexpected proxied calls: %v", calls)
	}
}

func TestAutoHostsDaemonAPIRequiresLoopbackAndBearerToken(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef0123456789"
	called := false
	handler := requireAutoHostsAPIToken(token, func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	request := func(host, origin, bearer string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "http://"+host+"/autohosts/config", nil)
		req.Host = host
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	if got := request("127.0.0.1:18765", "", ""); got.Code != http.StatusUnauthorized {
		t.Fatalf("missing bearer token status=%d; want 401", got.Code)
	}
	if got := request("example.com", "", token); got.Code != http.StatusForbidden {
		t.Fatalf("non-loopback Host status=%d; want 403", got.Code)
	}
	if got := request("127.0.0.1:18765", "http://evil.example", token); got.Code != http.StatusForbidden {
		t.Fatalf("foreign Origin status=%d; want 403", got.Code)
	}
	if got := request("127.0.0.1:18765", "http://127.0.0.1:18765", token); got.Code != http.StatusNoContent {
		t.Fatalf("valid authenticated request status=%d; want 204", got.Code)
	}
	if !called {
		t.Fatal("authenticated request did not reach the handler")
	}
}

func TestWebUILaunchDoesNotIssueSessionToArbitraryLoopbackGET(t *testing.T) {
	handler := newWebUIHandler("http://127.0.0.1:18765/status", "private-launch-token")
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:19876/", nil)
	req.Host = "127.0.0.1:19876"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("unauthenticated GET / issued a session: status=%d cookies=%d", rec.Code, len(rec.Result().Cookies()))
	}
}
