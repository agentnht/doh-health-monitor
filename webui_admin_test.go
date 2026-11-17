package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestWebUIData(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := initializeConfigSourceFiles(dir); err != nil {
		t.Fatal(err)
	}
	config := defaultConfig()
	if err := writeConfigAtomic(filepath.Join(dir, "config.json"), config); err != nil {
		t.Fatal(err)
	}
	return dir
}

func newAuthenticatedWebUIRequest(t *testing.T, handler http.Handler, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	const host = "127.0.0.1:19876"
	root := httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil)
	root.Host = host
	rootRecorder := httptest.NewRecorder()
	handler.ServeHTTP(rootRecorder, root)
	cookies := rootRecorder.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("root response did not issue a session cookie")
	}

	request := httptest.NewRequest(method, "http://"+host+path, bytes.NewReader(body))
	request.Host = host
	request.Header.Set("Origin", "http://"+host)
	request.AddCookie(cookies[0])
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestWebUIAdminAPIRequiresSessionCookie(t *testing.T) {
	dir := newTestWebUIData(t)
	handler := newWebUIHandlerWithDataDir("http://127.0.0.1:18765/status", "test-session", dir)
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:19876/api/v1/config", nil)
	request.Host = "127.0.0.1:19876"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated management API status=%d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}

func TestWebUIConfigAPIUpdatesValidatedSettingsAndDefaults(t *testing.T) {
	dir := newTestWebUIData(t)
	handler := newWebUIHandlerWithDataDir("http://127.0.0.1:18765/status", "test-session", dir)

	get := newAuthenticatedWebUIRequest(t, handler, http.MethodGet, "/api/v1/config", nil)
	if get.Code != http.StatusOK {
		t.Fatalf("GET config status=%d body=%s", get.Code, get.Body.String())
	}
	var view webUIEditableConfig
	if err := json.Unmarshal(get.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	view.Health.TimeoutSeconds = 9
	body, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	save := newAuthenticatedWebUIRequest(t, handler, http.MethodPost, "/api/v1/config", body)
	if save.Code != http.StatusOK {
		t.Fatalf("POST config status=%d body=%s", save.Code, save.Body.String())
	}
	config, err := loadConfigNoCreate(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if config.Health.TimeoutSeconds != 9 {
		t.Fatalf("saved health timeout=%d, want 9", config.Health.TimeoutSeconds)
	}

	reset := newAuthenticatedWebUIRequest(t, handler, http.MethodPost, "/api/v1/config/defaults", []byte(`{"section":"health"}`))
	if reset.Code != http.StatusOK {
		t.Fatalf("reset health status=%d body=%s", reset.Code, reset.Body.String())
	}
	config, err = loadConfigNoCreate(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if config.Health != defaultConfig().Health {
		t.Fatalf("health defaults not restored: %+v", config.Health)
	}
}

func TestWebUISourceEditorCommentsRowsAndValidatesBeforeWriting(t *testing.T) {
	dir := newTestWebUIData(t)
	update := webUISourceUpdate{
		Kind: "doh",
		Rows: []webUISourceRow{
			{Active: true, Editable: true, System: true, Fields: []string{systemDNSUpstreamID, ""}},
			{Active: true, Editable: true, Fields: []string{"example-provider", "https://dns.example/dns-query"}},
			{Active: false, Editable: true, Fields: []string{"disabled-provider", "https://disabled.example/dns-query"}},
		},
	}
	if err := saveWebUISources(dir, update); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "doh-servers.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "system-dns;\\n") ||
		!strings.Contains(string(data), "example-provider;https://dns.example/dns-query") ||
		!strings.Contains(string(data), "# disabled-provider;https://disabled.example/dns-query") {
		t.Fatalf("source rows were not serialized as active/commented lines: %s", data)
	}
	if _, err := parseDoHProviders(data); err != nil {
		t.Fatalf("saved DoH source does not validate: %v", err)
	}

	before := append([]byte(nil), data...)
	invalid := webUISourceUpdate{
		Kind: "doh",
		Rows: []webUISourceRow{
			{Active: true, Editable: true, System: true, Fields: []string{systemDNSUpstreamID, ""}},
			{Active: true, Editable: true, Fields: []string{"bad-id", "http://not-https.example/dns-query"}},
		},
	}
	if err := saveWebUISources(dir, invalid); err == nil {
		t.Fatal("invalid source update unexpectedly succeeded")
	}
	after, err := os.ReadFile(filepath.Join(dir, "doh-servers.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("invalid source update changed the existing file")
	}
}
	deleteSystem := webUISourceUpdate{Kind: "doh", Rows: []webUISourceRow{
		{Active: true, Editable: true, Fields: []string{"example-provider", "https://dns.example/dns-query"}},
	}}
	if err := saveWebUISources(dir, deleteSystem); err == nil {
		t.Fatal("deleting the protected system-dns row must be rejected")
	}
	disableSystem := webUISourceUpdate{Kind: "doh", Rows: []webUISourceRow{
		{Active: false, Editable: true, System: true, Fields: []string{systemDNSUpstreamID, ""}},
		{Active: true, Editable: true, Fields: []string{"example-provider", "https://dns.example/dns-query"}},
	}}
	if err := saveWebUISources(dir, disableSystem); err != nil {
		t.Fatalf("disabling system-dns should be allowed: %v", err)
	}
	disabledData, err := os.ReadFile(filepath.Join(dir, "doh-servers.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(disabledData), "# system-dns;") {
		t.Fatalf("disabled system-dns should remain as a comment row: %s", disabledData)
	}
	providers, err := parseDoHProviders(disabledData)
	if err != nil {
		t.Fatal(err)
	}
	for _, provider := range providers {
		if provider.ID == systemDNSUpstreamID {
			t.Fatal("commented system-dns should not be an active provider")
		}
	}
}

func TestWebUISourceRowsPreserveHeaderComments(t *testing.T) {
	rows := parseWebUISourceRows([]byte("# id;url — provider IDs remain stable\nalpha;https://dns.example/dns-query\n# beta;https://beta.example/dns-query\n"), 2, "id;url")
	if len(rows) != 3 {
		t.Fatalf("parsed %d rows, want 3", len(rows))
	}
	if rows[0].Editable || rows[0].Active {
		t.Fatal("header comment should be preserved as read-only")
	}
	if !rows[1].Editable || !rows[1].Active {
		t.Fatal("active row was not parsed as editable")
	}
	if !rows[2].Editable || rows[2].Active {
		t.Fatal("commented provider was not parsed as an inactive editable row")
	}
}

func TestWebUIGeminiKeyIsStoredPrivatelyWithoutReturningSecret(t *testing.T) {
	dir := newTestWebUIData(t)
	if err := saveWebUIGeminiKey(dir, "test-gemini-secret"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, defaultConfig().GeminiAPI.KeyFile)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("Gemini key permissions=%#o, want 0600", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != "test-gemini-secret" {
		t.Fatal("Gemini key file content mismatch")
	}
}

func TestWebUISafeListenerProbeRejectsPublicAddresses(t *testing.T) {
	for _, address := range []string{"0.0.0.0:5355", "192.0.2.1:5355", "dns.example:5355"} {
		if _, err := localListenAddress(address); err == nil {
			t.Errorf("localListenAddress(%q) unexpectedly allowed", address)
		}
	}
	for _, address := range []string{"127.0.0.1:5355", "localhost:18765", "[::1]:5355"} {
		if _, err := localListenAddress(address); err != nil {
			t.Errorf("localListenAddress(%q): %v", address, err)
		}
	}
}

func TestWebUIIntegrationOperationLogPersistsAndRedactsCredentials(t *testing.T) {
	dir := t.TempDir()
	logger := &webUIOperationLogger{dataDir: dir}
	logger.Printf("INTEGRATION action=INTEGRATE started")
	logger.Printf("Authorization: Bearer secret-token-value")

	lines, err := readWebUIIntegrationLog(dir, 50)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "INTEGRATION action=INTEGRATE started") {
		t.Fatalf("integration log is missing operation record: %s", joined)
	}
	if strings.Contains(joined, "secret-token-value") || !strings.Contains(joined, "[REDACTED]") {
		t.Fatalf("integration log did not redact credential: %s", joined)
	}
}

func TestWebUIPageHasTabsAndHeaderIntegrationActions(t *testing.T) {
	handler := webUIHandler()
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:19876/", nil)
	request.Host = "127.0.0.1:19876"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	page := recorder.Body.String()

	for _, label := range []string{"Конфигурация", "DoH-сервера", "Домены", "Проверка состояния", "Логи", "DeIntegrate", "Integrate"} {
		if !strings.Contains(page, label) {
			t.Errorf("Web UI page is missing %q", label)
		}
	}
	if strings.Contains(page, "integration-check") {
		t.Fatal("standalone integration check control must be removed from the UI")
	}
	if !strings.Contains(page, `data-page="tests"`) || !strings.Contains(page, `data-page-panel="tests"`) {
		t.Fatal("tests tab is not connected to its page")
	}
}

func TestWebUIIntegrationLogAPIRequiresSessionAndReturnsPersistedOperations(t *testing.T) {
	dir := t.TempDir()
	logger := &webUIOperationLogger{dataDir: dir}
	logger.Printf("INTEGRATION action=DEINTEGRATE completed successfully")

	handler := newWebUIHandlerWithDataDir("http://127.0.0.1:18765/status", "test-session", dir)
	unauthorized := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:19876/api/v1/integration/logs", nil)
	unauthorized.Host = "127.0.0.1:19876"
	unauthorizedRecorder := httptest.NewRecorder()
	handler.ServeHTTP(unauthorizedRecorder, unauthorized)
	if unauthorizedRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated integration log status=%d, want %d", unauthorizedRecorder.Code, http.StatusUnauthorized)
	}

	authorized := newAuthenticatedWebUIRequest(t, handler, http.MethodGet, "/api/v1/integration/logs", nil)
	if authorized.Code != http.StatusOK {
		t.Fatalf("authenticated integration log status=%d, body=%s", authorized.Code, authorized.Body.String())
	}
	if !strings.Contains(authorized.Body.String(), "DEINTEGRATE completed successfully") {
		t.Fatalf("integration log response is missing saved operation: %s", authorized.Body.String())
	}
}
