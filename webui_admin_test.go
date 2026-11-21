package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
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

var webUITestSessionCookies sync.Map

func newAuthenticatedWebUIRequest(t *testing.T, handler http.Handler, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	const host = "127.0.0.1:19876"
	const bootstrapToken = "test-session"
	cookieValue, ok := webUITestSessionCookies.Load(bootstrapToken)
	if !ok {
		root := httptest.NewRequest(http.MethodGet, "http://"+host+"/?token="+bootstrapToken, nil)
		root.Host = host
		rootRecorder := httptest.NewRecorder()
		handler.ServeHTTP(rootRecorder, root)
		cookies := rootRecorder.Result().Cookies()
		if rootRecorder.Code != http.StatusSeeOther || len(cookies) != 1 {
			t.Fatalf("valid bootstrap ticket exchange returned status=%d cookies=%d", rootRecorder.Code, len(cookies))
		}
		cookieValue = cookies[0]
		webUITestSessionCookies.Store(bootstrapToken, cookieValue)
	}
	cookie := cookieValue.(*http.Cookie)

	request := httptest.NewRequest(method, "http://"+host+path, bytes.NewReader(body))
	request.Host = host
	request.Header.Set("Origin", "http://"+host)
	request.AddCookie(cookie)
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
	view.DNSMode = "resolver"
	view.ResolverUpstreams = []ResolverUpstream{{ID: "primary", Name: "Primary", Type: "udp", Address: "9.9.9.9"}}
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
	if config.DNSMode != "resolver" || len(config.ResolverUpstreams) != 1 || config.ResolverUpstreams[0].ID != "primary" {
		t.Fatalf("DNS mode/upstreams not saved through Web UI: mode=%s upstreams=%+v", config.DNSMode, config.ResolverUpstreams)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.json.bak")); err != nil {
		t.Fatalf("Web UI config save did not create backup: %v", err)
	}

	// A client predating dns_mode/resolver_upstreams must not reset newer fields.
	legacyPayload := map[string]json.RawMessage{}
	if err := json.Unmarshal(body, &legacyPayload); err != nil {
		t.Fatal(err)
	}
	delete(legacyPayload, "dns_mode")
	delete(legacyPayload, "resolver_upstreams")
	legacyBody, err := json.Marshal(legacyPayload)
	if err != nil {
		t.Fatal(err)
	}
	legacySave := newAuthenticatedWebUIRequest(t, handler, http.MethodPost, "/api/v1/config", legacyBody)
	if legacySave.Code != http.StatusOK {
		t.Fatalf("legacy config POST status=%d body=%s", legacySave.Code, legacySave.Body.String())
	}
	config, err = loadConfigNoCreate(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if config.DNSMode != "resolver" || len(config.ResolverUpstreams) != 1 || config.ResolverUpstreams[0].ID != "primary" {
		t.Fatalf("legacy Web UI client unexpectedly reset DNS settings: mode=%s upstreams=%+v", config.DNSMode, config.ResolverUpstreams)
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

func TestWebUILocalHostsEditorAPIValidatesBacksUpAndPreservesComments(t *testing.T) {
	dir := newTestWebUIData(t)
	handler := newWebUIHandlerWithDataDir("http://127.0.0.1:18765/status", "test-session", dir)
	path := filepath.Join(dir, localHostsSourceFile)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	get := newAuthenticatedWebUIRequest(t, handler, http.MethodGet, "/api/v1/sources", nil)
	if get.Code != http.StatusOK {
		t.Fatalf("GET sources status=%d body=%s", get.Code, get.Body.String())
	}
	var sources webUISourcesResponse
	if err := json.Unmarshal(get.Body.Bytes(), &sources); err != nil {
		t.Fatal(err)
	}
	if len(sources.Hosts) == 0 || sources.Hosts[0].Editable || sources.Hosts[0].Raw != localHostsSourceHeader {
		t.Fatalf("local-hosts header/comment was not surfaced read-only: %+v", sources.Hosts)
	}

	update := webUISourceUpdate{Kind: "hosts", Rows: []webUISourceRow{
		{Active: false, Editable: false, Raw: localHostsSourceHeader},
		{Active: true, Editable: true, Fields: []string{"HOME.example.", "192.0.2.40,192.0.2.41", "2001:db8::40"}},
		{Active: false, Editable: true, Fields: []string{"disabled.example", "192.0.2.42", ""}},
	}}
	body, err := json.Marshal(update)
	if err != nil {
		t.Fatal(err)
	}
	save := newAuthenticatedWebUIRequest(t, handler, http.MethodPost, "/api/v1/sources", body)
	if save.Code != http.StatusOK {
		t.Fatalf("POST local hosts status=%d body=%s", save.Code, save.Body.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), localHostsSourceHeader) || !strings.Contains(string(data), "home.example;192.0.2.40,192.0.2.41;2001:db8::40") || !strings.Contains(string(data), "# disabled.example;192.0.2.42;") {
		t.Fatalf("local-hosts rows/comments were not saved as expected: %s", data)
	}
	backup, err := os.ReadFile(path + ".bak")
	if err != nil {
		t.Fatalf("read local-hosts backup: %v", err)
	}
	if !bytes.Equal(backup, before) {
		t.Fatalf("local-hosts backup does not preserve original bytes: got=%q want=%q", backup, before)
	}
	backupInfo, err := os.Stat(path + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	if backupInfo.Mode().Perm() != 0600 {
		t.Fatalf("local-hosts backup permissions=%#o, want 0600", backupInfo.Mode().Perm())
	}
	hosts, err := parseLocalHostsFile(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || !reflect.DeepEqual(hosts["home.example"].IPv4, []string{"192.0.2.40", "192.0.2.41"}) || len(hosts["home.example"].IPv6) != 1 {
		t.Fatalf("active local hosts map is incorrect: %+v", hosts)
	}

	invalid := webUISourceUpdate{Kind: "hosts", Rows: []webUISourceRow{
		{Active: true, Editable: true, Fields: []string{"bad..example", "192.0.2.99", ""}},
	}}
	invalidBody, err := json.Marshal(invalid)
	if err != nil {
		t.Fatal(err)
	}
	badSave := newAuthenticatedWebUIRequest(t, handler, http.MethodPost, "/api/v1/sources", invalidBody)
	if badSave.Code != http.StatusBadRequest {
		t.Fatalf("invalid hosts POST status=%d body=%s", badSave.Code, badSave.Body.String())
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, data) {
		t.Fatal("invalid local hosts update changed the live source file")
	}
	backupAfter, err := os.ReadFile(path + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(backupAfter, before) {
		t.Fatal("invalid local hosts update replaced the previous backup")
	}
}

func TestWriteManagedSourceWithBackupRejectsSymlinkBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, localHostsSourceFile)
	target := filepath.Join(dir, "target")
	original := []byte(localHostsSourceHeader + "\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path+".bak"); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if err := writeManagedSourceWithBackup(path, []byte(localHostsSourceHeader+"\nexample.test;192.0.2.1;\n")); err == nil {
		t.Fatal("symlink backup path should be rejected")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "unchanged" {
		t.Fatalf("backup symlink target was modified: %q", got)
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
	if !strings.Contains(string(data), "system-dns;\n") ||
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
	noActiveUpstreams := webUISourceUpdate{Kind: "doh", Rows: []webUISourceRow{
		{Active: false, Editable: true, System: true, Fields: []string{systemDNSUpstreamID, ""}},
	}}
	if err := saveWebUISources(dir, noActiveUpstreams); err == nil {
		t.Fatal("disabling system-dns without another enabled upstream must be rejected")
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

func TestWebUISourceRowsMarkSystemDNSAsProtectedAndEditable(t *testing.T) {
	rows := parseWebUISourceRows([]byte("# id;url\nsystem-dns;\n# system-dns;\n# free-form comment\n"), 2, "id;url")
	if len(rows) != 4 {
		t.Fatalf("parsed %d rows, want 4", len(rows))
	}
	if !rows[1].System || !rows[1].Editable || !rows[1].Active {
		t.Fatalf("active system DNS row was not identified: %+v", rows[1])
	}
	if !rows[2].System || !rows[2].Editable || rows[2].Active {
		t.Fatalf("commented system DNS row was not identified as disabled: %+v", rows[2])
	}
	if rows[3].Editable || rows[3].Raw != "# free-form comment" {
		t.Fatalf("free-form comment should remain read-only: %+v", rows[3])
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

func TestWebUIAdminCheckLogPersistsAndRedactsCredentials(t *testing.T) {
	dir := t.TempDir()
	logger := &webUIAdminLogger{dataDir: dir}
	logger.Printf("Xray policy/plugin check started")
	logger.Printf("Authorization: Bearer secret-token-value")

	lines, err := readWebUILogFile(filepath.Join(dir, "webui-admin-check.log"), 50)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "Xray policy/plugin check started") {
		t.Fatalf("admin check log is missing record: %s", joined)
	}
	if strings.Contains(joined, "secret-token-value") || !strings.Contains(joined, "[REDACTED]") {
		t.Fatalf("admin check log did not redact credential: %s", joined)
	}
}

func TestWebUIPageHasManagementTabsButNoPanelMutationActions(t *testing.T) {
	handler := newWebUIHandlerWithDataDir("http://127.0.0.1:18765/status", "test-session", "")
	recorder := newAuthenticatedWebUIRequest(t, handler, http.MethodGet, "/", nil)
	page := recorder.Body.String()

	for _, label := range []string{"Конфигурация", "DoH-сервера", "Домены", "Проверка состояния", "Логи", "Geosite DNS"} {
		if !strings.Contains(page, label) {
			t.Errorf("Web UI page is missing %q", label)
		}
	}
	for _, forbidden := range []string{"integration-add", "integration-remove", "DeIntegrate", ">Integrate<"} {
		if strings.Contains(page, forbidden) {
			t.Errorf("Web UI must not expose panel mutation control %q", forbidden)
		}
	}
	if !strings.Contains(page, `data-page="tests"`) || !strings.Contains(page, `data-page-panel="tests"`) {
		t.Fatal("tests tab is not connected to its page")
	}
}

func TestWebUIIntegrationMutationAPIIsDisabled(t *testing.T) {
	dir := newTestWebUIData(t)
	handler := newWebUIHandlerWithDataDir("http://127.0.0.1:18765/status", "test-session", dir)

	for _, action := range []string{"integrate", "remove"} {
		body := []byte(`{"action":"` + action + `","confirmed":true}`)
		response := newAuthenticatedWebUIRequest(t, handler, http.MethodPost, "/api/v1/integration", body)
		if response.Code != http.StatusGone {
			t.Fatalf("%s API status=%d, want %d; body=%s", action, response.Code, http.StatusGone, response.Body.String())
		}
		if !strings.Contains(response.Body.String(), "configure Xray manually") {
			t.Fatalf("%s API response does not explain manual Xray configuration: %s", action, response.Body.String())
		}
	}
}

func TestWebUILogsPreferPluginAndAdminFilesOverJournal(t *testing.T) {
	dataDir := newTestWebUIData(t)
	pluginLog := filepath.Join(filepath.Dir(dataDir), "plugin.log")
	adminLog := filepath.Join(dataDir, "webui-admin-check.log")
	if err := os.WriteFile(pluginLog, []byte("plugin-runtime-marker\nAuthorization: Bearer plugin-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(adminLog, []byte("admin-check-marker\n"), 0600); err != nil {
		t.Fatal(err)
	}
	lines, source, err := readWebUILogs(dataDir, 100)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(lines, "\n")
	if source != "plugin.log + webui-admin-check.log" {
		t.Fatalf("log source=%q, want plugin and admin files", source)
	}
	for _, want := range []string{"plugin-runtime-marker", "admin-check-marker", "[REDACTED]"} {
		if !strings.Contains(joined, want) {
			t.Errorf("combined logs missing %q: %s", want, joined)
		}
	}
	if strings.Contains(joined, "plugin-secret") {
		t.Fatal("plugin log exposed a bearer token")
	}
}

func TestReadWebUILogFileReturnsTailWhenFileExceedsReadWindow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plugin.log")
	content := strings.Repeat("old-log-line\n", (2<<20)/13) + "latest-marker\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	lines, err := readWebUILogFile(path, 20)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(lines, "\n"), "latest-marker") {
		t.Fatalf("tail read missed latest log entry: %v", lines)
	}
}

func TestWebUIDigResultClassifiesNODATAAndDNSFailures(t *testing.T) {
	tests := []struct {
		name string
		output string
		err error
		timedOut bool
		want string
	}{
		{name: "positive", output: ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\nexample.com. 60 IN A 192.0.2.1\n", want: "OK"},
		{name: "nodata", output: ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 2\n", want: "NODATA"},
		{name: "nxdomain", output: ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 3\n", want: "NXDOMAIN"},
		{name: "nxdomain with nonzero dig exit", output: ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 33\n", err: errors.New("exit status 9"), want: "NXDOMAIN"},
		{name: "servfail", output: ";; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 4\n", want: "SERVFAIL"},
		{name: "refused", output: ";; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 5\n", want: "REFUSED"},
		{name: "timeout", err: context.DeadlineExceeded, timedOut: true, want: "TIMEOUT"},
		{name: "dig timeout output", output: ";; communications error to 127.0.0.1#5355: timed out\\n", err: errors.New("exit status 9"), want: "TIMEOUT"},
		{name: "transport", err: errors.New("connection refused"), want: "TRANSPORT_ERROR"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := webUIDigResult("example.com", 1, "udp", test.output, 12, test.err, test.timedOut)
			if result.Status != test.want {
				t.Fatalf("status=%q, want %q (reason=%q)", result.Status, test.want, result.Reason)
			}
		})
	}
}

func TestWebUIDNSListenerCountsNODATAAsAReceivedDNSResponse(t *testing.T) {
	results := []webUITestResult{
		{Name: "empty.example TXT", Status: "NODATA", Transport: "udp"},
		{Name: "timeout.example A", Status: "TIMEOUT", Transport: "udp"},
	}
	listener := webUIDNSListenerResult("udp", "127.0.0.1:5355", results)
	if listener.Status != "OK" {
		t.Fatalf("NODATA is still a DNS response; listener status=%q reason=%q", listener.Status, listener.Reason)
	}
	warning := finalizeWebUITests(webUITestSummary{Tests: []webUITestResult{{Status: "NODATA"}}})
	if warning.Status != "Warning" || warning.Warnings != 1 || warning.Failed != 0 {
		t.Fatalf("NODATA summary=%+v, want warning without transport failure", warning)
	}
}

func TestWebUIDigArgsSelectTransport(t *testing.T) {
	udp := strings.Join(webUIDigArgs("127.0.0.1", "5355", "example.com", 1, "udp"), " ")
	tcp := strings.Join(webUIDigArgs("127.0.0.1", "5355", "example.com", 1, "tcp"), " ")
	if strings.Contains(udp, "+tcp") {
		t.Fatalf("UDP args contain +tcp: %s", udp)
	}
	if !strings.Contains(tcp, "+tcp") {
		t.Fatalf("TCP args missing +tcp: %s", tcp)
	}
}


func TestSaveWebUIGeminiKeyRejectsManagedFileTargets(t *testing.T) {
	dir := newTestWebUIData(t)
	configPath := filepath.Join(dir, "config.json")
	config, err := loadConfigNoCreate(configPath)
	if err != nil { t.Fatal(err) }
	config.GeminiAPI.KeyFile = "config.json"
	if err := writeConfigAtomic(configPath, config); err != nil { t.Fatal(err) }
	before, err := os.ReadFile(configPath)
	if err != nil { t.Fatal(err) }
	if err := saveWebUIGeminiKey(dir, "AAAAAAAAAAAAAAAAAAAAAAAA"); err == nil {
		t.Fatal("managed config.json target must be rejected")
	}
	after, err := os.ReadFile(configPath)
	if err != nil { t.Fatal(err) }
	if !bytes.Equal(before, after) { t.Fatal("rejected key save modified config.json") }
}

func TestRedactWebUILogLinePreservesSecretPrefix(t *testing.T) {
	got := redactWebUILogLine("Authorization: Bearer abc123SECRET")
	if !strings.Contains(got, "Authorization: Bearer [REDACTED]") {
		t.Fatalf("secret redaction damaged the prefix: %q", got)
	}
	if strings.Contains(got, "abc123SECRET") {
		t.Fatalf("secret remains in redacted output: %q", got)
	}
}


func TestWebUIDigOverflowResultsKeepOriginalIndexes(t *testing.T) {
	dir := t.TempDir()
	fakeDig := filepath.Join(dir, "dig")
	if err := os.WriteFile(fakeDig, []byte("#!/bin/sh\necho ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1'\necho 'example.com. 60 IN A 192.0.2.1'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	checks := make([]Check, 26)
	for i := range checks {
		checks[i] = Check{Domain: fmt.Sprintf("d%d.example.com", i), QTypes: []uint16{1, 28}}
	}
	results := runWebUIDigTests("127.0.0.1:5355", checks, "udp")
	if len(results) != 52 {
		t.Fatalf("result count=%d, want 52", len(results))
	}
	for i, result := range results {
		if result.Name == "" || result.Domain == "" {
			t.Fatalf("result %d is empty; overflow results must retain original indexes: %+v", i, result)
		}
	}
	for i := webUIAdminMaxDigQueries; i < len(results); i++ {
		if results[i].Status == "" || !strings.Contains(results[i].Reason, "лимит проверки") {
			t.Fatalf("overflow result %d is not marked as intentionally skipped: %+v", i, results[i])
		}
	}
}
