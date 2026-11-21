package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestInitializeConfigSourceFilesCreatesEmbeddedDefaults(t *testing.T) {
	dir := t.TempDir()
	if err := initializeConfigSourceFiles(dir); err != nil {
		t.Fatal(err)
	}
	dohPath := filepath.Join(dir, "doh-servers.txt")
	checksPath := filepath.Join(dir, "tst-domen.txt")
	hostsPath := filepath.Join(dir, localHostsSourceFile)
	dohInfo, err := os.Stat(dohPath)
	if err != nil {
		t.Fatal(err)
	}
	checksInfo, err := os.Stat(checksPath)
	if err != nil {
		t.Fatal(err)
	}
	hostsInfo, err := os.Stat(hostsPath)
	if err != nil {
		t.Fatal(err)
	}
	if dohInfo.Mode().Perm() != 0600 || checksInfo.Mode().Perm() != 0600 || hostsInfo.Mode().Perm() != 0600 {
		t.Fatalf("source file permissions = %o, %o and %o; want 0600", dohInfo.Mode().Perm(), checksInfo.Mode().Perm(), hostsInfo.Mode().Perm())
	}
	sources, err := readConfigSources(dohPath, checksPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(sources.Providers) != 7 {
		t.Fatalf("default providers = %d, want 7 including system-dns and Pereval", len(sources.Providers))
	}
	if !sources.SystemDNSEnabled {
		t.Fatal("embedded default source must enable system-dns")
	}
	if len(sources.LocalHosts) != 0 || len(sources.Checksums.Hosts) != 64 {
		t.Fatalf("embedded local hosts source should be empty and hashed: hosts=%+v checksum=%q", sources.LocalHosts, sources.Checksums.Hosts)
	}
	if len(sources.Checks) != 10 {
		t.Fatalf("default checks = %d, want 10", len(sources.Checks))
	}
	if sources.DoHURLs["dagami"] != "https://dns.dagami.ru/dns-query" {
		t.Fatalf("default Dagami endpoint = %q", sources.DoHURLs["dagami"])
	}
	if sources.DoHURLs["pereval"] != "https://free.pereval.top/dns-query" {
		t.Fatalf("default Pereval endpoint = %q", sources.DoHURLs["pereval"])
	}
	wantDomains := []string{
		"chatgpt.com",
		"claude.ai",
		"gemini.google.com",
		"elevenlabs.io",
		"grok.com",
		"www.perplexity.ai",
		"notebooklm.google.com",
		"notebook.google.com",
		"aistudio.google.com",
		"accounts.google.com",
	}
	gotDomains := make([]string, 0, len(sources.Checks))
	var gemini, notebook, accounts *Check
	for i := range sources.Checks {
		gotDomains = append(gotDomains, sources.Checks[i].Domain)
		switch sources.Checks[i].Domain {
		case "gemini.google.com":
			gemini = &sources.Checks[i]
		case "notebook.google.com":
			notebook = &sources.Checks[i]
		case "accounts.google.com":
			accounts = &sources.Checks[i]
		}
	}
	if !reflect.DeepEqual(gotDomains, wantDomains) {
		t.Errorf("default check domains = %v, want %v", gotDomains, wantDomains)
	}
	if gemini == nil || !gemini.Required || gemini.HTTPURL != "https://gemini.google.com/" || !reflect.DeepEqual(gemini.ExpectedStatus, []int{200}) {
		t.Errorf("Gemini default check = %+v", gemini)
	}
	if notebook == nil || !notebook.Required || notebook.HTTPURL != "https://notebook.google.com/" || !reflect.DeepEqual(notebook.ExpectedStatus, []int{200}) || !reflect.DeepEqual(notebook.QTypes, []uint16{1, 28}) {
		t.Errorf("Notebook default check = %+v", notebook)
	}
	if accounts == nil || !accounts.Required || !accounts.VerifyOIDC || accounts.HTTPURL != "https://accounts.google.com/.well-known/openid-configuration" {
		t.Errorf("Accounts default check = %+v", accounts)
	}
}

func TestInitializeConfigSourceFilesPreservesExistingUserFiles(t *testing.T) {
	dir := t.TempDir()
	doh := "# id;url\ncustom;https://resolver.example.net/dns-query\n"
	checks := "# domain;qtypes;required;http_url;expected_status;verify_oidc\nresolver.example.net;TXT;1;;;0\n"
	dohPath := filepath.Join(dir, "doh-servers.txt")
	checksPath := filepath.Join(dir, "tst-domen.txt")
	if err := os.WriteFile(dohPath, []byte(doh), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(checksPath, []byte(checks), 0600); err != nil {
		t.Fatal(err)
	}
	if err := initializeConfigSourceFiles(dir); err != nil {
		t.Fatal(err)
	}
	gotDoH, err := os.ReadFile(dohPath)
	if err != nil {
		t.Fatal(err)
	}
	gotChecks, err := os.ReadFile(checksPath)
	if err != nil {
		t.Fatal(err)
	}
	wantDoH := "# id;url\nsystem-dns;\ncustom;https://resolver.example.net/dns-query\n"
	if string(gotDoH) != wantDoH || string(gotChecks) != checks {
		t.Fatalf("existing user source files were not preserved with the system row migration: doh=%q checks=%q", gotDoH, gotChecks)
	}
}

func TestInitializeConfigSourceFilesMigratesLegacyLocalHosts(t *testing.T) {
	dir := t.TempDir()
	legacy := defaultConfig()
	legacy.LocalHosts = map[string]LocalHost{
		"LOCAL.example.": {IPv4: []string{"192.0.2.20"}, IPv6: []string{"2001:db8::20"}},
		"z.internal":     {IPv4: []string{"192.0.2.21"}},
	}
	if err := writeConfigAtomic(filepath.Join(dir, "config.json"), legacy); err != nil {
		t.Fatal(err)
	}
	if err := initializeConfigSourceFiles(dir); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, localHostsSourceFile))
	if err != nil {
		t.Fatal(err)
	}
	want := localHostsSourceHeader + "\nlocal.example;192.0.2.20;2001:db8::20\nz.internal;192.0.2.21;\n"
	if string(data) != want {
		t.Fatalf("migrated local hosts = %q, want %q", data, want)
	}
	parsed, err := parseLocalHostsFile(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != 2 || parsed["local.example"].IPv4[0] != "192.0.2.20" {
		t.Fatalf("migrated local hosts not parsed: %+v", parsed)
	}
	if err := os.WriteFile(filepath.Join(dir, localHostsSourceFile), []byte(localHostsSourceHeader+"\ncustom.example;192.0.2.30;\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := initializeConfigSourceFiles(dir); err != nil {
		t.Fatal(err)
	}
	preserved, err := os.ReadFile(filepath.Join(dir, localHostsSourceFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(preserved), "custom.example;192.0.2.30;") {
		t.Fatalf("existing local-hosts.txt was overwritten during initialization: %s", preserved)
	}
}

func TestParseLocalHostsFileValidatesExactHostAndAddressFamilies(t *testing.T) {
	got, err := parseLocalHostsFile([]byte(localHostsSourceHeader + "\n# disabled.example;192.0.2.1;\nLOCAL.example.;192.0.2.1,192.0.2.2;2001:db8::1\nforced-nodata.example;;\n"))
	if err != nil {
		t.Fatalf("valid local hosts rejected: %v", err)
	}
	if len(got) != 2 || !reflect.DeepEqual(got["local.example"].IPv4, []string{"192.0.2.1", "192.0.2.2"}) || !reflect.DeepEqual(got["local.example"].IPv6, []string{"2001:db8::1"}) {
		t.Fatalf("unexpected parsed local hosts: %+v", got)
	}
	if len(got["forced-nodata.example"].IPv4) != 0 || len(got["forced-nodata.example"].IPv6) != 0 {
		t.Fatalf("legacy empty host entry should be retained to force NODATA: %+v", got["forced-nodata.example"])
	}
	for _, raw := range []string{
		"bad..example;192.0.2.1;",
		"bad.example;2001:db8::1;",
		"bad.example;;192.0.2.1",
		"dup.example;192.0.2.1;\nDUP.example.;192.0.2.2;",
		"bad.example;192.0.2.1,; ",
		"bad.example;192.0.2.1;2001:db8::1;extra",
	} {
		if _, err := parseLocalHostsFile([]byte(raw)); err == nil {
			t.Errorf("invalid local-hosts row unexpectedly accepted: %q", raw)
		}
	}
}

func TestReadConfigSourcesLoadsManagedLocalHostsFile(t *testing.T) {
	dir := t.TempDir()
	if err := initializeConfigSourceFiles(dir); err != nil {
		t.Fatal(err)
	}
	hostsPath := filepath.Join(dir, localHostsSourceFile)
	data := []byte(localHostsSourceHeader + "\nservice.example;192.0.2.55;2001:db8::55\n")
	if err := os.WriteFile(hostsPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	sources, err := readConfigSources(filepath.Join(dir, "doh-servers.txt"), filepath.Join(dir, "tst-domen.txt"))
	if err != nil {
		t.Fatalf("read managed config sources: %v", err)
	}
	entry, ok := sources.LocalHosts["service.example"]
	if !ok || !reflect.DeepEqual(entry.IPv4, []string{"192.0.2.55"}) || !reflect.DeepEqual(entry.IPv6, []string{"2001:db8::55"}) {
		t.Fatalf("managed local hosts not loaded into sources: %+v", sources.LocalHosts)
	}
	if sources.Checksums.Hosts != configSourceChecksums(nil, nil, data).Hosts {
		t.Fatalf("local hosts checksum does not match file contents: %s", sources.Checksums.Hosts)
	}
	if err := os.WriteFile(hostsPath, []byte("invalid host row\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfigSources(filepath.Join(dir, "doh-servers.txt"), filepath.Join(dir, "tst-domen.txt")); err == nil {
		t.Fatal("invalid managed local hosts source was accepted")
	}
}

func TestLocalHostsSourceChangesChecksumAndConfigGeneration(t *testing.T) {
	first := configSourceChecksums([]byte("doh"), []byte("checks"), []byte(localHostsSourceHeader+"\n"))
	second := configSourceChecksums([]byte("doh"), []byte("checks"), []byte(localHostsSourceHeader+"\nsite.example;192.0.2.44;\n"))
	if first.Hosts == second.Hosts || first.Combined == second.Combined {
		t.Fatal("local-hosts source change did not alter its checksum")
	}
	cfg := defaultConfig()
	cfg.LocalHosts = map[string]LocalHost{"legacy.example": {IPv4: []string{"192.0.2.10"}}}
	providers, err := parseDoHProviders([]byte("system-dns;\ndagami;https://dns.dagami.ru/dns-query\n"))
	if err != nil {
		t.Fatal(err)
	}
	checks, err := parseHealthChecks([]byte("accounts.google.com;A;1;;;0\n"))
	if err != nil {
		t.Fatal(err)
	}
	generated, err := applyConfigSources(cfg, ConfigSources{
		Providers: providers, Checks: checks, LocalHosts: map[string]LocalHost{
			"site.example": {IPv4: []string{"192.0.2.44"}},
		},
		DoHURLs: map[string]string{"dagami": "https://dns.dagami.ru/dns-query"}, SystemDNSEnabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(generated.LocalHosts) != 1 || generated.LocalHosts["site.example"].IPv4[0] != "192.0.2.44" {
		t.Fatalf("runtime config did not use managed local-hosts source: %+v", generated.LocalHosts)
	}
}

func TestEnsureSystemDNSDoHEntryAddsEnabledRowForLegacyLists(t *testing.T) {
	legacy := []byte("# id;url\ndagami;https://dns.dagami.ru/dns-query\n")
	got, changed, err := ensureSystemDNSDoHEntry(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || !strings.Contains(string(got), "# id;url\nsystem-dns;\ndagami;") {
		t.Fatalf("legacy DoH list was not migrated with active system-dns row: changed=%v data=%q", changed, got)
	}

	disabled := []byte("# id;url\n# system-dns;\ndagami;https://dns.dagami.ru/dns-query\n")
	got, changed, err = ensureSystemDNSDoHEntry(disabled)
	if err != nil {
		t.Fatal(err)
	}
	if changed || string(got) != string(disabled) {
		t.Fatalf("explicitly disabled system-dns row must remain disabled: changed=%v data=%q", changed, got)
	}
	if _, _, err := ensureSystemDNSDoHEntry([]byte("system-dns;\n# system-dns;\n")); err == nil {
		t.Fatal("duplicate active/commented system DNS rows should be rejected")
	}
}

func TestMigrateLegacyDoHListUsesStableIDsAndPreservesURLs(t *testing.T) {
	legacy := []byte("# old URL-only format\nhttps://eu.geohide.ru/dns-query\nhttps://doh.dagami.ru/dns-query\nhttps://custom.example.net/resolve\n")
	got, changed, err := migrateLegacyDoHList(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("legacy list was not marked as migrated")
	}
	want := "# id;url — provider IDs remain stable when endpoint hostnames change\ngeohide-eu;https://eu.geohide.ru/dns-query\ndagami;https://doh.dagami.ru/dns-query\nprovider-custom-example-net;https://custom.example.net/resolve\n"
	if string(got) != want {
		t.Fatalf("migrated contents:\n%s\nwant:\n%s", got, want)
	}
}

func TestMigrateLegacyDoHListRejectsMixedFormats(t *testing.T) {
	legacy := []byte("https://doh.dagami.ru/dns-query\ndagami;https://dns.dagami.ru/dns-query\n")
	if _, _, err := migrateLegacyDoHList(legacy); err == nil {
		t.Fatal("expected mixed old and new formats to be rejected")
	}
}

func TestParseDoHProvidersKeepsIDWhenEndpointHostnameChanges(t *testing.T) {
	providers, err := parseDoHProviders([]byte("# id;url\ndagami;https://dns.dagami.ru/dns-query\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(providers) != 1 || providers[0].ID != "dagami" || providers[0].URL != "https://dns.dagami.ru/dns-query" {
		t.Fatalf("parsed providers = %+v", providers)
	}
}

func TestParseDoHProvidersAllowsSystemDNSWithoutDoHURL(t *testing.T) {
	providers, err := parseDoHProviders([]byte("# id;url\nsystem-dns;\ndagami;https://dns.dagami.ru/dns-query\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(providers) != 2 || providers[0].ID != systemDNSUpstreamID || !providers[0].System || providers[0].URL != "" {
		t.Fatalf("system DNS row = %+v", providers)
	}
}

func TestParseDoHProvidersRejectsDuplicateIDsAndInvalidSystemDNS(t *testing.T) {
	cases := [][]byte{
		[]byte("dagami;https://one.example/dns-query\ndagami;https://two.example/dns-query\n"),
		[]byte("system-dns;https://resolver.example/dns-query\n"),
		[]byte("system-dns;\nsystem-dns;\n"),
		[]byte("bad id;https://resolver.example/dns-query\n"),
		[]byte("dagami;http://resolver.example/dns-query\n"),
	}
	for _, input := range cases {
		if _, err := parseDoHProviders(input); err == nil {
			t.Errorf("expected invalid DoH source to be rejected: %q", input)
		}
	}
}

func TestParseHealthChecksParsesEveryConfigurableField(t *testing.T) {
	input := []byte("accounts.example.com;A,AAAA,TXT;1;https://accounts.example.com/.well-known/openid-configuration;200,302;1\n")
	checks, err := parseHealthChecks(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 1 {
		t.Fatalf("checks = %d, want 1", len(checks))
	}
	got := checks[0]
	if got.Domain != "accounts.example.com" || !got.Required || got.HTTPURL != "https://accounts.example.com/.well-known/openid-configuration" || !got.VerifyOIDC {
		t.Fatalf("parsed check = %+v", got)
	}
	if !reflect.DeepEqual(got.QTypes, []uint16{1, 28, 16}) {
		t.Fatalf("qtypes = %v, want [1 28 16]", got.QTypes)
	}
	if !reflect.DeepEqual(got.ExpectedStatus, []int{200, 302}) {
		t.Fatalf("expected statuses = %v, want [200 302]", got.ExpectedStatus)
	}
}

func TestParseHealthChecksAllowsDNSOnlyOptionalChecks(t *testing.T) {
	checks, err := parseHealthChecks([]byte("play.google.com;A,AAAA;0;;;0\n"))
	if err != nil {
		t.Fatal(err)
	}
	if checks[0].Required || checks[0].HTTPURL != "" || checks[0].VerifyOIDC || len(checks[0].ExpectedStatus) != 0 {
		t.Fatalf("DNS-only check has unexpected options: %+v", checks[0])
	}
}

func TestParseHealthChecksRejectsInvalidFields(t *testing.T) {
	cases := []string{
		"not a domain;A;1;;;0\n",
		"example.com;A;true;;;0\n",
		"example.com;A;1;http://example.com/;200;0\n",
		"example.com;A;1;https://other.example/;200;0\n",
		"example.com;A;1;https://example.com/;404,;0\n",
		"example.com;A;1;https://example.com/;200;1\n",
		"example.com;;1;;;0\n",
		"example.com;A;1;;;0\nexample.com;AAAA;0;;;0\n",
	}
	for _, input := range cases {
		if _, err := parseHealthChecks([]byte(input)); err == nil {
			t.Errorf("expected invalid health check source to be rejected: %q", input)
		}
	}
}

func TestApplyConfigSourcesGeneratesOrderedUpstreamsAndPreservesRuntimeSettings(t *testing.T) {
	cfg := defaultConfig()
	// Simulate an old config.json with hostname-based provider IDs.
	for i := range cfg.Upstreams {
		if cfg.Upstreams[i].ID == "dagami" {
			cfg.Upstreams[i].ID = "doh.dagami.ru"
			cfg.Upstreams[i].BootstrapIPs = []string{"192.0.2.10"}
		}
	}
	for i, id := range cfg.Groups[0].Upstreams {
		if id == "dagami" {
			cfg.Groups[0].Upstreams[i] = "doh.dagami.ru"
		}
	}
	cfg.Cache.MaxEntries = 321
	cfg.LocalHosts = map[string]LocalHost{"internal.example": {IPv4: []string{"192.0.2.20"}}}
	cfg.GeminiAPI.Enabled = true
	cfg.Integration = true

	providers, err := parseDoHProviders([]byte("system-dns;\ndagami;https://dns.dagami.ru/dns-query\nextra;https://extra.example.net/dns-query\n"))
	if err != nil {
		t.Fatal(err)
	}
	checks, err := parseHealthChecks([]byte("accounts.google.com;A,AAAA;1;https://accounts.google.com/.well-known/openid-configuration;200;1\n"))
	if err != nil {
		t.Fatal(err)
	}
	urls := make(map[string]string, len(providers))
	for _, provider := range providers {
		if !provider.System {
			urls[provider.ID] = provider.URL
		}
	}
	generated, err := applyConfigSources(cfg, ConfigSources{Providers: providers, Checks: checks, LocalHosts: map[string]LocalHost{"internal.example": {IPv4: []string{"192.0.2.20"}}}, DoHURLs: urls, SystemDNSEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	wantIDs := []string{systemDNSUpstreamID, "dagami", "extra"}
	gotIDs := make([]string, 0, len(generated.Upstreams))
	for _, upstream := range generated.Upstreams {
		gotIDs = append(gotIDs, upstream.ID)
	}
	if !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Fatalf("generated upstream IDs = %v, want %v", gotIDs, wantIDs)
	}
	if generated.Upstreams[1].Name != "Dagami" || !reflect.DeepEqual(generated.Upstreams[1].BootstrapIPs, []string{"192.0.2.10"}) {
		t.Fatalf("legacy Dagami metadata was not preserved: %+v", generated.Upstreams[1])
	}
	if !reflect.DeepEqual(generated.Groups[0].Upstreams, wantIDs) || len(generated.Groups[0].Checks) != 1 || !generated.Groups[0].Checks[0].VerifyOIDC {
		t.Fatalf("generated Google group = %+v", generated.Groups[0])
	}
	if generated.Cache.MaxEntries != 321 || len(generated.LocalHosts) != 1 || !generated.GeminiAPI.Enabled || !generated.Integration {
		t.Fatal("non-managed config settings were not preserved")
	}
}

func TestApplyConfigSourcesCanDisableSystemDNS(t *testing.T) {
	cfg := defaultConfig()
	providers, err := parseDoHProviders([]byte("# system-dns;\ndagami;https://dns.dagami.ru/dns-query\n"))
	if err != nil {
		t.Fatal(err)
	}
	urls := map[string]string{"dagami": "https://dns.dagami.ru/dns-query"}
	generated, err := applyConfigSources(cfg, ConfigSources{
		Providers: providers, DoHURLs: urls, SystemDNSEnabled: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, upstream := range generated.Upstreams {
		if upstream.ID == systemDNSUpstreamID {
			t.Fatal("disabled system-dns remained in generated upstreams")
		}
	}
	for _, id := range generated.Groups[0].Upstreams {
		if id == systemDNSUpstreamID {
			t.Fatal("disabled system-dns remained in the Google upstream group")
		}
	}
	if len(generated.Groups[0].Upstreams) != 1 || generated.Groups[0].Upstreams[0] != "dagami" {
		t.Fatalf("unexpected upstreams with system DNS disabled: %v", generated.Groups[0].Upstreams)
	}
	if err := validateConfig(generated); err != nil {
		t.Fatalf("configuration without system DNS should validate: %v", err)
	}
}

func TestConfigSourceChecksumsTrackBothFiles(t *testing.T) {
	first := configSourceChecksums([]byte("a"), []byte("b"))
	if first != configSourceChecksums([]byte("a"), []byte("b")) {
		t.Fatal("identical source contents produced different hashes")
	}
	if first == configSourceChecksums([]byte("changed"), []byte("b")) {
		t.Fatal("DoH source change did not change hashes")
	}
	if first == configSourceChecksums([]byte("a"), []byte("changed")) {
		t.Fatal("health check source change did not change hashes")
	}
	if len(first.DoH) != 64 || len(first.Checks) != 64 || len(first.Hosts) != 64 || len(first.Combined) != 64 {
		t.Fatalf("SHA-256 checksum length is invalid: %+v", first)
	}
}

func TestWriteConfigAtomicProducesReadableJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := defaultConfig()
	if err := writeConfigAtomic(path, cfg); err != nil {
		t.Fatal(err)
	}
	got, err := loadConfigNoCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.DNSListenUDP != cfg.DNSListenUDP || got.Groups[0].ID != "google" {
		t.Fatalf("read back generated config = %+v", got)
	}
}

func TestRejectedConfigReloadKeepsPreviousSnapshot(t *testing.T) {
	runtime := &Runtime{}
	previous := &Snapshot{cfg: defaultConfig()}
	runtime.snapshot.Store(previous)

	runtime.rejectConfigReload("invalid-source", "test invalid source")
	if runtime.currentSnapshot() != previous {
		t.Fatal("rejected configuration replaced the last valid runtime snapshot")
	}
	if runtime.lastError == "" {
		t.Fatal("rejected configuration did not publish an operational error")
	}
}

func TestParseHealthChecksRejectsTrailingSlashOnOIDCDiscoveryURL(t *testing.T) {
	input := []byte("accounts.example.com;A;1;https://accounts.example.com/.well-known/openid-configuration/;200;1\n")
	if _, err := parseHealthChecks(input); err == nil {
		t.Fatal("OIDC discovery URL with a trailing slash must be rejected during source parsing")
	}
}

func TestReadConfigSourcesRejectsSymlinkedSource(t *testing.T) {
	dir := t.TempDir()
	realDoH := filepath.Join(dir, "real-doh.txt")
	dohLink := filepath.Join(dir, "doh-servers.txt")
	checks := filepath.Join(dir, "tst-domen.txt")
	hosts := filepath.Join(dir, localHostsSourceFile)
	if err := os.WriteFile(realDoH, []byte("cloudflare;https://cloudflare-dns.com/dns-query\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDoH, dohLink); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(checks, []byte("example.com;A;1;https://example.com/;200;0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hosts, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfigSources(dohLink, checks, hosts); err == nil {
		t.Fatal("config source reader must reject symlinked files")
	}
}

func TestEmbeddedDoHDefaultsParseToApprovedProviderSet(t *testing.T) {
	data, err := embeddedConfigSources.ReadFile("defaults/doh-servers.txt")
	if err != nil {
		t.Fatal(err)
	}
	providers, err := parseDoHProviders(data)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"geohide-eu": true,
		"dagami":     true,
		"comss-one":  true,
		"bezmezhau":  true,
		"zapret":     true,
		"pereval":    true,
	}
	got := make(map[string]string, len(providers))
	for _, provider := range providers {
		if provider.System || provider.ID == systemDNSUpstreamID {
			continue
		}
		got[provider.ID] = provider.URL
	}
	if len(got) != len(want) {
		t.Fatalf("embedded DoH provider count=%d, want %d: %#v", len(got), len(want), got)
	}
	for id := range want {
		if got[id] == "" {
			t.Errorf("embedded default provider %q is missing", id)
		}
	}
}
