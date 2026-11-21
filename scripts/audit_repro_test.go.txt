package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"encoding/json"
)

func TestAudit_RedactReplacementLiteral(t *testing.T) {
	out := redactWebUILogLine("Authorization: Bearer abc123SECRET and apiToken: zzz999")
	t.Logf("REDACT OUTPUT: %q", out)
}

func TestAudit_DigOverflowEmptyResults(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "dig")
	os.WriteFile(fake, []byte("#!/bin/sh\necho ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1'\necho 'example. 60 IN A 1.2.3.4'\n"), 0755)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	var checks []Check
	for i := 0; i < 26; i++ {
		checks = append(checks, Check{Domain: fmt.Sprintf("d%d.example.com", i), QTypes: []uint16{1, 28}})
	}
	res := runWebUIDigTests("127.0.0.1:5355", checks, "udp")
	empty := 0
	for _, r := range res {
		if r.Status == "" && r.Name == "" {
			empty++
		}
	}
	sum := finalizeWebUITests(webUITestSummary{Tests: res})
	t.Logf("queries=%d results=%d empty_results=%d summary_status=%s failed=%d", 52, len(res), empty, sum.Status, sum.Failed)
}

func TestAudit_ValidListenAcceptsNonLoopbackAndBadPort(t *testing.T) {
	for _, tc := range []struct{ u, tcp, h string }{
		{"0.0.0.0:53", "0.0.0.0:53", "0.0.0.0:18765"},
		{"127.0.0.1:99999", "127.0.0.1:5355", "127.0.0.1:18765"},
		{"127.0.0.1:5355", "localhost:abc", "127.0.0.1:18765"},
	} {
		c := defaultConfig()
		c.DNSListenUDP, c.DNSListenTCP, c.HTTPListen = tc.u, tc.tcp, tc.h
		t.Logf("validateConfig(udp=%s tcp=%s http=%s) => %v", tc.u, tc.tcp, tc.h, validateConfig(c))
	}
}

func TestAudit_ErrorResponseShape(t *testing.T) {
	q := makeDNSQuery("example.com", 1)
	q = append(q, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0) // fake OPT
	binary.BigEndian.PutUint16(q[10:12], 1)
	r := servfailResponse(q)
	t.Logf("query len=%d resp len=%d QD=%d AN=%d NS=%d AR=%d rcode=%d (bytes after header remain: %d)",
		len(q), len(r), binary.BigEndian.Uint16(r[4:6]), binary.BigEndian.Uint16(r[6:8]),
		binary.BigEndian.Uint16(r[8:10]), binary.BigEndian.Uint16(r[10:12]), dnsRCode(r), len(r)-12)
	short := formerrResponse([]byte{1, 2, 3})
	t.Logf("formerr for 3-byte packet => len=%d", len(short))
}

func TestAudit_UDPTruncationNoTC(t *testing.T) {
	r := &Runtime{}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.serveUDPWithHandler(ctx, conn, func(q []byte) []byte {
		resp := make([]byte, 6000)
		copy(resp, q[:2])
		binary.BigEndian.PutUint16(resp[2:4], 0x8180)
		return resp
	})
	c, _ := net.DialUDP("udp", nil, conn.LocalAddr().(*net.UDPAddr))
	c.Write(makeDNSQuery("example.com", 1))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	t.Logf("handler returned 6000 bytes; client received n=%d err=%v TC-bit=%v", n, err, dnsTruncated(buf[:n]))
}

func TestAudit_OIDCTrailingSlashInconsistency(t *testing.T) {
	line := "example.com;A;1;https://example.com/.well-known/openid-configuration/;200;1\n"
	_, perr := parseHealthChecks([]byte(line))
	verr := verifyOIDCIssuer([]byte(`{"issuer":"https://example.com"}`), "https://example.com/.well-known/openid-configuration/")
	t.Logf("parseHealthChecks err=%v | verifyOIDCIssuer err=%v", perr, verr)
}

func TestAudit_URLErrorLeaksQuerySecret(t *testing.T) {
	u := &UpstreamRuntime{cfg: Upstream{ID: "x", URL: "https://127.0.0.1:1/dns-query?token=SUPERSECRET"}, client: &http.Client{Timeout: time.Second}}
	_, err := sendDoH(context.Background(), u, makeDNSQuery("example.com", 1))
	t.Logf("sendDoH error: %v | contains secret=%v", err, strings.Contains(fmt.Sprint(err), "SUPERSECRET"))
}

func TestAudit_GeminiKeyFileOverwritesConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := defaultConfig()
	cfg.GeminiAPI.KeyFile = "config.json"
	b, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile(filepath.Join(dir, "config.json"), b, 0600)
	err := saveWebUIGeminiKey(dir, "AAAAAAAAAAAAAAAAAAAAAAAA")
	after, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	_, lerr := loadConfigNoCreate(filepath.Join(dir, "config.json"))
	t.Logf("saveWebUIGeminiKey err=%v | config.json now=%q | loadConfigNoCreate err=%v", err, strings.TrimSpace(string(after)), lerr)
}

func TestAudit_SessionCookieGivenToAnyLoopbackClient(t *testing.T) {
	h := newWebUIHandlerWithDataDir("http://127.0.0.1:1/status", "SECRET-SESSION-TOKEN", t.TempDir())
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "127.0.0.1:40000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	cookies := rec.Result().Cookies()
	t.Logf("GET / without any credentials -> status=%d, Set-Cookie present=%v", rec.Code, len(cookies) > 0)
	req2 := httptest.NewRequest("GET", "/api/v1/logs", nil)
	req2.Host = "127.0.0.1:40000"
	for _, c := range cookies {
		req2.AddCookie(c)
	}
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	t.Logf("GET /api/v1/logs with that cookie -> status=%d (401 would mean protected)", rec2.Code)
}

func TestAudit_ResolverFailureReturnsNODATA(t *testing.T) {
	r := &Runtime{}
	s := &Snapshot{cfg: Config{DNSMode: "resolver", DNSQueryTimeoutSeconds: 1}}
	resp := r.resolverDNSResponse(makeDNSQuery("example.com", 1), s)
	t.Logf("all-upstreams-failed => rcode=%d answers=%d (SERVFAIL would be rcode 2)", dnsRCode(resp), dnsAnswerCount(resp))
}
