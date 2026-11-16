package main

import (
	"bufio"
	"fmt"
	"net/http"
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
	rec := httptestNewRecorder()
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

	badHost := req.Clone(req.Context())
	badHost.Host = "example.org"
	badHost.URL.Path = "/"
	badHostRecorder := httptestNewRecorder()
	handler.ServeHTTP(badHostRecorder, badHost)
	if badHostRecorder.Code != http.StatusForbidden {
		t.Fatalf("untrusted Host status=%d, want %d", badHostRecorder.Code, http.StatusForbidden)
	}

	badMethod := req.Clone(req.Context())
	badMethod.Method = http.MethodPost
	methodRecorder := httptestNewRecorder()
	handler.ServeHTTP(methodRecorder, badMethod)
	if methodRecorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status=%d, want %d", methodRecorder.Code, http.StatusMethodNotAllowed)
	}

	notFound := req.Clone(req.Context())
	notFound.URL.Path = "/api/anything"
	notFoundRecorder := httptestNewRecorder()
	handler.ServeHTTP(notFoundRecorder, notFound)
	if notFoundRecorder.Code != http.StatusNotFound {
		t.Fatalf("unknown path status=%d, want %d", notFoundRecorder.Code, http.StatusNotFound)
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
		done <- runWebUI()
	}()

	cleanup := func() {
		_ = controlWrite.Close()
		select {
		case <-done:
		case <-time.After(6 * time.Second):
		}
		os.Stdin, os.Stdout = oldStdin, oldStdout
		_ = controlRead.Close()
		_ = readyRead.Close()
		_ = readyWrite.Close()
	}
	defer cleanup()

	if err := readyRead.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(readyRead).ReadString('\n')
	if err != nil {
		t.Fatalf("read Web UI readiness line: %v", err)
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
		if err != nil {
			t.Fatalf("Web UI shutdown: %v", err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("Web UI did not stop after supervisor pipe EOF")
	}
}

// Small local recorder keeps the tests independent of external packages.
type webUIRecorder struct {
	header http.Header
	code   int
	body   strings.Builder
}

func httptestNewRecorder() *webUIRecorder {
	return &webUIRecorder{header: make(http.Header)}
}

func (r *webUIRecorder) Header() http.Header { return r.header }
func (r *webUIRecorder) WriteHeader(code int) { r.code = code }
func (r *webUIRecorder) Write(data []byte) (int, error) {
	if r.code == 0 {
		r.code = http.StatusOK
	}
	return r.body.Write(data)
}
