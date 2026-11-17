package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"net"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"lucx-doh-health-monitor/internal/autohosts"
)

func TestParseAAAARecordsAndRejectPrivateProbeTargets(t *testing.T) {
	query := makeDNSQuery("example.com", 28)
	response := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[6:8], 1)
	response = append(response, 0xc0, 0x0c)
	response = append(response, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16)
	ip := net.ParseIP("2001:4860:4860::8888").To16()
	response = append(response, ip...)
	ips, err := parseAddressRecords(response, 28)
	if err != nil { t.Fatal(err) }
	if len(ips) != 1 || ips[0] != "2001:4860:4860::8888" { t.Fatalf("unexpected AAAA records: %v", ips) }
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.1.1", "100.64.0.1", "192.0.2.1", "198.18.0.1", "::1", "fc00::1", "2001:db8::1", "2002::1"} {
		if isAutoHostsPublicIP(net.ParseIP(raw)) { t.Errorf("private/reserved address accepted: %s", raw) }
	}
	if !isAutoHostsPublicIP(net.ParseIP("8.8.8.8")) { t.Fatal("public IPv4 rejected") }
}

func TestAutoHostsControllerRequiresRepeatedFailureBeforeSwitch(t *testing.T) {
	now := time.Now().UTC()
	manager, err := autohosts.New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil { t.Fatal(err) }
	a := autohosts.Endpoint{ServerID:"a", URL:"https://a.example/dns-query", Hostname:"a.example", IPv4:[]string{"8.8.8.8"}}
	b := autohosts.Endpoint{ServerID:"b", URL:"https://b.example/dns-query", Hostname:"b.example", IPv4:[]string{"1.1.1.1"}}
	if err := manager.ApplyFullCycle("a", []autohosts.Endpoint{a,b}, nil, now); err != nil { t.Fatal(err) }
	controller := newAutoHostsController(nil, manager)
	controller.activeSince = now.Add(-20*time.Minute)
	first, err := controller.chooseActive([]autohosts.Endpoint{a,b}, []autohosts.ProbeResult{{ServerID:"b",Domain:"chatgpt.com",Success:true}}, now)
	if err != nil { t.Fatal(err) }
	if first != "a" { t.Fatalf("first failed cycle switched too early: %s", first) }
	second, err := controller.chooseActive([]autohosts.Endpoint{a,b}, []autohosts.ProbeResult{{ServerID:"b",Domain:"chatgpt.com",Success:true}}, now.Add(time.Minute))
	if err != nil { t.Fatal(err) }
	if second != "b" { t.Fatalf("expected switch after repeated failure, got %s", second) }
}


func TestAutoHostsJitterIsBounded(t *testing.T) {
	base := 5*time.Minute
	for i:=0; i<20; i++ {
		got := autoHostsJitter(base)
		if got < base*95/100 || got > base*105/100 {
			t.Fatalf("jitter outside ±5%%: base=%s got=%s",base,got)
		}
	}
}


func TestAutoHostsProbeURLRejectsNonHTTPSAndNon443Ports(t *testing.T) {
	cases:=[]struct{raw,domain string; want bool}{
		{"https://chatgpt.com/","chatgpt.com",true},
		{"https://chatgpt.com:443/","chatgpt.com",true},
		{"https://chatgpt.com:8443/","chatgpt.com",false},
		{"http://chatgpt.com/","chatgpt.com",false},
		{"https://evil.example/","chatgpt.com",false},
		{"https://user:pass@chatgpt.com/","chatgpt.com",false},
		{"https://chatgpt.com./","chatgpt.com",true},
	}
	for _,tc:=range cases {
		parsed,err:=url.Parse(tc.raw)
		if err!=nil { t.Fatalf("parse %q: %v",tc.raw,err) }
		if got:=validAutoHostsProbeURL(parsed,tc.domain);got!=tc.want { t.Errorf("validAutoHostsProbeURL(%q)=%v want %v",tc.raw,got,tc.want) }
	}
}


func TestPinnedHTTPSProbePreservesSNIHostAndDoesNotFollowRedirect(t *testing.T) {
	key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
	if err!=nil { t.Fatal(err) }
	now:=time.Now()
	template:=&x509.Certificate{
		SerialNumber:big.NewInt(42),
		Subject:pkix.Name{CommonName:"probe.example"},
		DNSNames:[]string{"probe.example"},
		NotBefore:now.Add(-time.Minute),
		NotAfter:now.Add(time.Hour),
		KeyUsage:x509.KeyUsageDigitalSignature,
		ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der,err:=x509.CreateCertificate(rand.Reader,template,template,&key.PublicKey,key)
	if err!=nil { t.Fatal(err) }
	keyDER,err:=x509.MarshalECPrivateKey(key)
	if err!=nil { t.Fatal(err) }
	cert,err:=tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der}),pem.EncodeToMemory(&pem.Block{Type:"EC PRIVATE KEY",Bytes:keyDER}))
	if err!=nil { t.Fatal(err) }
	parsedCert,err:=x509.ParseCertificate(der)
	if err!=nil { t.Fatal(err) }
	roots:=x509.NewCertPool()
	roots.AddCert(parsedCert)

	listener,err:=net.Listen("tcp","127.0.0.1:0")
	if err!=nil { t.Fatal(err) }
	type observedRequest struct { host,sni,path string }
	observed:=make(chan observedRequest,2)
	server:=&http.Server{TLSConfig:&tls.Config{Certificates:[]tls.Certificate{cert},MinVersion:tls.VersionTLS12},Handler:http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		sni:=""
		if r.TLS!=nil { sni=r.TLS.ServerName }
		observed<-observedRequest{host:r.Host,sni:sni,path:r.URL.Path}
		http.Redirect(w,r,"https://redirect-target.example/elsewhere",http.StatusFound)
	})}
	serveErr:=make(chan error,1)
	go func(){ serveErr<-server.Serve(tls.NewListener(listener,server.TLSConfig)) }()
	defer func(){ ctx,cancel:=context.WithTimeout(context.Background(),time.Second);defer cancel();_ = server.Shutdown(ctx) }()

	port:=listener.Addr().(*net.TCPAddr).Port
	client:=newPinnedHTTPClient("127.0.0.1","probe.example",3*time.Second)
	defer client.CloseIdleConnections()
	transport,ok:=client.Transport.(*http.Transport)
	if !ok { t.Fatal("pinned client transport has unexpected type") }
	transport.TLSClientConfig.RootCAs=roots

	target:= "https://probe.example:"+fmt.Sprint(port)+"/health"
	req,err:=http.NewRequest(http.MethodGet,target,nil)
	if err!=nil { t.Fatal(err) }
	resp,err:=client.Do(req)
	if err!=nil { t.Fatalf("TLS request to pinned IP failed: %v",err) }
	_ = resp.Body.Close()
	if resp.StatusCode!=http.StatusFound { t.Fatalf("status=%d, want redirect response 302",resp.StatusCode) }
	select {
	case got:=<-observed:
		if got.sni!="probe.example" { t.Errorf("TLS SNI=%q, want probe.example",got.sni) }
		if got.host!="probe.example:"+fmt.Sprint(port) { t.Errorf("HTTP Host=%q, want probe.example:%d",got.host,port) }
		if got.path!="/health" { t.Errorf("path=%q, want /health",got.path) }
	case <-time.After(time.Second):
		t.Fatal("HTTPS server did not receive the probe")
	}
	select {
	case extra:=<-observed:
		t.Fatalf("redirect was followed unexpectedly: %+v",extra)
	case <-time.After(100*time.Millisecond):
	}
	if !strings.Contains(target,"probe.example") { t.Fatal("test target must retain original hostname") }
}

func TestPinnedHTTPSProbeRejectsUntrustedCertificate(t *testing.T) {
	listener,err:=net.Listen("tcp","127.0.0.1:0")
	if err!=nil { t.Fatal(err) }
	cert,err:=tls.X509KeyPair(testProbeCertificatePEM(t),testProbePrivateKeyPEM(t))
	if err!=nil { t.Fatal(err) }
	server:=&http.Server{TLSConfig:&tls.Config{Certificates:[]tls.Certificate{cert}},Handler:http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.WriteHeader(http.StatusOK)})}
	go func(){ _=server.Serve(tls.NewListener(listener,server.TLSConfig)) }()
	defer func(){ctx,cancel:=context.WithTimeout(context.Background(),time.Second);defer cancel();_ = server.Shutdown(ctx)}()
	port:=listener.Addr().(*net.TCPAddr).Port
	client:=newPinnedHTTPClient("127.0.0.1","probe.example",2*time.Second)
	defer client.CloseIdleConnections()
	_,err=client.Get("https://probe.example:"+fmt.Sprint(port)+"/")
	if err==nil { t.Fatal("expected untrusted self-signed certificate to be rejected") }
}
