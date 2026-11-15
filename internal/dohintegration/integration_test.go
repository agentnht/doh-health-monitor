package dohintegration

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testXrayConfig() map[string]any {
	return map[string]any{
		"inbounds": []any{map[string]any{"tag":"api","protocol":"dokodemo-door"}},
		"outbounds": []any{},
		"routing": map[string]any{"rules":[]any{
			map[string]any{"type":"field","inboundTag":[]any{"api"},"outboundTag":"api"},
		}},
		"dns": map[string]any{"servers":[]any{}},
	}
}

func TestBuildPlanAddsPermanentDNSObjectsAndIsIdempotent(t *testing.T) {
	plan:=buildPlan(testXrayConfig(),true)
	if len(plan.Blockers)!=0 { t.Fatalf("unexpected blockers: %v",plan.Blockers) }
	if plan.OutboundTag==""||!plan.OutboundCreated||!plan.ServerCreated||!plan.RouteCreated { t.Fatalf("expected all permanent objects to be planned: %#v",plan) }
	outbounds,_:=listValue(plan.Proposed["outbounds"])
	if len(outbounds)!=1||str(mapValue(outbounds[0])["tag"])!="dns-out" { t.Fatalf("unexpected outbounds: %#v",outbounds) }
	rules,_:=listValue(mapValue(plan.Proposed["routing"])["rules"])
	if len(rules)!=2||!globalPort53Rule(mapValue(rules[1])) { t.Fatalf("unexpected routing rules: %#v",rules) }
	servers,_:=listValue(mapValue(plan.Proposed["dns"])["servers"])
	if len(servers)!=1 { t.Fatalf("expected one DNS server, got %#v",servers) }
	second:=buildPlan(plan.Proposed,true)
	if len(second.Blockers)!=0 { t.Fatalf("second plan blocked: %v",second.Blockers) }
	if len(second.Changes)!=0 { t.Fatalf("second plan should be idempotent, got changes: %v",second.Changes) }
	if canonical(second.Proposed)!=canonical(plan.Proposed) { t.Fatal("second plan changed the already-integrated config") }
}

func TestBuildPlanBlocksIncompatibleGlobalPort53Route(t *testing.T) {
	cfg:=testXrayConfig()
	outbounds:=[]any{map[string]any{"tag":"direct","protocol":"freedom"}}
	cfg["outbounds"]=outbounds
	rules:=mapValue(cfg["routing"])["rules"].([]any)
	mapValue(cfg["routing"])["rules"]=append(rules,map[string]any{"type":"field","network":"tcp,udp","port":"53","outboundTag":"direct"})
	plan:=buildPlan(cfg,true)
	if len(plan.Blockers)==0 { t.Fatal("expected incompatible port-53 route to block the plan") }
	if canonical(plan.Proposed)!=canonical(cfg) { t.Fatal("blocked plan must not return a mutated proposed config") }
}

func TestBuildPlanBlocksScopedLocalDNSServer(t *testing.T) {
	cfg:=testXrayConfig()
	cfg["dns"]=map[string]any{"servers":[]any{map[string]any{"address":"127.0.0.1","port":5355,"domains":[]any{"geosite:private"}}}}
	plan:=buildPlan(cfg,true)
	if len(plan.Blockers)==0 { t.Fatal("expected a scoped local DNS server to block automatic integration") }
}

func TestBuildPlanBlocksNumericQTypeZero(t *testing.T) {
	cfg:=testXrayConfig()
	cfg["outbounds"]=[]any{map[string]any{"tag":"custom-dns","protocol":"dns","settings":map[string]any{
		"rewriteAddress":"127.0.0.1","rewritePort":5355,"rules":[]any{map[string]any{"qType":json.Number("0")}},
	}}}
	plan:=buildPlan(cfg,true)
	if len(plan.Blockers)==0 { t.Fatal("expected numeric qType zero to block panel save") }
}

func TestBuildRemovePlanSelectsOnlyUnsharedPermanentObjects(t *testing.T) {
	integrated:=buildPlan(testXrayConfig(),true)
	if len(integrated.Blockers)!=0 { t.Fatal(integrated.Blockers) }
	plan:=buildRemovePlan(integrated.Proposed)
	if plan.Blocked||len(plan.Blockers)!=0 { t.Fatalf("unexpected remove blockers: %#v",plan) }
	if len(plan.RouteIndexes)!=1||len(plan.OutboundTags)!=1||len(plan.ServerIndexes)!=1 { t.Fatalf("unexpected remove plan: %#v",plan) }
}

func TestBuildRemovePlanPreservesExternallyUsedDNSOutbound(t *testing.T) {
	integrated:=buildPlan(testXrayConfig(),true)
	if len(integrated.Blockers)!=0 { t.Fatal(integrated.Blockers) }
	cfg:=cloneMap(integrated.Proposed)
	routing:=mapValue(cfg["routing"])
	rules,_:=listValue(routing["rules"])
	routing["rules"]=append(rules,map[string]any{"type":"field","port":"443","outboundTag":"dns-out"})
	plan:=buildRemovePlan(cfg)
	if plan.Blocked { t.Fatalf("external use should not block independent route removal: %#v",plan) }
	if len(plan.RouteIndexes)!=1 { t.Fatalf("expected only the selected permanent port-53 route, got %#v",plan.RouteIndexes) }
	if len(plan.OutboundTags)!=0||len(plan.ServerIndexes)!=0 { t.Fatalf("externally used outbound/server must be preserved: %#v",plan) }
	if len(plan.Blockers)==0 { t.Fatal("expected a preservation reason for externally used resources") }
}

func TestPanelNormalizeAddsLucXDNSAllowBeforePrivateBlock(t *testing.T) {
	cfg:=map[string]any{
		"outbounds":[]any{map[string]any{"tag":"direct","protocol":"freedom"}},
		"dns":map[string]any{"servers":[]any{
			map[string]any{"address":"127.0.0.1","port":5355},
			map[string]any{"address":"192.168.1.1","port":53},
		}},
		"routing":map[string]any{"rules":[]any{
			map[string]any{"type":"field","inboundTag":[]any{"api"},"outboundTag":"api"},
			map[string]any{"type":"field","ip":[]any{"geoip:private"},"outboundTag":"blocked"},
		}},
	}
	first:=panelNormalize(cfg)
	rules,_:=listValue(mapValue(first["routing"])["rules"])
	localAllow:=-1;block:=-1;count:=0;lanAllow:=false
	for i,v:=range rules{r:=mapValue(v);if str(r["ruleTag"])==dnsAllowTag{count++;if str(r["outboundTag"])!="direct"{t.Fatalf("unexpected DNS allow target: %#v",r)};if str(r["port"])=="5355"{ips:=tagList(r["ip"]);if len(ips)!=1||ips[0]!=dnsAddress{t.Fatalf("unexpected loopback DNS allow IPs: %#v",r["ip"])};localAllow=i};if str(r["port"])=="53"&&containsString(tagList(r["ip"]),"192.168.1.1"){lanAllow=true}};if str(r["outboundTag"])=="blocked"{block=i}}
	if count!=2||localAllow<0||!lanAllow||block<0||localAllow>=block{t.Fatalf("expected loopback and LAN DNS allows before private block: %#v",rules)}
	second:=panelNormalize(first)
	if canonical(first)!=canonical(second){t.Fatal("panel normalization is not idempotent")}
}

func TestServerEndpointParsesIPv4AndHTTPS(t *testing.T) {
	cases:=[]struct{value any;ip string;port int}{
		{"127.0.0.1:5355","127.0.0.1",5355},
		{map[string]any{"address":"127.0.0.1","port":json.Number("5355")},"127.0.0.1",5355},
		{"https://192.0.2.10/dns-query","192.0.2.10",443},
		{"https://192.0.2.10:8443/dns-query","192.0.2.10",8443},
	}
	for _,tc:=range cases{ip,port,ok:=serverEndpoint(tc.value);if !ok||ip!=tc.ip||port!=tc.port{t.Errorf("serverEndpoint(%#v) = %q,%d,%v",tc.value,ip,port,ok)}}
}

func TestDNSAResponseParser(t *testing.T) {
	id,query,err:=dnsQueryPacket("example.com");if err!=nil{t.Fatal(err)}
	response:=make([]byte,12)
	binary.BigEndian.PutUint16(response[:2],id)
	binary.BigEndian.PutUint16(response[2:4],0x8180)
	binary.BigEndian.PutUint16(response[4:6],1)
	binary.BigEndian.PutUint16(response[6:8],1)
	response=append(response,query[12:]...)
	response=append(response,0xc0,0x0c,0,1,0,1,0,0,0,60,0,4,203,0,113,8)
	answers,err:=parseDNSA(response,id)
	if err!=nil{t.Fatal(err)}
	if len(answers)!=1||answers[0]!="203.0.113.8"{t.Fatalf("unexpected A answers: %v",answers)}
}

func TestPanelAPIReadStateUsesLocalBearerAndDecodesSettings(t *testing.T) {
	const token="0123456789abcdef0123456789abcdef0123456789"
	server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		if r.Method!=http.MethodPost||r.URL.Path!="/panel/api/xray/"{http.Error(w,"wrong endpoint",404);return}
		if r.Header.Get("Authorization")!="Bearer "+token{http.Error(w,"missing bearer",401);return}
		w.Header().Set("Content-Type","application/json")
		_,_=w.Write([]byte("{\"success\":true,\"obj\":{\"xraySetting\":\"{\\\"dns\\\":{}}\",\"outboundTestUrl\":\"https://example.com\"}}"))
	}))
	defer server.Close()
	api,err:=NewPanelAPI(Endpoint{BaseURL:server.URL},token,time.Second,false,nil)
	if err!=nil{t.Fatal(err)}
	state,err:=api.ReadState()
	if err!=nil{t.Fatal(err)}
	if state.OutboundTestURL!="https://example.com"||mapValue(state.Config["dns"])==nil{t.Fatalf("unexpected panel state: %#v",state)}
}

func TestSavedCredentialMustRemainPrivate(t *testing.T) {
	path:=filepath.Join(t.TempDir(),"private","panel-api-auth.json")
	token:="0123456789abcdef0123456789abcdef0123456789"
	if err:=saveToken(path,token);err!=nil{t.Fatal(err)}
	got,err:=readSavedToken(path);if err!=nil{t.Fatal(err)}
	if got!=token{t.Fatal("saved credential changed")}
	if err:=os.Chmod(path,0644);err!=nil{t.Fatal(err)}
	if _,err:=readSavedToken(path);err==nil{t.Fatal("credential with group/world permissions must be rejected")}
}

func TestNormalizeBasePathRejectsTraversal(t *testing.T) {
	if _,err:=normalizeBasePath("/safe/../private");err==nil{t.Fatal("expected path traversal to be rejected")}
	got,err:=normalizeBasePath("admin/panel");if err!=nil{t.Fatal(err)}
	if got!="/admin/panel/"{t.Fatalf("unexpected normalized path %q",got)}
}

func TestTokenValidationRejectsWhitespace(t *testing.T) {
	if _,err:=validToken("short");err==nil{t.Fatal("short token must be rejected")}
	if _,err:=validToken("0123456789abcdef0123456789abcdef token");err==nil{t.Fatal("token containing whitespace must be rejected")}
	if _,err:=validToken(fmt.Sprintf("%032d",1));err!=nil{t.Fatalf("expected valid token: %v",err)}
}
