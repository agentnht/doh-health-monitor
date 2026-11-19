package dohintegration

import (
	"encoding/binary"
	"encoding/json"
	"bufio"
	"database/sql"
	"io"
	"net"
	"strconv"
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

func TestServerEndpointParsesIPv4(t *testing.T) {
	cases:=[]struct{value any;ip string;port int}{
		{"127.0.0.1:5355","127.0.0.1",5355},
		{map[string]any{"address":"127.0.0.1","port":json.Number("5355")},"127.0.0.1",5355},
		{"127.0.0.1","127.0.0.1",53},
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

func testDNSOutbound(tag string) map[string]any {
	return map[string]any{"tag":tag,"protocol":"dns","settings":map[string]any{"rewriteNetwork":"udp","rewriteAddress":dnsAddress,"rewritePort":dnsPort}}
}
func TestBuildPlanReusesFirstCompatibleOutboundInConfigOrder(t *testing.T) {
	cfg:=testXrayConfig();cfg["outbounds"]=[]any{testDNSOutbound("z-dns"),testDNSOutbound("a-dns")}
	plan:=buildPlan(cfg,true);if len(plan.Blockers)!=0{t.Fatalf("blockers: %v",plan.Blockers)}
	if plan.OutboundTag!="z-dns"||plan.OutboundCreated||!plan.RouteCreated{t.Fatalf("unexpected plan: %#v",plan)}
}
func TestBuildPlanBlocksEarlierIncompatibleGlobalPortRange(t *testing.T) {
	cfg:=testXrayConfig();cfg["outbounds"]=[]any{map[string]any{"tag":"direct","protocol":"freedom"},testDNSOutbound("dns-local")}
	routing:=mapValue(cfg["routing"]);routing["rules"]=append(routing["rules"].([]any),
		map[string]any{"type":"field","network":"tcp,udp","port":"53,443","outboundTag":"direct"},
		map[string]any{"type":"field","network":"tcp,udp","port":"53","outboundTag":"dns-local"})
	plan:=buildPlan(cfg,true);if len(plan.Blockers)==0{t.Fatal("incompatible earlier port range must block")}
	if canonical(plan.Proposed)!=canonical(cfg){t.Fatal("blocked plan mutated config")}
}
func TestBuildPlanReusesCompatibleGlobalPortRange(t *testing.T) {
	cfg:=testXrayConfig();cfg["outbounds"]=[]any{testDNSOutbound("dns-local")}
	r:=mapValue(cfg["routing"]);r["rules"]=append(r["rules"].([]any),map[string]any{"type":"field","network":"tcp,udp","port":"53,443","outboundTag":"dns-local"})
	p:=buildPlan(cfg,true);if len(p.Blockers)!=0||p.RouteCreated||p.OutboundTag!="dns-local"{t.Fatalf("unexpected broad-route plan: %#v",p)}
}
func TestBuildPlanResolvesBalancerToFirstSelectedDNSOutbound(t *testing.T) {
	cfg:=testXrayConfig();cfg["outbounds"]=[]any{testDNSOutbound("dns-z"),testDNSOutbound("dns-a")}
	r:=mapValue(cfg["routing"]);r["balancers"]=[]any{map[string]any{"tag":"dns-balancer","selector":[]any{"dns-"}}}
	r["rules"]=append(r["rules"].([]any),map[string]any{"type":"field","network":"tcp,udp","port":"53","balancerTag":"dns-balancer"})
	p:=buildPlan(cfg,true);if len(p.Blockers)!=0||p.RouteCreated||p.OutboundTag!="dns-z"{t.Fatalf("unexpected balancer plan: %#v",p)}
}
func TestBuildPlanHonorsOutboundTagOverBalancerTag(t *testing.T) {
	cfg:=testXrayConfig();cfg["outbounds"]=[]any{map[string]any{"tag":"direct","protocol":"freedom"},testDNSOutbound("dns-local")}
	r:=mapValue(cfg["routing"]);r["balancers"]=[]any{map[string]any{"tag":"dns-balancer","selector":[]any{"dns-"}}}
	r["rules"]=append(r["rules"].([]any),map[string]any{"type":"field","network":"tcp,udp","port":"53","outboundTag":"direct","balancerTag":"dns-balancer"})
	p:=buildPlan(cfg,true);if len(p.Blockers)==0{t.Fatal("outboundTag must take precedence over balancerTag")}
}
func TestBuildPlanAcceptsTwoSingleTransportRoutesAsCompleteDNSCoverage(t *testing.T) {
	cfg:=testXrayConfig();cfg["outbounds"]=[]any{testDNSOutbound("dns-first"),testDNSOutbound("dns-second")}
	r:=mapValue(cfg["routing"]);r["rules"]=append(r["rules"].([]any),
		map[string]any{"type":"field","network":"tcp","port":"53","outboundTag":"dns-first"},
		map[string]any{"type":"field","network":"udp","port":"53","outboundTag":"dns-second"})
	p:=buildPlan(cfg,true);if len(p.Blockers)!=0||p.RouteCreated||p.OutboundTag!="dns-first"{t.Fatalf("unexpected partial-route plan: %#v",p)}
}
func TestBuildPlanRejectsUnsupportedRuleTypeMatchingPort53(t *testing.T) {
	cfg:=testXrayConfig();cfg["outbounds"]=[]any{testDNSOutbound("dns-local")}
	r:=mapValue(cfg["routing"]);r["rules"]=append(r["rules"].([]any),map[string]any{"type":"logical","network":"tcp,udp","port":"53","outboundTag":"dns-local"})
	p:=buildPlan(cfg,true);if len(p.Blockers)==0{t.Fatal("unsupported port-53 rule type should block")}
}
func TestServerEndpointMatchesLucXStringAndMapForms(t *testing.T) {
	cases:=[]struct{value any;ip string;port int;valid bool}{
		{"127.0.0.1","127.0.0.1",53,true},{"127.0.0.1:5355","127.0.0.1",5355,true},{"[::1]:5355","::1",5355,true},
		{map[string]any{"address":"127.0.0.1","port":json.Number("5355")},"127.0.0.1",5355,true},
		{map[string]any{"address":"127.0.0.1:5355","port":json.Number("53")},"",0,false},
		{map[string]any{"address":"127.0.0.1","port":nil},"",0,false},{"https://127.0.0.1/dns-query","",0,false},
	}
	for _,c:=range cases{ip,port,ok:=serverEndpoint(c.value);if ip!=c.ip||port!=c.port||ok!=c.valid{t.Errorf("serverEndpoint(%#v)=(%q,%d,%v), want (%q,%d,%v)",c.value,ip,port,ok,c.ip,c.port,c.valid)}}
}
func TestOutboundMatcherRejectsMalformedRewriteSettings(t *testing.T) {
	base:=testDNSOutbound("dns-local");if !outboundMatchesDNS(base){t.Fatal("valid local DNS outbound should match")}
	badPort:=cloneMap(base);mapValue(badPort["settings"])["rewritePort"]="5355,5356";if outboundMatchesDNS(badPort){t.Fatal("ambiguous rewritePort should not match")}
	badNetwork:=cloneMap(base);mapValue(badNetwork["settings"])["rewriteNetwork"]=json.Number("1");if outboundMatchesDNS(badNetwork){t.Fatal("non-string rewriteNetwork should not match")}
	upper:=cloneMap(base);mapValue(upper["settings"])["rewriteNetwork"]="UDP";if !outboundMatchesDNS(upper){t.Fatal("rewriteNetwork comparison should be case-insensitive")}
}
func TestBuildRemovePlanPreservesDNSServerWhenReferencesCannotBeAnalyzed(t *testing.T) {
	p:=buildPlan(testXrayConfig(),true);if len(p.Blockers)!=0{t.Fatal(p.Blockers)}
	cfg:=cloneMap(p.Proposed);mapValue(cfg["dns"])["rules"]=nil
	remove:=buildRemovePlan(cfg);if len(remove.ServerIndexes)!=0||len(remove.Blockers)==0{t.Fatalf("malformed dns.rules was not preserved: %#v",remove)}
}
func TestBuildRemovePlanPreservesDNSServerReferencedByTag(t *testing.T) {
	p:=buildPlan(testXrayConfig(),true);if len(p.Blockers)!=0{t.Fatal(p.Blockers)}
	cfg:=cloneMap(p.Proposed);dns:=mapValue(cfg["dns"]);servers,_:=listValue(dns["servers"]);mapValue(servers[0])["tag"]="local-dns"
	dns["rules"]=[]any{map[string]any{"server":"local-dns","domain":[]any{"example.com"}}}
	remove:=buildRemovePlan(cfg);if len(remove.ServerIndexes)!=0||len(remove.Blockers)==0{t.Fatalf("referenced DNS server was not preserved: %#v",remove)}
}
func testDNSResponse(query []byte)[]byte{
	if len(query)<12{return nil};response:=make([]byte,12);binary.BigEndian.PutUint16(response[:2],binary.BigEndian.Uint16(query[:2]));binary.BigEndian.PutUint16(response[2:4],0x8180);binary.BigEndian.PutUint16(response[4:6],1);binary.BigEndian.PutUint16(response[6:8],1)
	response=append(response,query[12:]...);return append(response,0xc0,0x0c,0,1,0,1,0,0,0,60,0,4,203,0,113,8)
}
func TestUDPTCPDNSPositiveAnswersAgainstLocalTestServer(t *testing.T){
	udp,err:=net.ListenPacket("udp","127.0.0.1:0");if err!=nil{t.Fatal(err)};defer udp.Close()
	port:=udp.LocalAddr().(*net.UDPAddr).Port
	tcp,err:=net.Listen("tcp",net.JoinHostPort("127.0.0.1",strconv.Itoa(port)));if err!=nil{t.Fatal(err)};defer tcp.Close()
	go func(){buf:=make([]byte,4096);for{n,addr,e:=udp.ReadFrom(buf);if e!=nil{return};if response:=testDNSResponse(buf[:n]);len(response)>0{_,_=udp.WriteTo(response,addr)}}}()
	go func(){for{conn,e:=tcp.Accept();if e!=nil{return};go func(c net.Conn){defer c.Close();r:=bufio.NewReader(c);h:=make([]byte,2);if _,e:=io.ReadFull(r,h);e!=nil{return};q:=make([]byte,int(binary.BigEndian.Uint16(h)));if _,e:=io.ReadFull(r,q);e!=nil{return};response:=testDNSResponse(q);if len(response)==0{return};frame:=[]byte{byte(len(response)>>8),byte(len(response))};frame=append(frame,response...);_,_=c.Write(frame)}(conn)}}()
	udpAnswers,err:=queryDNSA(port,false,"example.com");if err!=nil{t.Fatalf("UDP self-test failed: %v",err)}
	tcpAnswers,err:=queryDNSA(port,true,"www.example.com");if err!=nil{t.Fatalf("TCP self-test failed: %v",err)}
	if len(udpAnswers)!=1||udpAnswers[0]!="203.0.113.8"{t.Fatalf("unexpected UDP answers: %v",udpAnswers)}
	if len(tcpAnswers)!=1||tcpAnswers[0]!="203.0.113.8"{t.Fatalf("unexpected TCP answers: %v",tcpAnswers)}
}
func TestTemporaryTunnelVerificationRejectsIdentityChanges(t *testing.T){
	expected,err:=buildTemporaryTunnel(15353,"added");if err!=nil{t.Fatal(err)}
	item:=cloneMap(expected);item["id"]=json.Number("17")
	if err:=verifyTemporaryTunnel(item,expected,17);err!=nil{t.Fatalf("valid Tunnel rejected: %v",err)}
	changed:=cloneMap(item);changed["listen"]="0.0.0.0";if err:=verifyTemporaryTunnel(changed,expected,17);err==nil{t.Fatal("changed listen address must be rejected")}
}
func TestTemporaryAllowRepairDetectsEarlierMatchingBlock(t *testing.T){
	rules:=[]any{map[string]any{"action":"block","network":"tcp,udp","port":"5355","ip":[]any{dnsAddress}},cloneMap(tempDNSFinalRule)}
	if temporaryAllowUsable(rules){t.Fatal("temporary allow behind block should not be considered usable")}
	if temporaryAllowInsertIndex(rules)!=0{t.Fatal("temporary allow should be inserted before matching block")}
	rules=[]any{cloneMap(tempDNSFinalRule),rules[0]};if !temporaryAllowUsable(rules){t.Fatal("temporary allow before block should be usable")}
}
func TestDiagnosticExternalUseAnalysisIgnoresPanelManagedDNSAllow(t *testing.T){
	resource:=diagnosticResource{ID:7,Tag:"diag-tunnel"};inbounds:=[]map[string]any{{"id":json.Number("7"),"tag":"diag-tunnel"}}
	cfg:=map[string]any{"routing":map[string]any{"rules":[]any{
		map[string]any{"type":"field","ruleTag":dnsAllowTag,"ip":[]any{dnsAddress},"port":"5355","outboundTag":"direct"},
		map[string]any{"type":"field","ip":[]any{dnsAddress},"port":"5355","outboundTag":"direct"},
		map[string]any{"type":"field","inboundTag":[]any{"diag-tunnel"},"port":"53","outboundTag":"direct"},
	}}}
	inRefs,finalRefs,err:=diagnosticExternalUses(cfg,[]diagnosticResource{resource},inbounds);if err!=nil{t.Fatal(err)}
	if len(inRefs[7])!=1||inRefs[7][0]!="routing.rules[2].inboundTag"{t.Fatalf("unexpected inbound refs: %#v",inRefs)}
	if len(finalRefs)!=1||finalRefs[0]!="routing.rules[1].outboundTag"{t.Fatalf("unexpected final-rule refs: %#v",finalRefs)}
}
func TestResolveTokenUsesExplicitEnvironmentCredentialFirst(t *testing.T){
	const token="0123456789abcdef0123456789abcdef0123456789";t.Setenv("XUI_API_TOKEN",token);opts:=DefaultOptions();opts.AuthFile=filepath.Join(t.TempDir(),"missing","credential.json")
	got,err:=resolveToken(opts,"",nil);if err!=nil{t.Fatal(err)};if got!=token{t.Fatal("environment token was not selected")}
}
func TestInstallerTokenFileIsReadOnlyAndParsed(t *testing.T){
	const token="0123456789abcdef0123456789abcdef0123456789";path:=filepath.Join(t.TempDir(),"install-result.env")
	if err:=os.WriteFile(path,[]byte("OTHER=value\nXUI_API_TOKEN='"+token+"'\n"),0600);err!=nil{t.Fatal(err)}
	got,err:=readInstallerToken(path);if err!=nil{t.Fatal(err)};if got!=token{t.Fatalf("unexpected token %q",got)}
	if err:=os.Chmod(path,0644);err!=nil{t.Fatal(err)};if _,err:=readInstallerToken(path);err==nil{t.Fatal("world-readable installer token file must be rejected")}
}
func TestSQLiteEndpointSettingsReadOnly(t *testing.T){
	path:=filepath.Join(t.TempDir(),"x-ui.db");db,err:=sql.Open("sqlite",path);if err!=nil{t.Fatal(err)}
	if _,err:=db.Exec("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT)");err!=nil{t.Fatal(err)}
	if _,err:=db.Exec("INSERT INTO settings(key,value) VALUES (?,?), (?,?)","webPort","33976","webBasePath","/panel");err!=nil{t.Fatal(err)}
	if err:=db.Close();err!=nil{t.Fatal(err)}
	settings,err:=readPanelSettings(path);if err!=nil{t.Fatal(err)}
	if settings["webPort"]!="33976"||settings["webBasePath"]!="/panel"{t.Fatalf("unexpected endpoint settings: %#v",settings)}
}
func TestDetectAndAuthorizeRejectsRemotePlainHTTP(t *testing.T){
	t.Setenv("XUI_API_TOKEN","0123456789abcdef0123456789abcdef0123456789");opts:=DefaultOptions();opts.BaseURL="http://198.51.100.25:2053"
	if _,_,err:=DetectAndAuthorize(opts,nil);err==nil{t.Fatal("remote plain HTTP should be rejected")}
}
func TestDetectAndAuthorizeUsesExplicitLoopbackAndEnvToken(t *testing.T){
	const token="0123456789abcdef0123456789abcdef0123456789";t.Setenv("XUI_API_TOKEN",token)
	server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){}));defer server.Close()
	opts:=DefaultOptions();opts.BaseURL=server.URL;endpoint,api,err:=DetectAndAuthorize(opts,nil)
	if err!=nil{t.Fatal(err)};if !IsLocalURL(endpoint.BaseURL)||api==nil{t.Fatalf("unexpected client: %#v %#v",endpoint,api)}
}
func TestExplicitPanelHTTPSRequiresExplicitTLSIdentity(t *testing.T){
	opts:=DefaultOptions();opts.BaseURL="https://127.0.0.1:2053"
	if _,_,err:=DetectAndAuthorize(opts,nil);err==nil{t.Fatal("HTTPS must require explicit TLS identity")}
}


func TestDiagnosticTunnelStartTimeoutCoversLucXApplyCycle(t *testing.T) {
	if diagnosticTunnelStartTimeout < 2*lucXRestartApplyInterval {
		t.Fatalf("diagnostic Tunnel startup timeout %s must cover at least two LucX-UI apply intervals (%s)",
			diagnosticTunnelStartTimeout, lucXRestartApplyInterval)
	}
}
