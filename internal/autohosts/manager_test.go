package autohosts

import (
 "errors"
 "path/filepath"
 "testing"
 "time"
)

func TestLookupEmergencyOffAndFamilySpecificNODATA(t *testing.T) {
 now:=time.Now().UTC()
 m,err:=New(filepath.Join(t.TempDir(),"auto-hosts.json"));if err!=nil{t.Fatal(err)}
 ep:=Endpoint{ServerID:"doh-a",URL:"https://dns.example/dns-query",Hostname:"dns.example",IPv4:[]string{"192.0.2.10"},IPv6:[]string{"2001:db8::10"}}
 if err=m.ApplyCycle("doh-a",ep,[]ProbeResult{{Domain:"ChatGPT.com.",Success:true,CheckedAt:now}},now);err!=nil{t.Fatal(err)}
 if err=m.SetEnabled(true);err!=nil{t.Fatal(err)}
 ips,ttl,matched:=m.Snapshot().Lookup("chatgpt.com",1,now.Add(time.Second))
 if !matched||len(ips)!=1||ips[0]!="192.0.2.10"||ttl<=0{t.Fatalf("unexpected A lookup: %v %v %v",ips,ttl,matched)}
 ips,_,matched=m.Snapshot().Lookup("chatgpt.com",28,now.Add(time.Second))
 if !matched||len(ips)!=1||ips[0]!="2001:db8::10"{t.Fatalf("unexpected AAAA lookup: %v %v",ips,matched)}
 if err=m.SetEmergencyOff(true);err!=nil{t.Fatal(err)}
 if _,_,matched=m.Snapshot().Lookup("chatgpt.com",1,now.Add(time.Second));matched{t.Fatal("Emergency OFF must bypass Auto Hosts")}
 if len(m.State().Domains)!=1{t.Fatal("Emergency OFF must preserve records")}
}
func TestIPv4OnlyAAAAIsNODATAAndGraceExpires(t *testing.T){
 now:=time.Now().UTC();m,err:=New(filepath.Join(t.TempDir(),"state.json"));if err!=nil{t.Fatal(err)}
 ep:=Endpoint{ServerID:"v4",URL:"https://dns.example/dns-query",Hostname:"dns.example",IPv4:[]string{"192.0.2.53"}}
 if err=m.ApplyCycle("v4",ep,[]ProbeResult{{Domain:"example.com",Success:true,CheckedAt:now}},now);err!=nil{t.Fatal(err)}
 if err=m.SetEnabled(true);err!=nil{t.Fatal(err)}
 ips,_,matched:=m.Snapshot().Lookup("example.com",28,now.Add(time.Second))
 if !matched||len(ips)!=0{t.Fatalf("expected NODATA, got %v matched=%v",ips,matched)}
 if err=m.ApplyCycle("v4",ep,[]ProbeResult{{Domain:"example.com",Success:false,CheckedAt:now.Add(time.Minute)}},now.Add(time.Minute));err!=nil{t.Fatal(err)}
 if _,_,matched=m.Snapshot().Lookup("example.com",1,now.Add(31*time.Minute));matched{t.Fatal("expired record must not be served")}
}
func TestPinnedAndDryRunDoNotMutateState(t *testing.T){
 now:=time.Now().UTC();m,err:=New(filepath.Join(t.TempDir(),"state.json"));if err!=nil{t.Fatal(err)}
 a:=Endpoint{ServerID:"a",URL:"https://a.example/dns-query",Hostname:"a.example",IPv4:[]string{"192.0.2.1"}}
 if err=m.ApplyCycle("a",a,nil,now);err!=nil{t.Fatal(err)}
 if err=m.SetPinned("a");err!=nil{t.Fatal(err)}
 b:=Endpoint{ServerID:"b",URL:"https://b.example/dns-query",Hostname:"b.example",IPv4:[]string{"192.0.2.2"}}
 if err=m.ApplyCycle("b",b,nil,now);!errors.Is(err,ErrPinnedServer){t.Fatalf("expected pinned error, got %v",err)}
 before:=m.State()
 proposed,err:=m.DryRun("a",a,[]ProbeResult{{Domain:"new.example",Success:true,CheckedAt:now}},now)
 if err!=nil{t.Fatal(err)}
 if _,ok:=proposed["new.example"];!ok{t.Fatal("dry run omitted successful domain")}
 after:=m.State()
 if before.ActiveServer!=after.ActiveServer||len(after.Domains)!=0{t.Fatal("dry run mutated persistent state")}
}
func TestPersistenceAndDomainNormalization(t *testing.T){
 path:=filepath.Join(t.TempDir(),"state.json");m,err:=New(path);if err!=nil{t.Fatal(err)}
 now:=time.Now().UTC();ep:=Endpoint{ServerID:"a",URL:"https://dns.example/dns-query",Hostname:"dns.example",IPv4:[]string{"192.0.2.1"}}
 if err=m.ApplyCycle("a",ep,[]ProbeResult{{Domain:"WWW.Example.com.",Success:true,CheckedAt:now}},now);err!=nil{t.Fatal(err)}
 reloaded,err:=New(path);if err!=nil{t.Fatal(err)}
 if _,ok:=reloaded.State().Domains["www.example.com"];!ok{t.Fatal("normalized domain was not persisted")}
 if reloaded.Snapshot().ActiveServer!="a"{t.Fatal("active server was not restored")}
}


func TestFullCyclePersistsAllServerDomainPairsButPublishesOnlyActive(t *testing.T) {
	now := time.Now().UTC()
	m, err := New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil { t.Fatal(err) }
	a := Endpoint{ServerID:"a", URL:"https://a.example/dns-query", Hostname:"a.example", IPv4:[]string{"192.0.2.1"}}
	b := Endpoint{ServerID:"b", URL:"https://b.example/dns-query", Hostname:"b.example", IPv4:[]string{"192.0.2.2"}}
	results := []ProbeResult{
		{ServerID:"a", Domain:"chatgpt.com", Success:true, CheckedAt:now},
		{ServerID:"b", Domain:"chatgpt.com", Success:false, CheckedAt:now, Error:"website unreachable"},
		{ServerID:"b", Domain:"claude.ai", Success:true, CheckedAt:now},
	}
	if err := m.ApplyFullCycle("a", []Endpoint{a,b}, results, now); err != nil { t.Fatal(err) }
	state := m.State()
	if len(state.ProbeResults) != 3 { t.Fatalf("expected all 3 pair results persisted, got %d", len(state.ProbeResults)) }
	if len(state.Domains) != 1 { t.Fatalf("only active-server domain should be published, got %v", state.Domains) }
	if _, ok := state.Domains["chatgpt.com"]; !ok { t.Fatal("active server's successful domain missing") }
	if _, ok := state.Domains["claude.ai"]; ok { t.Fatal("inactive server's successful domain must not be published") }
	if _, ok := state.Endpoints["b"]; !ok { t.Fatal("inactive endpoint missing from state") }
}
