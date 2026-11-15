package dohintegration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

const dnsAddress = "127.0.0.1"
const dnsPort = 5355
const dnsAllowTag = "xui-dns-allow"
const temporaryFinalRuleKey = "direct.settings.finalRules"

var dnsOutboundTemplate = map[string]any{
	"tag":"dns-out","protocol":"dns",
	"settings":map[string]any{"rewriteNetwork":"udp","rewriteAddress":dnsAddress,"rewritePort":dnsPort},
}
var dnsServerTemplate = map[string]any{"address":dnsAddress,"port":dnsPort,"domains":[]any{},"skipFallback":false}
var dnsRouteTemplate = map[string]any{"enabled":true,"network":"tcp,udp","port":"53","type":"field"}
var tempDNSFinalRule = map[string]any{"action":"allow","network":"tcp,udp","port":"5355","ip":[]any{dnsAddress}}

type DNSPlan struct {
	Proposed map[string]any
	Expected map[string]any
	OutboundTag string
	Changes,Warnings,Blockers []string
	OutboundCreated,RouteCreated,ServerCreated bool
	RuleTag string
}
type RemovePlan struct {
	RouteIndexes []int
	OutboundTags []string
	ServerIndexes []int
	Blockers,Warnings []string
	Blocked bool
}

func cloneMap(in map[string]any)map[string]any{
	b,_:=json.Marshal(in);dec:=json.NewDecoder(bytes.NewReader(b));dec.UseNumber();var out map[string]any;_ = dec.Decode(&out);if out==nil{return map[string]any{}};return out
}
func canonical(v any)string{b,_:=json.Marshal(v);return string(b)}
func mapValue(v any)map[string]any{m,_:=v.(map[string]any);return m}
func listValue(v any)([]any,bool){a,ok:=v.([]any);return a,ok}
func objectList(parent map[string]any,key string,create bool)([]any,error){
	v,ok:=parent[key];if !ok&&create{a:=[]any{};parent[key]=a;return a,nil}
	if !ok{return []any{},nil}
	a,ok:=v.([]any);if !ok{return nil,problem("%s must be an array",key)}
	for _,item:=range a{if _,ok:=item.(map[string]any);!ok{return nil,problem("%s must contain only objects",key)}}
	return a,nil
}
func str(v any)string{s,_:=v.(string);return s}
func boolValue(v any)bool{b,_:=v.(bool);return b}
func intValue(v any)(int64,bool){return asInt(v)}
func stringTokens(v any)map[string]bool{
	out:=map[string]bool{}
	switch x:=v.(type){case string:for _,p:=range strings.Split(x,","){p=strings.ToLower(strings.TrimSpace(p));if p!=""{out[p]=true}}
	case []any:for _,p:=range x{if s,ok:=p.(string);ok&&strings.TrimSpace(s)!=""{out[strings.ToLower(strings.TrimSpace(s))]=true}}
	case []string:for _,p:=range x{if strings.TrimSpace(p)!=""{out[strings.ToLower(strings.TrimSpace(p))]=true}}
	};return out
}
func tagList(v any)[]string{
	switch x:=v.(type){case string:if x!=""{return []string{x}}
	case []any:out:=[]string{};for _,item:=range x{if s,ok:=item.(string);ok&&s!=""{out=append(out,s)}};return out}
	return nil
}
func portContains(v any,wanted int)bool{
	switch x:=v.(type){
	case json.Number:n,e:=x.Int64();return e==nil&&int(n)==wanted
	case float64:return int(x)==wanted&&x==float64(wanted)
	case int:return x==wanted
	case int64:return x==int64(wanted)
	case string:
		for _,part:=range strings.Split(x,","){part=strings.TrimSpace(part);if part==""{continue};if strings.Contains(part,"-"){ends:=strings.SplitN(part,"-",2);if len(ends)!=2{return true};lo,e1:=strconv.Atoi(strings.TrimSpace(ends[0]));hi,e2:=strconv.Atoi(strings.TrimSpace(ends[1]));if e1!=nil||e2!=nil{return true};if lo<=wanted&&wanted<=hi{return true}}else{n,e:=strconv.Atoi(part);if e!=nil{return true};if n==wanted{return true}}}
	};return false
}
func validPortSelector(v string)bool{
	if strings.TrimSpace(v)==""{return false}
	for _,part:=range strings.Split(v,","){p:=strings.TrimSpace(part);if p==""{return false};if strings.Contains(p,"-"){a:=strings.SplitN(p,"-",2);if _,e:=strconv.Atoi(strings.TrimSpace(a[0]));e!=nil{return false};if _,e:=strconv.Atoi(strings.TrimSpace(a[1]));e!=nil{return false}}else if _,e:=strconv.Atoi(p);e!=nil{return false}}
	return true
}
func portSelectorMayMatch(v any,wanted int)bool{
	switch x:=v.(type){case []any:if len(x)==0{return true};for _,p:=range x{if portSelectorMayMatch(p,wanted){return true}};return false
	case bool:return true
	case json.Number, float64, int, int64:return portContains(x,wanted)
	case string:if portContains(x,wanted){return true};return !validPortSelector(x)
	default:return true}
}
func networkIntersectsDNS(v any)bool{
	if v==nil||v==""{return true}
	t:=stringTokens(v);if len(t)==0{return true};if t["tcp"]||t["udp"]{return true}
	for n:=range t{if n!="tcp"&&n!="udp"&&n!="quic"{return true}}
	return false
}
func ruleMayMatchPort53(rule map[string]any)bool{
	if rule["enabled"]==false||rule["port"]==nil{return false}
	if _,ok:=rule["port"].(bool);ok{return false}
	return portContains(rule["port"],53)&&networkIntersectsDNS(rule["network"])
}
func globalPort53Rule(rule map[string]any)bool{
	if rule["enabled"]==false||strDefault(rule["type"],"field")!="field"||!portContains(rule["port"],53){return false}
	switch p:=rule["port"].(type){case string:if strings.TrimSpace(p)!="53"{return false};case json.Number,int,int64,float64:if !portContains(p,53){return false};default:return false}
	networks:=stringTokens(rule["network"]);if len(networks)>0&&!(len(networks)==2&&networks["tcp"]&&networks["udp"]){return false}
	allowed:=map[string]bool{"type":true,"ruleTag":true,"enabled":true,"network":true,"port":true,"outboundTag":true,"balancerTag":true,"remarks":true,"comment":true}
	for k:=range rule{if !allowed[k]{return false}}
	return str(rule["outboundTag"])!=""||str(rule["balancerTag"])!=""
}
func globalProtocolPort53Rule(rule map[string]any)bool{
	if !ruleMayMatchPort53(rule)||strDefault(rule["type"],"field")!="field"{return false}
	allowed:=map[string]bool{"type":true,"ruleTag":true,"enabled":true,"network":true,"port":true,"outboundTag":true,"balancerTag":true,"remarks":true,"comment":true}
	for k:=range rule{if !allowed[k]{return false}}
	networks:=stringTokens(rule["network"]);return len(networks)==0||networks["tcp"]||networks["udp"]
}
func globalPort53Overlap(rule map[string]any)bool{
	if !ruleMayMatchPort53(rule)||strDefault(rule["type"],"field")!="field"{return false}
	n:=stringTokens(rule["network"]);if len(n)>0&&!(n["tcp"]&&n["udp"]){return false}
	allowed:=map[string]bool{"type":true,"ruleTag":true,"enabled":true,"network":true,"port":true,"outboundTag":true,"balancerTag":true,"remarks":true,"comment":true}
	for k:=range rule{if !allowed[k]{return false}};return true
}
func strDefault(v any,d string)string{if s,ok:=v.(string);ok&&s!=""{return s};return d}

func truthy(v any)bool{
	switch x:=v.(type){
	case nil:return false
	case bool:return x
	case string:return x!=""
	case json.Number:return x!="0"&&x!=""
	case float64:return x!=0
	case int:return x!=0
	case int64:return x!=0
	case []any:return len(x)>0
	case map[string]any:return len(x)>0
	default:return true
	}
}
func integerValue(v any)(int64,bool){
	switch x:=v.(type){
	case json.Number:n,e:=x.Int64();return n,e==nil
	case int:return int64(x),true
	case int64:return x,true
	case float64:return int64(x),x==float64(int64(x))
	case string:n,e:=strconv.ParseInt(strings.TrimSpace(x),10,64);return n,e==nil
	default:return 0,false
	}
}

func outboundMatchesDNS(item map[string]any)bool{
	if str(item["protocol"])!="dns"{return false}
	settings:=mapValue(item["settings"]);if settings==nil{return false}
	topAllowed:=map[string]bool{"tag":true,"protocol":true,"settings":true,"sendThrough":true,"streamSettings":true,"proxySettings":true,"mux":true,"userLevel":true}
	for k:=range item{if !topAllowed[k]{return false}}
	setAllowed:=map[string]bool{"rewriteNetwork":true,"rewriteAddress":true,"rewritePort":true,"rules":true,"blockTypes":true,"nonIPQuery":true,"userLevel":true}
	for k:=range settings{if !setAllowed[k]{return false}}
	if str(settings["rewriteAddress"])!=dnsAddress{return false}
	port,ok:=integerValue(settings["rewritePort"]);if !ok||port!=dnsPort{return false}
	if rn,exists:=settings["rewriteNetwork"];exists&&rn!=nil{
		value,ok:=rn.(string);if !ok{return false};value=strings.ToLower(value);if value!="tcp"&&value!="udp"{return false}
	}
	dnsRules,ok:=listValue(settings["rules"]);if _,exists:=settings["rules"];exists&&!ok{return false}
	for _,v:=range dnsRules{r,ok:=v.(map[string]any);if !ok||r["action"]!="direct"{return false};if r["qType"]!=nil&&r["qType"]!=""&&canonical(r["qType"])!="[]"{return false};if r["qtype"]!=nil&&r["qtype"]!=""&&canonical(r["qtype"])!="[]"{return false};if r["domain"]!=nil&&r["domain"]!=""&&canonical(r["domain"])!="[]"{return false};for k:=range r{if k!="action"&&k!="rCode"{return false}}}
	if v,ok:=settings["blockTypes"];ok&&truthy(v){return false}
	if v,ok:=settings["nonIPQuery"];ok&&v!=nil&&v!=""&&v!="direct"{return false}
	if truthy(item["proxySettings"])||truthy(item["streamSettings"])||truthy(item["mux"]){return false}
	if send,ok:=item["sendThrough"];ok&&truthy(send){value,ok:=send.(string);if !ok{return false};ip:=net.ParseIP(value);if ip==nil||!ip.IsLoopback(){return false}}
	return true
}
func uniqueTag(preferred string,used map[string]bool,forbidden []string)string{
	bases:=[]string{preferred,preferred+"-doh-health-monitor","doh-health-monitor-"+preferred,"xray-"+preferred,"custom-"+preferred}
	prefixMatch:=func(s string)bool{for _,p:=range forbidden{if p==""||strings.HasPrefix(s,p){return true}};return false}
	for _,b:=range bases{if !used[b]&&!prefixMatch(b){return b}}
	for _,b:=range bases{for i:=2;i<1000;i++{s:=fmt.Sprintf("%s-%d",b,i);if !used[s]&&!prefixMatch(s){return s}}}
	return ""
}
func dnsServerList(parent map[string]any)([]any,error){
	v,ok:=parent["servers"];if !ok{a:=[]any{};parent["servers"]=a;return a,nil}
	a,ok:=v.([]any);if !ok{return nil,problem("dns.servers must be an array of objects or address strings")}
	for _,item:=range a{switch item.(type){case string,map[string]any:default:return nil,problem("dns.servers must contain only objects or address strings")}}
	return a,nil
}
func serverEndpoint(v any)(string,int,bool){
	address:="";var portValue any;hasExplicitPort:=false
	switch item:=v.(type){
	case string:address=item
	case map[string]any:
		value,ok:=item["address"].(string);if !ok{return "",0,false};address=value
		portValue,hasExplicitPort=item["port"]
	default:return "",0,false
	}
	address=strings.TrimSpace(address);if address==""{return "",0,false}
	if hasExplicitPort&&portValue==nil{return "",0,false}
	if !hasExplicitPort{
		if strings.HasPrefix(address,"[")&&strings.Contains(address,"]:"){
			idx:=strings.Index(address,"]:");portValue=address[idx+2:];address=address[1:idx];hasExplicitPort=true
		}else if strings.Count(address,":")==1{
			host,embedded,_:=strings.Cut(address,":");if _,err:=strconv.Atoi(embedded);err==nil{address=host;portValue=embedded;hasExplicitPort=true}
		}
	}
	if !hasExplicitPort{portValue=53}
	port,ok:=integerValue(portValue);if !ok||port<1||port>65535{return "",0,false}
	ip:=net.ParseIP(strings.Trim(address,"[]"));if ip==nil{return "",0,false}
	return ip.String(),int(port),true
}
func serverGeneral(v any)bool{
	m,ok:=v.(map[string]any);if !ok{return true}
	for _,k:=range []string{"domains","expectedIPs","expectIPs","unexpectedIPs"}{v:=m[k];if v!=nil&&v!=""&&canonical(v)!="[]"{return false}}
	if m["skipFallback"]==true{return false};if q:=str(m["queryStrategy"]);q!=""&&q!="UseIP"{return false};return true
}
func ruleMayMatchLoopbackWithoutPort(rule map[string]any)bool{
	if rule["enabled"]==false||rule["port"]!=nil{return false}
	if strDefault(rule["type"],"field")!="field"{return true}
	if rule["domain"]!=nil{has:=false;for _,k:=range []string{"ip","source","sourcePort","inboundTag","user","attrs"}{if rule[k]!=nil{has=true}};if !has{return false}}
	values:=tagList(rule["ip"]);if len(values)==0{return true}
	target:=net.ParseIP(dnsAddress)
	for _,v:=range values{low:=strings.ToLower(v);if low=="geoip:private"||low=="geoip:loopback"{return true};if ip:=net.ParseIP(v);ip!=nil{if ip.Equal(target){return true};continue};_,network,err:=net.ParseCIDR(v);if err!=nil{return true};if network.Contains(target){return true}}
	return false
}
func resolveBalancer(tag string,balancers []any,outboundIndex map[string]map[string]any,outboundOrder []string)([]string,string){
	matches:=[]map[string]any{};for _,v:=range balancers{m:=mapValue(v);if str(m["tag"])==tag{matches=append(matches,m)}}
	if len(matches)!=1{return nil,fmt.Sprintf("Balancer tag %q is missing or ambiguous",tag)}
	selector:=tagList(matches[0]["selector"]);if len(selector)==0{return nil,fmt.Sprintf("Balancer %q has no valid selector list",tag)}
	selected:=[]string{};for _,t:=range outboundOrder{for _,p:=range selector{if strings.HasPrefix(t,p){selected=append(selected,t);break}}}
	if fb:=str(matches[0]["fallbackTag"]);fb!=""{if _,ok:=outboundIndex[fb];!ok{return nil,fmt.Sprintf("Balancer %q has a missing fallbackTag",tag)};found:=false;for _,s:=range selected{if s==fb{found=true}};if !found{selected=append(selected,fb)}}
	if len(selected)==0{return nil,fmt.Sprintf("Balancer %q selects no configured outbounds",tag)}
	for _,s:=range selected{if !outboundMatchesDNS(outboundIndex[s]){return nil,fmt.Sprintf("Balancer %q selects incompatible outbound %q",tag,s)}}
	return selected,""
}

func buildDNSPlan(original map[string]any)DNSPlan{
	plan:=DNSPlan{Proposed:cloneMap(original)}
	cfg:=plan.Proposed
	outbounds,err:=objectList(cfg,"outbounds",true);if err!=nil{plan.Blockers=append(plan.Blockers,err.Error());return failedDNSPlan(original,plan)}
	routing:=mapValue(cfg["routing"]);if cfg["routing"]==nil{routing=map[string]any{};cfg["routing"]=routing};if routing==nil{plan.Blockers=append(plan.Blockers,"routing must be an object");return failedDNSPlan(original,plan)}
	rules,err:=objectList(routing,"rules",true);if err!=nil{plan.Blockers=append(plan.Blockers,err.Error());return failedDNSPlan(original,plan)}
	balancers,err:=objectList(routing,"balancers",false);if err!=nil{plan.Blockers=append(plan.Blockers,err.Error());return failedDNSPlan(original,plan)}
	inbounds,err:=objectList(cfg,"inbounds",false);if err!=nil{plan.Blockers=append(plan.Blockers,err.Error());return failedDNSPlan(original,plan)}
	used:=map[string]bool{};outIndex:=map[string]map[string]any{};balancerTags:=map[string]bool{}
	for _,v:=range inbounds{if t:=str(mapValue(v)["tag"]);t!=""{used[t]=true}}
	for _,v:=range outbounds{m:=mapValue(v);t:=str(m["tag"]);if t!=""{used[t]=true;if _,ok:=outIndex[t];ok{plan.Blockers=append(plan.Blockers,fmt.Sprintf("Duplicate outbound tag %q; outbound references are ambiguous",t))}else{outIndex[t]=m}}}
	for _,v:=range balancers{t:=str(mapValue(v)["tag"]);if t!=""{used[t]=true;if balancerTags[t]{plan.Blockers=append(plan.Blockers,fmt.Sprintf("Duplicate balancer tag %q",t))};balancerTags[t]=true}}
	apiTag:=str(mapValue(cfg["api"])["tag"]);if apiTag!=""{used[apiTag]=true}
	dns:=mapValue(cfg["dns"]);if dns!=nil{if t:=str(dns["tag"]);t!=""{used[t]=true};servers,_:=listValue(dns["servers"]);for _,v:=range servers{if t:=str(mapValue(v)["tag"]);t!=""{used[t]=true}}}
	for _,v:=range rules{m:=mapValue(v);for _,k:=range []string{"tag","ruleTag","inboundTag","outboundTag","balancerTag"}{for _,t:=range tagList(m[k]){used[t]=true}}}
	for _,v:=range balancers{if t:=str(mapValue(v)["fallbackTag"]);t!=""{used[t]=true}}
	for _,section:=range []string{"observatory","burstObservatory"}{m:=mapValue(cfg[section]);for _,p:=range tagList(m["subjectSelector"]){used["#selector:"+p]=true}}
	reverse:=mapValue(cfg["reverse"]);for _,key:=range []string{"bridges","portals"}{items,_:=listValue(reverse[key]);for _,v:=range items{if t:=str(mapValue(v)["tag"]);t!=""{used[t]=true}}}
	outboundOrder:=[]string{};for _,v:=range outbounds{t:=str(mapValue(v)["tag"]);if t!=""{outboundOrder=append(outboundOrder,t)}}
	forbidden:=[]string{};for _,v:=range balancers{for _,p:=range tagList(mapValue(v)["selector"]){forbidden=append(forbidden,p)}}
	for _,section:=range []string{"observatory","burstObservatory"}{for _,p:=range tagList(mapValue(cfg[section])["subjectSelector"]){forbidden=append(forbidden,p)}}
	compatible:=map[string]map[string]any{};for t,m:=range outIndex{if outboundMatchesDNS(m){compatible[t]=m}}
	globalMatches:=[]int{};for i,v:=range rules{if globalPort53Rule(mapValue(v)){globalMatches=append(globalMatches,i)}}
	chosen:="";routeCovered:=false;broadRoutes:=[]struct{i int;tag string}{}
	scopedOrder:=[]string{}
	if len(globalMatches)>0{
		idx:=globalMatches[0]
		for i:=0;i<idx;i++{if i>0&&ruleMayMatchLoopbackWithoutPort(mapValue(rules[i])){plan.Blockers=append(plan.Blockers,"An earlier broad routing rule can intercept rewritten loopback DNS before the port-53 route")}}
		for i:=0;i<idx;i++{r:=mapValue(rules[i]);if !globalProtocolPort53Rule(r)||globalPort53Rule(r){continue}
			target:=str(r["outboundTag"])
			if target!=""{
				if !outboundMatchesDNS(outIndex[target]){plan.Blockers=append(plan.Blockers,fmt.Sprintf("Earlier global port-53-overlap rule at routing.rules[%d] shadows the DNS route with incompatible outbound %q",i,target))}
			}else if bal:=str(r["balancerTag"]);bal!=""{
				if selected,e:=resolveBalancer(bal,balancers,outIndex,outboundOrder);e!=""||len(selected)==0{plan.Blockers=append(plan.Blockers,fmt.Sprintf("Earlier global port-53-overlap rule at routing.rules[%d] shadows the DNS route with incompatible balancer: %s",i,e))}
			}else{plan.Blockers=append(plan.Blockers,fmt.Sprintf("Earlier global port-53-overlap rule at routing.rules[%d] has no compatible target",i))}
		}
		for n,index:=range globalMatches{r:=mapValue(rules[index]);target:=str(r["outboundTag"]);bal:=str(r["balancerTag"]);resolved:=target;if resolved==""&&bal!=""{selected,e:=resolveBalancer(bal,balancers,outIndex,outboundOrder);if e!=""{plan.Blockers=append(plan.Blockers,e)}else if len(selected)>0{resolved=selected[0]}}
			if resolved==""||!outboundMatchesDNS(outIndex[resolved]){plan.Blockers=append(plan.Blockers,fmt.Sprintf("Existing global port-53 rule #%d does not resolve to the local DNS endpoint",n+1))}else if chosen==""{chosen=resolved}}
		routeCovered=chosen!=""
		if len(globalMatches)>1{plan.Warnings=append(plan.Warnings,"Multiple global port-53 rules already exist; all compatible rules are preserved")}
	}else{
		partialRoutes:=[]struct{i int;network map[string]bool;tag string}{}
		for i,v:=range rules{r:=mapValue(v);if !globalProtocolPort53Rule(r){continue};if globalPort53Overlap(r){target:=str(r["outboundTag"]);if outboundMatchesDNS(outIndex[target]){broadRoutes=append(broadRoutes,struct{i int;tag string}{i,target})}else{bal:=str(r["balancerTag"]);selected,e:=resolveBalancer(bal,balancers,outIndex,outboundOrder);if e==""&&len(selected)>0{broadRoutes=append(broadRoutes,struct{i int;tag string}{i,selected[0]})}else{plan.Blockers=append(plan.Blockers,fmt.Sprintf("Broad port-53 rule at routing.rules[%d] has incompatible target",i))}};continue}
			networks:=stringTokens(r["network"]);covered:=map[string]bool{};for n:=range networks{if n=="tcp"||n=="udp"{covered[n]=true}}
			target:=str(r["outboundTag"]);if target!=""{if !outboundMatchesDNS(outIndex[target]){plan.Blockers=append(plan.Blockers,fmt.Sprintf("Existing global port-53 rule at routing.rules[%d] targets incompatible outbound %q",i,target))}else{partialRoutes=append(partialRoutes,struct{i int;network map[string]bool;tag string}{i,covered,target})}}else{bal:=str(r["balancerTag"]);selected,e:=resolveBalancer(bal,balancers,outIndex,outboundOrder);if e!=""{plan.Blockers=append(plan.Blockers,fmt.Sprintf("Existing global port-53 rule at routing.rules[%d] has incompatible balancer: %s",i,e))}else if len(selected)>0{partialRoutes=append(partialRoutes,struct{i int;network map[string]bool;tag string}{i,covered,selected[0]})}}
		}
		if len(broadRoutes)>0{sort.Slice(broadRoutes,func(i,j int)bool{return broadRoutes[i].i<broadRoutes[j].i});chosen=broadRoutes[0].tag;routeCovered=true;plan.Warnings=append(plan.Warnings,"An existing broad port-range rule already routes TCP/UDP port 53 to a compatible local DNS outbound")}
		covered:=map[string]bool{};for _,p:=range partialRoutes{for n:=range p.network{covered[n]=true};if !containsString(scopedOrder,p.tag){scopedOrder=append(scopedOrder,p.tag)}}
		if !routeCovered&&covered["tcp"]&&covered["udp"]{routeCovered=true;plan.Warnings=append(plan.Warnings,"Existing global TCP-only/UDP-only rules cover both DNS transports")}
		if !routeCovered&&len(partialRoutes)>0{sort.Slice(partialRoutes,func(i,j int)bool{return partialRoutes[i].i<partialRoutes[j].i});chosen=partialRoutes[0].tag;plan.Warnings=append(plan.Warnings,"An existing single-transport port-53 rule is reused; a fallback will complete the other transport")}
		if !routeCovered&&chosen==""{
			for _,v:=range rules{r:=mapValue(v);if !ruleMayMatchPort53(r){continue};target:=str(r["outboundTag"]);bal:=str(r["balancerTag"]);resolved:=target;if resolved==""&&bal!=""{selected,e:=resolveBalancer(bal,balancers,outIndex,outboundOrder);if e==""&&len(selected)>0{resolved=selected[0]}}
				if resolved!=""&&outboundMatchesDNS(outIndex[resolved])&&!containsString(scopedOrder,resolved){scopedOrder=append(scopedOrder,resolved)}
			}
			if len(scopedOrder)>0{chosen=scopedOrder[0]}else if len(compatible)>0{tags:=[]string{};for _,t:=range outboundOrder{if _,ok:=compatible[t];ok{tags=append(tags,t)}};if len(tags)>0{chosen=tags[0];if len(tags)>1{plan.Warnings=append(plan.Warnings,"Multiple compatible local DNS outbounds exist; the first is reused")}}}
		}
	}
	if chosen==""&&len(plan.Blockers)==0&&!routeCovered{
		tag:=uniqueTag("dns-out",used,forbidden);if tag==""{plan.Blockers=append(plan.Blockers,"No safe unique DNS outbound tag is available")}else{ob:=cloneMap(dnsOutboundTemplate);ob["tag"]=tag;outbounds=append(outbounds,ob);cfg["outbounds"]=outbounds;outIndex[tag]=ob;outboundOrder=append(outboundOrder,tag);chosen=tag;plan.OutboundCreated=true;plan.Changes=append(plan.Changes,fmt.Sprintf("ADD outbound %s to %s:%d",tag,dnsAddress,dnsPort))}
	}
	plan.OutboundTag=chosen
	dns=mapValue(cfg["dns"]);if cfg["dns"]==nil{dns=map[string]any{};cfg["dns"]=dns};if dns==nil{plan.Blockers=append(plan.Blockers,"dns must be an object");return failedDNSPlan(original,plan)}
	servers,err:=dnsServerList(dns);if err!=nil{plan.Blockers=append(plan.Blockers,err.Error());return failedDNSPlan(original,plan)}
	endpointMatches:=[]any{};generalMatches:=[]any{}
	for _,v:=range servers{ip,p,ok:=serverEndpoint(v);if ok&&ip==dnsAddress&&p==dnsPort{endpointMatches=append(endpointMatches,v);if serverGeneral(v){generalMatches=append(generalMatches,v)}}}
	if len(generalMatches)>0{plan.Warnings=append(plan.Warnings,"Existing general DNS server entries at 127.0.0.1:5355 are reused")}
	if len(generalMatches)==0&&len(endpointMatches)>0{plan.Blockers=append(plan.Blockers,"127.0.0.1:5355 exists only as a scoped DNS server; refusing to add a general entry")}
	if len(endpointMatches)==0{servers=append(servers,cloneMap(dnsServerTemplate));dns["servers"]=servers;plan.ServerCreated=true;plan.Changes=append(plan.Changes,"ADD dns.servers 127.0.0.1:5355")}
	if len(globalMatches)==0&&len(broadRoutes)==0&&chosen!=""&&!routeCovered{
		scoped:=[]int{};for i,v:=range rules{if ruleMayMatchPort53(mapValue(v)){scoped=append(scoped,i)}}
		lastScoped:=0;if len(scoped)>0{lastScoped=scoped[len(scoped)-1]}
		broad:=len(rules);for i,v:=range rules{if i>0&&ruleMayMatchLoopbackWithoutPort(mapValue(v)){broad=i;break}}
		insert:=0;if len(rules)>0{insert=lastScoped+1;if insert<1{insert=1}}
		if insert>broad{plan.Blockers=append(plan.Blockers,"Existing routing order has a broad rule before a safe port-53 insertion position")}else{
			usedRuleTags:=map[string]bool{};for t:=range used{usedRuleTags[t]=true};ruleTag:=uniqueTag("doh-health-monitor-dns-port53",usedRuleTags,nil)
			if ruleTag==""{plan.Blockers=append(plan.Blockers,"No unique routing ruleTag is available")}else{r:=cloneMap(dnsRouteTemplate);r["outboundTag"]=chosen;r["ruleTag"]=ruleTag;rules=append(rules,nil);copy(rules[insert+1:],rules[insert:]);rules[insert]=r;routing["rules"]=rules;plan.RouteCreated=true;plan.RuleTag=ruleTag;plan.Changes=append(plan.Changes,fmt.Sprintf("ADD global TCP/UDP port-53 route at routing.rules[%d]",insert))}
		}
	}
	for i,v:=range rules{r:=mapValue(v);if !ruleMayMatchPort53(r){continue};if strDefault(r["type"],"field")!="field"{plan.Blockers=append(plan.Blockers,fmt.Sprintf("routing.rules[%d] uses an unsupported rule type for port-53 DNS traffic",i));continue};target:=str(r["outboundTag"]);bal:=str(r["balancerTag"]);if target!=""{if _,ok:=outIndex[target];!ok&&!(target==chosen&&plan.OutboundCreated){plan.Blockers=append(plan.Blockers,fmt.Sprintf("routing.rules[%d] references missing outbound %q",i,target))}}else if bal!=""{if !balancerTags[bal]{plan.Blockers=append(plan.Blockers,fmt.Sprintf("routing.rules[%d] references missing balancer %q",i,bal))}}else{plan.Blockers=append(plan.Blockers,fmt.Sprintf("routing.rules[%d] matches DNS port 53 but has no outbound/balancer target",i))}}
	if len(plan.Blockers)>0{return failedDNSPlan(original,plan)}
	plan.Expected=panelNormalize(cfg)
	return plan
}

func failedDNSPlan(original map[string]any,p DNSPlan)DNSPlan{
	p.Proposed=cloneMap(original);p.Expected=cloneMap(original);p.Changes=nil;p.OutboundCreated=false;p.RouteCreated=false;p.ServerCreated=false;p.OutboundTag="";p.RuleTag="";return p
}
func containsString(items []string,want string)bool{for _,v:=range items{if v==want{return true}};return false}

func hasNumericQTypeZero(cfg map[string]any)bool{
	outbounds,_:=listValue(cfg["outbounds"]);for _,v:=range outbounds{ob:=mapValue(v);if strings.ToLower(str(ob["protocol"]))!="dns"{continue};settings:=mapValue(ob["settings"]);rules,_:=listValue(settings["rules"]);for _,r:=range rules{value:=mapValue(r)["qType"];if n,ok:=asInt(value);ok&&n==0{return true}}};return false
}
func isAPIRule(rule map[string]any)bool{return str(rule["outboundTag"])=="api"&&stringTokens(rule["inboundTag"])["api"]}

func ipValues(v any)[]string{return tagList(v)}
func blockedDNSIP(ip net.IP)bool{
	if ip==nil{return false};if ip.IsLoopback()||ip.IsLinkLocalUnicast()||ip.IsLinkLocalMulticast()||ip.IsMulticast()||ip.IsUnspecified()||ip.IsPrivate(){return true}
	cidrs:=[]string{"100.64.0.0/10","2002::/16","2001::/32","64:ff9b:1::/48","fec0::/10","64:ff9b::/96"}
	for _,raw:=range cidrs{_,network,err:=net.ParseCIDR(raw);if err==nil&&network.Contains(ip){if raw=="64:ff9b::/96"&&ip.To4()==nil{embedded:=net.IP(ip[len(ip)-4:]);return blockedDNSIP(embedded)};return true}}
	return false
}
func dnsPrivateGroups(cfg map[string]any)map[int][]string{
	groups:=map[int]map[string]bool{};dns:=mapValue(cfg["dns"]);servers,_:=listValue(dns["servers"])
	for _,v:=range servers{ip,port,ok:=serverEndpoint(v);if !ok{continue};addr:=net.ParseIP(ip);if !blockedDNSIP(addr){continue};if groups[port]==nil{groups[port]=map[string]bool{}};groups[port][ip]=true}
	out:=map[int][]string{};for p,set:=range groups{for ip:=range set{out[p]=append(out[p],ip)};sort.Strings(out[p])};return out
}
func panelNormalize(cfg map[string]any)map[string]any{
	result:=cloneMap(cfg);routing:=mapValue(result["routing"]);if routing==nil{return result}
	rules,_:=listValue(routing["rules"]);groups:=dnsPrivateGroups(result);clean:=[]any{}
	for _,v:=range rules{r:=mapValue(v);if str(r["ruleTag"])==dnsAllowTag{continue};if legacyManagedDNSAllow(r,groups){continue};clean=append(clean,cloneMap(r))}
	privateBlock:=-1;for i,v:=range clean{r:=mapValue(v);if str(r["outboundTag"])=="blocked"{for _,ip:=range ipValues(r["ip"]){if strings.EqualFold(ip,"geoip:private"){privateBlock=i;break}}};if privateBlock>=0{break}}
	if privateBlock>=0&&len(groups)>0{
		ports:=[]int{};for p:=range groups{ports=append(ports,p)};sort.Ints(ports)
		additions:=[]any{};for _,p:=range ports{ips:=groups[p];arr:=make([]any,len(ips));for i,ip:=range ips{arr[i]=ip};additions=append(additions,map[string]any{"type":"field","ruleTag":dnsAllowTag,"ip":arr,"port":strconv.Itoa(p),"outboundTag":"direct"})}
		combined:=append([]any{},clean[:privateBlock]...);combined=append(combined,additions...);combined=append(combined,clean[privateBlock:]...);clean=combined
	}
	routing["rules"]=clean;result["routing"]=routing;return result
}
func legacyManagedDNSAllow(rule map[string]any,groups map[int][]string)bool{
	if str(rule["type"])!="field"||str(rule["outboundTag"])!="direct"||rule["ip"]==nil||rule["port"]==nil{return false}
	for k,v:=range rule{if k=="type"||k=="outboundTag"||k=="ip"||k=="port"{continue};if k=="enabled"&&v==true{continue};return false}
	port,err:=strconv.Atoi(fmt.Sprint(rule["port"]));if err!=nil{return false};wanted:=ipValues(rule["ip"]);sort.Strings(wanted)
	for p,ips:=range groups{if p==port&&equalStrings(wanted,ips){return true}};return false
}
func equalStrings(a,b []string)bool{if len(a)!=len(b){return false};for i:=range a{if a[i]!=b[i]{return false}};return true}

func buildPlan(cfg map[string]any,requireAPIRule bool)DNSPlan{
	if cfg==nil{return DNSPlan{Blockers:[]string{"xraySetting must be a JSON object"}}}
	if hasNumericQTypeZero(cfg){return DNSPlan{Proposed:cloneMap(cfg),Expected:cloneMap(cfg),Blockers:[]string{"Panel save would rewrite numeric DNS qType 0; refusing to change unrelated DNS settings"}}}
	p:=buildDNSPlan(cfg);if len(p.Blockers)>0{return p}
	routing:=mapValue(p.Proposed["routing"]);rules,_:=listValue(routing["rules"])
	apiIndexes:=[]int{};for i,v:=range rules{if isAPIRule(mapValue(v)){apiIndexes=append(apiIndexes,i)}}
	if requireAPIRule&&(len(apiIndexes)!=1||apiIndexes[0]!=0){p.Blockers=append(p.Blockers,"LucX-UI requires api-inbound -> api-outbound at routing.rules[0]")}
	normalized:=panelNormalize(p.Proposed)
	beforeRules,_:=listValue(mapValue(cfg["routing"])["rules"]);afterRules,_:=listValue(mapValue(normalized["routing"])["rules"])
	cursor:=0
	for _,old:=range beforeRules{found:=false;for cursor<len(afterRules){if canonical(old)==canonical(afterRules[cursor]){found=true;cursor++;break};cursor++};if !found{p.Blockers=append(p.Blockers,"Panel DNS synchronization would rewrite or remove an existing routing rule");break}}
	privateBlock:=false;for _,v:=range rules{r:=mapValue(v);if str(r["outboundTag"])=="blocked"{for _,ip:=range ipValues(r["ip"]){if strings.EqualFold(ip,"geoip:private"){privateBlock=true}}}}
	if privateBlock{count:=0;for _,v:=range p.ProposedOutbounds(){if str(mapValue(v)["tag"])=="direct"{count++}};if count!=1{p.Blockers=append(p.Blockers,"A private-IP block exists without exactly one direct outbound for the panel-managed DNS exception")}}
	if privateBlock{exists:=false;dns:=mapValue(normalized["dns"]);servers,_:=listValue(dns["servers"]);for _,v:=range servers{ip,port,ok:=serverEndpoint(v);if ok&&ip==dnsAddress&&port==dnsPort{exists=true}};if !exists{p.Blockers=append(p.Blockers,"Panel normalization did not preserve the local DNS server endpoint")}}
	p.Expected=normalized
	if canonical(normalized)!=canonical(p.Proposed){p.Changes=append(p.Changes,"PANEL-MANAGED: LucX-UI will reconcile its xui-dns-allow rule")}
	if len(p.Blockers)>0{return failedDNSPlan(cfg,p)}
	return p
}
func (p DNSPlan)ProposedOutbounds()[]any{a,_:=listValue(p.Proposed["outbounds"]);return a}

func outboundReferenceReasons(cfg map[string]any,tag string,ignored map[int]bool)[]string{
	reasons:=[]string{};routing:=mapValue(cfg["routing"]);rules,_:=listValue(routing["rules"])
	for i,v:=range rules{if ignored[i]{continue};if containsString(tagList(mapValue(v)["outboundTag"]),tag){reasons=append(reasons,fmt.Sprintf("routing.rules[%d].outboundTag",i))}}
	balancers,_:=listValue(routing["balancers"]);for i,v:=range balancers{b:=mapValue(v);if str(b["fallbackTag"])==tag{reasons=append(reasons,fmt.Sprintf("routing.balancers[%d].fallbackTag",i))};for _,p:=range tagList(b["selector"]){if strings.HasPrefix(tag,p){reasons=append(reasons,fmt.Sprintf("routing.balancers[%d].selector",i));break}}}
	for _,name:=range []string{"observatory","burstObservatory"}{m:=mapValue(routing[name]);if m==nil{m=mapValue(cfg[name])};for _,p:=range tagList(m["subjectSelector"]){if strings.HasPrefix(tag,p){reasons=append(reasons,name+".subjectSelector")}}}
	outbounds,_:=listValue(cfg["outbounds"]);for i,v:=range outbounds{o:=mapValue(v);if str(o["tag"])==tag{continue};if str(mapValue(o["proxySettings"])["tag"])==tag{reasons=append(reasons,fmt.Sprintf("outbounds[%d].proxySettings.tag",i))};if str(mapValue(mapValue(o["streamSettings"])["sockopt"])["dialerProxy"])==tag{reasons=append(reasons,fmt.Sprintf("outbounds[%d].streamSettings.sockopt.dialerProxy",i))}}
	return reasons
}
func dnsServerReferenceReasons(cfg map[string]any,server any)[]string{
	dnsValue,hasDNS:=cfg["dns"];if !hasDNS||dnsValue==nil{return nil}
	dns,ok:=dnsValue.(map[string]any);if !ok{return []string{"dns is not an object; external DNS-server references cannot be analyzed safely"}}
	rulesValue,hasRules:=dns["rules"];if !hasRules{return nil}
	rules,ok:=rulesValue.([]any);if !ok{return []string{"dns.rules is not an array; external DNS-server references cannot be analyzed safely"}}
	tag:=str(mapValue(server)["tag"]);ip,port,endpointOK:=serverEndpoint(server);reasons:=[]string{}
	for i,v:=range rules{
		rule,ok:=v.(map[string]any);if !ok{return []string{fmt.Sprintf("dns.rules[%d] is not an object; external DNS-server references cannot be analyzed safely",i)}}
		for _,target:=range tagList(rule["server"]){
			match:=tag!=""&&target==tag
			if sip,sp,sok:=serverEndpoint(target);endpointOK&&sok&&ip==sip&&port==sp{match=true}
			if match{reasons=append(reasons,fmt.Sprintf("dns.rules[%d].server",i));break}
		}
	}
	return reasons
}
func buildRemovePlan(cfg map[string]any)RemovePlan{
	spec:=buildPlan(cfg,false);plan:=RemovePlan{}
	if len(spec.Blockers)>0{plan.Blocked=true;plan.Blockers=append(plan.Blockers,spec.Blockers...);plan.Warnings=append(plan.Warnings,"Desired Integrate plan has blockers; Remove cannot safely identify resources");return plan}
	if spec.OutboundTag==""{plan.Warnings=append(plan.Warnings,"Integrate plan does not select a local DNS outbound");return plan}
	outbounds,_:=listValue(cfg["outbounds"]);outIndex:=map[string]map[string]any{};outboundOrder:=[]string{};tagCounts:=map[string]int{}
	for _,v:=range outbounds{o:=mapValue(v);t:=str(o["tag"]);if t!=""{tagCounts[t]++;outIndex[t]=o;outboundOrder=append(outboundOrder,t)}}
	routing:=mapValue(cfg["routing"]);rules,_:=listValue(routing["rules"]);balancers,_:=listValue(routing["balancers"])
	routeSelected:=false
	for i,v:=range rules{r:=mapValue(v);if !globalPort53Rule(r){continue};target:=str(r["outboundTag"]);bal:=str(r["balancerTag"]);resolved:=[]string{}
		if target!=""&&outboundMatchesDNS(outIndex[target]){resolved=[]string{target}}else if bal!=""{selected,e:=resolveBalancer(bal,balancers,outIndex,outboundOrder);if e==""{resolved=selected}}
		if len(resolved)>0&&resolved[0]==spec.OutboundTag{plan.RouteIndexes=append(plan.RouteIndexes,i);routeSelected=true;break}
	}
	matches:=0;for _,v:=range outbounds{o:=mapValue(v);if str(o["tag"])==spec.OutboundTag&&outboundMatchesDNS(o){matches++}}
	if matches!=1||tagCounts[spec.OutboundTag]!=1{if matches>0||tagCounts[spec.OutboundTag]>0{plan.Blockers=append(plan.Blockers,fmt.Sprintf("Planned DNS outbound %q is missing, duplicated, or ambiguous; preserving it",spec.OutboundTag))}}else{
		ignored:=map[int]bool{};for _,i:=range plan.RouteIndexes{ignored[i]=true};refs:=outboundReferenceReasons(cfg,spec.OutboundTag,ignored);if len(refs)>0{plan.Blockers=append(plan.Blockers,fmt.Sprintf("Planned DNS outbound %q is used outside the integration plan by: %s",spec.OutboundTag,strings.Join(refs,", ")))}else{plan.OutboundTags=append(plan.OutboundTags,spec.OutboundTag)}
	}
	dns:=mapValue(cfg["dns"]);servers,serversOK:=listValue(dns["servers"]);if !serversOK&&dns["servers"]!=nil{plan.Blockers=append(plan.Blockers,"dns.servers must be an array of objects or address strings");return plan}
	for _,v:=range servers{switch v.(type){case string,map[string]any:default:plan.Blockers=append(plan.Blockers,"dns.servers must contain only objects or address strings");return plan}}
	endpointIndexes:=[]int{};generalIndexes:=[]int{}
	for i,v:=range servers{ip,p,ok:=serverEndpoint(v);if ok&&ip==dnsAddress&&p==dnsPort{endpointIndexes=append(endpointIndexes,i);if serverGeneral(v){generalIndexes=append(generalIndexes,i)}}}
	if len(endpointIndexes)==1&&len(generalIndexes)==1{
		i:=generalIndexes[0];if len(plan.OutboundTags)==0{plan.Blockers=append(plan.Blockers,"Local DNS server retained because its matching outbound is shared or ambiguous")}else if refs:=dnsServerReferenceReasons(cfg,servers[i]);len(refs)>0{plan.Blockers=append(plan.Blockers,"Local DNS server used outside the integration plan by: "+strings.Join(refs,", "))}else{plan.ServerIndexes=append(plan.ServerIndexes,i)}
	}else if len(endpointIndexes)>0{plan.Blockers=append(plan.Blockers,"Multiple or scoped local DNS server entries are ambiguous and will be preserved")}
	if !routeSelected&&len(plan.OutboundTags)==0&&len(plan.ServerIndexes)==0{plan.Warnings=append(plan.Warnings,"No unshared permanent DNS objects are removable")}
	return plan
}
