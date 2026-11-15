package dohintegration

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

const (
	pluginID = "doh-health-monitor"
	tokenName = "doh-health-monitor-integration"
	defaultAuthFile = "/var/lib/doh-health-monitor-panel-auth/panel-api-auth.json"
	installerTokenFile = "/etc/x-ui/install-result.env"
	defaultService = "lucx-plugin-doh-health-monitor"
	defaultStatusURL = "http://127.0.0.1:18765/status"
	maxResponseBytes = 8 << 20
)

type Error struct { Message string }
func (e *Error) Error() string { return e.Message }
func problem(format string, args ...any) error { return &Error{Message: fmt.Sprintf(format,args...)} }

type Options struct {
	BaseURL, PanelDB, AuthFile string
	Timeout time.Duration
	Service, StatusURL string
	Port int
	AllowInsecureHTTP bool
	TLSMode, TLSName string
}

func DefaultOptions() Options {
	return Options{AuthFile:defaultAuthFile,Timeout:15*time.Second,Service:defaultService,StatusURL:defaultStatusURL,Port:5355,TLSMode:"auto"}
}

type Endpoint struct { BaseURL, HostHeader, ServerName, VerifyIP string }

func IsLocalURL(raw string) bool {
	u,err:=url.Parse(raw);if err!=nil||u.Hostname()=="" {return false}
	if strings.EqualFold(u.Hostname(),"localhost"){return true}
	ip:=net.ParseIP(u.Hostname());return ip!=nil&&ip.IsLoopback()
}

func normalizeBasePath(value string)(string,error){
	p:=strings.TrimSpace(value);if p==""{p="/"}
	for _,r:=range p {if r<0x20||strings.ContainsRune("?#\\ ",r){return "",problem("LucX-UI webBasePath contains unsupported URL characters")}}
	if !strings.HasPrefix(p,"/"){p="/"+p}
	out:=[]string{}
	for _,part:=range strings.Split(p,"/"){if part==""{continue};if part=="."||part==".."{return "",problem("LucX-UI webBasePath contains a relative path segment")};out=append(out,part)}
	if len(out)==0{return "/",nil};return "/"+strings.Join(out,"/")+"/",nil
}

func runningPanelContext()(map[string]string,string,error){
	env:=map[string]string{}
	for _,k:=range []string{"XUI_PORT","XUI_DB_FOLDER","XUI_DB_TYPE"}{if v,ok:=os.LookupEnv(k);ok{env[k]=v}}
	cwd:="/usr/local/x-ui"
	entries,err:=os.ReadDir("/proc");if err!=nil{return env,cwd,nil}
	type procInfo struct{env map[string]string;cwd,exe string}
	matches:=[]procInfo{}
	for _,entry:=range entries{
		if _,err:=strconv.Atoi(entry.Name());err!=nil{continue}
		root:=filepath.Join("/proc",entry.Name())
		exe,err:=os.Readlink(filepath.Join(root,"exe"));if err!=nil{continue}
		exe=strings.TrimSuffix(exe," (deleted)");if filepath.Base(exe)!="x-ui"{continue}
		raw,err:=os.ReadFile(filepath.Join(root,"environ"));if err!=nil{continue}
		values:=map[string]string{}
		for _,item:=range bytes.Split(raw,[]byte{0}){k,v,ok:=bytes.Cut(item,[]byte("="));if !ok{continue};key:=string(k);switch key{case "XUI_PORT","XUI_DB_FOLDER","XUI_DB_TYPE":values[key]=string(v)}}
		procCwd,err:=os.Readlink(filepath.Join(root,"cwd"));if err!=nil{continue}
		matches=append(matches,procInfo{values,procCwd,exe})
	}
	if len(matches)>0{
		preferred:=[]procInfo{};for _,m:=range matches{if m.exe=="/usr/local/x-ui/x-ui"{preferred=append(preferred,m)}};if len(preferred)>0{matches=preferred}
		if len(matches)>1{first:=matches[0];for _,m:=range matches[1:]{if m.cwd!=first.cwd||!sameEnv(m.env,first.env){return nil,"",problem("Multiple LucX-UI processes have different runtime settings; specify --base-url and --panel-db")}}}
		for k,v:=range matches[0].env{env[k]=v};cwd=matches[0].cwd
	}
	return env,cwd,nil
}

func sameEnv(a,b map[string]string)bool{if len(a)!=len(b){return false};for k,v:=range a{if b[k]!=v{return false}};return true}

func PluginDataDir()(string,error){
 if value:=strings.TrimSpace(os.Getenv("LUCX_PLUGIN_DATA"));value!=""{absolute,err:=filepath.Abs(value);if err!=nil{return "",problem("Could not resolve plugin data directory")};return absolute,nil}
 _,cwd,err:=runningPanelContext();if err!=nil{return "",err};candidate:=filepath.Join(cwd,"bin","plugins",pluginID,"data")
 return candidate,nil
}

func secureRead(path string,max int64)([]byte,error){
	fd,err:=syscall.Open(path,syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,0)
	if err!=nil{if errors.Is(err,syscall.ENOENT){return nil,nil};return nil,problem("Could not safely open local credential file: %s",path)}
	f:=os.NewFile(uintptr(fd),path);defer f.Close()
	st,err:=f.Stat();if err!=nil{return nil,problem("Could not inspect local credential file")}
	if !st.Mode().IsRegular()||st.Mode().Perm()&0o077!=0{return nil,problem("Credential file must be a private regular file with mode 0600 or stricter: %s",path)}
	if sys,ok:=st.Sys().(*syscall.Stat_t);ok&&sys.Uid!=uint32(os.Geteuid()){return nil,problem("Credential file must be owned by uid %d: %s",os.Geteuid(),path)}
	if st.Size()>max{return nil,problem("Credential file is unexpectedly large")}
	data,err:=io.ReadAll(io.LimitReader(f,max+1));if err!=nil||int64(len(data))>max{return nil,problem("Could not read local credential file safely")}
	return data,nil
}

func validToken(token string)(string,error){
	v:=strings.TrimSpace(token);if len(v)<32{return "",problem("LucX-UI API credential is empty or has an invalid format")}
	for _,r:=range v{if r<0x21||r>0x7e{return "",problem("LucX-UI API credential is empty or has an invalid format")}}
	return v,nil
}

func readInstallerToken(path string)(string,error){
	data,err:=secureRead(path,65536);if err!=nil||data==nil{return "",err}
	for _,line:=range strings.Split(string(data),"\n"){k,v,ok:=strings.Cut(line,"=");if !ok||strings.TrimSpace(k)!="XUI_API_TOKEN"{continue}
		v=strings.TrimSpace(v);if len(v)>=2&&((v[0]=='"'&&v[len(v)-1]=='"')||(v[0]=='\''&&v[len(v)-1]=='\'')){v=v[1:len(v)-1]}
		return validToken(v)
	};return "",nil
}

func readSavedToken(path string)(string,error){
	data,err:=secureRead(path,65536);if err!=nil||data==nil{return "",err}
	var m map[string]any;if json.Unmarshal(data,&m)!=nil{return "",problem("Saved LucX-UI API credential file is malformed")}
	name,_:=m["token_name"].(string);format,_:=m["format"].(float64);token,_:=m["token"].(string)
	if name!=tokenName||format!=1{return "",problem("Saved LucX-UI API credential file has an unsupported format")}
	return validToken(token)
}

func saveToken(path,token string)error{
	value,err:=validToken(token);if err!=nil{return err}
	dir:=filepath.Dir(path);if err:=os.MkdirAll(dir,0o700);err!=nil{return problem("Could not create the private LucX-UI credential directory")}
	if err:=os.Chmod(dir,0o700);err!=nil{return problem("Could not secure the LucX-UI credential directory")}
	info,err:=os.Stat(dir);if err!=nil||!info.IsDir()||info.Mode().Perm()&0o077!=0{return problem("LucX-UI credential directory must be a private directory")}
	if st,ok:=info.Sys().(*syscall.Stat_t);ok&&st.Uid!=uint32(os.Geteuid()){return problem("LucX-UI credential directory must be owned by uid %d",os.Geteuid())}
	if _,err:=os.Lstat(path);err==nil{return problem("Refusing to overwrite an existing LucX-UI credential file")}else if !errors.Is(err,os.ErrNotExist){return problem("Could not inspect the existing LucX-UI credential file")}
	data,_:=json.Marshal(map[string]any{"format":1,"token_name":tokenName,"token":value});data=append(data,'\n')
	tmp,err:=os.CreateTemp(dir,".panel-api-auth-*");if err!=nil{return problem("Could not create temporary credential file")}
	name:=tmp.Name();defer os.Remove(name)
	if err:=tmp.Chmod(0o600);err!=nil{tmp.Close();return problem("Could not secure temporary credential file")}
	if _,err:=tmp.Write(data);err!=nil{tmp.Close();return problem("Could not write credential file")}
	if err:=tmp.Sync();err!=nil{tmp.Close();return problem("Could not sync credential file")}
	if err:=tmp.Close();err!=nil{return problem("Could not close credential file")}
	if err:=os.Link(name,path);err!=nil{return problem("Could not atomically create credential file")}
	dirFile,err:=os.Open(dir);if err==nil{_ = dirFile.Sync();_ = dirFile.Close()}
	return nil
}

var tokenLine=regexp.MustCompile("(?m)^apiToken:\\s*(\\S+)\\s*$")

func panelCLI(panelCwd string)(string,error){
	entries,_:=os.ReadDir("/proc");found:=map[string]bool{}
	for _,e:=range entries{if _,x:=strconv.Atoi(e.Name());x!=nil{continue};exe,x:=os.Readlink(filepath.Join("/proc",e.Name(),"exe"));if x!=nil{continue};exe=strings.TrimSuffix(exe," (deleted)");if filepath.Base(exe)=="x-ui"{if st,x:=os.Stat(exe);x==nil&&st.Mode().IsRegular()&&st.Mode().Perm()&0o111!=0{found[exe]=true}}}
	if len(found)>1{return "",problem("Multiple LucX-UI executables are running; cannot select a local token provider")}
	for p:=range found{return p,nil}
	candidates:=[]string{};if panelCwd!=""{candidates=append(candidates,filepath.Join(panelCwd,"x-ui"))};if p,x:=exec.LookPath("x-ui");x==nil{candidates=append(candidates,p)}
	for _,p:=range candidates{if st,x:=os.Stat(p);x==nil&&st.Mode().IsRegular(){return p,nil}}
	return "",problem("Could not locate the local LucX-UI CLI to provision an API credential")
}

func mintToken(panelCwd,authFile string)(string,error){
	cli,err:=panelCLI(panelCwd);if err!=nil{return "",err}
	ctx,cancel:=context.WithTimeout(context.Background(),8*time.Second);defer cancel()
	help,err:=exec.CommandContext(ctx,cli,"setting","-h").CombinedOutput()
	if err!=nil||!bytes.Contains(help,[]byte("-getApiToken"))||!bytes.Contains(help,[]byte("-tokenName"))||!bytes.Contains(help,[]byte("-tokenScope")){return "",problem("This LucX-UI build does not expose non-interactive API-token provisioning; no token was requested or changed")}
	ctx,cancel=context.WithTimeout(context.Background(),20*time.Second);defer cancel()
	out,err:=exec.CommandContext(ctx,cli,"setting","-getApiToken","-tokenName",tokenName,"-tokenScope","admin").CombinedOutput()
	if err!=nil{return "",problem("LucX-UI could not provision its local integration API credential")}
	match:=tokenLine.FindSubmatch(out);if len(match)!=2{return "",problem("LucX-UI did not return an API credential; no panel settings were changed")}
	value,err:=validToken(string(match[1]));if err!=nil{return "",err};if err:=saveToken(authFile,value);err!=nil{return "",err};return value,nil
}

func resolveToken(opts Options,panelCwd string,logger Logger)(string,error){
	if v:=strings.TrimSpace(os.Getenv("XUI_API_TOKEN"));v!=""{logger.Printf("PASS: using XUI_API_TOKEN from command environment (secret hidden)");return validToken(v)}
	v,err:=readInstallerToken(installerTokenFile);if err!=nil{return "",err};if v!=""{logger.Printf("PASS: loaded installer-provided LucX-UI credential (secret hidden)");return v,nil}
	v,err=readSavedToken(opts.AuthFile);if err!=nil{return "",err};if v!=""{logger.Printf("PASS: reusing protected local integration credential (secret hidden)");return v,nil}
	v,err=mintToken(panelCwd,opts.AuthFile);if err!=nil{return "",err};logger.Printf("PASS: created dedicated LucX-UI API credential with admin scope; stored mode 0600");return v,nil
}

func readPanelSettings(dbPath string)(map[string]string,error){
	st,err:=os.Stat(dbPath);if err!=nil||!st.Mode().IsRegular(){return nil,problem("LucX-UI SQLite database not found; specify --base-url")}
	u:=url.URL{Scheme:"file",Path:dbPath};db,err:=sql.Open("sqlite",u.String()+"?mode=ro");if err!=nil{return nil,problem("Could not open LucX-UI endpoint database read-only")}
	defer db.Close();db.SetMaxOpenConns(1)
	ctx,cancel:=context.WithTimeout(context.Background(),4*time.Second);defer cancel()
	conn,err:=db.Conn(ctx);if err!=nil{return nil,problem("Could not open LucX-UI endpoint database read-only")};defer conn.Close()
	if _,err:=conn.ExecContext(ctx,"PRAGMA query_only=ON");err!=nil{return nil,problem("Could not enable read-only LucX-UI database access")}
	rows,err:=conn.QueryContext(ctx,"SELECT key, value FROM settings WHERE key IN (?, ?, ?, ?, ?)","webPort","webBasePath","webCertFile","webKeyFile","webDomain")
	if err!=nil{return nil,problem("Could not read LucX-UI endpoint settings; specify --base-url")}
	defer rows.Close();result:=map[string]string{}
	for rows.Next(){var k string;var v sql.NullString;if err:=rows.Scan(&k,&v);err!=nil{return nil,problem("Could not parse LucX-UI endpoint settings")};if v.Valid{result[k]=v.String}}
	if err:=rows.Err();err!=nil{return nil,problem("Could not read LucX-UI endpoint settings")}
	return result,nil
}

func resolvePanelPath(value,cwd string)string{if value==""{return ""};if !filepath.IsAbs(value){return filepath.Clean(filepath.Join(cwd,value))};return filepath.Clean(value)}

func normalizeHost(value string)(string,error){
	u,err:=url.Parse("//"+value);if err!=nil||u.Hostname()==""||u.User!=nil||u.Port()!=""||u.Path!=""||u.RawQuery!=""||u.Fragment!=""||strings.ContainsAny(value," \t\r\n"){return "",problem("LucX-UI webDomain is not a plain hostname")}
	return u.Hostname(),nil
}

func detectEndpoint(opts Options)(Endpoint,string,error){
	env,cwd,err:=runningPanelContext();if err!=nil{return Endpoint{},"",err}
	dbPath:=opts.PanelDB
	if dbPath==""{
		kind:=strings.ToLower(strings.TrimSpace(env["XUI_DB_TYPE"]));if kind!=""&&kind!="sqlite"&&kind!="sqlite3"{return Endpoint{},"",problem("Automatic endpoint discovery supports SQLite panels only; specify --base-url")}
		folder:=strings.TrimSpace(env["XUI_DB_FOLDER"]);if folder==""{folder="/etc/x-ui"};if !filepath.IsAbs(folder){folder=filepath.Join(cwd,folder)};dbPath=filepath.Join(folder,"x-ui.db")
	}
	settings,err:=readPanelSettings(dbPath);if err!=nil{return Endpoint{},"",err}
	port:=2053;if p:=strings.TrimSpace(settings["webPort"]);p!=""{port,err=strconv.Atoi(p);if err!=nil{return Endpoint{},"",problem("LucX-UI webPort setting is invalid")}}
	if p:=strings.TrimSpace(env["XUI_PORT"]);p!=""{if n,e:=strconv.Atoi(p);e==nil&&n>0&&n<=65535{port=n}}
	if port<1||port>65535{return Endpoint{},"",problem("LucX-UI panel port is outside the valid range")}
	basePath,err:=normalizeBasePath(settings["webBasePath"]);if err!=nil{return Endpoint{},"",err}
	certFile,keyFile:=strings.TrimSpace(settings["webCertFile"]),strings.TrimSpace(settings["webKeyFile"])
	tlsEnabled:=false;var leaf *x509.Certificate
	if certFile!=""||keyFile!=""{
		if certFile==""||keyFile==""{return Endpoint{},"",problem("LucX-UI has incomplete TLS certificate/key configuration; refusing HTTP fallback")}
		pair,e:=tls.LoadX509KeyPair(resolvePanelPath(certFile,cwd),resolvePanelPath(keyFile,cwd));if e!=nil||len(pair.Certificate)==0{return Endpoint{},"",problem("LucX-UI TLS certificate/key could not be loaded")}
		leaf,e=x509.ParseCertificate(pair.Certificate[0]);if e!=nil{return Endpoint{},"",problem("Could not inspect LucX-UI TLS certificate")};tlsEnabled=true
	}
	scheme:="http";if tlsEnabled{scheme="https"}
	hostHeader,sni,verifyIP:="","",""
	domain:=strings.TrimSpace(settings["webDomain"])
	if domain!=""{
		host,e:=normalizeHost(domain);if e!=nil{return Endpoint{},"",e}
		if ip:=net.ParseIP(host);ip!=nil{
			hostHeader=net.JoinHostPort(host,strconv.Itoa(port));if tlsEnabled{sni="localhost";verifyIP=ip.String()}
		}else{hostHeader=net.JoinHostPort(host,strconv.Itoa(port));if tlsEnabled{sni=host}
		}
	}else if tlsEnabled{
		if len(leaf.IPAddresses)>0{sni="localhost";verifyIP=leaf.IPAddresses[0].String()}else if len(leaf.DNSNames)>0{sni=leaf.DNSNames[0]}else{return Endpoint{},"",problem("Configured LucX-UI certificate has no DNS/IP SAN")}
	}
	return Endpoint{BaseURL:fmt.Sprintf("%s://127.0.0.1:%d%s",scheme,port,strings.TrimSuffix(basePath,"/")),HostHeader:hostHeader,ServerName:sni,VerifyIP:verifyIP},cwd,nil
}

func validateEndpointMode(e Endpoint,mode,name string)(Endpoint,error){
	u,err:=url.Parse(e.BaseURL);if err!=nil{return e,problem("Invalid panel URL")}
	switch mode{
	case "", "auto":if name!=""{return e,problem("--tls-name requires --tls-mode ip or domain")}
	case "http":if u.Scheme!="http"||name!=""{return e,problem("--tls-mode http requires HTTP and no --tls-name")};e.ServerName="";e.VerifyIP=""
	case "ip":if u.Scheme!="https"||name==""{return e,problem("--tls-mode ip requires HTTPS and --tls-name")};ip:=net.ParseIP(name);if ip==nil{return e,problem("--tls-name must be an IP address")};e.ServerName="localhost";e.VerifyIP=ip.String()
	case "domain":if u.Scheme!="https"||name==""{return e,problem("--tls-mode domain requires HTTPS and --tls-name")};host,err:=normalizeHost(name);if err!=nil||net.ParseIP(host)!=nil{return e,problem("--tls-name must be a DNS hostname")};e.ServerName=host;e.VerifyIP="";port:=u.Port();if port==""{port="443"};e.HostHeader=net.JoinHostPort(host,port)
	default:return e,problem("Unknown TLS mode")
	}
	return e,nil
}

func makeHTTPClient(e Endpoint,timeout time.Duration,allowHTTP bool)(*http.Client,error){
	u,err:=url.Parse(e.BaseURL);if err!=nil||u.Host==""||u.User!=nil||u.RawQuery!=""||u.Fragment!=""||(u.Scheme!="http"&&u.Scheme!="https"){return nil,problem("--base-url must be an absolute http(s) URL without credentials/query/fragment")}
	if u.Scheme=="http"&&!allowHTTP&&!IsLocalURL(e.BaseURL){return nil,problem("Plain HTTP is refused for non-loopback hosts")}
	cfg:=&tls.Config{MinVersion:tls.VersionTLS12}
	if e.ServerName!=""{cfg.ServerName=e.ServerName}
	if e.VerifyIP!=""{
		cfg.InsecureSkipVerify=true
		expected:=e.VerifyIP
		cfg.VerifyConnection=func(state tls.ConnectionState)error{
			if len(state.PeerCertificates)==0{return errors.New("TLS peer did not provide a certificate")}
			intermediates:=x509.NewCertPool();for _,c:=range state.PeerCertificates[1:]{intermediates.AddCert(c)}
			_,err:=state.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName:expected,Intermediates:intermediates});return err
		}
	}
	transport:=&http.Transport{TLSClientConfig:cfg,Proxy:nil,ResponseHeaderTimeout:timeout}
	return &http.Client{Transport:transport,Timeout:timeout},nil
}

type Logger interface { Printf(string,...any) }
type PanelAPI struct { root,token,hostHeader string; client *http.Client; logger Logger }

func NewPanelAPI(e Endpoint,token string,timeout time.Duration,allowHTTP bool,logger Logger)(*PanelAPI,error){
	client,err:=makeHTTPClient(e,timeout,allowHTTP);if err!=nil{return nil,err}
	return &PanelAPI{root:strings.TrimRight(e.BaseURL,"/"),token:token,hostHeader:e.HostHeader,client:client,logger:logger},nil
}

func (p *PanelAPI) request(method,path string,form url.Values,payload any)(map[string]any,error){
	var body io.Reader;contentType:=""
	if form!=nil{body=strings.NewReader(form.Encode());contentType="application/x-www-form-urlencoded"}
	if payload!=nil{b,err:=json.Marshal(payload);if err!=nil{return nil,problem("Could not encode panel API request")};body=bytes.NewReader(b);contentType="application/json"}
	req,err:=http.NewRequest(method,p.root+path,body);if err!=nil{return nil,problem("Could not create panel API request")}
	req.Header.Set("Authorization","Bearer "+p.token);req.Header.Set("Accept","application/json");req.Header.Set("User-Agent","doh-health-monitor/2.1.0")
	if contentType!=""{req.Header.Set("Content-Type",contentType)};if p.hostHeader!=""{req.Host=p.hostHeader}
	resp,err:=p.client.Do(req);if err!=nil{return nil,problem("Could not reach LucX-UI API; network details suppressed")};defer resp.Body.Close()
	data,err:=io.ReadAll(io.LimitReader(resp.Body,maxResponseBytes+1));if err!=nil{return nil,problem("Could not read LucX-UI API response")}
	if len(data)>maxResponseBytes{return nil,problem("LucX-UI API response exceeded the size limit")}
	if resp.StatusCode<200||resp.StatusCode>=300{return nil,problem("LucX-UI API HTTP error (%d); response body suppressed",resp.StatusCode)}
	dec:=json.NewDecoder(bytes.NewReader(data));dec.UseNumber();var env map[string]any
	if err:=dec.Decode(&env);err!=nil{return nil,problem("LucX-UI API returned invalid JSON")}
	if env["success"]!=true{return nil,problem("LucX-UI API reported an unsuccessful request")}
	return env,nil
}

func parseObject(value any,description string)(map[string]any,error){
	if s,ok:=value.(string);ok{dec:=json.NewDecoder(strings.NewReader(s));dec.UseNumber();var v map[string]any;if err:=dec.Decode(&v);err!=nil||v==nil{return nil,problem("LucX-UI returned invalid %s JSON",description)};return v,nil}
	v,ok:=value.(map[string]any);if !ok||v==nil{return nil,problem("LucX-UI response does not contain %s",description)};return v,nil
}
func parseArray(value any,description string)([]any,error){
	if s,ok:=value.(string);ok{dec:=json.NewDecoder(strings.NewReader(s));dec.UseNumber();var v []any;if err:=dec.Decode(&v);err!=nil{return nil,problem("LucX-UI returned invalid %s JSON",description)};return v,nil}
	v,ok:=value.([]any);if !ok{return nil,problem("LucX-UI response does not contain %s",description)};return v,nil
}

type State struct { Config map[string]any; OutboundTestURL string }
func (p *PanelAPI) ReadState()(State,error){
	env,err:=p.request(http.MethodPost,"/panel/api/xray/",url.Values{},nil);if err!=nil{return State{},err}
	obj,err:=parseObject(env["obj"],"Xray settings");if err!=nil{return State{},err}
	cfg,err:=parseObject(obj["xraySetting"],"xraySetting");if err!=nil{return State{},err}
	testURL,ok:=obj["outboundTestUrl"].(string);if !ok||strings.TrimSpace(testURL)==""{return State{},problem("Panel did not return outboundTestUrl; refusing to overwrite panel metadata")}
	return State{Config:cfg,OutboundTestURL:testURL},nil
}
func (p *PanelAPI) Update(cfg map[string]any,testURL string)error{
	data,err:=json.Marshal(cfg);if err!=nil{return problem("Could not encode Xray settings")}
	_,err=p.request(http.MethodPost,"/panel/api/xray/update",url.Values{"xraySetting":{string(data)},"outboundTestUrl":{testURL}},nil);return err
}
func (p *PanelAPI) inboundRequest(method,suffix string,payload any)(map[string]any,error){return p.request(method,"/panel/api/inbounds/"+strings.TrimLeft(suffix,"/"),nil,payload)}
func (p *PanelAPI) ListInbounds()([]map[string]any,error){
	env,err:=p.inboundRequest(http.MethodGet,"list",nil);if err!=nil{return nil,err};arr,err:=parseArray(env["obj"],"inbound list");if err!=nil{return nil,err}
	out:=make([]map[string]any,0,len(arr));for _,item:=range arr{m,ok:=item.(map[string]any);if !ok{return nil,problem("LucX-UI returned an invalid inbound entry")};out=append(out,m)};return out,nil
}
func (p *PanelAPI) AddInbound(inbound map[string]any)(map[string]any,error){
	if inbound["protocol"]!="tunnel"{return nil,problem("Only a Tunnel inbound can be created by this integration")}
	env,err:=p.inboundRequest(http.MethodPost,"add",inbound);if err!=nil{return nil,err};obj,err:=parseObject(env["obj"],"created inbound");if err!=nil{return nil,err}
	id,ok:=asInt(obj["id"]);if !ok||id<=0{return nil,problem("LucX-UI did not return a valid Tunnel ID")};return obj,nil
}
func (p *PanelAPI) DeleteInbound(id int64)error{if id<=0{return problem("Refusing to delete an inbound without a valid ID")};_,err:=p.inboundRequest(http.MethodPost,"del/"+strconv.FormatInt(id,10),nil);return err}

func asInt(v any)(int64,bool){switch n:=v.(type){case json.Number:i,e:=n.Int64();return i,e==nil;case int:return int64(n),true;case int64:return n,true;case float64:return int64(n),float64(int64(n))==n};return 0,false}

func DetectAndAuthorize(opts Options,logger Logger)(Endpoint,*PanelAPI,error){
	var endpoint Endpoint;var cwd string;var err error
	if opts.BaseURL!=""{
		u,e:=url.Parse(opts.BaseURL);if e!=nil{return endpoint,nil,problem("Invalid --base-url")}
		endpoint=Endpoint{BaseURL:opts.BaseURL}
		if u.Scheme=="https"&&opts.TLSMode=="auto"{return endpoint,nil,problem("An explicit HTTPS --base-url requires --tls-mode ip/domain and --tls-name")}
		_,cwd,err=runningPanelContext()
	}else{endpoint,cwd,err=detectEndpoint(opts)}
	if err!=nil{return endpoint,nil,err}
	endpoint,err=validateEndpointMode(endpoint,opts.TLSMode,opts.TLSName);if err!=nil{return endpoint,nil,err}
	if !IsLocalURL(endpoint.BaseURL){return endpoint,nil,problem("Panel API URL must use localhost/loopback")}
	parsed,_:=url.Parse(endpoint.BaseURL);if logger!=nil{path:="root path";if parsed.Path!=""{path="configured path (hidden)"};logger.Printf("Panel endpoint detected: %s://127.0.0.1:%s (%s)",parsed.Scheme,parsed.Port(),path);if endpoint.HostHeader!=""{logger.Printf("Panel domain Host header/TLS SNI will be used")}}
	token,err:=resolveToken(opts,cwd,logger);if err!=nil{return endpoint,nil,err}
	api,err:=NewPanelAPI(endpoint,token,opts.Timeout,opts.AllowInsecureHTTP,logger);return endpoint,api,err
}

func checkPluginHealth(opts Options,logger Logger)error{
	if !regexp.MustCompile("^[A-Za-z0-9_.@-]+$").MatchString(opts.Service){return problem("Invalid DoH Health Monitor systemd service name")}
	if !IsLocalURL(opts.StatusURL){return problem("DoH Health Monitor status URL must use localhost/loopback")}
	systemctl,err:=exec.LookPath("systemctl");if err!=nil{return problem("Required preflight tool systemctl was not found")}
	ss,err:=exec.LookPath("ss");if err!=nil{return problem("Required preflight tool ss was not found")}
	run:=func(timeout time.Duration,name string,args ...string)([]byte,error){ctx,cancel:=context.WithTimeout(context.Background(),timeout);defer cancel();cmd:=exec.CommandContext(ctx,name,args...);cmd.Stdin=nil;out,e:=cmd.CombinedOutput();if ctx.Err()!=nil{return nil,ctx.Err()};return out,e}
	load,err:=run(5*time.Second,systemctl,"show","--property=LoadState","--value",opts.Service);if err!=nil||strings.TrimSpace(string(load))!="loaded"{return problem("DoH Health Monitor service %q is not installed/loaded; no panel API operation was attempted",opts.Service)}
	if _,err:=run(5*time.Second,systemctl,"is-active","--quiet",opts.Service);err!=nil{return problem("DoH Health Monitor service %q is not active; no panel API operation was attempted",opts.Service)}
	if logger!=nil{logger.Printf("PASS: DoH Health Monitor service %q is installed and active",opts.Service)}
	for _,item:=range []struct{name,flag string}{{"TCP","-ltn"},{"UDP","-lun"}}{
		out,err:=run(5*time.Second,ss,"-H",item.flag);if err!=nil||!listenerHasLoopback(string(out),opts.Port){return problem("DoH Health Monitor loopback listener %d/%s is not active; no panel API operation was attempted",opts.Port,item.name)}
		if logger!=nil{logger.Printf("PASS: DoH Health Monitor loopback listener %d/%s is active",opts.Port,item.name)}
	}
	client:=&http.Client{Timeout:3*time.Second};req,_:=http.NewRequest(http.MethodGet,opts.StatusURL,nil);req.Header.Set("Accept","application/json")
	resp,err:=client.Do(req);if err!=nil{return problem("DoH Health Monitor status API is unavailable; no panel API operation was attempted")};defer resp.Body.Close()
	data,err:=io.ReadAll(io.LimitReader(resp.Body,(1<<20)+1));if err!=nil||resp.StatusCode<200||resp.StatusCode>=300||len(data)>1<<20{return problem("DoH Health Monitor status API is unavailable; no panel API operation was attempted")}
	var status map[string]any;if json.Unmarshal(data,&status)!=nil||status==nil{return problem("DoH Health Monitor status API returned invalid JSON")}
	if logger!=nil{logger.Printf("PASS: DoH Health Monitor status API returns a JSON object")};return nil
}

func listenerHasLoopback(output string,port int)bool{
	re:=regexp.MustCompile(fmt.Sprintf("(127\\.0\\.0\\.1|\\[?::1\\]?):%d(\\s|$)",port))
	for _,line:=range strings.Split(output,"\n"){if re.MatchString(line){return true}};return false
}
