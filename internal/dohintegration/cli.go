package dohintegration

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

func RunCommand(args []string,logger Logger)error{
	if len(args)==0{return problem("Expected integrate or remove")}
	action:=strings.ToLower(strings.TrimSpace(args[0]))
	if action!="integrate"&&action!="remove"&&action!="check"{return problem("Unknown directive %q; supported directives: integrate, remove, check",action)}
	if os.Geteuid()!=0{return problem("Run %s as root on the LucX-UI VPS",action)}
	opts:=DefaultOptions()
	fs:=flag.NewFlagSet("doh-health-monitor "+action,flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&opts.BaseURL,"base-url","","Panel URL; local SQLite discovery is used when omitted")
	fs.StringVar(&opts.PanelDB,"panel-db","","Custom LucX-UI SQLite database path for read-only endpoint discovery")
	fs.StringVar(&opts.AuthFile,"panel-auth-file",opts.AuthFile,"Root-only integration credential file")
	fs.DurationVar(&opts.Timeout,"timeout",opts.Timeout,"Panel API request timeout")
	fs.StringVar(&opts.Service,"plugin-service",opts.Service,"DoH Health Monitor systemd service")
	fs.StringVar(&opts.StatusURL,"plugin-status-url",opts.StatusURL,"DoH Health Monitor status endpoint")
	fs.IntVar(&opts.Port,"plugin-port",opts.Port,"DoH Health Monitor DNS listener port")
	fs.BoolVar(&opts.AllowInsecureHTTP,"allow-insecure-http",false,"Allow non-loopback HTTP panel API (not recommended)")
	fs.StringVar(&opts.TLSMode,"tls-mode",opts.TLSMode,"TLS identity mode for explicit endpoints: auto, http, ip, domain")
	fs.StringVar(&opts.TLSName,"tls-name","","Expected certificate IP or DNS hostname")
	if err:=fs.Parse(args[1:]);err!=nil{return problem("Invalid %s arguments",action)}
	if fs.NArg()!=0{return problem("Unexpected arguments after %s options",action)}
	if opts.Timeout<=0{return problem("--timeout must be greater than zero")}
	if opts.Port<1||opts.Port>65535{return problem("--plugin-port must be between 1 and 65535")}
	if opts.BaseURL!=""&&opts.PanelDB!=""{return problem("--panel-db is only valid when --base-url is omitted")}
	if action=="check" {
		return checkPluginHealth(opts,logger)
	}
	if action=="integrate" {
		if err:=checkPluginHealth(opts,logger);err!=nil{return fmt.Errorf("%s preflight failed: %w",action,err)}
	}
	_,api,err:=DetectAndAuthorize(opts,logger)
	if err!=nil{return fmt.Errorf("%s panel authorization failed: %w",action,err)}
	switch action{
	case "integrate":err=Integrate(api,opts,logger)
	case "remove":err=Remove(api,logger)
	}
	if err!=nil{return fmt.Errorf("%s failed: %w",action,err)}
	return nil
}

func ValidateOptions(opts Options)error{
	if opts.Timeout==0{opts.Timeout=15*time.Second}
	if opts.Timeout<0{return problem("Invalid timeout")}
	return nil
}
