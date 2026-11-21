package plugincheck

import (
	"flag"
	"os"
	"strings"
)

func RunCommand(args []string, logger Logger) error {
	if len(args) == 0 {
		return problem("Expected read-only check")
	}
	action := strings.ToLower(strings.TrimSpace(args[0]))
	if action != "check" {
		return problem("Panel integration commands are not part of this plugin; configure Xray manually and use the read-only check")
	}
	if os.Geteuid() != 0 {
		return problem("Run check as root on the LucX-UI VPS")
	}

	opts := DefaultOptions()
	fs := flag.NewFlagSet("doh-health-monitor check", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.DurationVar(&opts.Timeout, "timeout", opts.Timeout, "Local preflight timeout")
	fs.StringVar(&opts.Service, "plugin-service", opts.Service, "DoH Health Monitor systemd service")
	fs.StringVar(&opts.StatusURL, "plugin-status-url", opts.StatusURL, "Minimal plugin health endpoint (loopback only)")
	fs.IntVar(&opts.Port, "plugin-port", opts.Port, "Plugin DNS listener port")
	if err := fs.Parse(args[1:]); err != nil {
		return problem("Invalid check arguments")
	}
	if fs.NArg() != 0 {
		return problem("Unexpected arguments after check options")
	}
	if opts.Timeout <= 0 {
		return problem("--timeout must be greater than zero")
	}
	if opts.Port < 1 || opts.Port > 65535 {
		return problem("--plugin-port must be between 1 and 65535")
	}
	return checkPluginHealth(opts, logger)
}
