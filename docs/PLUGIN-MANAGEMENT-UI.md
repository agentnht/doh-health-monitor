# Plugin management UI

**Status:** Implemented management interface for DoH Health Monitor 2.3.0 (release candidate).

## Purpose and scope

The plugin has two operator interfaces:

1. An interactive SSH menu bundled in the plugin ZIP.
2. An on-demand browser UI reachable only through an SSH local port-forward.

Both interfaces manage the plugin and run read-only diagnostics. They do not write or remove Xray DNS rules. The approved Geosite DNS policy is configured manually according to [GEOSITE-DNS-ROUTING-DESIGN.md](GEOSITE-DNS-ROUTING-DESIGN.md).

## SSH management menu

The installed menu is:

```bash
bash /usr/local/x-ui/bin/plugins/doh-health-monitor/scripts/plugin-management.sh
```

On first launch from the installed package, it creates `/usr/local/bin/dhm` only when that path is unused. It never overwrites an existing file or a symlink that points elsewhere. A GitHub bootstrap invocation remains available:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/agentnht/doh-health-monitor/feature/geosite-dns-routing/scripts/plugin-management.sh)
```

The menu requires root and offers:

- **Check:** Go-side read-only plugin preflight plus the packaged read-only Xray DNS structure checker.
- **Web:** start the temporary Web UI process and print an SSH local-forward command.
- **Exit.**

Legacy Xray `integrate` and `remove` operations are intentionally disabled for this DNS design. The menu must not reintroduce these actions or download a mutable checker script and execute it as root. The checker shipped in the ZIP is used directly.

### SSH tunnel account and address

The generated tunnel command uses this account preference:

1. Explicit `SSH_TUNNEL_USER`, when set.
2. `SUDO_USER`, so an administrator who entered the root shell through `sudo -i` can forward the Web UI using their permitted non-root SSH account.
3. `USER`, then `root` as a last resort.

The account is validated before it is inserted into the printed command. The server address can be explicitly supplied with `SERVER_ADDRESS`; otherwise the menu uses the SSH connection metadata or asks the operator. The local browser port defaults to `19876`; the server-side port is dynamically assigned by Go and must not be substituted.

The readiness protocol is a single line, `WEB_UI_READY port=<number>`. The shell validates the line and port range before printing the command. The Go process listens on `127.0.0.1` only. Closing the menu's control pipe or sending a termination signal shuts down the temporary Web UI without stopping the DNS daemon.

## On-demand Web UI

The Web UI is compiled into the Go plugin binary and is not started with the DNS daemon. Selecting **Web** in the SSH menu starts a separate temporary process.

- The operating system allocates a free port by binding `127.0.0.1:0`.
- Go reports the actual bound port through stdout only after the listener is active.
- The SSH menu owns a control pipe; EOF or a termination signal triggers graceful HTTP shutdown.
- The DNS daemon and its listeners are not restarted when the Web UI stops.

The browser is opened at the forwarded local URL, normally `http://127.0.0.1:19876/`.

## Dashboard and pages

The dashboard shows:

- DNS UDP/TCP listener addresses and daemon counters.
- **ActiveDoHSelector separately from the health monitor's group `active_upstream`:** active server ID, hostname, available IP addresses, score/check count, generation, selection time and freshness deadline.
- Existing health monitor groups and their upstream health details.

The management tabs are:

- **Configuration:** supported allowlisted fields from `config.json`, cache, health, bootstrap resolvers and Gemini settings.
- **DoH servers:** edit `doh-servers.txt`; the protected `system-dns` row can be disabled but not deleted or assigned a DoH URL.
- **Domains:** edit DNS/HTTP health checks in `tst-domen.txt`.
- **Checks:** plugin preflight, file/config validation, configured DNS listener queries and read-only Xray DNS structure check.
- **Logs:** bounded and redacted application/admin log output.

The DNS check page tests the configured local UDP and TCP plugin listeners separately. It reports positive answers, `NOERROR/NODATA`, `NXDOMAIN`, `SERVFAIL`, `REFUSED`, timeout and transport failure distinctly. `NODATA` and `NXDOMAIN` are shown as DNS-response warnings; neither is mislabeled as a transport timeout. A local listener check is not a substitute for client → sing-box → AWG → Xray end-to-end verification.

The current browser editor does not yet expose `dns_mode` or `resolver_upstreams`. These belong to a later, separate UI task; they must not be mixed with ActiveDoH DoH endpoint sources or bootstrap resolver addresses.

## Logs

The daemon can redirect stdout/stderr to the package-level `plugin.log`, while Web UI read-only check diagnostics are written to `$LUCX_PLUGIN_DATA/webui-admin-check.log`. The Logs page reads both local files when present, gives the runtime `plugin.log` its own labelled section, and includes the administrative check log as a separate source. The systemd journal is used as a fallback when local application log files are unavailable. Log output is bounded, symlink-safe and passed through credential redaction.

## Web API and security

The temporary HTTP server listens only on loopback. Each launch creates a random per-session token, issued as an HttpOnly, SameSite=Strict cookie. Management API requests require the cookie. The handler validates the Host and Origin, applies `no-store`, `nosniff`, frame and referrer protections, and serves only embedded UI assets.

Current API surface:

- `GET /api/v1/status` — sanitized daemon status, including the ActiveDoH selection.
- `GET/POST /api/v1/config` and `POST /api/v1/config/defaults` — allowlisted config editing.
- `GET/POST /api/v1/sources` — DoH and health-check source lists.
- `POST /api/v1/gemini-key` — store the secret in a private file; never return it.
- `GET /api/v1/logs` — bounded/redacted application and administration logs.
- `POST /api/v1/tests/run` — run read-only checks.

The legacy `POST /api/v1/integration` endpoint accepts only the read-only `check` action. Attempts to request `integrate` or `remove` return HTTP 410 Gone. The obsolete `/api/v1/integration/logs` route is not exposed.

The UI does not provide arbitrary file paths, arbitrary shell commands, or Xray mutation operations. File names are allowlisted, request bodies and row counts are bounded, configuration/source files are validated before an atomic write, and secret files use restrictive permissions.

## Regression coverage

CI covers JavaScript syntax, shell syntax and SSH menu helper tests. Go tests cover:

- Web UI loopback/Host/Origin/session protections and graceful process shutdown.
- Sanitized status projection, including ActiveDoH fields without endpoint URL secrets.
- Configuration/source validation and secret-file handling.
- Plugin/admin log source selection, bounded tail reads and secret redaction.
- DNS status classification for NODATA/NXDOMAIN/server failures versus transport errors.
- Separate UDP/TCP listener diagnostics and read-only Xray checker integration.
