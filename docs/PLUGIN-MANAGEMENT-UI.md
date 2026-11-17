# Plugin management UI

**Status:** Implemented in release 2.2.1; this document describes the current SSH and browser management interfaces.

## Goal

Provide two ways to administer the DoH Health Monitor plugin:

1. An interactive SSH menu, launched from the script bundled in the plugin ZIP; the GitHub-hosted invocation remains available as a bootstrap alternative.
2. A browser-based management UI, started on demand from that SSH menu and accessed through an SSH local port-forward.

The SSH and web interfaces must call the same Go-side management logic. They must not implement separate versions of integration, removal, or diagnostics.

## 1. SSH management menu

The administrator connects to the server over SSH and launches the interactive Bash menu as root. The preferred entry point is the copy bundled in the installed plugin ZIP:

```bash
bash /usr/local/x-ui/bin/plugins/doh-health-monitor/scripts/plugin-management.sh
```

On its first launch from the installed package directory, the script creates `/usr/local/bin/dhm` as a symlink to that packaged script. Subsequent launches can use `dhm`. The script does not overwrite an existing file or a symlink pointing elsewhere. If the plugin itself is uninstalled, the administrator removes the now-dangling link with `rm -f /usr/local/bin/dhm`.

The GitHub process-substitution entry point remains available as a limited bootstrap method:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/agentnht/doh-health-monitor/main/scripts/plugin-management.sh)
```

Because the GitHub version is streamed rather than executed from a persistent installed file, this entry point does not create the `dhm` symlink. It deliberately does not download or execute a second shell script; the full read-only Xray checker is available only from the packaged installation.

The menu requires root. It locates the installed plugin executable from `LUCX_PLUGIN_DATA` or the running LucX-UI process working directory. The script presents these actions:

- **Integrate** — invoke the existing Go `integrate` operation.
- **Remove** — invoke the existing Go `remove` operation.
- **Check** — run read-only diagnostics and display plugin/integration status.
- **Web** — start the on-demand web management server.

The existing daemon behavior remains unchanged: starting the binary without a management command starts the DNS daemon. The `check` action must not modify Xray or plugin configuration.

For a package-installed launch, the adjacent `scripts/check-dns-integration.sh` is used locally. The GitHub process-substitution launch does not download a mutable branch script and therefore reports the full checker as unavailable; use the package-installed menu for complete diagnostics. The script is an orchestration/presentation layer. Administrative operations and their validation remain in Go. The current menu invokes the existing Go `integrate` and `remove` commands after explicit confirmation. Integrate saves permanent DNS objects first, then performs a temporary TCP/UDP Tunnel self-test. LucX-UI applies pending Xray changes asynchronously on a 30-second background cadence, so the self-test allows up to 75 seconds for the temporary Tunnel listeners to appear and polls only once (rather than timing out before the panel's next apply cycle). A failed self-test does not roll back or remove the already verified permanent DNS integration; temporary diagnostic resources are cleaned up separately. Its `check` item first invokes the Go `check` command for read-only service/listener/status diagnostics, then runs the adjacent `scripts/check-dns-integration.sh` included in the ZIP for read-only Xray configuration checks. When the menu is launched from GitHub by process substitution, the full checker is intentionally unavailable; the menu never downloads and executes mutable remote code as root. The shell checker skips duplicate service/listener/status probes when called by the menu; standalone use still performs the complete check. The menu requires `jq` for Xray JSON checks, and the GitHub bootstrap mode does not require a secondary checker download. The menu reports a missing plugin binary or failed operation rather than silently continuing. The `web` menu item starts the separate Go Web UI process. The shell keeps the coprocess stdin writer open as a control pipe, parses the readiness line, and prints the SSH tunnel command plus browser URL.

## 2. On-demand Web UI

**Agreed:** the HTTP server is not started automatically with the DNS daemon. It is started only when the administrator selects **Web** in the SSH menu.

**Agreed implementation model:** the Web UI server is part of the existing Go plugin application and is compiled into the same plugin executable. It is not a separately installed Node/Python service or an additional binary. The web handlers and management API live in Go; static HTML/CSS/JavaScript assets should be embedded in the Go executable (for example, with `embed`) so the UI does not depend on external files after installation.

Implemented scope: the embedded Web UI provides the status dashboard plus authenticated management pages for supported configuration fields, DoH and health-check source files, operational DNS tests, logs, Gemini key upload, and confirmation-protected Integrate/Remove actions. The browser API validates input before writing and reuses the existing Go integration workflow.

Expected lifecycle:

1. The SSH menu starts the web server as a separately managed process.
2. The Go web server asks the operating system to allocate an available TCP port by listening on `127.0.0.1:0`.
3. After the listener is successfully created, Go obtains the actual assigned port from the listener.
4. **Agreed port handoff:** Go reports readiness and the assigned port through stdout. The SSH script reads this readiness message and uses the reported port to construct the tunnel command and browser URL. No port file or lookup of LucX-UI configuration is involved.
5. The administrator opens an SSH local port-forward from their workstation, targeting that actual server-side port.
6. The administrator visits the forwarded local address in a browser.
7. Stopping the web server does not stop or restart the DNS daemon.

**Agreed port strategy:** the Go web server dynamically selects its own port. It does not read or depend on LucX-UI's `http.port`. Binding to `127.0.0.1:0` lets the operating system allocate a free port as part of creating the listener, avoiding a separate check-then-bind race. The server must keep that same listener open; it must not probe a port, close it, and later attempt to bind again.

The stdout readiness message must be a stable, documented machine-readable contract so the shell script can parse it reliably. **Proposed agreed format:** `WEB_UI_READY port=<number>`. It is emitted only after the listener is active and includes the actual TCP port. Reserve stdout for this protocol; diagnostic and error messages go to stderr so they cannot corrupt parsing. If startup fails before readiness, Go must exit with a non-zero status and provide a useful error on stderr. The SSH script waits no longer than 10 seconds for readiness, while also detecting early process exit; timeout or malformed output causes cleanup and a clear error.

The script prints two ready-to-copy lines: the SSH command and the browser URL. It resolves the SSH target in this order: an explicit `SERVER_ADDRESS` environment override; the third field (server-side address) of sshd's `SSH_CONNECTION` environment variable; or an interactive prompt if that variable is unavailable. This avoids printing a literal placeholder. When the VPS is behind NAT, a proxy, or a bastion where the server-side address from `SSH_CONNECTION` is not reachable from the Windows workstation, set `SERVER_ADDRESS` explicitly to the public IP or DNS name used to connect. The command has this form, with `REMOTE_PORT` replaced by the actual server-side port reported by Go:

```powershell
ssh -o ExitOnForwardFailure=yes -L 19876:127.0.0.1:REMOTE_PORT root@SERVER_ADDRESS
```

The local workstation port (`19876` in this example) is chosen on the Windows workstation, not by the remote VPS script. The remote script cannot inspect or reserve a Windows TCP port. If SSH reports that the local port is already occupied, the administrator chooses another free local port by replacing `19876` in the command with that port, then retries. The browser URL printed by the script must use the same local port (for example, `http://127.0.0.1:19876/`; update it to match if the local port is changed). The remote port in the command does not change. `-o ExitOnForwardFailure=yes` makes SSH fail immediately if it cannot bind the requested local forwarding port. No remote-side check of the Windows port is attempted.

The SSH script should supervise the Go web-server process as its child, keep it in the foreground of the management session, and stop/wait for that exact child on normal exit. It must not use an unvalidated PID file or broad process-name matching to terminate processes.

**Agreed session lifecycle and firewall policy:**
- Do not inspect, add, or remove UFW rules. Because the listener is bound only to `127.0.0.1`, it is not reachable directly from external network interfaces; SSH local port forwarding is the access path.
- On normal menu exit, Ctrl+C, or catchable termination/hangup signals, the shell script must stop the child web-server process and wait for it to exit. The DNS daemon is not a child of this temporary web session and must remain untouched.
- Add a second, server-side safeguard for abrupt SSH disconnects: the script provides the Go process with a dedicated control pipe whose write end is held open by the supervising shell. Go monitors that pipe; EOF means the supervising SSH session has gone away, so Go performs graceful HTTP shutdown and exits. This avoids depending solely on shell traps, which cannot run after every kind of disconnect or forced termination.
- Go should use a bounded graceful-shutdown period, then close remaining HTTP connections if necessary. The shell should also detect early child exit and clean up without leaving a stale process.
- No idle timeout is required for the initial placeholder milestone; the web process lives only for the SSH management session.

Implementation: the Bash menu starts the Go `web` mode as a coprocess. Bash retains the coprocess stdin writer while Go reads stdin until EOF. Closing that writer on normal stop, or its automatic closure when the SSH supervisor disappears, triggers bounded graceful HTTP shutdown. Go also handles INT, TERM, and HUP. The stdout readiness protocol is `WEB_UI_READY port=<number>`; all diagnostics remain on stderr.

## 3. Port allocation and SSH tunnel

No lookup of LucX-UI's `http.port` is required. That file belongs to the panel and is unrelated to the plugin's management listener.

Example Windows terminal command printed by the script (the remote port is replaced with the actual port reported by Go on stdout):

```powershell
ssh -o ExitOnForwardFailure=yes -L 19876:127.0.0.1:REMOTE_PORT root@SERVER_ADDRESS
```

If local port `19876` is occupied, choose another free local port and replace only the first port in the `-L` argument. For example, for local port `19877` use `-L 19877:127.0.0.1:REMOTE_PORT`; open the matching browser address `http://127.0.0.1:19877/`. Do not change `REMOTE_PORT`.

Keep both SSH sessions open while using the UI: the original management session running the menu (which supervises the Web UI process) and this separate tunnel session. Then open the matching `http://127.0.0.1:LOCAL_PORT/` address in the browser. The server must bind exclusively to loopback.

### SSH host-key warning on Windows

If OpenSSH reports `REMOTE HOST IDENTIFICATION HAS CHANGED`, do not immediately delete the saved key or disable host-key checking. First verify the new server host-key fingerprint through a trusted VPS console or hosting-provider control panel. Only after the fingerprint has been independently confirmed as belonging to this VPS, remove the stale known_hosts entry from Windows PowerShell:

```powershell
ssh-keygen -R SERVER_ADDRESS
```

Replace `SERVER_ADDRESS` with the VPS IP address or hostname used in the SSH command. Then reconnect normally and compare the fingerprint shown by SSH with the independently verified fingerprint before accepting the new key. A changed host key can be legitimate after a server rebuild or key rotation, but can also indicate a man-in-the-middle attack. Never work around this warning with `StrictHostKeyChecking=no`.

### Web UI session shutdown test

Perform these checks while the DNS daemon is running if desired; none of the tests should stop, restart, or reconfigure it.

1. **Normal stop:** while the Web UI is open, return to the original SSH management terminal and press Enter at the menu's Web UI prompt. The script should print that Web UI has stopped and return to the menu. Choose `0` to exit the menu. The browser tab may still display its already-loaded page; refresh it and verify that the browser reports a connection failure (the Web UI page is no longer served) through the still-open tunnel.
2. **Ctrl+C:** start Web UI again, then press Ctrl+C in the original management terminal. The shell trap should close the control pipe, wait for the Go child, and exit the menu session. Refresh the browser page; the browser should report a connection failure because the Web UI is no longer being served.
3. **Abrupt management-session loss:** start Web UI again, keep the separate tunnel session open, then close the original management SSH terminal/window without using the menu's normal exit. After the SSH connection is gone, refresh the browser page. The Go process should observe EOF on its control pipe, perform graceful shutdown, and the page should become unavailable. This specifically checks the server-side EOF safeguard.
4. **Tunnel-only disconnect:** close only the second SSH terminal that carries the port-forward. This should make the browser page unavailable from the workstation, but it should **not** stop Web UI while the original management session remains active. Return to the original terminal and press Enter to stop Web UI cleanly.

For an additional server-side check after a stop, reconnect to the VPS and inspect only matching Web UI processes:

```bash
pgrep -af 'doh-health-monitor web' || true
```

No matching Web UI process should remain after the management session has ended. Do not kill processes by name as part of this test. The DNS daemon is a separate process and must remain running.

## 4. Security requirements

- Bind the plugin web server exclusively to loopback (`127.0.0.1`), never to a public or wildcard interface.
- Do not modify UFW or other host firewall rules for this feature; SSH forwarding reaches the loopback listener without opening a public inbound port.
- Do not expose the management UI directly to the Internet.
- Use SSH port forwarding as the supported remote access path.
- Do not send panel credentials, admin credentials, or other secrets to browser code.
- Do not log secrets.
- Require explicit confirmation for state-changing operations in the web UI.
- Keep web-server lifecycle independent from the DNS daemon.
- Protect process-control files and any runtime state with appropriate filesystem permissions.
- Treat requests as untrusted even though the service binds to loopback.
- Validate `Host` and `Origin` for browser requests and implement CSRF protection for state-changing requests.
- Generate a cryptographically random per-session access token. Do not put it in the URL, stdout, or logs; keep it in a protected session mechanism (for example, a `HttpOnly`, `SameSite=Strict` cookie) and require it for management API access.
- Expose only an explicit allowlist of plugin management operations through the API. Never provide arbitrary shell execution, command passthrough, or a generic terminal endpoint.
- Require a separate explicit confirmation in the UI before every state-changing operation.

## 5. Web API and security model

The authenticated browser API exposes the following management operations:

- `GET /api/v1/status` — safe operational summary of the DNS daemon.
- `GET/POST /api/v1/config` and `POST /api/v1/config/defaults` — read and update the supported editable configuration fields, or reset supported sections.
- `GET/POST /api/v1/sources` — read and update `doh-servers.txt` and `tst-domen.txt`.
- `POST /api/v1/gemini-key` — save the Gemini API key to its configured private file; key contents are never returned.
- `GET /api/v1/logs` and `GET /api/v1/integration/logs` — bounded plugin and integration-operation logs.
- `POST /api/v1/tests/run` — run operational checks, including real DNS queries against the configured UDP listener.
- `POST /api/v1/integration` — invoke `check`, `integrate` or `remove`; state-changing operations require explicit confirmation.

The Web UI does not expose arbitrary file paths, arbitrary commands or a shell. Editable configuration is an allowlist: the `local_hosts` map is not currently part of the browser editor and remains configurable through `config.json`.

The root page issues a cryptographically random per-Web-UI-session token in an `HttpOnly`, `SameSite=Strict` cookie. The token is never placed in the URL, page source, stdout or logs. All management API routes require the session cookie; Host and Origin are checked against loopback/same-origin. Responses use `Cache-Control: no-store`, a restrictive Content Security Policy and no CORS headers. POST handlers accept bounded JSON bodies, reject unknown fields and validate input before writing. Integrate and Remove require explicit per-operation confirmation.

The overview displays daemon reachability, version, listener addresses, counters, cache and Gemini state, upstream-group health, and expandable per-upstream check details. Additional pages expose configuration editing, DoH/check source editors, status tests and logs. Source-file changes are picked up by the daemon's existing reload mechanism. Configuration changes that alter listener addresses or the concurrent DNS limit are marked as requiring a daemon restart; the Web UI does not restart systemd services. Integrate/Remove invoke the existing Go workflow after confirmation. No arbitrary command execution is available from the browser.

## 6. Shared management layer

The intended relationship is:

```text
SSH shell menu ───────┐
                      ├── Go management layer ── integrate / remove / check
Browser Web UI ─ HTTP ┘
```

The web API should expose only the operations and status needed by the UI. It should reuse existing Go integration and diagnostic logic rather than duplicating it. **Agreed security boundary:** the UI may invoke only a narrow allowlist of Go management operations; it must never execute arbitrary shell commands or expose a terminal. State-changing operations require explicit user confirmation.

## 6. Delivery status

1. **Architecture and interface contract:** agreed and documented.
2. **SSH menu:** implemented; invokes the Go integration/removal and read-only check commands, plus read-only Xray configuration diagnostics.
3. **Web UI lifecycle:** implemented; separate Go mode, embedded page, loopback-only dynamic listener, readiness protocol, SSH tunnel and control-pipe shutdown. The temporary web process is supervised by the management SSH session.
4. **Authenticated status and management API:** implemented; per-session HttpOnly cookie, loopback Host/Origin checks, bounded JSON requests, validation-before-write, file allowlist and secret redaction.
5. **Management pages and actions:** implemented; supported config editor, DoH/check source editors, Gemini key upload, operational tests, logs and confirmation-protected Integrate/Remove actions. `local_hosts` editing and domain-based DNS routing are not part of this release.

## 7. Remaining scope boundary

- The Web UI does not yet provide a `local_hosts` editor or domain-based Smart DNS routing; these are separate future features.
- The temporary Web UI process remains bound to the supervising SSH management session; no background service or idle-timeout behavior is introduced.

## Scope note

This document describes the 2.2.1 implementation: SSH menu, session-bound Web UI, authenticated status and management APIs, supported config/source editors, operational tests, logs and confirmed integration actions. DNS daemon behavior remains unchanged when the Web UI is started or stopped.
