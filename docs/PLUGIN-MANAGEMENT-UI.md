# Plugin management UI — architecture proposal

**Status:** Draft architecture; no implementation decisions beyond the items explicitly marked as agreed.

## Goal

Provide two ways to administer the DoH Health Monitor plugin:

1. An interactive SSH menu, launched by a shell script hosted in this GitHub repository.
2. A browser-based management UI, started on demand from that SSH menu and accessed through an SSH local port-forward.

The SSH and web interfaces must call the same Go-side management logic. They must not implement separate versions of integration, removal, or diagnostics.

## 1. SSH management menu

The administrator connects to the server over SSH and launches the repository-hosted shell script. The script presents these actions:

- **Integrate** — invoke the existing Go `integrate` operation.
- **Remove** — invoke the existing Go `remove` operation.
- **Check** — run read-only diagnostics and display plugin/integration status.
- **Web** — start the on-demand web management server.

The existing daemon behavior remains unchanged: starting the binary without a management command starts the DNS daemon. The `check` action must not modify Xray or plugin configuration.

The script is an orchestration/presentation layer. Administrative operations and their validation remain in Go. The script must report missing dependencies, unavailable plugin binaries, and operation failures clearly; it must not silently continue after an error.

## 2. On-demand Web UI

**Agreed:** the HTTP server is not started automatically with the DNS daemon. It is started only when the administrator selects **Web** in the SSH menu.

**Agreed implementation model:** the Web UI server is part of the existing Go plugin application and is compiled into the same plugin executable. It is not a separately installed Node/Python service or an additional binary. The web handlers and management API live in Go; static HTML/CSS/JavaScript assets should be embedded in the Go executable (for example, with `embed`) so the UI does not depend on external files after installation.

Initial milestone: a minimal placeholder page, sufficient to verify that the server starts, serves HTTP, and can be reached through an SSH tunnel. This milestone is not the full management UI.

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

The script prints two ready-to-copy lines: the SSH command and the browser URL. The command must have this form, with `REMOTE_PORT` replaced by the actual server-side port reported by Go and `SERVER_ADDRESS` replaced by the server address:

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

The exact shell mechanism for creating/inheriting the control pipe and the stdout readiness-line format must be specified during implementation.

## 3. Port allocation and SSH tunnel

No lookup of LucX-UI's `http.port` is required. That file belongs to the panel and is unrelated to the plugin's management listener.

Example Windows terminal command printed by the script (the remote port is replaced with the actual port reported by Go on stdout):

```powershell
ssh -o ExitOnForwardFailure=yes -L 19876:127.0.0.1:REMOTE_PORT root@SERVER_ADDRESS
```

If local port `19876` is occupied, choose another free local port and replace only the first port in the `-L` argument. For example, for local port `19877` use `-L 19877:127.0.0.1:REMOTE_PORT`; open the matching browser address `http://127.0.0.1:19877/`. Do not change `REMOTE_PORT`.

Keep both SSH sessions open while using the UI: the original management session running the menu (which supervises the Web UI process) and this separate tunnel session. Then open the matching `http://127.0.0.1:LOCAL_PORT/` address in the browser. The server must bind exclusively to loopback.

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

## 5. Shared management layer

The intended relationship is:

```text
SSH shell menu ───────┐
                      ├── Go management layer ── integrate / remove / check
Browser Web UI ─ HTTP ┘
```

The web API should expose only the operations and status needed by the UI. It should reuse existing Go integration and diagnostic logic rather than duplicating it. **Agreed security boundary:** the UI may invoke only a narrow allowlist of Go management operations; it must never execute arbitrary shell commands or expose a terminal. State-changing operations require explicit user confirmation.

## 6. Proposed delivery stages

1. **Architecture and interface contract:** settle command names, stdout readiness contract, web-server lifecycle, and the initial API boundary.
2. **SSH menu:** implement the repository-hosted interactive script and connect its actions to existing Go commands.
3. **Web placeholder:** implement on-demand start/stop and a minimal page; validate access through SSH forwarding.
4. **Web API:** expose read-only status/diagnostics and then guarded integration/removal operations.
5. **Full UI:** add plugin configuration, upstreams/groups, health state, integration status, and logs as their contracts are agreed.

## 7. Open decisions

- Which exact command/script URL and invocation format should be documented for administrators?
- Should the SSH script download and execute the current script on each run, or should it be installed locally and updated explicitly?
- The initial lifecycle is session-bound: the web process exits when the supervising SSH management session ends; no idle timeout is planned for the placeholder milestone.
- The agreed per-session protection is a random access token kept out of URLs, stdout, and logs, plus Host/Origin validation and CSRF protection; implementation details must be reviewed during development.
- What exact read-only checks should the first `check` menu item perform and how should results be presented?

## Scope note

This document records the proposed architecture and agreed direction only. It does not implement the shell script, HTTP server, web page, API, or any daemon behavior.
