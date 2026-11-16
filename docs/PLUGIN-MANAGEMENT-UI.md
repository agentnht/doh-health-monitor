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

Initial milestone: a minimal placeholder page, sufficient to verify that the server starts, serves HTTP, and can be reached through an SSH tunnel. This milestone is not the full management UI.

Expected lifecycle:

1. The SSH menu starts the web server as a separately managed process.
2. The Go web server asks the operating system to allocate an available TCP port by listening on `127.0.0.1:0`.
3. After the listener is successfully created, Go obtains the actual assigned port from the listener and reports it to the SSH menu (for example, through a readiness message or a protected runtime file).
4. The administrator opens an SSH local port-forward from their workstation, targeting that actual server-side port.
5. The administrator visits the forwarded local address in a browser.
6. Stopping the web server does not stop or restart the DNS daemon.

**Agreed port strategy:** the Go web server dynamically selects its own port. It does not read or depend on LucX-UI's `http.port`. Binding to `127.0.0.1:0` lets the operating system allocate a free port as part of creating the listener, avoiding a separate check-then-bind race. The server must keep that same listener open; it must not probe a port, close it, and later attempt to bind again.

The actual bound port must be communicated reliably to the SSH script only after the listener is active. The script then prints the exact SSH tunnel command and browser URL. The local workstation port may be a convenient fixed value (for example, `19876`) or another locally available port; the remote target must always be the dynamically assigned plugin web port.

The implementation needs a defined way to track the web process and stop it safely (for example, a PID file with process identity validation). It must avoid killing an unrelated process if a stale PID file exists. Exact start/stop interaction and idle timeout policy remain to be designed.

## 3. Port allocation and SSH tunnel

No lookup of LucX-UI's `http.port` is required. That file belongs to the panel and is unrelated to the plugin's management listener.

Example Windows terminal command (the local port is an example; the remote port must be replaced with the actual port reported by the Go server):

```powershell
ssh -L 19876:127.0.0.1:ACTUAL_PLUGIN_WEB_PORT root@SERVER_ADDRESS
```

Keep this SSH session open while using the UI. Then open:

```text
http://127.0.0.1:19876/
```

The script should print a ready-to-copy command containing the real server-side port, not the placeholder shown above. The server must bind exclusively to loopback.

## 4. Security requirements

- Bind the plugin web server exclusively to loopback (`127.0.0.1`), never to a public or wildcard interface.
- Do not expose the management UI directly to the Internet.
- Use SSH port forwarding as the supported remote access path.
- Do not send panel credentials, admin credentials, or other secrets to browser code.
- Do not log secrets.
- Require explicit confirmation for state-changing operations in the web UI.
- Keep web-server lifecycle independent from the DNS daemon.
- Protect process-control files and any runtime state with appropriate filesystem permissions.
- Treat requests as untrusted even though the service binds to loopback.

## 5. Shared management layer

The intended relationship is:

```text
SSH shell menu ───────┐
                      ├── Go management layer ── integrate / remove / check
Browser Web UI ─ HTTP ┘
```

The web API should expose only the operations and status needed by the UI. It should reuse existing Go integration and diagnostic logic rather than duplicating it.

## 6. Proposed delivery stages

1. **Architecture and interface contract:** settle command names, dynamic port reporting, web-server lifecycle, and the initial API boundary.
2. **SSH menu:** implement the repository-hosted interactive script and connect its actions to existing Go commands.
3. **Web placeholder:** implement on-demand start/stop and a minimal page; validate access through SSH forwarding.
4. **Web API:** expose read-only status/diagnostics and then guarded integration/removal operations.
5. **Full UI:** add plugin configuration, upstreams/groups, health state, integration status, and logs as their contracts are agreed.

## 7. Open decisions

- Which exact command/script URL and invocation format should be documented for administrators?
- Should the SSH script download and execute the current script on each run, or should it be installed locally and updated explicitly?
- How should the Go server communicate readiness and its dynamically assigned port to the SSH script (stdout handshake or protected runtime file)?
- Should the web process run until explicitly stopped, or should it have an idle timeout?
- What authentication or per-session protection is required in addition to SSH tunneling?
- What exact read-only checks should the first `check` menu item perform and how should results be presented?

## Scope note

This document records the proposed architecture and agreed direction only. It does not implement the shell script, HTTP server, web page, API, or any daemon behavior.
