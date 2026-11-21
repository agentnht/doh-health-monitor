# Security Policy

## Supported versions

Security fixes are developed against the latest published release. Users should upgrade to the latest release before requesting support for a vulnerability affecting an older version.

## Reporting a vulnerability

Please do not publish exploit details, credentials, tokens, or a working proof of concept in a public issue.

If GitHub private vulnerability reporting is enabled for this repository, use **Security → Report a vulnerability** to submit the report privately. If that option is unavailable, open a minimal public issue asking maintainers for a private reporting channel; do not include sensitive reproduction details until a private channel has been established.

Include the affected release/commit, the relevant component, impact, and concise reproduction steps once a private channel is available.

## Scope

The plugin is designed as a local sidecar. Its DNS and HTTP listeners are expected to bind only to loopback addresses. Reports involving the plugin's DNS handling, Web UI, configuration file handling, update/install scripts, or its interactions with the LucX-UI/Xray runtime are in scope.

There is no guaranteed response or remediation SLA. Please allow maintainers reasonable time to acknowledge and investigate a report.


## Local HTTP API access

The daemon binds its HTTP listener to a loopback IP. The unauthenticated `GET /healthz` endpoint is intentionally limited to a plain `ok` response for platform health checks. Detailed `GET /status` requires an `Authorization: Bearer` token.

The daemon generates a fresh 256-bit token on each start and atomically stores it at `$LUCX_PLUGIN_DATA/status-api.token` with mode `0600`; the data directory is expected to be mode `0700`. The Web UI backend reads the token locally and proxies detailed status to the browser only after its own session-cookie checks. Do not copy or disclose the token file.
