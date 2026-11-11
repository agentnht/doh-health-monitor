# LucX-UI / DoH Health Monitor integration notes

This document records the integration shape inspected and validated for the
DoH Health Monitor 2.0.0 deployment. It is implementation guidance, not an
installer and not authorization to change a production panel.

## Validated target environment

The target panel reported `3.11.0-lucx.357` (`/usr/local/x-ui/x-ui -v`). The
corresponding LucX-UI source tag was inspected for API and Xray-setting behavior.
The installed binary checksum was recorded separately during troubleshooting;
this repository does not claim a cryptographic match between that binary and
the source tag.

Observed deployment values:

- DNS listener: `127.0.0.1:5355`, UDP and TCP.
- Status endpoint: `http://127.0.0.1:18765/status`.
- systemd unit: `lucx-plugin-doh-health-monitor`.
- Xray runtime config: `/usr/local/x-ui/bin/config.json`.
- LucX-UI SQLite database: `/etc/x-ui/x-ui.db`.
- Xray template setting: `settings.xrayTemplateConfig`.

An earlier revision of the runtime integration checker was reported as passing
on the deployment with 8 OK, 0 WARN, 0 FAIL. A health cycle was also observed with upstream checks
updated, API status updated, and no query failures during that sample. These
are operator-reported host results, not CI assertions.

## Xray template invariants

The inspected template already contained the required DNS path:

```json
{
  "tag": "dns-out",
  "protocol": "dns",
  "settings": {
    "rewriteNetwork": "udp",
    "rewriteAddress": "127.0.0.1",
    "rewritePort": 5355
  }
}
```

It also contained a DNS server at `127.0.0.1:5355`, an active global
TCP/UDP port-53 rule routed to `dns-out`, and an `xui-dns-allow` rule allowing
`127.0.0.1:5355` through `direct`. The allow rule appeared before the
`geoip:private` block rule.

Integration tools must preserve these behaviors:

1. Keep TCP/UDP destination port 53 routed to `dns-out`.
2. Keep the local `xui-dns-allow` exception before private-IP blocking rules.
3. Preserve `dns-doqd` and every unrelated user-configured outbound and rule.
4. Do not add firewall `REDIRECT` rules for this loopback integration.
5. Do not treat the monitor's health-check domain list as a QNAME allowlist.
   Health checks select an upstream; every user query sent to the local
   listener is resolved through the selected upstream (subject to configured
   local host overrides).

The Xray template is not necessarily the complete runtime configuration.
LucX-UI can inject specialized AWG, subscription, and sidecar outbounds at
runtime. A future integration must not replace the template or assume that
all runtime outbounds are represented in `xrayTemplateConfig`.

## LucX-UI API and restart considerations

For the inspected source version:

- `POST /panel/api/xray/` reads Xray settings; the response contains a JSON
  string/object for `xraySetting` along with panel-generated metadata.
- `POST /panel/api/xray/update` accepts a serialized `xraySetting`, validates
  and normalizes it through `SaveXraySetting`, stores `xrayTemplateConfig`,
  and calls the Xray restart/reconciliation path when Xray is running.
- The hot-diff implementation covers the Xray API-reloadable sections
  (inbounds, outbounds, routing rules/balancers). DNS changes are not among
  those hot-reload sections and can require a full Xray process restart.

Therefore, the scripts in this PR do not call the panel API, do not write the
live panel database, and do not restart Xray. Any future live apply feature
requires an explicit operator-controlled step and a separately reviewed
restart/rollback plan.

## Tooling in this PR

- `scripts/check-dns-integration.sh`: read-only checks for the plugin service,
  TCP/UDP listener, status API, runtime Xray DNS outbound/server/rules.
- `scripts/doh-integration-dry-run.py`: legacy offline planner. It reads a JSON
  fixture or SQLite in read-only mode and shows how its staging transform would
  add or correct target fields. It never writes and is not the production API
  adapter.
- `scripts/doh-integration-staging.py`: clones a source SQLite DB into a
  separate staging file, then supports dry-run, verify, apply and rollback
  against that staging file only. It is for synthetic/staging validation, not
  for the live panel database.
- `scripts/lucx-ui-doh-api.py`: production-facing, additive-only adapter using
  the LucX-UI panel API. It reads the current template, adds only missing
  `dns-out`, `dns.servers: 127.0.0.1:5355`, and a global TCP/UDP port-53 rule.
  Existing outbounds, DNS servers, and user routing rules are not edited or
  removed. The port-53 rule is inserted immediately after the panel's internal
  `api -> api` rule, so it applies to all inbound tunnels before user routing
  rules. The adapter does not create `xui-dns-allow` itself: LucX-UI's
  `EnsureDnsServerRouting` hook manages that rule from private DNS endpoints.
- The API adapter refuses to save when the panel would also move/create its
  internal API route, rewrite an existing numeric DNS `qType: 0`, or remove or
  reorder an existing routing rule during DNS allow-rule normalization. Its
  preflight models the panel's normalization using the proposed DNS endpoints,
  including legacy allow rules that the panel might newly adopt. It preserves
  `outboundTestUrl` metadata, prompts for a hidden Bearer token, avoids secrets
  in output, and stores local before/after backups with mode `0600`. Rollback
  is guarded by an exact read-back comparison so it cannot overwrite later
  panel changes.
- The `POST /panel/api/xray/` read handler is read-only for ordinary current
  templates, but this LucX-UI source version also auto-heals a legacy wrapped
  `xrayTemplateConfig` by calling `SaveXraySetting` during the read. The
  adapter never writes SQLite itself; on such a legacy database, the panel may
  perform that internal repair as part of its own API behavior.
- DNS updates through `POST /panel/api/xray/update` may cause a full Xray
  process restart when the core is running. `apply` requires explicit restart
  approval; `check` and `plan` do not submit an update. The tool never writes
  the panel SQLite DB or runtime Xray config directly.
- `tests/test_doh_integration.py` and `tests/test_lucx_ui_doh_api.py` cover
  transformations, conflict handling, preservation, API response decoding,
  and mock-panel request/response behavior without requiring a live panel.

A real panel database or full Xray config must not be committed as a fixture:
those files can contain private panel settings, identifiers, credentials, or
user-specific routing. Tests should use minimal synthetic data.

## Manual validation already performed

During development against a private VPS, the operator reported:

- read-only SQLite extraction of the template;
- dry-run against the panel DB: no proposed changes;
- dry-run against a separately-created JSON fixture: no proposed changes;
- transformation tests for missing/incorrect DNS elements, duplicate and
  conflict rejection, preservation of unrelated config, and no input mutation;
- idempotency checks: a second transform after correction proposed no changes;
- staging clone, dry-run and verify against a private staging copy: no proposed
  changes, mode `0600`;
- staging writer lifecycle against a separate throwaway SQLite copy: a test-only
  `rewritePort=9999` value was corrected to `5355`, read-back verification
  passed, rollback restored `9999`, and a subsequent dry-run proposed the
  correction again. The operator reported that the live panel DB was not touched.

These are operator-reported manual results on staging/test copies, not a live
production write. The automated suite independently exercises the same lifecycle
on synthetic SQLite files. No live panel API update or Xray restart is performed
by these tools.


## Source references inspected

The following links point to the LucX-UI source tag matching the reported panel
version. They document the version-specific behavior summarized above; the
installed VPS binary was not cryptographically matched to the tag.

- [LucX-UI v3.11.0-lucx.357 source tag](https://github.com/AlexeyLCP/lucx-ui/tree/v3.11.0-lucx.357)
- [Xray settings controller and API routes](https://github.com/AlexeyLCP/lucx-ui/blob/v3.11.0-lucx.357/internal/web/controller/xray_setting.go)
- [Xray settings persistence and validation](https://github.com/AlexeyLCP/lucx-ui/blob/v3.11.0-lucx.357/internal/web/service/xray_setting.go)
- [Xray hot-diff section support](https://github.com/AlexeyLCP/lucx-ui/blob/v3.11.0-lucx.357/internal/xray/hot_diff.go)
