# LucX-UI / DoH Health Monitor integration notes

This document records the integration shape inspected and validated for the
DoH Health Monitor 2.0.1 release line. It is implementation guidance, not an
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

Before reading Xray settings, the production adapter performs a mandatory
DoH Health Monitor preflight: it verifies that the
configured systemd unit is installed and active, checks TCP and UDP loopback
listeners on port 5355, and requires the local `/status` endpoint to return a
JSON object. Defaults match the plugin deployment; alternate service, status
URL and listener port can be supplied explicitly. A missing/stopped plugin or
failed listener/status check stops the adapter before any panel API request.

The production adapter never asks the operator to paste a Bearer token. It
first reads `XUI_API_TOKEN` from the installer's protected
`/etc/x-ui/install-result.env` (mode `0600`), then checks its own saved
credential via `--panel-auth-file`. If neither exists, it discovers the running
panel executable and uses the LucX-UI CLI to create a dedicated
`doh-health-monitor-integration` token with `admin` scope. The plaintext is
stored in `/var/lib/doh-health-monitor-panel-auth/panel-api-auth.json` with
mode `0600`; tokens with other names are not rotated. This first-time fallback
changes only the panel's API-token store, not the Xray template. If the local
CLI cannot safely create a separate token, the adapter stops without asking for
a secret. Deployments may also supply `XUI_API_TOKEN` through the process
environment. The adapter never writes the panel SQLite DB directly or runtime
Xray config. If `--base-url` is omitted, it reads only
`webPort`, `webBasePath`, `webCertFile`, `webKeyFile`, and `webDomain`
from local SQLite using `mode=ro`, taking the runtime `XUI_PORT` override
into account. The actual base path is not printed. TLS is detected from panel settings and
the configured leaf certificate SANs: without a certificate the adapter uses
HTTP only over loopback; for an IP SAN certificate it sends SNI `localhost`,
retains mandatory certificate-chain validation, and separately requires an
exact matching IP SAN; for a DNS SAN certificate it uses the DNS name for
standard hostname verification and SNI. An explicit HTTPS `--base-url`
requires `--tls-mode ip --tls-name IP` or
`--tls-mode domain --tls-name DOMAIN`; local HTTP can be selected with
`--tls-mode http`. No mode disables TLS chain verification. Pass
`--panel-db` for a non-default SQLite location, or `--base-url` explicitly
for PostgreSQL and other nonstandard deployments. The local Xray core version is detected for diagnostics only. An unlisted or
unavailable version is reported as a notice and does not block execution. The
LucX-UI version is also informational. Compatibility is assessed through the
actual panel API response, configuration structure, conflict checks, and
read-back verification rather than a hard-coded core-version allowlist.
Compatibility is detected by API behavior and response shape, not by a
hard-coded LucX-UI version allowlist: the adapter must successfully read the
Xray settings endpoint, decode `xraySetting`, preserve `outboundTestUrl`, and
validate the configuration structure understood by its planner. Unknown or
missing fields are a hard stop. The write/update endpoint cannot be safely
probed without changing panel state; therefore read-only `check`/`plan` reports
that write capability is unverified, and the update contract must first be
validated on a separate staging panel. An unrecognized API response or
configuration structure remains a hard stop, because the adapter cannot
safely predict the panel's save behavior.

## Tooling in this PR

- \`scripts/check-dns-integration.sh\`: read-only checks for the plugin service,
  TCP/UDP listener, status API, DNS server, and the active port-53 route together
  with the outbound selected by that route. It does not assume the outbound is
  named \`dns-out\`.
- \`scripts/xray_dns_planner.py\`: pure shared semantic inventory/planner. It
  examines the Xray template's inbounds, outbounds, DNS servers, routing rules,
  balancers, and the relevant tag references. It reuses an existing local DNS
  outbound regardless of its tag only when its effective target is
  \`127.0.0.1:5355/udp\` and its DNS rules/transport do not divert queries. A
  global balancer is reusable only when all selector matches and its
  \`fallbackTag\` lead to compatible DNS outbounds.
- New objects are additive. The planner selects a free outbound tag and a free
  routing \`ruleTag\`, considers existing inbound/outbound/balancer/API/rule tags,
  and avoids outbound names captured by existing balancer selector prefixes.
  The chosen outbound tag is used consistently by the generated routing rule.
  If \`dns-out\` is already occupied by a different function, it is preserved and
  a different free tag is selected. Existing objects and routing rules are not
  rewritten to force a match.
- Routing analysis considers first-match order and all explicit port-53
  overlaps. Narrower rules are preserved ahead of a fallback route. A broad
  rule/range that would shadow a new route is reused only if it already sends
  the traffic to a fully compatible local DNS target; otherwise planning stops
  with a conflict rather than proposing an unreachable rule. Missing or
  ambiguous outbound/balancer references are blockers. An ambiguous choice
  between several compatible DNS outbounds is also a blocker, not a guess.
- \`scripts/lucx-ui-doh-api.py\`: panel API adapter. Its \`build_plan\` delegates
  to the shared planner, then models LucX-UI's own \`xui-dns-allow\`
  normalization, API-route invariant, and known save-time side effects.
  \`check\` and \`plan\` are read-only. \`apply\` uses the same plan and validates
  the saved result through API read-back.
- \`scripts/doh-integration-dry-run.py\` loads the same planner used by the API
  adapter; it no longer has a separate set of transformation rules.
  \`scripts/doh-integration-staging.py\` clones a source SQLite DB into a
  separate staging file and supports dry-run, verify, apply, rollback, and
  cleanup against that staging file only. It never writes the source/live DB.
- Before planning permanent changes, \`apply\` queries the panel API for leftover
  inbounds with the reserved \`doh-health-monitor-selftest-\` remark prefix and
  verifies the complete Tunnel identity/settings. It also checks for the exact
  reserved \`allow/tcp,udp/5355/127.0.0.1\` entry in
  \`direct.settings.finalRules\`. Only verified resources are deleted. A
  malformed or ambiguous reserved object is preserved and blocks apply.
  Recovery-journal files are treated as opaque private markers at this stage:
  their contents are not read to decide what to delete. After both resource
  classes are independently verified absent, stale marker files with the
  reserved filename, owner, and mode are removed.
- The end-to-end self-test creates a loopback-only temporary \`tunnel\` inbound
  through the official inbound API, tests positive A answers over UDP and TCP,
  and verifies that the plugin query counter increases while failures remain
  zero. In its \`finally\` path, Tunnel deletion/listener verification and
  temporary \`finalRule\` deletion are attempted independently; failure of one
  cleanup does not skip the other. A recovery marker is retained if either
  resource cannot be verified absent. Permanent DNS changes are not rolled back
  automatically when the connectivity test fails.
- The adapter retains a private pre-update API snapshot (mode \`0600\`) for
  delayed rollback after successful read-back. Rollback removes only DNS
  outbound/server/port-53 route objects that this operation actually created,
  using their recorded before/after identity rather than assuming a fixed tag.
  Reused objects are never treated as owned. If an added outbound was edited or
  has acquired later routing/balancer references, rollback stops rather than
  leaving broken links. Unrelated settings and current \`outboundTestUrl\`
  metadata are preserved.
- Panel Xray-settings and inbound API updates may each restart Xray; \`apply\`
  requires explicit restart approval. The adapter requires root on the
  LucX-UI VPS and a localhost/loopback panel API URL. It never writes SQLite or
  runtime Xray configuration directly.
- The Xray template returned by LucX-UI may not contain all runtime-injected
  AWG, subscription, or sidecar objects. The planner does not claim to inspect
  those hidden runtime additions; it reports/uses what is present in the panel
  template and refuses unsafe or ambiguous template-level dependencies.
- The API adapter refuses to save when the panel would also move/create its
  internal API route, rewrite an existing numeric DNS \`qType: 0\`, or remove or
  reorder an existing routing rule during DNS allow-rule normalization. It
  preserves \`outboundTestUrl\`, resolves local API authorization automatically,
  and avoids exposing credentials. The panel's read handler may itself repair
  a legacy wrapped \`xrayTemplateConfig\`; the adapter never performs that DB
  write directly.

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


### Selective rollback

The delayed `rollback` action does not restore the entire pre-apply Xray snapshot. It identifies only the three integration objects that were absent before apply and present in the verified after-snapshot: outbound `dns-out`, DNS server `127.0.0.1:5355`, and the global TCP/UDP port-53 routing rule targeting `dns-out`. It removes an object only if its current representation still exactly matches the saved post-apply object. If an owned object was edited after apply, rollback stops rather than deleting the edited object. Objects already absent are treated as already removed. All unrelated current Xray settings, later panel changes, and the current `outboundTestUrl` metadata are preserved. The resulting configuration is written and verified through the LucX-UI API, including the panel's DNS-rule normalization.
