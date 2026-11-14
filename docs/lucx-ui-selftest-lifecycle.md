# LucX-UI self-test lifecycle: decision and staging handoff

Status: agreed design; implementation is pending. This document preserves the exact decisions and known VPS state for the next implementation session.

## Design decision

Keep the temporary self-test to two resources:
1. a temporary loopback Tunnel inbound with a unique remark;
2. the exact temporary direct Freedom finalRule allowing TCP/UDP to 127.0.0.1:5355.

Do not require a full recovery journal or a saved copy of the entire finalRules array for the normal path. The live LucX-UI API is authoritative. Permanent DNS integration is separate: inspect current config, reuse compatible objects, add only missing objects, and never manage the panel-owned xui-dns-allow rule.

## Required lifecycle

### Read-only preflight
- Read current inbounds and Xray settings through the panel API.
- Recover any existing reserved Tunnel marker before starting a new test.
- Verify candidate port is unused by panel inbounds and TCP/UDP listeners.
- Verify the exact temporary rule is absent. If already present, do not claim or delete it.
- Validate the direct Freedom outbound and insertion point before matching block rules.
- Check for external references/dependencies; do not mutate during preflight.

### Create and test
1. Create the uniquely marked Tunnel FIRST. Remark prefix: doh-health-monitor-selftest- plus random suffix. Listen only on 127.0.0.1; rewrite DNS to 127.0.0.1:53; allowedNetwork tcp,udp; temporary port.
2. Read back and verify exact Tunnel identity/settings.
3. Re-read live finalRules. If the exact temporary rule appeared or relevant rules changed, stop without claiming/overwriting.
4. Add exactly this rule once, before matching block rules, preserving all other rules:
~~~json
{"action":"allow","network":"tcp,udp","port":"5355","ip":["127.0.0.1"]}
~~~
5. Read back, then run UDP and TCP DNS probes through the Tunnel and validate the plugin status/counter.

### Cleanup order — MUST be rule first, Tunnel second
1. Read current panel config. Verify the exact temporary rule is present exactly once and ownership is established; check external dependencies.
2. Remove only that exact rule. Never restore a stale full-list snapshot.
3. Read back: exact temporary rule absent; unrelated current rules preserved.
4. Verify Tunnel exact ID/remark/protocol/listen/port/settings and no external references, then delete it.
5. Read back: Tunnel absent and its TCP/UDP listeners gone.

This order is intentional: if cleanup is interrupted after rule removal, the uniquely marked Tunnel remains as a recovery anchor. Never delete the Tunnel first, or a crash could leave an unidentifiable orphan rule. If ownership/dependency checks fail, stop and preserve the resource for manual inspection. Never touch the plugin's own 127.0.0.1:5355 listener.

## Recovery rules without mandatory journal
- Marker + exact rule: verify both and dependencies; remove rule, verify, then Tunnel.
- Marker without rule: verify and remove only Tunnel.
- Ambiguous/duplicate marker, altered Tunnel identity, or external references: stop.
- No marker + exact rule: do NOT infer ownership from rule shape alone. Stop unless an independent trusted ownership record proves this run created it.
- No marker + no exact rule: no temporary resources remain.

Creation order (Tunnel then rule) and cleanup order (rule then Tunnel) make normal crash windows discoverable from live panel state. A small diagnostic marker is optional but must never be required for normal cleanup.

## Known legacy VPS state — do not lose this context

The previous staging command `sudo python3 scripts/lucx-ui-doh-api.py --approve-restart apply` stopped before permanent changes because old cleanup rejected a format-1 journal.

Journal:
- Path: /root/.local/state/lucx-ui-doh/backups/recovery/lucx-doh-selftest-817de6b08c61fb60.json
- format 1; state manual-inspection-ready; inbound_id 1
- remark doh-health-monitor-selftest-817de6b08c61fb60
- port 15353; expected Tunnel listen 127.0.0.1; rewrite 127.0.0.1:53; allowedNetwork tcp,udp
- original_final_rules is absent; current code rejects this old format.

Operator-provided listener output:
- no listener on 15353;
- TCP and UDP listeners on 127.0.0.1:5355 belong to the DoH Health Monitor plugin and are expected. Never remove them.

Persistent backups:
- lucx-doh-20261112T110629Z-3fa53d.json: before/after both show baseline finalRules [{"action":"block","ip":["geoip:private"]},{"action":"allow"}].
- lucx-doh-20261113T052003Z-69d995.json: before includes the exact temporary rule followed by that baseline; after has the baseline without the temporary rule.

These backups are evidence, NOT a substitute for a fresh live API read. Before cleanup, inspect current inbounds and current direct.settings.finalRules. Confirm whether inbound ID 1 / the unique remark exists and whether the exact rule is present. Do not synthesize a v2 journal, edit/delete the old journal, or delete a rule based only on ss/backups. Preserve both backups and old journal until live-state cleanup is verified. Add a narrowly scoped legacy recovery path only when ownership is independently established; otherwise stop with precise manual instructions.

## Required tests

1. Compatible permanent objects reused; only missing objects added; apply idempotent.
2. Pre-existing exact temp rule blocks test and is never removed.
3. Assert creation order: Tunnel before finalRule.
4. Failure after Tunnel create/before rule leaves Tunnel only; recovery removes only Tunnel.
5. Failure after rule insertion leaves both; recovery removes rule first, then Tunnel.
6. Failure after rule removal/before Tunnel deletion leaves Tunnel only; recovery removes Tunnel.
7. Assert Tunnel is never deleted before rule absence is read-back verified.
8. External dependencies, duplicate exact rules, changed unrelated rules, ambiguous direct outbound, duplicate markers, or altered Tunnel identity cause safe stop.
9. Preserve unrelated rules added/changed after test creation; no stale snapshot restore.
10. Plugin listeners on 5355 are never mistaken for temporary Tunnel listeners.
11. Format-1 legacy journal without snapshot: recover only if live ownership is independently established; otherwise preserve it and report manual inspection.
12. Rule without marker/trusted ownership is never auto-deleted.
13. Both UDP/TCP probes must pass before success.
14. Read-back verification after every API mutation.

## Acceptance / handoff

- No mandatory journal on normal success path; no normal cleanup dependency on a full finalRules snapshot.
- Only exact owned temp rule and exact uniquely marked Tunnel are removable.
- Temporary rule removed and verified before Tunnel deletion.
- All unit tests, Python compilation, shell syntax, and both GitHub Actions workflows pass on the new head.
- Disposable staging completes apply -> UDP/TCP self-test -> cleanup, with read-back after each mutation.
- Keep PR #6 open and Draft until code and disposable staging validation pass. Do not claim unit tests equal staging validation.
- Do not rerun staging apply while the legacy format-1 state is unresolved. First implement this lifecycle in scripts/lucx-ui-doh-api.py and tests/test_lucx_ui_doh_api.py; then CI; then read-only live-state inspection and explicit legacy recovery. Panel API writes may restart Xray, so retain --approve-restart.
