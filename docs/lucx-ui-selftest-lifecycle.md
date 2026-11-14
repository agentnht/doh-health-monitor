# LucX-UI panel reconciliation: Integrate and Remove

**Authoritative design and handoff for PR #6.** This document describes the implementation in `scripts/lucx-ui-doh-api.py`. It supersedes the earlier backup, journal, snapshot-rollback, and separate test/cleanup workflows.

## One model, two directives

The panel adapter has exactly two directives:

- **Integrate** — build the desired DNS integration plan from the current panel configuration, reuse compatible existing objects, add only missing permanent objects, then run the temporary UDP/TCP end-to-end test.
- **Remove** — build the same semantic integration specification against current panel state, identify matching integration objects, inspect references, and remove only objects that are no longer shared or used elsewhere. Remove never creates temporary test resources.

Each invocation is one explicit directive. Its plan is calculated from the live configuration returned by LucX-UI immediately before the work. There is no operation ID, persistent execution state, recovery command, historical configuration restore, or partial-operation mode. The CLI accepts only `integrate` and `remove`; `--plan-only` previews either directive without panel writes.

No full Xray snapshots, saved pre-change rule arrays, backup files, ownership journals, or rollback files are created or read by the adapter. If an API write cannot be verified, no old config is restored; the next Integrate or Remove invocation calculates a new plan from the current panel state.

## Shared semantic planning

Both directives use `build_plan` and the shared `scripts/xray_dns_planner.py` semantic matchers. The plan recognizes DNS behavior by protocol, endpoint, transport, policy, route shape, and relationships, not by a fixed tag name.

The Integrate plan:

1. Read the current `xraySetting` and panel metadata through the LucX-UI API.
2. Recognize compatible local DNS outbounds, general DNS server entries, and port-53 routing paths regardless of nonstandard outbound tags.
3. Reuse compatible objects without editing them.
4. Add only missing permanent DNS objects and preserve panel-owned `xui-dns-allow`, user routes, FakeDNS, unrelated outbounds, and DNS policies.
5. Read the saved settings back through the panel API and verify the planned result.

The same semantic identity is used by Remove; it does not rely on a historical ownership list or assume that the generated tag `dns-out` was used.

## Integrate: temporary UDP/TCP self-test

The test uses only a loopback Tunnel that rewrites DNS to `127.0.0.1:53`, allows TCP and UDP, and binds an available local port in the reserved test range. It verifies positive A answers over both transports and checks that the plugin query counter increases without increasing the failure counter.

The order is deliberate:

1. Read current `direct.settings.finalRules`. If the exact test allow rule exists once, classify it as **reused**. If it is absent, classify it as **added by this test**. Duplicates are an ambiguity and block the test.
2. Create the unique Tunnel first, with the classification included in its reserved remark: `doh-health-monitor-selftest-added-<token>` or `...-reused-<token>`.
3. Read back and verify the exact Tunnel identity and DNS rewrite settings.
4. If the rule was absent, re-read the current config, add only that exact rule, and verify it through API read-back. If the rule was pre-existing, do not write or later delete it.
5. Run UDP and TCP probes and validate plugin counters.
6. Cleanup in strict order: remove and verify the rule only when this test added it; then delete the exact Tunnel and verify its absence and both TCP/UDP listeners are gone.

The Tunnel remark is a small live identity marker for this one temporary test relationship. It does not identify permanent integration objects and is not a separate journal. A legacy remark from the earlier adapter (`doh-health-monitor-selftest-<hex-token>`) is recognized as an old test Tunnel; the earlier implementation created its exact finalRule before the Tunnel and refused a rule that was already present, so that legacy Tunnel identifies the matching rule as test-added. A matching finalRule without any reserved Tunnel is treated as pre-existing/reused and is not deleted.

If rule cleanup cannot be verified, the Tunnel is not deleted; its reserved remark remains available for the next Integrate or Remove invocation to re-plan from live API state. No filesystem marker, backup, or recovery mode is used.

## Remove: semantic discovery and dependency checks

Remove does not create a Tunnel or a temporary finalRule. It first reconciles only verified leftover self-test Tunnels, then builds the permanent removal plan from the current panel settings.

The planner identifies:

- Global TCP/UDP port-53 route rules that route to a compatible local DoH outbound, including a DNS-only balancer path when every selected target is compatible.
- Outbounds whose actual protocol/settings resolve to the plugin endpoint `127.0.0.1:5355`, regardless of their tag.
- General (not domain-scoped or otherwise restricted) DNS server entries for `127.0.0.1:5355`.

Removal is dependency ordered and re-planned after every verified API write:

1. Remove only identified integration port-53 routes and verify the live read-back.
2. Re-read the current panel config. Remove a matching DNS outbound only when it has no remaining routing-rule, balancer selector/fallback, observatory selector, proxySettings, or dialerProxy references.
3. Re-read again. Remove the matching DNS server only when it is general and not referenced by any DNS policy rule.
4. Read the final config and report remaining shared, scoped, duplicate, or ambiguous objects.

A shared or ambiguous object is preserved. Panel-owned `xui-dns-allow`, user routes, FakeDNS, unrelated outbounds, DNS entries, and the plugin's own TCP/UDP listeners on port 5355 are never cleanup targets. Remove may clear a previously-created test Tunnel, but it never creates temporary test rules.

## CLI

Run on the LucX-UI VPS as root. Preview either directive without writing:

```bash
sudo python3 scripts/lucx-ui-doh-api.py --plan-only integrate
sudo python3 scripts/lucx-ui-doh-api.py --plan-only remove
```

Execute only the selected directive after reviewing its plan:

```bash
sudo python3 scripts/lucx-ui-doh-api.py --approve-restart integrate
sudo python3 scripts/lucx-ui-doh-api.py --approve-restart remove
```

The panel API may restart Xray, so a mutating directive requires `--approve-restart` or interactive confirmation. Integrate checks plugin service, listeners, and status before changing the panel. Remove does not require a healthy/running plugin.

## Known legacy staging VPS context

This information is retained so a later session does not have to reconstruct the prior incident. It is not an input to the new algorithm.

The previous command `sudo python3 scripts/lucx-ui-doh-api.py --approve-restart apply` stopped before permanent DNS changes because the old adapter required a valid format-2 recovery journal but found an old format-1 file.

Operator-provided old recovery file:
- `/root/.local/state/lucx-ui-doh/backups/recovery/lucx-doh-selftest-817de6b08c61fb60.json`
- format 1; state `manual-inspection-ready`; `inbound_id=1`
- remark `doh-health-monitor-selftest-817de6b08c61fb60`
- Tunnel port 15353; listen `127.0.0.1`; rewrite `127.0.0.1:53`; allowedNetwork `tcp,udp`
- no `original_final_rules` field.

Operator-provided listener output:
- No listener on port 15353 at the time of inspection. This did not establish whether the inbound still existed in the panel.
- TCP and UDP listeners on `127.0.0.1:5355` belonged to the DoH Health Monitor plugin and are expected. Never remove them.

Two old backup files were also observed:
- `lucx-doh-20261112T110629Z-3fa53d.json`: its displayed before/after `direct.finalRules` were the original private-block rule and generic allow.
- `lucx-doh-20261113T052003Z-69d995.json`: its displayed before rules included the temporary test allow; its displayed after rules did not.

The new adapter does not read these old files or use them to decide ownership. It discovers any remaining reserved Tunnel and its associated temporary test rule through the live panel APIs. If the old Tunnel exists and validates, its legacy remark permits cleanup of the rule that the old adapter had added. If no reserved Tunnel exists, an identical finalRule is treated as pre-existing and preserved; do not remove it based only on the old journal or backup files. The plugin listeners on 5355 are never touched.

## Regression coverage and acceptance

The Python tests cover:
- Idempotent Integrate and reuse of compatible permanent objects.
- Nonstandard local DNS outbound tags and route relationship discovery.
- Remove ordering: route first, fresh read/reference scan, outbound, then DNS server.
- Preservation of outbound references from other routes, balancers, observatory, proxy chaining, and DNS policy rules.
- Preservation of scoped, duplicate, shared, or ambiguous candidates.
- Test rule reuse vs test-added ownership, Tunnel-first creation, rule-first cleanup, and legacy Tunnel-marker reconciliation.
- Explicit confirmation phrases for Integrate and Remove.
- Existing TLS identity, endpoint discovery, credentials, DNS protocol, and panel API safety checks.

The GitHub Actions workflows must pass on the current PR head. A disposable staging panel must still complete the end-to-end cycle `Integrate → UDP/TCP self-test → Remove` before the PR is treated as production-ready. Keep PR #6 open and Draft until that staging cycle is confirmed.