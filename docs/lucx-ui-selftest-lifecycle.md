# LucX-UI panel reconciliation: integrate, remove, and self-test

**Authoritative design for PR #6.** This document supersedes earlier descriptions of snapshot-based rollback, journal-based ownership, and separate cleanup heuristics.

## Only two panel directives

The adapter works from the live panel configuration. It never saves a full before/after Xray configuration snapshot and never tries to restore an old configuration.

The operator selects exactly one directive:

- **Integrate:** calculate which compatible integration objects are already present, reuse them, and add only the missing objects. Run the temporary UDP/TCP self-test as part of the integration procedure.
- **Remove:** identify current objects that implement the integration, check their dependencies, and remove only those that can be safely detached. Remove does not create temporary test rules.

There is no third "partial operation", "resume", or "recovery" directive. No operation ID, journal, or saved execution state is used. Each invocation is simply Integrate or Remove, planned afresh from the configuration that exists at that moment.

The same semantic planner and object/reference analysis must be shared by both directives. Do not build separate tag-based heuristics for apply, uninstall, rollback, or cleanup.

### Plan, execute, verify

1. Read the current Xray configuration and inbounds through the LucX-UI API.
2. Build the complete plan for the selected directive from that live state.
3. Show planned changes and blockers. A read-only plan must not modify the panel.
4. Apply only changes belonging to the selected directive, one panel API mutation at a time.
5. Read the panel state back after each mutation and verify its result before making a dependent change.

A later invocation is not a continuation of an old operation: it is a new explicit Integrate or Remove request, and its plan is calculated from the then-current panel state. There is no restore-to-before behavior and no hidden automatic rollback. If a candidate is shared, ambiguous, or still referenced, the current plan leaves it untouched and reports why.

The plan is the complete definition of what the selected directive should do against the current configuration.

### Explicitly prohibited architecture

For panel Xray configuration changes, do not create or require:
- a full pre-change or post-change Xray configuration snapshot;
- a persistent copy of the old `finalRules`, routing rules, outbounds, or DNS arrays for restoration;
- a recovery journal that is required to decide whether the next run can proceed;
- a delayed snapshot-based `rollback` workflow.

Do not restore an old configuration or overwrite current user changes. The inverse operation is **Remove integration**: it plans against the current state and removes the integration objects that remain safe to remove. Existing historical backup files on the staging VPS are legacy artifacts only; the new algorithm must not read them as its source of truth, create more of them, or depend on them.

A small diagnostic record may be used only if it does not become an ownership database or a prerequisite for recalculating and executing the live-state plan.

## Integrating the permanent DNS path

- Inspect current inbounds, outbounds, DNS servers, routing rules, balancers, and references through the panel API.
- Reuse compatible existing objects regardless of their tag/name where semantic behavior matches.
- Add only missing objects in the planner's delta.
- Choose new tags only for objects genuinely missing; preserve existing tags and user rule order.
- Preserve unrelated objects, user routes, FakeDNS, AWG/subscription/sidecar-related config visible in the panel template.
- Never create, edit, or delete the panel-managed `xui-dns-allow` rule.
- A second integration plan after successful apply should report the target state already satisfied, with no duplicate objects and no further changes.

## Removing the permanent DNS path

Removal is the inverse desired-state operation, not a restore from a saved baseline.

### Read-only discovery plan

1. Read the current live panel config.
2. Build the canonical integration specification using the same planner as Integrate.
3. Find candidate integration objects by their semantic fingerprints and relationships, not only by fixed tags:
   - DNS outbound implementing the local DNS bridge to the plugin endpoint (for example, DNS rewrite to `127.0.0.1:5355`);
   - DNS server entry pointing to the plugin endpoint with compatible behavior;
   - port-53 TCP/UDP routing rule(s) directing DNS traffic to the candidate outbound;
   - dynamically selected tags and supporting objects recognized by the planner.
4. Treat generated tags/ruleTags (such as `dns-out` and `doh-health-monitor-dns-port53`) as supporting evidence, never as the only ownership test.
5. Build the reference/dependency graph from the current config. Check routing rules, balancers, DNS references, observatory selectors, proxy chains, and every other supported use of candidate tags/objects.
6. Produce a read-only removal plan listing each candidate, evidence for its integration role, references found, and whether it is safe to remove.

### Safe removal order

1. Remove only verified integration-specific port-53 route(s); read back and verify they are absent.
2. Recompute references against the new live config.
3. Remove a candidate DNS outbound only if it is now unreferenced and the semantic evidence still identifies it as integration plumbing; read back.
4. Recompute dependencies again.
5. Remove a matching local DNS server entry only if it is not shared by unrelated DNS policy; read back.
6. Re-read all relevant Xray settings and report what was removed, what remains shared/reused/ambiguous, and why.

Preserve shared, reused, and ambiguous objects. If a compatible object was present before installation but is now exclusively part of the integration path, it may be removed only when the current semantic/reference plan proves this is safe. If another user route, balancer, DNS policy, or proxy chain still relies on it, keep it. The Remove plan must list what is safe to delete and what remains blocked; speculative deletion is not.

Do not bulk-delete by tag/prefix. Do not restore an old rules array. Do not create temporary rules during Remove integration. The next Remove invocation simply replans from live state and continues.

## Temporary end-to-end self-test

The self-test is separate from permanent integration and uses at most two temporary objects:

1. a loopback-only Tunnel inbound with a unique remark;
2. the exact temporary direct Freedom `finalRule` allowing TCP/UDP to `127.0.0.1:5355`, but only when that rule is actually missing from the live config.

Exact rule shape:

~~~json
{
  "action": "allow",
  "network": "tcp,udp",
  "port": "5355",
  "ip": ["127.0.0.1"]
}
~~~

### Test plan and execution

- Read live inbounds and current `direct.settings.finalRules`.
- Generate the desired test objects and compute the delta. An existing compatible rule is reused, not added or later treated as a new addition by the current invocation.
- Verify the candidate Tunnel port is unused in panel inbounds and local TCP/UDP listeners.
- Validate the direct Freedom outbound and insertion point; the temporary allow must precede matching block rules.
- Create the temporary Tunnel first: listen only on `127.0.0.1`; rewrite DNS to `127.0.0.1:53`; `allowedNetwork=tcp,udp`; reserved temporary port; unique remark.
- Read back and verify the exact Tunnel identity/settings.
- Re-read live rules and recalculate the remaining delta. If relevant state changed, stop rather than overwrite it.
- Add only the missing temporary allow rule, if it is still part of this invocation's delta.
- Read back, run both UDP and TCP DNS probes, and validate plugin status/counters.

### Temporary test cleanup

- Re-read live config and dependencies.
- Remove only the temporary rule that the test operation actually added; do not delete a compatible rule that was already present/reused.
- Verify the rule is absent and unrelated live rules are preserved.
- Then delete the exact temporary Tunnel and verify it is absent and its TCP/UDP listeners are gone.
- This order ensures interruption after rule removal leaves a discoverable Tunnel, rather than an orphan rule with no associated test inbound.
- Never touch the plugin's own `127.0.0.1:5355` listeners.

A reserved Tunnel remark identifies a temporary test inbound only; it is not an ownership database for permanent DNS objects. If the live panel state contains an ambiguous test object that the current Integrate plan cannot safely classify, report the blocker and do not guess or delete a pre-existing object.

## Known legacy staging VPS state

The previous staging command `sudo python3 scripts/lucx-ui-doh-api.py --approve-restart apply` stopped before permanent changes because the old implementation rejected a format-1 recovery journal.

Known old journal:
- Path: `/root/.local/state/lucx-ui-doh/backups/recovery/lucx-doh-selftest-817de6b08c61fb60.json`
- format 1; state `manual-inspection-ready`; `inbound_id=1`
- remark `doh-health-monitor-selftest-817de6b08c61fb60`
- port 15353; expected Tunnel listen 127.0.0.1; rewrite 127.0.0.1:53; allowedNetwork tcp,udp
- no `original_final_rules` field.

Operator-provided listener output:
- no listener on port 15353;
- TCP and UDP listeners on `127.0.0.1:5355` belong to the DoH Health Monitor plugin and are expected. Never remove them.

Two old persistent backup files were observed:
- `lucx-doh-20261112T110629Z-3fa53d.json`: before/after displayed baseline finalRules `[{"action":"block","ip":["geoip:private"]},{"action":"allow"}]`.
- `lucx-doh-20261113T052003Z-69d995.json`: before included the temporary rule plus that baseline; after displayed the baseline without it.

These files are historical artifacts from the old implementation only. Do not use their content to decide current ownership, synthesize new journals, or restore any configuration. The next staging operation must inspect current inbounds and current `direct.settings.finalRules` through the panel API and calculate the selected action's plan from that live state. Legacy files must not block the new planner.

## Regression tests and acceptance criteria

1. Compatible permanent DNS objects are reused; only missing objects are added; repeated Integrate is idempotent.
2. Removal discovery finds generated-tag and renamed-but-semantically-equivalent integration objects.
3. Removal does not delete a DNS outbound referenced by unrelated routing, balancer, proxy-chain, or observatory objects.
4. A shared DNS server entry is preserved.
5. A unique integration route is removed first; the outbound is removed only after read-back and fresh zero-reference scan.
6. Panel-owned `xui-dns-allow`, user routes, FakeDNS, and unrelated outbounds/DNS servers remain unchanged.
7. Ambiguous/duplicate candidates are listed as blockers; no speculative deletion occurs.
8. Each new Integrate or Remove invocation computes its entire plan from the current live config; it does not load or continue a prior execution.
9. No full Xray snapshots, historical rule arrays, mandatory journals, or snapshot-based rollback files are created or needed.
10. Temporary test reuses pre-existing compatible rule and never deletes it as though it were newly added.
11. Test creates Tunnel before any missing temporary allow rule; cleanup removes and verifies the rule before deleting Tunnel.
12. Every API mutation is read back before a dependent mutation; an invocation reports success only for the requested plan it completed, otherwise it reports the blocking error without restoring old state.
13. Plugin listeners on 5355 are never mistaken for temporary Tunnel listeners.
14. Both UDP and TCP probes pass before self-test success.
15. Every panel API mutation is followed by read-back verification.

All Python compilation/unit tests/shell syntax checks and both GitHub Actions workflows must pass on the new head. A disposable staging panel must complete Integrate -> UDP/TCP self-test -> Remove with read-back after every mutation. Keep PR #6 open and Draft until code and staging validation pass. Panel API writes may restart Xray; retain explicit `--approve-restart`.

## Next implementation work

The current adapter still contains legacy backup/journal/rollback behavior. Remove that architecture rather than adapting it into a new journal format or adding a resume/recovery mode. Refactor `scripts/lucx-ui-doh-api.py`, `scripts/xray_dns_planner.py` if required, `tests/test_lucx_ui_doh_api.py`, and the API documentation around the single live-state reconciliation model above. Then run both GitHub workflows. Only after CI passes should the staging VPS run the new read-only plan/inspection and selected operation.
