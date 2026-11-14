# LucX-UI self-test lifecycle: desired-state diff and staging handoff

**Status:** agreed design; implementation is pending. This document is the authoritative handoff for the next session. It supersedes any PR comment or earlier wording that suggests a recovery journal is needed to prove who originally wrote a rule.

## Core idea: calculate what the script would add

We do not need to persist an ownership journal or a complete before-snapshot to answer “which records are ours?”. We calculate that from the live panel configuration and the same desired-state planner used for provisioning.

For every run:

1. Read the current LucX-UI/Xray config through the panel API.
2. Build the desired integration/test specification.
3. Run the planner against the current config. Its output is the exact **delta**: the records that are missing and that this run would add.
4. Anything already present and semantically compatible is **reused/pre-existing from the perspective of this run**. Do not add it again and do not claim it for cleanup.
5. Apply only the delta. Keep the exact records actually added by this invocation in memory.
6. After the test, remove only the temporary records from that invocation's delta, after checking that they are no longer referenced and are safe to remove.

This is the ownership model: **current config + desired-state plan = existing/reused records versus missing records this run will add**. We do not try to reconstruct a historical author for every matching rule. A full config snapshot, mandatory recovery journal, or persistent provenance database is not required.

The planner must be deterministic and shared with permanent provisioning; do not maintain a second set of hand-written “looks like ours” heuristics.

## Permanent integration

- Inspect the panel's current outbounds, DNS servers, routing rules and references.
- Reuse compatible existing entries regardless of tag/name where semantic behavior matches.
- Add only missing entries returned by the planner's delta.
- Preserve all unrelated entries and user order.
- Never create, edit or delete the panel-managed `xui-dns-allow` rule.
- Re-running apply must be idempotent: after a successful run, the next plan should report those permanent entries as already satisfied/reused, not as fresh additions.

## Temporary self-test: two records

The test needs only two temporary objects:

1. one temporary loopback Tunnel inbound, with a unique remark and exact expected settings;
2. one exact temporary direct Freedom `finalRule` allowing TCP/UDP to `127.0.0.1:5355`.

Expected temporary rule:

~~~json
{
  "action": "allow",
  "network": "tcp,udp",
  "port": "5355",
  "ip": ["127.0.0.1"]
}
~~~

### Before creating anything

- Read current inbounds and Xray settings.
- Generate the exact desired temporary test objects and calculate the delta against live state.
- If an equivalent/compatible temporary object is already present, classify it as present/reused; do not claim it as newly added by this invocation.
- If a reserved Tunnel from an interrupted prior test is present, validate its exact identity/settings and inspect the paired rule through the same desired-state comparison before recovery.
- Verify a candidate test port is free in panel inbounds and local TCP/UDP listeners.
- Validate the direct Freedom outbound and insertion point; the temporary allow must precede matching block rules.
- Check external references/dependencies before removing any object.
- Do not mutate config during preflight.

### Create and test

- Create the temporary Tunnel first (listen only on `127.0.0.1`; rewrite DNS to `127.0.0.1:53`; `allowedNetwork=tcp,udp`; reserved temporary port; unique remark).
- Read back and verify exact identity/settings.
- Re-read current rules and recalculate/validate the remaining delta. If a relevant object appeared or changed since planning, stop rather than overwrite it.
- Add the missing exact temporary `finalRule` only if it is still absent and is part of this run's computed delta; insert it before matching block rules.
- Read back the API state.
- Run both UDP and TCP DNS probes through the temporary Tunnel and validate plugin status/counter.

### Cleanup after a successful test

- Use the in-memory delta from this invocation to identify exactly which temporary records this invocation added.
- Before deletion, read current live config and confirm the exact records are still present as expected, are present only once, and have no external references/dependencies.
- Remove only the exact temporary `finalRule` added by this run; never restore an old full `finalRules` array.
- Read back and verify the rule is absent and all unrelated current rules are preserved.
- Then remove only the exact temporary Tunnel inbound added by this run; verify its identity/ID/settings and that no references remain.
- Read back and verify the inbound is absent and its TCP/UDP listeners are gone.
- If cleanup cannot prove the candidate is the exact temporary object from this test operation, stop safely and explain the blocker. Never touch the plugin's own `127.0.0.1:5355` listener.

## Next-run recovery: re-plan, do not replay a journal

At the beginning of the next run, read the live panel state and regenerate the desired-state plan. Do not require a saved pre-run `finalRules` snapshot.

- A compatible permanent DNS object already present is reused; it is not a new addition and must not be removed.
- A reserved temporary Tunnel with the expected identity indicates an interrupted self-test candidate. Inspect the exact paired temporary rule using the same deterministic test-object specification. If both form the known temporary test pair, check dependencies and clean up the temporary rule first, then the Tunnel.
- A verified reserved Tunnel with no temporary rule can be removed as an interrupted test whose rule was never inserted (or was already cleaned).
- An isolated matching allow rule with no verified temporary Tunnel is not enough to prove the script created it. The planner should classify it as already present/reused; do not delete it merely because its JSON looks familiar.
- Duplicate or altered temporary objects, changed dependencies, ambiguous direct outbound, or concurrent changes are a safe-stop condition.
- A full recovery journal is not a prerequisite. A small diagnostic marker may exist, but the live-state plan—not the journal—is authoritative.

The unique Tunnel remark is an identity field for finding/verifying the temporary inbound, not a substitute for the desired-state diff and not a historical ownership database for ordinary permanent rules.

## Cleanup ordering

When both temporary objects exist, remove the rule first, verify it is absent, then remove the Tunnel. That way a crash after rule removal leaves a recognizable temporary Tunnel, not an unidentifiable orphan rule. Never delete the Tunnel while the temporary rule remains.

## Known legacy staging VPS state — preserve this context

The previous staging command `sudo python3 scripts/lucx-ui-doh-api.py --approve-restart apply` stopped before permanent changes because old cleanup rejected a format-1 recovery journal.

Journal:
- Path: `/root/.local/state/lucx-ui-doh/backups/recovery/lucx-doh-selftest-817de6b08c61fb60.json`
- format 1; state `manual-inspection-ready`; `inbound_id=1`
- remark `doh-health-monitor-selftest-817de6b08c61fb60`
- port 15353; expected Tunnel listen 127.0.0.1; rewrite 127.0.0.1:53; allowedNetwork tcp,udp
- `original_final_rules` is absent; current code rejects this old format.

Operator-provided listener output:
- no listener on port 15353;
- TCP and UDP listeners on `127.0.0.1:5355` belong to the DoH Health Monitor plugin and are expected. Never remove them.

Persistent backups:
- `lucx-doh-20261112T110629Z-3fa53d.json`: before/after both show baseline finalRules `[{"action":"block","ip":["geoip:private"]},{"action":"allow"}]`.
- `lucx-doh-20261113T052003Z-69d995.json`: before includes the exact temporary rule followed by that baseline; after has the baseline without the temporary rule.

The backups are historical evidence, not a substitute for a fresh live API read. The next staging operation must inspect current inbounds and current `direct.settings.finalRules` through the panel API, then classify the live state using the desired-state/test-object plan above. Do not synthesize a format-2 journal, alter/delete the old journal, or remove a rule based only on `ss` output or backup history. Preserve both persistent backups and the old journal until cleanup is read-back verified. The 5355 plugin listeners are expected.

## Required regression tests

1. Compatible permanent DNS objects are reused; only missing objects are added; repeated apply is idempotent.
2. The planner's delta exactly matches records actually sent to the panel API.
3. A compatible pre-existing object is not claimed as a new addition and is not removed during cleanup.
4. Tunnel is created before the temporary finalRule.
5. A failure after Tunnel creation but before rule insertion leaves a discoverable Tunnel; next run replans and removes only the verified temporary Tunnel.
6. A failure after rule insertion leaves the known temporary pair; next run replans, checks dependencies, removes rule first, then Tunnel.
7. A failure after rule removal but before Tunnel deletion leaves only the Tunnel; next run removes only the verified Tunnel.
8. An isolated matching finalRule without a verified Tunnel is treated as present/reused and is not auto-deleted.
9. External references, duplicate exact rules, changed unrelated finalRules, ambiguous direct outbound, duplicate markers, altered Tunnel identity, or concurrent changes cause a safe stop.
10. Unrelated finalRules added/changed after creation are preserved; never restore a stale full-list snapshot.
11. The plugin TCP/UDP listeners on 5355 are never mistaken for temporary Tunnel listeners.
12. Both UDP and TCP probes must pass before the self-test reports success.
13. Every API mutation is followed by read-back verification.
14. Legacy format-1 journal without a snapshot does not block re-planning from live state; do not require conversion to format 2.

## Acceptance criteria and next steps

- Ownership is determined from the live desired-state delta, not a mandatory recovery journal.
- Existing compatible entries are reused and never removed as though the current invocation created them.
- Only exact temporary entries added by the current test run (or a verified interrupted temporary pair recovered by re-planning) are eligible for cleanup.
- Temporary rule is removed and verified before Tunnel deletion.
- All Python compilation/unit tests/shell syntax checks and both GitHub Actions workflows pass on the new head.
- A disposable staging panel completes apply -> UDP/TCP self-test -> cleanup, with API read-back after each mutation.
- Keep PR #6 open and Draft until code and disposable staging validation pass.
- Do not rerun staging apply while the old live state is unresolved. First implement the desired-state delta lifecycle in `scripts/lucx-ui-doh-api.py` and `tests/test_lucx_ui_doh_api.py`; then CI; then read-only live staging inspection and explicit legacy recovery. Panel API writes may restart Xray, so retain the explicit `--approve-restart` guard.


## Removing the permanent integration: inverse semantic planner

Uninstall is the inverse of provisioning, but it is **not** temporary self-test cleanup and does not create temporary rules.

Do not depend on a saved pre-install snapshot, a journal, or a list of historical object IDs. Re-read the current panel configuration and use the same canonical integration specification/planner to discover the objects that currently implement this integration.

### Discovery plan (read-only)

1. Build the canonical desired integration plan exactly as the provisioning command does.
2. In the current config, find candidate objects by their semantic shape and relationships, not only by fixed names:
   - DNS outbound whose protocol/settings implement the plugin's local DNS bridge (for example, DNS rewrite to 127.0.0.1:5355);
   - DNS server entry pointing to the plugin endpoint 127.0.0.1:5355 with matching behavior;
   - port-53 TCP/UDP routing rule(s) that direct DNS traffic to the candidate DNS outbound (including dynamically selected tags and panel-normalized variants);
   - any integration-specific supporting objects that the same planner recognizes.
3. Use recognizable tags/ruleTags such as dns-out and doh-health-monitor-dns-port53 as supporting evidence, not as the only test. A renamed or differently tagged but semantically equivalent object may still be a candidate.
4. Build a complete reference/dependency graph from the current configuration. Check every use of the candidate outbound/rule targets, including routing rules, balancers, DNS-related references, observatory selectors, proxy chains and any other supported reference locations. Check whether the DNS server entry is shared or part of unrelated DNS policy.
5. Produce a read-only removal plan that lists each candidate, the evidence that it belongs to the integration, every discovered reference, and the reason it is safe or unsafe to remove. No panel changes during planning.

### Removal decision

- Remove an integration-specific port-53 route only when its match/action/target relationship identifies it as part of the DoH integration and it has no other semantic role. Do not remove panel-owned xui-dns-allow or unrelated user rules.
- Remove the DNS outbound only after the integration route has been removed and read-back verified, and only if the current reference scan proves no other object uses it.
- Remove the local DNS server entry only when it matches the integration endpoint/configuration and is not shared by other DNS policy. If other rules/objects rely on it, retain it.
- Preserve any shared, reused, or ambiguous object. It is acceptable for uninstall to report a partial removal and explain what remains; it is not acceptable to delete an object merely because its endpoint looks familiar.
- If two candidates are semantically indistinguishable, or evidence is insufficient to distinguish integration plumbing from a pre-existing user object, stop before deleting the ambiguous object and report it in the plan.
- A candidate can be identified as likely integration plumbing by the combination of its config fingerprint, its connection to the integration's port-53 rule, known generated tags, and absence of unrelated references. No one clue should be treated as conclusive in isolation.

### Mutation order and verification

1. Show the removal plan and blockers first. Require the explicit restart approval used by other panel mutations.
2. Remove only the verified integration-specific routing rule(s); read back and verify those exact rules are absent while unrelated rule order/content is preserved.
3. Recompute references from the updated live config. Remove a candidate DNS outbound only if now unreferenced; read back.
4. Recompute dependencies again. Remove the plugin DNS server entry only if it is still a verified integration candidate and no longer shared/used; read back.
5. Re-read the complete relevant Xray settings and report exactly what was removed, what was preserved as shared/ambiguous, and any blockers.

Never restore a historical full snapshot during uninstall. Never bulk-delete by tag prefix. The current live config plus semantic candidate discovery and reference analysis are authoritative.

### Uninstall regression tests

- Finds generated-tag and renamed-but-semantically-equivalent integration candidates.
- Does not delete a matching local DNS outbound that is used by an unrelated routing rule, balancer, proxy chain, or observatory selector.
- Does not delete a shared DNS server entry.
- Removes a unique integration port-53 route, then removes its outbound only after read-back and a fresh zero-reference scan.
- Leaves panel-owned xui-dns-allow, unrelated user routes, DNS servers, FakeDNS, and unrelated outbounds unchanged.
- Ambiguous or duplicate candidates are listed as blockers; no speculative delete occurs.
- Re-running uninstall is idempotent: already absent objects are reported as absent, not errors.
- Every mutation is followed by panel API read-back; partial cleanup is reported accurately.
