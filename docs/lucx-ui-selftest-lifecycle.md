# LucX-UI panel reconciliation: Integrate and Remove

**Current design for PR #6.** This document describes the permanent DNS workflow and the separate temporary staging diagnostics.

## Permanent directives

### Integrate

1. Check the DoH Health Monitor service, UDP/TCP listeners on `127.0.0.1:5355`, and its local status API.
2. Read the current LucX-UI Xray settings once and build the desired DNS integration plan.
3. Stop without panel writes if the plan contains blocking conflicts.
4. Apply only missing permanent DNS integration records. If no permanent changes are needed, leave the config unchanged.
5. Ensure one diagnostic Tunnel exists (create it only if absent), then test positive DNS A answers over UDP and TCP.
6. After the UDP/TCP self-test attempt, reconcile every diagnostic-plan resource against the current live configuration. For each matching inbound and finalRule, inspect references outside the diagnostic plan. Remove it only when no external use exists; preserve it when external use exists or dependency analysis is ambiguous. This decision is independent of whether the object existed before the run or was marked added/reused.

If the diagnostic Tunnel already exists, Integrate tests it rather than creating a second one. Cleanup is attempted after both successful and failed tests. The permanent DNS integration remains applied if testing fails. If cleanup also fails, report that separately from the self-test result.

### Remove

1. Read the current Xray settings and build the same desired-state plan used by Integrate.
2. If that plan has blocking conflicts, stop without changing the panel.
3. Match only the live resources selected by that plan: the selected global port-53 route, selected local DNS outbound, and one general DNS server entry for `127.0.0.1:5355`.
4. Check references outside the plan. Preserve anything used by unrelated routing rules, balancers/selectors, observatory, proxy chaining, or DNS policy rules. Preserve scoped, duplicate, shared, and ambiguous entries.
5. Treat the exact `direct.settings.finalRules` allow for TCP/UDP `127.0.0.1:5355` as an integration resource: remove it when no other DNS resource outside the Remove plan uses that endpoint. Keep the `direct` freedom outbound, `geoip:private` block, fallback allow, and all unrelated finalRules unchanged.
6. Apply the safe removals in one panel update and verify the saved state through a fresh API read.

Remove never creates, tests, or deletes diagnostic Tunnel resources. It does not infer ownership from permanent-object markers, journals, snapshots, or historical state.

## Temporary staging diagnostics

These commands exist only to investigate LucX-UI/Xray behavior and are not intended as permanent product functionality. They will be removed from the project when staging debugging is complete.

- `tunnel create`: create one loopback-only diagnostic Tunnel and add the temporary DNS allow rule only when needed. Leave both in place.
- `tunnel test`: test an already-created Tunnel with positive UDP and TCP DNS A queries. It performs no panel writes and no cleanup.
- `tunnel status`: inspect diagnostic resources without changing them.
- `tunnel remove`: explicitly reconcile diagnostic resources using the same live external-reference check as Integrate. Remove each inbound/finalRule only if it has no use outside the diagnostic plan; preserve externally used or ambiguous resources.

The staging-only commands do not automatically clean up after `tunnel test`; use `tunnel status` to inspect the state and invoke `tunnel remove` when explicit cleanup is intended. Integrate, by contrast, always attempts cleanup after its self-test attempt.

## CLI

Run on the LucX-UI VPS as root:

```bash
sudo python3 scripts/lucx-ui-doh-api.py integrate
sudo python3 scripts/lucx-ui-doh-api.py remove

# Temporary staging diagnostics only:
sudo python3 scripts/lucx-ui-doh-api.py tunnel create
sudo python3 scripts/lucx-ui-doh-api.py tunnel test
sudo python3 scripts/lucx-ui-doh-api.py tunnel status
sudo python3 scripts/lucx-ui-doh-api.py tunnel remove
```

There is no `--plan-only` option. A panel update may automatically restart Xray; the adapter prints a NOTICE and does not ask for interactive confirmation. The legacy `--approve-restart` flag is not required.

## Safety boundaries

- No full Xray configuration snapshots, backup files, ownership journals, or snapshot-based rollback.
- Integrate attempts diagnostic cleanup after either self-test outcome. Each inbound and finalRule is removed only when the live configuration shows no external use outside the diagnostic plan; creation markers and pre-existence do not decide ownership. Remove never touches diagnostic Tunnel resources.
- Remove uses the same desired-state planner as Integrate and preserves external/shared references.
- Every panel write is verified by reading the current settings back through the LucX-UI API.
- The adapter does not write the panel SQLite database or runtime Xray config directly.
- A failed UDP/TCP self-test does not revert the permanent integration. Cleanup is still attempted; externally used or ambiguous diagnostic resources are reported and retained.

## Validation

On code/test commit `2c4ec9d134100454ff737f80da58999648275387`, the DoH integration tests workflow passed (Python compilation and full unittest suite, including direct-finalRule removal and external-use cases). General Go CI is still in progress. The revised Remove and live-reference cleanup have not yet been exercised on the staging VPS.
