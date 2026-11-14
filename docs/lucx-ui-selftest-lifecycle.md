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
5. Remove operates only on permanent DNS-plan resources: the selected port-53 route, DNS outbound, and DNS server. It must not inspect or modify inbounds or `direct.settings.finalRules`; diagnostic cleanup is Integrate's responsibility.
6. Apply the safe removals in one panel update and verify the saved state through a fresh API read.

Remove never creates, tests, inspects, or deletes diagnostic Tunnel inbounds or diagnostic finalRules. It does not infer ownership from permanent-object markers, journals, snapshots, or historical state.

## Diagnostic lifecycle

The diagnostic Tunnel and temporary allow finalRule are internal resources used only by Integrate. Integrate ensures the Tunnel exists, runs positive UDP and TCP DNS A-answer probes, then attempts cleanup using live external-reference analysis. Each inbound/finalRule is removed only when it has no use outside the diagnostic plan; externally used or ambiguous resources are preserved. Cleanup is attempted after either successful or failed tests, and cleanup errors are reported separately.

## CLI

Run on the LucX-UI VPS as root:

```bash
sudo python3 scripts/lucx-ui-doh-api.py integrate
sudo python3 scripts/lucx-ui-doh-api.py remove
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
