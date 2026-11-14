# LucX-UI panel reconciliation: Integrate and Remove

**Current design for PR #6.** This document describes the permanent DNS workflow and the separate temporary staging diagnostics.

## Permanent directives

### Integrate

1. Check the DoH Health Monitor service, UDP/TCP listeners on `127.0.0.1:5355`, and its local status API.
2. Read the current LucX-UI Xray settings once and build the desired DNS integration plan.
3. Stop without panel writes if the plan contains blocking conflicts.
4. Apply only missing permanent DNS integration records. If no permanent changes are needed, leave the config unchanged.
5. Ensure one diagnostic Tunnel exists (create it only if absent), then test positive DNS A answers over UDP and TCP.
6. Leave the diagnostic Tunnel and temporary rule in place after success or failure. There is no automatic cleanup and no rollback to an old config.

If the diagnostic Tunnel already exists, Integrate tests it rather than creating a second one. If the UDP/TCP self-test fails, the permanent DNS configuration remains applied and the diagnostic resources remain available for inspection.

### Remove

1. Read the current Xray settings and build the same desired-state plan used by Integrate.
2. If that plan has blocking conflicts, stop without changing the panel.
3. Match only the live resources selected by that plan: the selected global port-53 route, selected local DNS outbound, and one general DNS server entry for `127.0.0.1:5355`.
4. Check references outside the plan. Preserve anything used by unrelated routing rules, balancers/selectors, observatory, proxy chaining, or DNS policy rules. Preserve scoped, duplicate, shared, and ambiguous entries.
5. Apply the safe removals in one panel update and verify the saved state through a fresh API read.

Remove never creates, tests, or deletes diagnostic Tunnel resources. It does not infer ownership from permanent-object markers, journals, snapshots, or historical state.

## Temporary staging diagnostics

These commands exist only to investigate LucX-UI/Xray behavior and are not intended as permanent product functionality. They will be removed from the project when staging debugging is complete.

- `tunnel create`: create one loopback-only diagnostic Tunnel and add the temporary DNS allow rule only when needed. Leave both in place.
- `tunnel test`: test an already-created Tunnel with positive UDP and TCP DNS A queries. It performs no panel writes and no cleanup.
- `tunnel status`: inspect diagnostic resources without changing them.
- `tunnel remove`: explicitly remove the diagnostic Tunnel and only the temporary rule that the diagnostic tooling can safely identify as its own. A reused rule must be preserved.

There is no automatic cleanup after a successful or failed test. Use `tunnel status` to inspect the current state and invoke `tunnel remove` only when explicit cleanup is intended.

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
- Integrate and Remove do not automatically clean up diagnostic Tunnel resources.
- Remove uses the same desired-state planner as Integrate and preserves external/shared references.
- Every panel write is verified by reading the current settings back through the LucX-UI API.
- The adapter does not write the panel SQLite database or runtime Xray config directly.
- A failed UDP/TCP self-test does not revert the permanent integration; inspect and clean up diagnostic resources explicitly.

## Validation

Both GitHub Actions workflows passed on code commit `865a9ca6b3d095c5a427efb09e089a5f7a3a8ece`: DoH integration tests (Python compilation and full unittest suite) and general Go CI (go vet, go test, and Linux amd64 build). Subsequent commits updated documentation only. The revised Integrate → UDP/TCP self-test → Remove sequence has not yet been exercised on the staging VPS.
