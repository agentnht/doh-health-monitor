# Audit reproduction snippets

The audit reproductions are stored as `.go.txt` so Go's recursive package discovery
(`go test ./...`, `go vet ./...`) does not treat two different package declarations
inside `scripts/` as one Go package.

Run them from the repository root by copying each snippet to its target Go package:

```bash
set -e
trap 'rm -f audit_repro_test.go internal/activedoh/activedoh_failover_audit_test.go' EXIT
cp scripts/audit_repro_test.go.txt ./audit_repro_test.go
cp scripts/activedoh_failover_audit_test.go.txt internal/activedoh/activedoh_failover_audit_test.go
go test -run '^TestAudit_' -v .
go test -run '^TestAuditFailoverLatency$' -v ./internal/activedoh
```

These are regression reproductions for the audit findings, not production test files.
Permanent regression tests are maintained in the respective package test files.
