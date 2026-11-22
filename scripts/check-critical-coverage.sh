#!/usr/bin/env bash
set -euo pipefail

coverage_file="${1:-coverage.out}"
threshold="${COVERAGE_THRESHOLD:-60}"

if [[ ! -f "$coverage_file" ]]; then
  echo "coverage profile not found: $coverage_file" >&2
  exit 2
fi

report="$(go tool cover -func="$coverage_file")"
required=(
  "handleDNS"
  "serveUDP"
  "serveUDPWithHandler"
  "reloadLoop"
  "activeDoHLoop"
  "runActiveDoHSelection"
  "runActiveDoHSelectionWithProbe"
  "activeDoHCandidates"
  "activeDoHChecks"
  "activeDoHRetryDelay"
  "runActiveDoHLoop"
  "waitForActiveDoH"
)

failed=0
for function in "${required[@]}"; do
  actual="$(awk -v fn="$function" '($2 == fn || $2 ~ ("\\." fn "$")) { gsub(/%/, "", $3); print $3; exit }' <<<"$report")"
  if [[ -z "$actual" ]]; then
    echo "COVERAGE ERROR: function not found in coverage profile: $function" >&2
    failed=1
    continue
  fi
  if awk -v actual="$actual" -v threshold="$threshold" 'BEGIN { exit !(actual > threshold) }'; then
    printf 'COVERAGE OK: %-48s %s%% (required > %s%%)\n' "$function" "$actual" "$threshold"
  else
    printf 'COVERAGE LOW: %-48s %s%% (required > %s%%)\n' "$function" "$actual" "$threshold" >&2
    failed=1
  fi
done

exit "$failed"
