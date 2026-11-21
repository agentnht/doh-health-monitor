#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/plugin-management.sh"
fail_test() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
pass() { printf '[PASS] %s\n' "$*"; }

export USER=root SUDO_USER=alice
unset SSH_TUNNEL_USER || true
[[ "$(resolve_ssh_tunnel_user)" == "alice" ]] || fail_test "SUDO_USER fallback"
pass "SUDO_USER is selected after sudo"
export SSH_TUNNEL_USER=operator
[[ "$(resolve_ssh_tunnel_user)" == "operator" ]] || fail_test "explicit SSH_TUNNEL_USER"
pass "SSH_TUNNEL_USER override"
export SSH_TUNNEL_USER='bad user'
if resolve_ssh_tunnel_user >/dev/null 2>&1; then fail_test "invalid account accepted"; fi
pass "invalid account rejected"
expected='ssh -o ExitOnForwardFailure=yes -L 19876:127.0.0.1:41237 operator@203.0.113.8'
[[ "$(build_ssh_tunnel_command 19876 41237 operator 203.0.113.8)" == "$expected" ]] || fail_test "tunnel command format"
pass "tunnel command uses the selected account"
[[ "$(parse_web_ui_ready_port 'WEB_UI_READY port=41237')" == "41237" ]] || fail_test "valid readiness line"
for invalid in "" "WEB_UI_READY port=0" "WEB_UI_READY port=65536" "WEB_UI_READY port=abc" "noise WEB_UI_READY port=19876"; do
  if parse_web_ui_ready_port "$invalid" >/dev/null 2>&1; then fail_test "invalid readiness accepted: $invalid"; fi
done
pass "readiness protocol and port range validated"
export SERVER_ADDRESS=203.0.113.8
[[ "$(resolve_server_address)" == "203.0.113.8" ]] || fail_test "server address override"
pass "explicit server address override"
printf 'All plugin management shell tests passed.\n'
