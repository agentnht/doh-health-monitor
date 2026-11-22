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
ready_line='WEB_UI_READY port=41237 token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
[[ "$(parse_web_ui_ready_port "$ready_line")" == "41237" ]] || fail_test "valid readiness line"
[[ "$(parse_web_ui_ready_token "$ready_line")" == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ]] || fail_test "valid bootstrap token"
for invalid in "" "WEB_UI_READY port=41237" "WEB_UI_READY port=0 token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" "WEB_UI_READY port=65536 token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" "WEB_UI_READY port=abc token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" "noise WEB_UI_READY port=19876 token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; do
  if parse_web_ui_ready_port "$invalid" >/dev/null 2>&1; then fail_test "invalid readiness accepted: $invalid"; fi
done
pass "readiness protocol, one-time token and port range validated"
menu_output="$(show_menu)"
grep -Fq '3) Переключить DNS mode / настроить resolver upstreams' <<<"$menu_output" || fail_test "DNS mode menu entry"
grep -Fq '3) run_dns_config' "$SCRIPT_DIR/plugin-management.sh" || fail_test "DNS mode menu dispatch"
pass "DNS mode menu entry is connected to the CLI action"

# Simulate systemd unit states so the menu selects the active process manager.
MOCK_PANEL_LOAD="loaded"
MOCK_STANDALONE_LOAD="loaded"
MOCK_PANEL_ACTIVE="inactive"
MOCK_STANDALONE_ACTIVE="active"
systemctl() {
  local command="${1:-}" service
  service="${@: -1}"
  case "$command" in
    show)
      case "$service" in
        "$PANEL_SERVICE_NAME") printf '%s\\n' "$MOCK_PANEL_LOAD" ;;
        "$SYSTEMD_SERVICE_NAME") printf '%s\\n' "$MOCK_STANDALONE_LOAD" ;;
        *) return 1 ;;
      esac
      ;;
    is-active)
      case "$service" in
        "$PANEL_SERVICE_NAME") [[ "$MOCK_PANEL_ACTIVE" == "active" ]] ;;
        "$SYSTEMD_SERVICE_NAME") [[ "$MOCK_STANDALONE_ACTIVE" == "active" ]] ;;
        *) return 1 ;;
      esac
      ;;
    *) return 1 ;;
  esac
}

[[ "$(detect_plugin_service)" == "$SYSTEMD_SERVICE_NAME" ]] || fail_test "standalone active service detection"
pass "read-only check detects active standalone systemd service"

MOCK_PANEL_ACTIVE="active"
MOCK_STANDALONE_ACTIVE="inactive"
[[ "$(detect_plugin_service)" == "$PANEL_SERVICE_NAME" ]] || fail_test "panel active service detection"
pass "read-only check preserves panel-managed service detection"

MOCK_PANEL_ACTIVE="active"
MOCK_STANDALONE_ACTIVE="active"
if detect_plugin_service >/dev/null 2>&1; then fail_test "both active managers accepted"; fi
pass "read-only check rejects two simultaneously active managers"

MOCK_PANEL_LOAD="not-found"
MOCK_STANDALONE_LOAD="loaded"
MOCK_PANEL_ACTIVE="inactive"
MOCK_STANDALONE_ACTIVE="inactive"
[[ "$(detect_plugin_service)" == "$SYSTEMD_SERVICE_NAME" ]] || fail_test "standalone inactive unit detection"
pass "read-only check identifies an installed but inactive standalone unit"

MOCK_PANEL_LOAD="loaded"
MOCK_STANDALONE_LOAD="loaded"
if detect_plugin_service >/dev/null 2>&1; then fail_test "two inactive installed managers accepted"; fi
pass "read-only check rejects ambiguous inactive manager configuration"

MOCK_PANEL_LOAD="not-found"
MOCK_STANDALONE_LOAD="not-found"
[[ "$(detect_plugin_service)" == "$PANEL_SERVICE_NAME" ]] || fail_test "legacy panel diagnostic fallback"
pass "read-only check retains the panel diagnostic when no standalone unit is installed"

unit="$(render_systemd_service /opt/doh-health-monitor/bin/doh-health-monitor /opt/doh-health-monitor /opt/doh-health-monitor/data 2.3.5)"
grep -Fq 'Type=simple' <<<"$unit" || fail_test "systemd service type"
grep -Fqx 'WorkingDirectory=/opt/doh-health-monitor' <<<"$unit" || fail_test "systemd working directory must be absolute and unquoted"
grep -Fq 'Restart=on-failure' <<<"$unit" || fail_test "systemd failure restart policy"
grep -Fq 'RestartSec=5s' <<<"$unit" || fail_test "systemd restart delay"
grep -Fq 'LUCX_PLUGIN_DATA=/opt/doh-health-monitor/data' <<<"$unit" || fail_test "systemd data directory"
grep -Fq 'ExecStart="/opt/doh-health-monitor/bin/doh-health-monitor"' <<<"$unit" || fail_test "systemd executable"
pass "systemd service is foreground, restart-on-failure and gets the standalone data path"

healthcheck="$(render_systemd_healthcheck /opt/doh-health-monitor/bin/doh-health-monitor /opt/doh-health-monitor/data)"
grep -Fq 'healthcheck' <<<"$healthcheck" || fail_test "periodic health command"
grep -Fq 'systemctl restart "$SERVICE"' <<<"$healthcheck" || fail_test "healthcheck restarts failed service"
grep -Fq 'systemctl reset-failed "$SERVICE"' <<<"$healthcheck" || fail_test "healthcheck recovers a failed unit"
grep -Fq 'systemd' <<<"$menu_output" || fail_test "systemd submenu"
pass "periodic health helper checks /healthz and recovers failed units"

grep -Fq '4) Настроить systemd-автозапуск' <<<"$menu_output" || fail_test "systemd menu entry"
grep -Fq '4) manage_systemd_autostart' "$SCRIPT_DIR/plugin-management.sh" || fail_test "systemd menu dispatch"
pass "systemd autostart is reachable from plugin-management menu"

export SERVER_ADDRESS=203.0.113.8
[[ "$(resolve_server_address)" == "203.0.113.8" ]] || fail_test "server address override"
pass "explicit server address override"
printf 'All plugin management shell tests passed.\n'
