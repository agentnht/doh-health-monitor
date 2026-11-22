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
        "$PANEL_SERVICE_NAME") printf '%s\n' "$MOCK_PANEL_LOAD" ;;
        "$SYSTEMD_SERVICE_NAME") printf '%s\n' "$MOCK_STANDALONE_LOAD" ;;
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

unit="$(render_panel_api_autostart /usr/local/x-ui/bin/plugins/doh-health-monitor/scripts/plugin-management.sh /usr/local/x-ui/bin/plugins/doh-health-monitor/data x-ui.service)"
grep -Fq 'Type=oneshot' <<<"$unit" || fail_test "panel API autostart must be a one-shot unit"
grep -Fq 'After=network-online.target x-ui.service' <<<"$unit" || fail_test "panel API autostart ordering"
grep -Fq 'Wants=network-online.target x-ui.service' <<<"$unit" || fail_test "panel API autostart dependency"
grep -Fq 'LUCX_PLUGIN_DATA=/usr/local/x-ui/bin/plugins/doh-health-monitor/data' <<<"$unit" || fail_test "panel API data directory"
grep -Fq 'ExecStart=/bin/bash "/usr/local/x-ui/bin/plugins/doh-health-monitor/scripts/plugin-management.sh" --panel-api-start-on-boot' <<<"$unit" || fail_test "panel API startup command"
grep -Fq 'Restart=on-failure' <<<"$unit" || fail_test "panel API startup retry policy"
pass "boot unit invokes the root helper after x-ui.service and does not own the daemon"

[[ "$(extract_panel_setting port $'port: 2053\nwebBasePath: /admin/')" == "2053" ]] || fail_test "panel port parser"
[[ "$(extract_panel_setting webBasePath $'port: 2053\nwebBasePath: /admin/')" == "/admin/" ]] || fail_test "panel base path parser"
[[ "$(panel_api_token_from_output $'noise\napiToken: AbCdEf0123456789_-AbCdEf0123456789_-AbCdEf0123456789_-')" == "AbCdEf0123456789_-AbCdEf0123456789_-AbCdEf0123456789_-" ]] || fail_test "CLI API token parser"
panel_api_json_success '{"success":true,"obj":{}}' || fail_test "successful API response parser"
if panel_api_json_success '{"success":false,"msg":"denied"}'; then fail_test "API error response accepted"; fi
[[ "$(panel_api_json_running '{"success":true,"obj":{"running":true}}')" == "running" ]] || fail_test "running status parser"
[[ "$(panel_api_json_running '{"success":true,"obj":{"running":false}}')" == "stopped" ]] || fail_test "stopped status parser"
[[ "$(panel_api_token_id_from_response '{"success":true,"obj":[{"id":7,"name":"doh-health-monitor-plugin-management","scope":"admin"}]}')" == "7" ]] || fail_test "one-shot token ID parser"
panel_api_host_valid "panel.example.com" || fail_test "valid panel webDomain rejected"
panel_api_host_valid "192.0.2.10" || fail_test "valid IPv4 Host rejected"
if panel_api_host_valid "-panel.example.com" || panel_api_host_valid "panel..example.com" || panel_api_host_valid "panel.example.com/path"; then
  fail_test "invalid panel webDomain accepted"
fi
PANEL_API_HOST_HEADER="panel.example.com"
PANEL_API_PORT="2053"
PANEL_API_BASE_URL="http://127.0.0.1:2053/panel/api"
PANEL_API_CURL_CONFIG="/run/test-curl-config"
PANEL_API_INSECURE=0
curl() { printf '%s\n' "$@"; }
panel_api_request GET "/plugins/doh-health-monitor/status" || fail_test "mocked panel API request"
grep -Fq 'Host: panel.example.com:2053' <<<"$PANEL_API_RESPONSE" || fail_test "panel webDomain Host header missing"
grep -Fq 'http://127.0.0.1:2053/panel/api/plugins/doh-health-monitor/status' <<<"$PANEL_API_RESPONSE" || fail_test "API request must connect to loopback, not webDomain"
unset -f curl
pass "panel API Host override is sent while the TCP URL stays on loopback"
pass "panel API response, status, token and webDomain parsers handle valid and rejected input"

grep -Fq '4) Управление через LucX-UI API и автозапуск' <<<"$menu_output" || fail_test "panel API menu entry"
grep -Fq '4) manage_panel_api_autostart' "$SCRIPT_DIR/plugin-management.sh" || fail_test "panel API menu dispatch"
grep -Fq '7) Настроить webDomain (Host) для API панели' "$SCRIPT_DIR/plugin-management.sh" || fail_test "panel webDomain submenu entry"
grep -Fq '7) configure_panel_api_host' "$SCRIPT_DIR/plugin-management.sh" || fail_test "panel webDomain submenu dispatch"
pass "panel API lifecycle, autostart and webDomain configuration are reachable from plugin-management menu"

export SERVER_ADDRESS=203.0.113.8
[[ "$(resolve_server_address)" == "203.0.113.8" ]] || fail_test "server address override"
pass "explicit server address override"
printf 'All plugin management shell tests passed.\n'
