#!/usr/bin/env bash
# Read-only structural check for the approved Xray Geosite DNS routing design.
set -uo pipefail

DOH_SERVICE="${DOH_SERVICE:-lucx-plugin-doh-health-monitor}"
DOH_STATUS_URL="${DOH_STATUS_URL:-http://127.0.0.1:18765/status}"
XRAY_CONFIG="${XRAY_CONFIG:-/usr/local/x-ui/bin/config.json}"
PLUGIN_PORT="${DOH_PLUGIN_PORT:-5355}"

if [[ ! "$PLUGIN_PORT" =~ ^[0-9]{1,5}$ ]] || (( 10#$PLUGIN_PORT < 1 || 10#$PLUGIN_PORT > 65535 )); then
  printf '[FAIL] Некорректный DOH_PLUGIN_PORT: ожидается порт 1..65535.\n' >&2
  exit 2
fi
PLUGIN_PORT=$((10#$PLUGIN_PORT))

ok=0
warn=0
fail=0
pass() { printf '[OK]   %s\n' "$*"; ok=$((ok + 1)); }
warning() { printf '[WARN] %s\n' "$*"; warn=$((warn + 1)); }
error() { printf '[FAIL] %s\n' "$*"; fail=$((fail + 1)); }

if ! command -v jq >/dev/null 2>&1; then
  error "jq не установлен; проверка JSON невозможна"
  printf '\nИтог: %d OK, %d WARN, %d FAIL\n' "$ok" "$warn" "$fail"
  exit 2
fi

if [[ "${DOH_SKIP_PLUGIN_HEALTH_CHECK:-0}" != "1" ]]; then
  if systemctl is-active --quiet "$DOH_SERVICE"; then
    pass "Сервис $DOH_SERVICE запущен"
  else
    error "Сервис $DOH_SERVICE не активен"
  fi

  if command -v ss >/dev/null 2>&1; then
    for proto in tcp udp; do
      flag="-t"
      [[ "$proto" == "udp" ]] && flag="-u"
      if ss -H -l "$flag" 2>/dev/null | grep -Eq "127\\.0\\.0\\.1:${PLUGIN_PORT}([[:space:]]|$)"; then
        pass "Порт ${PLUGIN_PORT}/${proto} слушается на loopback"
      else
        error "Порт ${PLUGIN_PORT}/${proto} не слушается на 127.0.0.1"
      fi
    done
  else
    warning "Команда ss отсутствует; проверка сокетов пропущена"
  fi

  status_file="$(mktemp)"
  if curl --fail --silent --show-error --max-time 3 "$DOH_STATUS_URL" -o "$status_file" 2>/dev/null &&
     jq -e . "$status_file" >/dev/null 2>&1; then
    version="$(jq -r '.version // "unknown"' "$status_file")"
    pass "Status API отвечает корректным JSON (version: $version)"
  else
    error "Status API недоступен или вернул некорректный JSON: $DOH_STATUS_URL"
  fi
  rm -f "$status_file"
fi

if [[ ! -r "$XRAY_CONFIG" ]]; then
  error "Не найден доступный для чтения Xray config: $XRAY_CONFIG"
else
  pass "Xray config доступен: $XRAY_CONFIG"

  # Discover the outbound referenced by the global TCP/UDP port-53 route.
  dns_tag="$(jq -r '
    first(
      .routing.rules[]? |
      select(
        .type == "field" and
        .enabled != false and
        ((.port | tostring) == "53") and
        ((.network // "tcp,udp") | tostring | contains("tcp")) and
        ((.network // "tcp,udp") | tostring | contains("udp")) and
        ((.outboundTag // "") != "")
      ) |
      .outboundTag
    ) // empty
  ' "$XRAY_CONFIG" 2>/dev/null)"

  if [[ -z "$dns_tag" ]]; then
    error "Не найдено глобальное routing-правило TCP/UDP port 53 с outboundTag"
  elif jq -e --arg tag "$dns_tag" --arg port "$PLUGIN_PORT" '
    any(.outbounds[]?;
      .tag == $tag and
      .protocol == "dns" and
      .settings.rewriteAddress == "127.0.0.1" and
      ((.settings.rewritePort | tostring) == $port) and
      .settings.rewriteNetwork == "udp"
    )
  ' "$XRAY_CONFIG" >/dev/null; then
    pass "Port-53 route использует DNS outbound $dns_tag с rewrite UDP 127.0.0.1:$PLUGIN_PORT"
  else
    error "Outbound $dns_tag не соответствует rewrite UDP 127.0.0.1:$PLUGIN_PORT"
  fi

  if [[ -n "$dns_tag" ]]; then
    if jq -e --arg tag "$dns_tag" '
      [.outbounds[]? | select(.tag == $tag and .protocol == "dns")] as $outbounds |
      ($outbounds | length) == 1 and
      ($outbounds[0].settings.rules | type) == "array" and
      ($outbounds[0].settings.rules) as $rules |
      ([$rules | to_entries[] |
        select(
          .value.action == "direct" and
          any(.value.domain[]?; type == "string" and startswith("geosite:"))
        ) | .key]) as $geosite_direct |
      ([$rules | to_entries[] |
        select(
          .value.action == "hijack" and
          ((.value | keys - ["action", "rCode"]) | length) == 0
        ) | .key]) as $catchall_hijack |
      ($geosite_direct | length) > 0 and
      ($catchall_hijack | length) == 1 and
      ($geosite_direct | min) < $catchall_hijack[0] and
      $catchall_hijack[0] == (($rules | length) - 1)
    ' "$XRAY_CONFIG" >/dev/null; then
      pass "DNS outbound содержит Geosite direct перед последним catch-all hijack"
    else
      error "DNS outbound должен содержать Geosite direct и последний безусловный catch-all hijack"
    fi

    if jq -e --arg tag "$dns_tag" '
      .routing.rules as $rules |
      [$rules | to_entries[] |
        select(
          .value.type == "field" and
          .value.enabled != false and
          .value.outboundTag == $tag and
          ((.value.port | tostring) == "53") and
          ((.value.network // "tcp,udp") | tostring | contains("tcp")) and
          ((.value.network // "tcp,udp") | tostring | contains("udp"))
        ) | .key] as $dns_routes |
      [$rules | to_entries[] |
        select(
          ((.value.ip // []) | index("geoip:private")) != null
        ) | .key] as $private_blocks |
      ($dns_routes | length) > 0 and
      (($private_blocks | length) == 0 or
       ($dns_routes | min) < ($private_blocks | min))
    ' "$XRAY_CONFIG" >/dev/null; then
      pass "TCP/UDP port-53 route расположен до geoip:private block (если он есть)"
    else
      error "Port-53 route отсутствует или расположен после geoip:private block"
    fi
  fi

  if jq -e '(.dns.servers | type) == "array" and (.dns.servers | length) > 0' "$XRAY_CONFIG" >/dev/null; then
    pass "Для встроенного DNS Xray задан хотя бы один upstream dns.servers"
  else
    error "Для catch-all hijack не задан upstream в dns.servers"
  fi
fi

printf '\nИтог: %d OK, %d WARN, %d FAIL\n' "$ok" "$warn" "$fail"
(( fail == 0 )) || exit 1
exit 0
