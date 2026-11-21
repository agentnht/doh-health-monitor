#!/usr/bin/env bash
# Read-only structural check for the approved Xray Geosite DNS design.
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

# Report the plugin's effective DNS mode and active endpoint from its read-only status API.
status_file="$(mktemp)"
if curl --fail --silent --show-error --max-time 3 "$DOH_STATUS_URL" -o "$status_file" 2>/dev/null &&
   jq -e . "$status_file" >/dev/null 2>&1; then
  dns_mode="$(jq -r '.dns_mode // "unknown"' "$status_file")"
  case "$dns_mode" in
    endpoint_ip)
      pass "Текущий DNS mode: endpoint_ip (режим 1)"
      active_id="$(jq -r '.active_doh.server_id // empty' "$status_file")"
      if [[ -n "$active_id" ]]; then
        active_host="$(jq -r '.active_doh.hostname // "unknown"' "$status_file")"
        active_ipv4="$(jq -r '(.active_doh.ipv4 // []) | join(", ")' "$status_file")"
        active_ipv6="$(jq -r '(.active_doh.ipv6 // []) | join(", ")' "$status_file")"
        active_score="$(jq -r 'if .active_doh.score != null and .active_doh.check_count != null then "\(.active_doh.score)/\(.active_doh.check_count)" else "unknown" end' "$status_file")"
        pass "Активный DoH server: $active_id ($active_host), score=$active_score"
        printf '[INFO]   Active endpoint IPv4: %s\n' "${active_ipv4:-нет}"
        printf '[INFO]   Active endpoint IPv6: %s\n' "${active_ipv6:-нет}"
      else
        warning "DNS mode 1 активен, но актуальный DoH endpoint пока не выбран"
      fi
      ;;
    resolver)
      pass "Текущий DNS mode: resolver (режим 2)"
      ;;
    *)
      warning "Текущий DNS mode не распознан: $dns_mode"
      ;;
  esac
else
  warning "Не удалось получить DNS mode и active DoH server из Status API"
fi
rm -f "$status_file"

if [[ ! -r "$XRAY_CONFIG" ]]; then
  error "Не найден доступный для чтения Xray config: $XRAY_CONFIG"
else
  pass "Xray config доступен: $XRAY_CONFIG"

  route_count="$(jq -r '
    [
      .routing.rules[]? |
      select(
        .type == "field" and
        .enabled != false and
        .port == "53" and
        .network == "tcp,udp" and
        ((.outboundTag | type) == "string") and
        (.outboundTag | length) > 0
      )
    ] | length
  ' "$XRAY_CONFIG" 2>/dev/null || printf '0')"

  if [[ "$route_count" != "1" ]]; then
    error "Ожидается ровно одно глобальное routing-правило type=field, network=tcp,udp, port=53; найдено: $route_count"
    dns_tag=""
  else
    dns_tag="$(jq -r '
      first(
        .routing.rules[]? |
        select(
          .type == "field" and
          .enabled != false and
          .port == "53" and
          .network == "tcp,udp" and
          ((.outboundTag | type) == "string") and
          (.outboundTag | length) > 0
        ) |
        .outboundTag
      ) // empty
    ' "$XRAY_CONFIG" 2>/dev/null)"
    if jq -e --arg tag "$dns_tag" '
      [.routing.rules[]? |
        select(
          .type == "field" and
          .enabled != false and
          .port == "53" and
          .network == "tcp,udp" and
          .outboundTag == $tag
        )] as $routes |
      ($routes | length) == 1 and
      (($routes[0] | keys) - ["type", "enabled", "port", "network", "outboundTag", "ruleTag", "remarks", "comment"] | length) == 0
    ' "$XRAY_CONFIG" >/dev/null; then
      pass "Найдено одно глобальное правило TCP/UDP port 53 → $dns_tag"
    else
      error "Port-53 routing rule содержит дополнительные selectors или некорректные параметры"
    fi
  fi

  if [[ -n "$dns_tag" ]]; then
    if jq -e --arg tag "$dns_tag" --arg port "$PLUGIN_PORT" '
      [.outbounds[]? | select(.tag == $tag and .protocol == "dns")] as $outbounds |
      ($outbounds | length) == 1 and
      $outbounds[0].settings.rewriteAddress == "127.0.0.1" and
      (($outbounds[0].settings.rewritePort | tostring) == $port) and
      $outbounds[0].settings.rewriteNetwork == "udp"
    ' "$XRAY_CONFIG" >/dev/null; then
      pass "DNS outbound $dns_tag использует UDP rewrite на 127.0.0.1:$PLUGIN_PORT"
    else
      error "DNS outbound $dns_tag должен быть уникальным и использовать UDP rewrite на 127.0.0.1:$PLUGIN_PORT"
    fi

    direct_domains="$(jq -r --arg tag "$dns_tag" '
      [
        .outbounds[]? |
        select(.tag == $tag and .protocol == "dns") |
        .settings.rules[]? |
        select(.action == "direct" and (.domain | type) == "array") |
        .domain[]
      ] | unique | join(", ")
    ' "$XRAY_CONFIG" 2>/dev/null || true)"
    if jq -e --arg tag "$dns_tag" '
      [
        .outbounds[]? |
        select(.tag == $tag and .protocol == "dns") |
        .settings.rules[]? |
        select(
          .action == "direct" and
          (.domain | type) == "array" and
          (.domain | length) > 0
        )
      ] | length > 0
    ' "$XRAY_CONFIG" >/dev/null; then
      pass "DNS policy содержит direct rule с domain: ${direct_domains}"
    else
      error "dns-out.settings.rules должен содержать хотя бы одно правило action=direct с непустым массивом domain"
    fi

    if jq -e --arg tag "$dns_tag" '
      .routing.rules as $rules |
      [$rules | to_entries[] |
        select(
          .value.type == "field" and
          .value.enabled != false and
          .value.outboundTag == $tag and
          .value.port == "53" and
          .value.network == "tcp,udp"
        ) | .key] as $dns_routes |
      [$rules | to_entries[] |
        select(
          ((.value.ip // []) | index("geoip:private")) != null
        ) | .key] as $private_blocks |
      ($dns_routes | length) == 1 and
      (($private_blocks | length) == 0 or
       ($dns_routes[0] < ($private_blocks | min)))
    ' "$XRAY_CONFIG" >/dev/null; then
      pass "Port-53 route расположен до geoip:private block (если он есть)"
    else
      error "Port-53 route отсутствует или расположен после geoip:private block"
    fi
  fi

  if jq -e '(.dns.servers | type) == "array" and (.dns.servers | length) > 0' "$XRAY_CONFIG" >/dev/null; then
    pass "Для встроенного DNS Xray задан upstream в dns.servers"
  else
    error "Для catch-all hijack не задан upstream в dns.servers"
  fi

  if jq -e --arg port "$PLUGIN_PORT" '
    any(.dns.servers[]?;
      if type == "string" then
        . == ("127.0.0.1:" + $port)
      elif type == "object" then
        .address == "127.0.0.1" and ((.port // 53 | tostring) == $port)
      else
        false
      end
    )
  ' "$XRAY_CONFIG" >/dev/null; then
    error "Plugin listener не должен добавляться в dns.servers: он вызывается через dns-out rewrite target"
  else
    pass "Plugin listener не прописан в dns.servers (DNS path использует rewrite target)"
  fi
fi

printf '\nИтог: %d OK, %d WARN, %d FAIL\n' "$ok" "$warn" "$fail"
(( fail == 0 )) || exit 1
exit 0
