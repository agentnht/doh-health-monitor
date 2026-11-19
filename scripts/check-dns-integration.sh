#!/usr/bin/env bash
# Read-only integration check for doh-health-monitor and LucX-UI/Xray.
set -uo pipefail
DOH_SERVICE="${DOH_SERVICE:-lucx-plugin-doh-health-monitor}"
DOH_STATUS_URL="${DOH_STATUS_URL:-http://127.0.0.1:18765/status}"
XRAY_CONFIG="${XRAY_CONFIG:-/usr/local/x-ui/bin/config.json}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
plugin_data_dir="${LUCX_PLUGIN_DATA:-$(cd -- "$SCRIPT_DIR/.." && pwd -P)/data}"
plugin_config="$plugin_data_dir/config.json"
if [[ -n "${DOH_PLUGIN_PORT:-}" ]]; then
  PLUGIN_UDP_PORT="$DOH_PLUGIN_PORT"
  PLUGIN_TCP_PORT="${DOH_PLUGIN_TCP_PORT:-$DOH_PLUGIN_PORT}"
else
  if ! command -v jq >/dev/null 2>&1 || [[ ! -r "$plugin_config" ]]; then
    printf '[FAIL] Не удалось прочитать статические DNS listener-ы из %s.\n' "$plugin_config" >&2
    exit 2
  fi
  udp_listen="$(jq -r '.dns_listen_udp // empty' "$plugin_config")"
  tcp_listen="$(jq -r '.dns_listen_tcp // empty' "$plugin_config")"
  if [[ "$udp_listen" != 127.0.0.1:* || "$tcp_listen" != 127.0.0.1:* ]]; then
    printf '[FAIL] DNS listener-ы должны быть loopback IPv4 адресами из config.json.\n' >&2
    exit 2
  fi
  PLUGIN_UDP_PORT="${udp_listen##*:}"
  PLUGIN_TCP_PORT="${tcp_listen##*:}"
fi
for value in "$PLUGIN_UDP_PORT" "$PLUGIN_TCP_PORT"; do
  if [[ ! "$value" =~ ^[0-9]{1,5}$ ]] || (( 10#$value < 1 || 10#$value > 65535 )); then
    printf '[FAIL] Некорректный статический DNS listener port.\n' >&2
    exit 2
  fi
done
PLUGIN_UDP_PORT=$((10#$PLUGIN_UDP_PORT))
PLUGIN_TCP_PORT=$((10#$PLUGIN_TCP_PORT))
ok=0; warn=0; fail=0
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
    port="$PLUGIN_TCP_PORT"
    [[ "$proto" == "udp" ]] && flag="-u" && port="$PLUGIN_UDP_PORT"
    if ss -H -l "$flag" 2>/dev/null | grep -Eq "127\\.0\\.0\\.1:${port}([[:space:]]|$)"; then
      pass "Порт ${port}/${proto} слушается"
    else
      error "Порт ${port}/${proto} не слушается"
    fi
  done
else
  warning "Команда ss отсутствует; проверка сокетов пропущена"
fi
status_file="$(mktemp)"
status_token_file="$plugin_data_dir/auto-hosts-api.token"
status_token=""
token_meta=""
if [[ -f "$status_token_file" && ! -L "$status_token_file" ]]; then
  token_meta="$(stat -c '%a:%u' -- "$status_token_file" 2>/dev/null || true)"
  token_mode="${token_meta%%:*}"
  token_uid="${token_meta##*:}"
  if [[ "$token_uid" == "$EUID" && "$token_mode" =~ ^[0-7]{3,4}$ ]] &&
     (( (8#$token_mode & 077) == 0 )); then
    IFS= read -r status_token < "$status_token_file" || status_token=""
  fi
fi
if [[ "$status_token" =~ ^[A-Za-z0-9_-]{40,128}$ ]] &&
   printf 'header = "Authorization: Bearer %s"\n' "$status_token" |
     curl --config - --fail --silent --show-error --max-time 3 "$DOH_STATUS_URL" -o "$status_file" 2>/dev/null &&
   jq -e . "$status_file" >/dev/null 2>&1; then
  active="$(jq -r '.groups.google.active_upstream // .active_upstream // "не указан"' "$status_file")"
  pass "Status API отвечает корректным JSON (active_upstream: $active)"
else
  error "Status API недоступен, токен отсутствует/некорректен или JSON некорректен: $DOH_STATUS_URL"
fi
status_token=""
rm -f "$status_file"

fi

if [[ ! -r "$XRAY_CONFIG" ]]; then
  error "Не найден доступный для чтения Xray config: $XRAY_CONFIG"
else
  pass "Xray config доступен: $XRAY_CONFIG"
  if jq -e --arg plugin_port "$PLUGIN_UDP_PORT" '
    any(.outbounds[]?;
      .protocol == "dns" and
      .settings.rewriteAddress == "127.0.0.1" and
      ((.settings.rewritePort | tostring) == $plugin_port)
    )
  ' "$XRAY_CONFIG" >/dev/null; then
    pass "DNS outbound указывает на 127.0.0.1:${PLUGIN_UDP_PORT}"
  else
    error "DNS outbound на 127.0.0.1:${PLUGIN_UDP_PORT} отсутствует или несовместим"
  fi

  if jq -e --arg plugin_port "$PLUGIN_UDP_PORT" '
    . as $root |
    any($root.routing.rules[]?;
      .type == "field" and
      ((.network // "tcp,udp") | tostring | contains("tcp")) and
      ((.network // "tcp,udp") | tostring | contains("udp")) and
      ((.port | tostring) == "53") and
      ((.outboundTag // "") as $tag |
        any($root.outbounds[]?; .tag == $tag and .protocol == "dns" and
          .settings.rewriteAddress == "127.0.0.1" and
          ((.settings.rewritePort | tostring) == $plugin_port)))
    )
  ' "$XRAY_CONFIG" >/dev/null; then
    pass "Routing rule направляет TCP/UDP port 53 в локальный DNS outbound"
  else
    error "Полный DNS route на 127.0.0.1:${PLUGIN_UDP_PORT} не найден"
  fi

  if jq -e '
    any(.routing.rules[]?;
      ((.ip // []) | index("geoip:private")) != null
    )
  ' "$XRAY_CONFIG" >/dev/null; then
    if jq -e --arg port "$PLUGIN_PORT" '
      (.routing.rules // []) as $rules |
      [$rules | to_entries[] | select(
        .value.ruleTag == "xui-dns-allow" and
        (($port == (.value.port | tostring)) and
         ((.value.ip // []) | index("127.0.0.1")) != null)
      )] as $allow |
      [$rules | to_entries[] | select(((.value.ip // []) | index("geoip:private")) != null)] as $private |
      ($allow | length) == 1 and
      ($allow[0].value.ip // [] | index("127.0.0.1")) != null and
      (($allow[0].value.port | tostring) == $port) and
      $allow[0].value.outboundTag == "direct" and
      $allow[0].key < $private[0].key
    ' "$XRAY_CONFIG" >/dev/null; then
      pass "xui-dns-allow корректно разрешает localhost до блокировки private IP"
    else
      error "xui-dns-allow отсутствует, дублируется, неверно настроен или расположен после private-IP block"
    fi
  else
    pass "geoip:private block отсутствует; xui-dns-allow не требуется"
  fi
fi
printf '\nИтог: %d OK, %d WARN, %d FAIL\n' "$ok" "$warn" "$fail"
(( fail == 0 )) || exit 1
exit 0
