#!/usr/bin/env bash
# Read-only integration check for doh-health-monitor and LucX-UI/Xray.
set -uo pipefail
DOH_SERVICE="${DOH_SERVICE:-lucx-plugin-doh-health-monitor}"
DOH_STATUS_URL="${DOH_STATUS_URL:-http://127.0.0.1:18765/status}"
XRAY_CONFIG="${XRAY_CONFIG:-/usr/local/x-ui/bin/config.json}"
PLUGIN_PORT="5355"
ok=0; warn=0; fail=0
pass() { printf '[OK]   %s\n' "$*"; ok=$((ok + 1)); }
warning() { printf '[WARN] %s\n' "$*"; warn=$((warn + 1)); }
error() { printf '[FAIL] %s\n' "$*"; fail=$((fail + 1)); }

if ! command -v jq >/dev/null 2>&1; then
  error "jq не установлен; проверка JSON невозможна"
  printf '\nИтог: %d OK, %d WARN, %d FAIL\n' "$ok" "$warn" "$fail"
  exit 2
fi
if systemctl is-active --quiet "$DOH_SERVICE"; then
  pass "Сервис $DOH_SERVICE запущен"
else
  error "Сервис $DOH_SERVICE не активен"
fi
if command -v ss >/dev/null 2>&1; then
  for proto in tcp udp; do
    if ss -H -l "$\{proto}" 2>/dev/null | grep -Eq "127\\.0\\.0\\.1:5355([[:space:]]|$)"; then
      pass "Порт 5355/$\{proto} слушается"
    else
      error "Порт 5355/$\{proto} не слушается"
    fi
  done
else
  warning "Команда ss отсутствует; проверка сокетов пропущена"
fi
status_file="$(mktemp)"
if curl --fail --silent --show-error --max-time 3 "$DOH_STATUS_URL" -o "$status_file" 2>/dev/null &&
   jq -e . "$status_file" >/dev/null 2>&1; then
  active="$(jq -r '.active_upstream // "не указан"' "$status_file")"
  pass "Status API отвечает корректным JSON (active_upstream: $active)"
else
  error "Status API недоступен или вернул некорректный JSON: $DOH_STATUS_URL"
fi
rm -f "$status_file"

if [[ ! -r "$XRAY_CONFIG" ]]; then
  error "Не найден доступный для чтения Xray config: $XRAY_CONFIG"
else
  pass "Xray config доступен: $XRAY_CONFIG"
  if jq -e --argjson port "$PLUGIN_PORT" '
    any(.outbounds[]?;
      .tag == "dns-out" and .protocol == "dns" and
      .settings.rewriteAddress == "127.0.0.1" and .settings.rewritePort == $port)
  ' "$XRAY_CONFIG" >/dev/null; then
    pass "dns-out направляет DNS на 127.0.0.1:5355"
  else
    error "dns-out не направляет DNS на 127.0.0.1:5355"
  fi
  if jq -e --argjson port "$PLUGIN_PORT" '
    any(.dns.servers[]?;
      .address == "127.0.0.1" and .port == $port)
  ' "$XRAY_CONFIG" >/dev/null; then
    pass "В dns.servers найден 127.0.0.1:5355"
  else
    error "В dns.servers не найден сервер 127.0.0.1:5355"
  fi
  if jq -e --argjson port "$PLUGIN_PORT" '
    any(.routing.rules[]?;
      .ruleTag == "xui-dns-allow" and
      ((.ip // []) | index("127.0.0.1")) != null and
      ((.port | tostring) == ($port | tostring)) and .outboundTag == "direct")
  ' "$XRAY_CONFIG" >/dev/null; then
    pass "Правило xui-dns-allow разрешает 127.0.0.1:5355"
  else
    error "xui-dns-allow не соответствует порту 5355"
  fi
fi
printf '\nИтог: %d OK, %d WARN, %d FAIL\n' "$ok" "$warn" "$fail"
(( fail == 0 )) || exit 1
exit 0
