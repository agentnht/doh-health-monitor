#!/usr/bin/env bash
# Read-only integration check for doh-health-monitor and LucX-UI/Xray.
set -uo pipefail
DOH_SERVICE="${DOH_SERVICE:-lucx-plugin-doh-health-monitor}"
DOH_STATUS_URL="${DOH_STATUS_URL:-http://127.0.0.1:18765/status}"
XRAY_CONFIG="${XRAY_CONFIG:-/usr/local/x-ui/bin/config.json}"
PLUGIN_PORT=5355
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
    flag="-t"
    [[ "$proto" == "udp" ]] && flag="-u"
    if ss -H -l "$flag" 2>/dev/null | grep -Eq "127\\.0\\.0\\.1:5355([[:space:]]|$)"; then
      pass "Порт 5355/${proto} слушается"
    else
      error "Порт 5355/${proto} не слушается"
    fi
  done
else
  warning "Команда ss отсутствует; проверка сокетов пропущена"
fi
status_file="$(mktemp)"
if curl --fail --silent --show-error --max-time 3 "$DOH_STATUS_URL" -o "$status_file" 2>/dev/null &&
   jq -e . "$status_file" >/dev/null 2>&1; then
  active="$(jq -r '.groups.google.active_upstream // .active_upstream // "не указан"' "$status_file")"
  pass "Status API отвечает корректным JSON (active_upstream: $active)"
else
  error "Status API недоступен или вернул некорректный JSON: $DOH_STATUS_URL"
fi
rm -f "$status_file"

if [[ ! -r "$XRAY_CONFIG" ]]; then
  error "Не найден доступный для чтения Xray config: $XRAY_CONFIG"
else
  pass "Xray config доступен: $XRAY_CONFIG"
  route_json="$(jq -ce '
    [
      .routing.rules[]?
      | select(.enabled != false and (.type // "field") == "field")
      | select((.port | tostring) == "53")
      | select(
          ((.network // "tcp,udp")
            | if type == "array" then map(ascii_downcase) | sort
              else split(",") | map(gsub("\\s"; "") | ascii_downcase) | sort
              end) == ["tcp", "udp"]
        )
      | select((keys - ["enabled", "network", "port", "type", "ruleTag", "remarks", "comment", "outboundTag", "balancerTag"]) | length == 0)
      | select((.outboundTag // "") != "" or (.balancerTag // "") != "")
    ]
    | if length == 1 then .[0] else empty end
  ' "$XRAY_CONFIG" 2>/dev/null)" || route_json=""
  outbound_tag=""
  balancer_tag=""
  if [[ -n "$route_json" ]]; then
    outbound_tag="$(jq -r '.outboundTag // empty' <<<"$route_json")"
    balancer_tag="$(jq -r '.balancerTag // empty' <<<"$route_json")"
  fi
  if [[ -n "$outbound_tag" ]] && jq -e --arg tag "$outbound_tag" --arg port "$PLUGIN_PORT" '
    any(.outbounds[]?;
      .tag == $tag and .protocol == "dns" and
      .settings.rewriteAddress == "127.0.0.1" and
      (.settings.rewritePort | tostring) == $port and
      ((.settings.rewriteNetwork // "udp") == "udp" or (.settings.rewriteNetwork // "") == "tcp") and
      all((.settings.rules // [])[];
        .action == "direct" and
        ((.qType // .qtype // []) == []) and
        ((.domain // []) == []) and
        ((keys - ["action", "rCode"]) | length == 0)
      ) and
      ((.settings.blockTypes // []) | length == 0) and
      (.settings.nonIPQuery // "direct") == "direct" and
      (.proxySettings // null) == null and
      (.streamSettings // null) == null and
      (.mux // null) == null and
      ((.sendThrough // "127.0.0.1") | try (test("^(127\\.|::1$)")) catch false))
  ' "$XRAY_CONFIG" >/dev/null; then
    pass "Outbound $outbound_tag направляет DNS на 127.0.0.1:5355"
  elif [[ -n "$balancer_tag" ]] && jq -e --arg tag "$balancer_tag" --arg port "$PLUGIN_PORT" '
    (.outbounds // []) as $outbounds
    | [.routing.balancers[]? | select(.tag == $tag)] as $balancers
    | ($balancers | length) == 1
      and ($balancers[0].selector | type == "array" and length > 0)
      and all($balancers[0].selector[]; type == "string" and length > 0)
      and (
        (
          [
            $outbounds[]?
            | .tag as $outbound_tag
            | select($outbound_tag != null and any($balancers[0].selector[]; . as $prefix | ($outbound_tag | startswith($prefix))))
            | $outbound_tag
          ]
          + [($balancers[0].fallbackTag // empty)]
          | unique
        ) as $selected
        | ($selected | length) > 0
          and all($selected[]; . as $selected_tag
            | any($outbounds[]?;
                .tag == $selected_tag and .protocol == "dns" and
                .settings.rewriteAddress == "127.0.0.1" and
                (.settings.rewritePort | tostring) == $port and
                ((.settings.rewriteNetwork // "udp") == "udp" or (.settings.rewriteNetwork // "") == "tcp") and
                all((.settings.rules // [])[]; .action == "direct") and
                ((.settings.blockTypes // []) | length == 0) and
                (.settings.nonIPQuery // "direct") == "direct" and
                (.proxySettings // null) == null and
                (.streamSettings // null) == null and
                (.mux // null) == null and
                ((.sendThrough // "127.0.0.1") | try (test("^(127\\.|::1$)")) catch false)
            )
          )
      )
  ' "$XRAY_CONFIG" >/dev/null; then
    pass "Balancer $balancer_tag направляет DNS на 127.0.0.1:5355"
  else
    error "Не найдено единственное глобальное TCP/UDP правило порта 53 с совместимым outbound/balancer"
  fi
  if jq -e --arg port "$PLUGIN_PORT" '
    any(.dns.servers[]?;
      if type == "string" then . == ("127.0.0.1:" + $port)
      else .address == "127.0.0.1" and (.port | tostring) == $port
      end)
  ' "$XRAY_CONFIG" >/dev/null; then
    pass "В dns.servers найден 127.0.0.1:5355"
  else
    error "В dns.servers не найден 127.0.0.1:5355"
  fi

  if jq -e --arg port "$PLUGIN_PORT" '
    (.routing.rules // []) as $rules |
    [$rules | to_entries[] | select(.value.ruleTag == "xui-dns-allow")] as $allow |
    [$rules | to_entries[] | select(((.value.ip // []) | index("geoip:private")) != null)] as $private |
    ($allow | length) == 1 and
    ($allow[0].value.ip // [] | index("127.0.0.1")) != null and
    (($allow[0].value.port | tostring) == $port) and
    $allow[0].value.outboundTag == "direct" and
    (($private | length) == 0 or $allow[0].key < $private[0].key)
  ' "$XRAY_CONFIG" >/dev/null; then
    pass "xui-dns-allow корректно разрешает localhost до блокировки private IP"
  else
    error "xui-dns-allow отсутствует, дублируется, неверно настроен или расположен после private-IP block"
  fi
fi
printf '\nИтог: %d OK, %d WARN, %d FAIL\n' "$ok" "$warn" "$fail"
(( fail == 0 )) || exit 1
exit 0
