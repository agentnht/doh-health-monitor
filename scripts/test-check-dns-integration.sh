#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CHECKER="$SCRIPT_DIR/check-dns-integration.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
CONFIG="$TMP_DIR/xray-config.json"
OUTPUT="$TMP_DIR/check-output.txt"

write_approved_config() {
  cat >"$CONFIG" <<'JSON'
{
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {
        "finalRules": [
          {"action": "block", "ip": ["geoip:private"]},
          {"action": "allow"}
        ]
      }
    },
    {"tag": "blocked", "protocol": "blackhole", "settings": {}},
    {
      "tag": "dns-out",
      "protocol": "dns",
      "settings": {
        "rewriteNetwork": "udp",
        "rewriteAddress": "127.0.0.1",
        "rewritePort": 5355,
        "rules": [
          {"action": "direct", "domain": ["geosite:habr"]},
          {"action": "hijack"}
        ]
      }
    }
  ],
  "routing": {
    "rules": [
      {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
      {
        "type": "field",
        "enabled": true,
        "port": "53",
        "network": "tcp,udp",
        "outboundTag": "dns-out",
        "ruleTag": "doh-health-monitor-dns-port53"
      },
      {"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"}
    ],
    "domainStrategy": "AsIs"
  },
  "dns": {"servers": ["https://9.9.9.9/dns-query"]}
}
JSON
}

expect_pass() {
  local label="$1"
  if DOH_SKIP_PLUGIN_HEALTH_CHECK=1 XRAY_CONFIG="$CONFIG" DOH_PLUGIN_PORT=5355 bash "$CHECKER" >"$OUTPUT" 2>&1; then
    printf '[PASS] %s\n' "$label"
  else
    cat "$OUTPUT" >&2
    printf '[FAIL] %s (checker unexpectedly rejected config)\n' "$label" >&2
    exit 1
  fi
}

expect_fail() {
  local label="$1"
  if DOH_SKIP_PLUGIN_HEALTH_CHECK=1 XRAY_CONFIG="$CONFIG" DOH_PLUGIN_PORT=5355 bash "$CHECKER" >"$OUTPUT" 2>&1; then
    cat "$OUTPUT" >&2
    printf '[FAIL] %s (checker unexpectedly accepted config)\n' "$label" >&2
    exit 1
  else
    printf '[PASS] %s\n' "$label"
  fi
}

# Stub only the status API request so mode reporting is deterministic in CI.
mkdir -p "$TMP_DIR/mock-bin"
cat >"$TMP_DIR/mock-bin/curl" <<'MOCK'
#!/usr/bin/env bash
set -e
out=""
while (($#)); do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    --config) [[ "$2" == "-" ]]; shift 2 ;;
    *) shift ;;
  esac
done
config="$(cat)"
[[ "$config" == "header = \"Authorization: Bearer ${MOCK_STATUS_TOKEN:-}\"" ]]
[[ -n "$out" && -n "${MOCK_STATUS_JSON:-}" ]]
cp "$MOCK_STATUS_JSON" "$out"
MOCK
chmod +x "$TMP_DIR/mock-bin/curl"
export PATH="$TMP_DIR/mock-bin:$PATH"
export DOH_STATUS_URL="http://127.0.0.1:18765/status"
export MOCK_STATUS_TOKEN="$(printf '%064d' 0)"
export LUCX_PLUGIN_DATA="$TMP_DIR/status-data"
mkdir -p "$LUCX_PLUGIN_DATA"
printf '%s\n' "$MOCK_STATUS_TOKEN" > "$LUCX_PLUGIN_DATA/status-api.token"
chmod 0600 "$LUCX_PLUGIN_DATA/status-api.token"
cat >"$TMP_DIR/status-mode1.json" <<'JSON'
{"dns_mode":"endpoint_ip","active_doh":{"server_id":"active-test","hostname":"doh.example.net","ipv4":["192.0.2.10"],"ipv6":["2001:db8::10"],"score":6,"check_count":8}}
JSON
export MOCK_STATUS_JSON="$TMP_DIR/status-mode1.json"

# There is geoip:private, but no xui-dns-allow, no finalRules localhost
# exception and no 127.0.0.1:5355 entry in dns.servers: this is intentional.
write_approved_config
expect_pass "approved Geosite config passes without legacy localhost exception"
grep -Fq "Текущий DNS mode: endpoint_ip (режим 1)" "$OUTPUT"
grep -Fq "Активный DoH server: active-test (doh.example.net), score=6/8" "$OUTPUT"
grep -Fq "Active endpoint IPv4: 192.0.2.10" "$OUTPUT"
grep -Fq "Active endpoint IPv6: 2001:db8::10" "$OUTPUT"

cat >"$TMP_DIR/status-mode2.json" <<'JSON'
{"dns_mode":"resolver"}
JSON
export MOCK_STATUS_JSON="$TMP_DIR/status-mode2.json"
expect_pass "resolver mode status is reported"
grep -Fq "Текущий DNS mode: resolver (режим 2)" "$OUTPUT"
export MOCK_STATUS_JSON="$TMP_DIR/status-mode1.json"

write_approved_config
jq '(.outbounds[] | select(.tag == "dns-out") | .settings.rules[0].domain) = ["geosite:cn", "domain:example.org"]' "$CONFIG" >"$TMP_DIR/mutated.json"
mv "$TMP_DIR/mutated.json" "$CONFIG"
expect_pass "arbitrary direct domain values are accepted"

write_approved_config
jq '(.outbounds[] | select(.tag == "dns-out") | .settings.rules) |= reverse' "$CONFIG" >"$TMP_DIR/mutated.json"
mv "$TMP_DIR/mutated.json" "$CONFIG"
expect_pass "DNS rules may contain any order and additional rules"

write_approved_config
jq '(.outbounds[] | select(.tag == "dns-out") | .settings.rules[0].action) = "hijack"' "$CONFIG" >"$TMP_DIR/mutated.json"
mv "$TMP_DIR/mutated.json" "$CONFIG"
expect_fail "at least one direct rule is required"

write_approved_config
jq '(.outbounds[] | select(.tag == "dns-out") | .settings.rules[0]) = {"action":"direct"}' "$CONFIG" >"$TMP_DIR/mutated.json"
mv "$TMP_DIR/mutated.json" "$CONFIG"
expect_fail "direct rule must contain a non-empty domain array"

write_approved_config
jq '(.outbounds[] | select(.tag == "dns-out") | .settings.rewriteNetwork) = "tcp"' "$CONFIG" >"$TMP_DIR/mutated.json"
mv "$TMP_DIR/mutated.json" "$CONFIG"
expect_fail "approved local rewrite transport is UDP"

write_approved_config
jq '(.routing.rules) |= (.[0:1] + .[2:] + .[1:2])' "$CONFIG" >"$TMP_DIR/mutated.json"
mv "$TMP_DIR/mutated.json" "$CONFIG"
expect_fail "port-53 route must precede geoip:private block"

write_approved_config
jq '.dns.servers += [{"address":"127.0.0.1","port":5355}]' "$CONFIG" >"$TMP_DIR/mutated.json"
mv "$TMP_DIR/mutated.json" "$CONFIG"
expect_fail "plugin listener must not be added to dns.servers"

write_approved_config
jq '.routing.rules += [.routing.rules[1]]' "$CONFIG" >"$TMP_DIR/mutated.json"
mv "$TMP_DIR/mutated.json" "$CONFIG"
expect_fail "duplicate global port-53 routes are ambiguous"

printf 'All DNS integration checker tests passed.\n'
