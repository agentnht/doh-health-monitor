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

# There is geoip:private, but no xui-dns-allow, no finalRules localhost
# exception and no 127.0.0.1:5355 entry in dns.servers: this is intentional.
write_approved_config
expect_pass "approved Geosite config passes without legacy localhost exception"

write_approved_config
jq '(.outbounds[] | select(.tag == "dns-out") | .settings.rules[0].domain) = ["domain:example.com"]' "$CONFIG" >"$TMP_DIR/mutated.json"
mv "$TMP_DIR/mutated.json" "$CONFIG"
expect_fail "Geosite direct rule is required"

write_approved_config
jq '(.outbounds[] | select(.tag == "dns-out") | .settings.rules) |= reverse' "$CONFIG" >"$TMP_DIR/mutated.json"
mv "$TMP_DIR/mutated.json" "$CONFIG"
expect_fail "catch-all hijack must follow Geosite direct"

write_approved_config
jq '(.outbounds[] | select(.tag == "dns-out") | .settings.rewriteNetwork) = "tcp"' "$CONFIG" >"$TMP_DIR/mutated.json"
mv "$TMP_DIR/mutated.json" "$CONFIG"
expect_fail "approved local rewrite transport is UDP"

write_approved_config
jq '(.routing.rules) |= (.[0:1] + .[2:] + .[1:2])' "$CONFIG" >"$TMP_DIR/mutated.json"
mv "$TMP_DIR/mutated.json" "$CONFIG"
expect_fail "port-53 route must precede geoip:private block"

printf 'All DNS integration checker tests passed.\n'
