#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CHECKER="$SCRIPT_DIR/check-dns-integration.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CONFIG="$TMP_DIR/xray-config.json"
OUTPUT="$TMP_DIR/check-output.txt"

cat >"$CONFIG" <<'JSON'
{
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 62789,
      "protocol": "tunnel",
      "settings": {"rewriteAddress": "127.0.0.1"},
      "tag": "api"
    }
  ],
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
      {
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "blocked"
      }
    ],
    "domainStrategy": "AsIs"
  },
  "dns": {
    "servers": [
      {
        "address": "https://9.9.9.9/dns-query",
        "domains": [],
        "expectedIPs": [],
        "unexpectedIPs": [],
        "skipFallback": false,
        "finalQuery": true,
        "tag": "quad",
        "queryStrategy": "UseIP",
        "disableCache": false,
        "timeoutMs": 4000,
        "serveStale": false,
        "serveExpiredTTL": 0
      }
    ],
    "queryStrategy": "UseIP",
    "disableCache": false,
    "disableFallback": false,
    "disableFallbackIfMatch": false,
    "enableParallelQuery": false,
    "useSystemHosts": false,
    "serveStale": false,
    "serveExpiredTTL": 0
  }
}
JSON

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

# Approved layout deliberately has geoip:private but no xui-dns-allow,
# no direct.settings.finalRules exception, and no 127.0.0.1:5355 dns.servers entry.
expect_pass "approved Geosite DNS config does not require legacy localhost allow rule"

jq '(.outbounds[] | select(.tag == "dns-out") | .settings.rules[0].domain) = ["domain:example.com"]' "$CONFIG" >"$TMP_DIR/no-geosite.json"
cp "$TMP_DIR/no-geosite.json" "$CONFIG"
expect_fail "Geosite direct rule is required"

cat >"$CONFIG" <<'JSON'
{
  "outbounds": [
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
      {"type": "field", "port": "53", "network": "tcp,udp", "outboundTag": "dns-out"}
    ]
  },
  "dns": {"servers": ["https://9.9.9.9/dns-query"]}
}
JSON
jq '(.outbounds[] | select(.tag == "dns-out") | .settings.rules) |= reverse' "$CONFIG" >"$TMP_DIR/reversed.json"
cp "$TMP_DIR/reversed.json" "$CONFIG"
expect_fail "catch-all hijack must follow Geosite direct"

jq '(.outbounds[] | select(.tag == "dns-out") | .settings.rewriteNetwork) = "tcp"' "$CONFIG" >"$TMP_DIR/tcp.json"
cp "$TMP_DIR/tcp.json" "$CONFIG"
expect_fail "approved local rewrite transport is UDP"

# Restore the complete fixture and move the port-53 rule behind geoip:private.
cat >"$CONFIG" <<'JSON'
{
  "outbounds": [
    {"tag": "direct", "protocol": "freedom", "settings": {}},
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
      {"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"},
      {"type": "field", "port": "53", "network": "tcp,udp", "outboundTag": "dns-out"}
    ]
  },
  "dns": {"servers": ["https://9.9.9.9/dns-query"]}
}
JSON
expect_fail "port-53 route must precede geoip:private block"

printf 'All DNS integration checker tests passed.\n'
