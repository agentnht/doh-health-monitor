#!/usr/bin/env python3
"""Read-only planner for the LucX-UI / DoH Health Monitor Xray integration.

The script reads either a JSON fixture or xrayTemplateConfig from SQLite in
read-only mode. It never writes files, database records, panel settings, or
runtime Xray configuration.
"""

from __future__ import annotations

import argparse
import copy
import difflib
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

DB_DEFAULT = "/etc/x-ui/x-ui.db"
SETTING_KEY = "xrayTemplateConfig"

DNS_OUT = {
    "tag": "dns-out",
    "protocol": "dns",
    "settings": {
        "rewriteNetwork": "udp",
        "rewriteAddress": "127.0.0.1",
        "rewritePort": 5355,
    },
}

DNS_SERVER = {
    "address": "127.0.0.1",
    "port": 5355,
    "domains": [],
    "skipFallback": False,
}

DNS_ALLOW = {
    "ip": ["127.0.0.1"],
    "outboundTag": "direct",
    "port": "5355",
    "ruleTag": "xui-dns-allow",
    "type": "field",
}

DNS_PORT_RULE = {
    "enabled": True,
    "network": "tcp,udp",
    "outboundTag": "dns-out",
    "port": "53",
    "type": "field",
}


def one(items: list[dict[str, Any]], predicate, description: str):
    found = [item for item in items if predicate(item)]
    if len(found) > 1:
        raise RuntimeError(f"Ambiguous configuration: multiple {description}")
    return found[0] if found else None


def _require_object(value: Any, description: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError(f"Invalid {description}: expected JSON object")
    return value


def _require_object_list(value: Any, description: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(x, dict) for x in value):
        raise RuntimeError(f"Invalid {description}: expected array of objects")
    return value


def _network_tokens(rule: dict[str, Any]) -> set[str]:
    value = rule.get("network", "")
    if not isinstance(value, str):
        return set()
    return {token.strip().lower() for token in value.split(",") if token.strip()}


def transform(original: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Return a corrected deep copy and change descriptions; never mutate input.

    Ambiguous duplicate/conflicting structures fail closed rather than creating
    another rule or silently replacing a different routing decision.
    """
    if not isinstance(original, dict):
        raise RuntimeError("Xray config root must be a JSON object")

    cfg = copy.deepcopy(original)
    changes: list[str] = []

    outbounds = _require_object_list(cfg.setdefault("outbounds", []), "outbounds")
    dns_out = one(
        outbounds,
        lambda item: item.get("tag") == "dns-out",
        "dns-out outbounds",
    )
    if dns_out is None:
        outbounds.append(copy.deepcopy(DNS_OUT))
        changes.append("add dns-out")
    else:
        for key in ("tag", "protocol"):
            expected = DNS_OUT[key]
            if dns_out.get(key) != expected:
                dns_out[key] = copy.deepcopy(expected)
                changes.append(f"set dns-out.{key}")

        settings = dns_out.get("settings")
        if settings is None:
            settings = {}
            dns_out["settings"] = settings
        _require_object(settings, "dns-out.settings")
        for key, expected in DNS_OUT["settings"].items():
            if settings.get(key) != expected:
                settings[key] = copy.deepcopy(expected)
                changes.append(f"set dns-out.settings.{key}")

    dns = _require_object(cfg.setdefault("dns", {}), "dns")
    servers = _require_object_list(dns.setdefault("servers", []), "dns.servers")
    local_server = one(
        servers,
        lambda item: item.get("address") == "127.0.0.1"
        and str(item.get("port", "")) == "5355",
        "DNS servers for 127.0.0.1:5355",
    )
    if local_server is None:
        servers.append(copy.deepcopy(DNS_SERVER))
        changes.append("add DNS server 127.0.0.1:5355")
    else:
        for key, expected in DNS_SERVER.items():
            if local_server.get(key) != expected:
                local_server[key] = copy.deepcopy(expected)
                changes.append(f"set local DNS server.{key}")

    routing = _require_object(cfg.setdefault("routing", {}), "routing")
    rules = _require_object_list(routing.setdefault("rules", []), "routing.rules")

    # The target is a global TCP+UDP port-53 rule. A rule with the same scope
    # but a different outbound is a policy conflict, not something to rewrite.
    port53 = one(
        rules,
        lambda item: str(item.get("port", "")) == "53"
        and _network_tokens(item) == {"tcp", "udp"},
        "global TCP/UDP port 53 rules",
    )
    if port53 is None:
        # Avoid silently overriding narrower custom port-53 handling.
        partial_port53 = [
            item for item in rules
            if str(item.get("port", "")) == "53"
            and _network_tokens(item).intersection({"tcp", "udp"})
        ]
        if partial_port53:
            raise RuntimeError(
                "Conflicting/narrower port-53 routing rules found; manual review required"
            )
        rules.insert(0, copy.deepcopy(DNS_PORT_RULE))
        changes.append("add TCP/UDP port 53 -> dns-out rule")
    else:
        if port53.get("outboundTag") not in (None, "dns-out"):
            raise RuntimeError(
                "Global TCP/UDP port 53 rule routes elsewhere; refusing to replace policy"
            )
        for key, expected in DNS_PORT_RULE.items():
            if port53.get(key) != expected:
                port53[key] = copy.deepcopy(expected)
                changes.append(f"set port 53 rule.{key}")

    allow = one(
        rules,
        lambda item: item.get("ruleTag") == "xui-dns-allow",
        "xui-dns-allow rules",
    )
    if allow is None:
        untagged_allow = [
            item for item in rules
            if str(item.get("port", "")) == "5355"
            and "127.0.0.1" in (item.get("ip") or [])
        ]
        if untagged_allow:
            raise RuntimeError(
                "An untagged rule already matches 127.0.0.1:5355; manual review required"
            )
        private_index = next(
            (
                index for index, rule in enumerate(rules)
                if "geoip:private" in (rule.get("ip") or [])
            ),
            len(rules),
        )
        rules.insert(private_index, copy.deepcopy(DNS_ALLOW))
        changes.append("add xui-dns-allow before private-IP block")
    else:
        for key, expected in DNS_ALLOW.items():
            if allow.get(key) != expected:
                allow[key] = copy.deepcopy(expected)
                changes.append(f"set xui-dns-allow.{key}")

        allow_index = rules.index(allow)
        private_index = next(
            (
                index for index, rule in enumerate(rules)
                if "geoip:private" in (rule.get("ip") or [])
            ),
            len(rules),
        )
        if allow_index > private_index:
            rules.pop(allow_index)
            rules.insert(private_index, allow)
            changes.append("move xui-dns-allow before private-IP block")

    return cfg, changes


def load_config(args: argparse.Namespace) -> dict[str, Any]:
    if args.config:
        config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    else:
        db_path = Path(args.db).expanduse().resolve()
        uri = f"{db_path.as_uri()}?mode=ro"
        con = sqlite3.connect(uri, uri=True, timeout=10)
        try:
            row = con.execute(
                "SELECT value FROM settings WHERE key=?", (SETTING_KEY,)
            ).fetchone()
        finally:
            con.close()
        if row is None:
            raise RuntimeError(f"{SETTING_KEY} not found in {db_path}")
        config = json.loads(row[0])
    if not isinstance(config, dict):
        raise RuntimeError("Xray config root must be a JSON object")
    return config


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only DoH/Xray integration dry-run"
    )
    parser.add_argument("--db", default=DB_DEFAULT, help="SQLite DB opened read-only")
    parser.add_argument("--config", help="JSON fixture instead of SQLite")
    args = parser.parse_args()

    try:
        original = load_config(args)
        proposed, changes = transform(original)
        print("Source:", args.config or args.db)
        print("Mode: READ-ONLY / DRY-RUN")
        print()
        if not changes:
            print("OK: configuration already matches the target.")
            print("No changes proposed.")
            return 0
        print("Proposed changes:")
        for change in changes:
            print(" -", change)
        before = json.dumps(original, indent=2, ensure_ascii=False).splitlines(keepends=True)
        after = json.dumps(proposed, indent=2, ensure_ascii=False).splitlines(keepends=True)
        print("\n--- DRY-RUN DIFF ---")
        sys.stdout.writelines(difflib.unified_diff(
            before, after, fromfile="current", tofile="proposed"
        ))
        print("\nNo files or database records were modified.")
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
