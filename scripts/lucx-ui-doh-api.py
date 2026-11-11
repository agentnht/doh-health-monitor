#!/usr/bin/env python3
"""Safe additive LucX-UI DoH integration through the panel API.

This tool never opens or writes the panel SQLite database and never writes the
runtime Xray config. It reads the current xraySetting through the panel API,
adds only missing DNS integration elements, and submits the preserved template
back through the panel API after explicit approval of the possible Xray restart.
"""

from __future__ import annotations

import argparse
import copy
import getpass
import ipaddress
import json
import os
import secrets
import stat
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

VERSION = "1.0.0"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024

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
DNS_PORT_RULE = {
    "enabled": True,
    "network": "tcp,udp",
    "outboundTag": "dns-out",
    "port": "53",
    "type": "field",
}
DNS_ALLOW_TAG = "xui-dns-allow"


class IntegrationError(RuntimeError):
    pass


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def object_list(parent: dict, key: str, description: str) -> list[dict]:
    if key not in parent:
        parent[key] = []
    value = parent[key]
    if not isinstance(value, list) or any(not isinstance(x, dict) for x in value):
        raise IntegrationError(f"Invalid {description}: expected an array of objects")
    return value


def _as_tokens(value: object) -> set[str]:
    if isinstance(value, str):
        return {x.strip().lower() for x in value.split(",") if x.strip()}
    if isinstance(value, list):
        return {str(x).strip().lower() for x in value if str(x).strip()}
    return set()


def _port_contains(value: object, wanted: int) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value == wanted
    if not isinstance(value, str):
        return False
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            left, right = part.split("-", 1)
            try:
                if int(left) <= wanted <= int(right):
                    return True
            except ValueError:
                continue
        else:
            try:
                if int(part) == wanted:
                    return True
            except ValueError:
                continue
    return False


def _ip_values(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [x for x in value if isinstance(x, str)]
    return []


def _is_api_rule(rule: dict) -> bool:
    if rule.get("outboundTag") != "api":
        return False
    return "api" in _as_tokens(rule.get("inboundTag"))


def _global_port53_rule(rule: dict) -> bool:
    port = rule.get("port")
    if rule.get("enabled") is False:
        return False
    if isinstance(port, bool):
        return False
    if isinstance(port, int):
        if port != 53:
            return False
    elif isinstance(port, str):
        if port.strip() != "53":
            return False
    else:
        return False

    networks = _as_tokens(rule.get("network"))
    if networks and networks != {"tcp", "udp"}:
        return False
    # Any inboundTag, domain, IP, protocol, source, or balancer selector
    # would narrow/alter the intended all-tunnel TCP+UDP interception.
    allowed = {
        "type", "ruleTag", "enabled", "network", "port",
        "outboundTag", "remarks", "comment",
    }
    if any(key not in allowed for key in rule):
        return False
    return rule.get("type", "field") == "field"


def _split_ip_address(address: str, explicit_port: object = None) -> tuple[str, int] | None:
    address = address.strip()
    if not address:
        return None

    scheme = ""
    if "://" in address:
        scheme, address = address.split("://", 1)
        address = address.split("/", 1)[0]
    else:
        address = address.split("/", 1)[0]

    remote_doh = scheme.lower() in {"https", "h2c"}
    port = 443 if remote_doh else 53
    host = address

    if address.startswith("[") and "]" in address:
        end = address.index("]")
        host = address[1:end]
        suffix = address[end + 1:]
        if suffix.startswith(":") and suffix[1:].isdigit():
            port = int(suffix[1:])
    elif address.count(":") == 1:
        candidate_host, candidate_port = address.rsplit(":", 1)
        if candidate_port.isdigit():
            host, port = candidate_host, int(candidate_port)

    if explicit_port is not None and not remote_doh:
        try:
            parsed_port = int(explicit_port)
            if parsed_port > 0:
                port = parsed_port
        except (TypeError, ValueError):
            pass

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    return str(ip), port


def _is_blocked_ip(ip_text: str) -> bool:
    ip = ipaddress.ip_address(ip_text)
    private_networks = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("fc00::/7"),
    ]
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return True
    if any(ip.version == network.version and ip in network for network in private_networks):
        return True
    extra = [
        ipaddress.ip_network("100.64.0.0/10"),
        ipaddress.ip_network("2002::/16"),
        ipaddress.ip_network("2001::/32"),
        ipaddress.ip_network("64:ff9b:1::/48"),
        ipaddress.ip_network("fec0::/10"),
    ]
    if any(ip.version == network.version and ip in network for network in extra):
        return True
    nat64 = ipaddress.ip_network("64:ff9b::/96")
    if ip.version == 6 and ip in nat64:
        embedded = ipaddress.ip_address(int(ip) & 0xFFFFFFFF)
        return _is_blocked_ip(str(embedded))
    return False


def _dns_private_groups(config: dict) -> list[tuple[int, list[str]]]:
    dns = config.get("dns", {})
    if not isinstance(dns, dict):
        return []
    servers = dns.get("servers", [])
    if not isinstance(servers, list):
        return []
    grouped: dict[int, set[str]] = {}
    for entry in servers:
        address = ""
        explicit_port = None
        if isinstance(entry, str):
            address = entry
        elif isinstance(entry, dict):
            address = entry.get("address", "") if isinstance(entry.get("address", ""), str) else ""
            explicit_port = entry.get("port")
        endpoint = _split_ip_address(address, explicit_port)
        if endpoint is None:
            continue
        ip, port = endpoint
        if _is_blocked_ip(ip):
            grouped.setdefault(port, set()).add(ip)
    return [(port, sorted(grouped[port])) for port in sorted(grouped)]


def _legacy_managed_dns_allow(rule: dict, groups: list[tuple[int, list[str]]]) -> bool:
    if rule.get("type") != "field" or rule.get("outboundTag") != "direct":
        return False
    if "ip" not in rule or "port" not in rule:
        return False
    for key, value in rule.items():
        if key in {"type", "outboundTag", "ip", "port"}:
            continue
        if key == "enabled" and value is True:
            continue
        return False
    port = rule.get("port")
    ips = sorted(_ip_values(rule.get("ip")))
    return any(str(group_port) == str(port) and group_ips == ips for group_port, group_ips in groups)


def panel_normalize_dns_allow_rules(config: dict) -> dict:
    """Model LucX-UI EnsureDnsServerRouting for safe before/after verification."""
    result = copy.deepcopy(config)
    routing = result.get("routing")
    if not isinstance(routing, dict):
        return result
    rules = routing.get("rules", [])
    if not isinstance(rules, list) or any(not isinstance(x, dict) for x in rules):
        raise IntegrationError("Invalid routing.rules; cannot predict panel normalization")

    groups = _dns_private_groups(result)
    clean = []
    for rule in rules:
        if rule.get("ruleTag") == DNS_ALLOW_TAG:
            continue
        if _legacy_managed_dns_allow(rule, groups):
            continue
        clean.append(copy.deepcopy(rule))

    private_block = next(
        (
            i for i, rule in enumerate(clean)
            if rule.get("outboundTag") == "blocked"
            and any(x.lower() == "geoip:private" for x in _ip_values(rule.get("ip")))
        ),
        -1,
    )
    if private_block >= 0 and groups:
        managed = [
            {
                "type": "field",
                "ruleTag": DNS_ALLOW_TAG,
                "ip": ips,
                "port": str(port),
                "outboundTag": "direct",
            }
            for port, ips in groups
        ]
        clean[private_block:private_block] = managed
    routing["rules"] = clean
    result["routing"] = routing
    return result


def _has_numeric_qtype_zero(config: dict) -> bool:
    outbounds = config.get("outbounds", [])
    if not isinstance(outbounds, list):
        return False
    for outbound in outbounds:
        if not isinstance(outbound, dict) or str(outbound.get("protocol", "")).lower() != "dns":
            continue
        settings = outbound.get("settings", {})
        if not isinstance(settings, dict):
            continue
        dns_rules = settings.get("rules", [])
        if not isinstance(dns_rules, list):
            continue
        for rule in dns_rules:
            if isinstance(rule, dict):
                value = rule.get("qType")
                if isinstance(value, (int, float)) and not isinstance(value, bool) and value == 0:
                    return True
    return False


@dataclass
class Plan:
    proposed: dict
    expected_saved: dict
    changes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)


def build_plan(original: dict) -> Plan:
    if not isinstance(original, dict):
        raise IntegrationError("xraySetting must be a JSON object")
    cfg = copy.deepcopy(original)
    plan = Plan(proposed=cfg, expected_saved={})

    outbounds = object_list(cfg, "outbounds", "outbounds")
    dns_matches = [x for x in outbounds if x.get("tag") == "dns-out"]
    if len(dns_matches) > 1:
        plan.blockers.append("More than one outbound uses tag dns-out")
    elif not dns_matches:
        outbounds.append(copy.deepcopy(DNS_OUT))
        plan.changes.append("ADD outbounds[dns-out] (DNS outbound to 127.0.0.1:5355)")
    else:
        current = dns_matches[0]
        settings = current.get("settings")
        if (
            current.get("protocol") != "dns"
            or not isinstance(settings, dict)
            or any(settings.get(k) != v for k, v in DNS_OUT["settings"].items())
        ):
            plan.blockers.append("Existing dns-out has different settings; it will not be overwritten")

    dns = cfg.get("dns")
    if dns is None:
        dns = {}
        cfg["dns"] = dns
    if not isinstance(dns, dict):
        plan.blockers.append("dns is not an object")
        dns = {}
    servers = dns.setdefault("servers", [])
    if not isinstance(servers, list) or any(not isinstance(x, (dict, str)) for x in servers):
        plan.blockers.append("Invalid dns.servers; expected an array of objects or address strings")
        servers = []

    local_servers = []
    for server in servers:
        address = ""
        explicit_port = None
        if isinstance(server, str):
            address = server
        elif isinstance(server, dict):
            address = server.get("address", "") if isinstance(server.get("address", ""), str) else ""
            explicit_port = server.get("port")
        endpoint = _split_ip_address(address, explicit_port)
        if endpoint == ("127.0.0.1", 5355):
            local_servers.append(server)

    if len(local_servers) > 1:
        plan.blockers.append("Multiple DNS server entries already target 127.0.0.1:5355")
    elif not local_servers:
        old_groups = {port: ips for port, ips in _dns_private_groups(original)}
        if 5355 in old_groups:
            plan.blockers.append(
                "Panel groups private DNS allow-rules by port; adding 127.0.0.1:5355 would rewrite an existing port-5355 allow-rule"
            )
        servers.append(copy.deepcopy(DNS_SERVER))
        plan.changes.append("ADD dns.servers entry 127.0.0.1:5355")
    else:
        existing = local_servers[0]
        if isinstance(existing, dict) and existing.get("domains"):
            plan.blockers.append(
                "Existing 127.0.0.1:5355 DNS server is domain-scoped; it will not be replaced or duplicated"
            )
        else:
            plan.warnings.append("DNS server 127.0.0.1:5355 already exists; preserved unchanged")

    routing = cfg.get("routing")
    if routing is None:
        routing = {}
        cfg["routing"] = routing
    if not isinstance(routing, dict):
        plan.blockers.append("routing is not an object")
        routing = {}
    rules = object_list(routing, "rules", "routing.rules")

    api_indexes = [i for i, rule in enumerate(rules) if _is_api_rule(rule)]
    if len(api_indexes) != 1 or api_indexes[0] != 0:
        plan.blockers.append(
            "LucX-UI requires its api-inbound -> api-outbound rule at routing.rules[0]; the panel would add or move it during save"
        )

    if _has_numeric_qtype_zero(original):
        plan.blockers.append(
            "Panel save would rewrite an existing numeric DNS qType 0 to string '0'; refusing to change an unrelated DNS setting"
        )

    # Verify that the panel's own DNS-rule synchronization would not remove,
    # reorder, or rewrite an existing routing rule before this tool submits.
    try:
        after_normalized = panel_normalize_dns_allow_rules(cfg)
        before_rules = original.get("routing", {}).get("rules", []) if isinstance(original.get("routing"), dict) else []
        after_before_rules = after_normalized.get("routing", {}).get("rules", []) if isinstance(after_normalized.get("routing"), dict) else []
        cursor = 0
        for old_rule in before_rules:
            while cursor < len(after_before_rules) and canonical(after_before_rules[cursor]) != canonical(old_rule):
                cursor += 1
            if cursor >= len(after_before_rules):
                plan.blockers.append(
                    "Panel DNS synchronization would rewrite or remove an existing routing rule; manual review required"
                )
                break
            cursor += 1
    except IntegrationError as exc:
        plan.blockers.append(str(exc))

    # The panel creates its own xui-dns-allow exception for private DNS
    # endpoints. This tool never creates, edits, or moves that managed rule.
    # We only verify that a required direct outbound exists for that rule.
    private_block_exists = any(
        rule.get("outboundTag") == "blocked"
        and any(x.lower() == "geoip:private" for x in _ip_values(rule.get("ip")))
        for rule in rules
    )
    if private_block_exists:
        direct_matches = [x for x in outbounds if x.get("tag") == "direct"]
        if len(direct_matches) != 1:
            plan.blockers.append(
                "A private-IP block exists, but there is not exactly one direct outbound for the panel-managed DNS exception"
            )

    broad_port53 = [
        (i, rule) for i, rule in enumerate(rules)
        if _global_port53_rule(rule)
    ]
    if len(broad_port53) > 1:
        plan.blockers.append("Multiple global TCP/UDP port-53 rules exist; routing order is ambiguous")
    elif broad_port53:
        index, rule = broad_port53[0]
        target = rule.get("outboundTag")
        if target != "dns-out":
            plan.blockers.append(
                "An existing global TCP/UDP port-53 rule routes to another outbound; it will not be overwritten"
            )
        elif index != 1:
            plan.blockers.append(
                "The global port-53 -> dns-out rule is not immediately after the panel API rule; it will not be moved"
            )
        else:
            plan.warnings.append("Global TCP/UDP port-53 -> dns-out rule already exists; preserved unchanged")
    else:
        if api_indexes == [0]:
            rules.insert(1, copy.deepcopy(DNS_PORT_RULE))
            plan.changes.append(
                "ADD global TCP/UDP port 53 -> dns-out at routing.rules[1] (covers every inbound/tunnel)"
            )

    # The panel's save pipeline also normalizes its managed DNS exception.
    # Predict that panel-owned addition so read-back can be verified exactly.
    try:
        plan.expected_saved = panel_normalize_dns_allow_rules(cfg)
        if canonical(plan.expected_saved) != canonical(cfg):
            plan.changes.append(
                "PANEL-MANAGED: LucX-UI will add/reconcile its xui-dns-allow exception for private DNS servers"
            )
        expected_rules = plan.expected_saved.get("routing", {}).get("rules", [])
        if private_block_exists:
            managed = [
                rule for rule in expected_rules
                if rule.get("ruleTag") == DNS_ALLOW_TAG
                and rule.get("port") == "5355"
                and "127.0.0.1" in _ip_values(rule.get("ip"))
            ]
            if not managed:
                plan.blockers.append(
                    "Panel normalization did not produce the expected xui-dns-allow rule for 127.0.0.1:5355"
                )
            else:
                plan.warnings.append(
                    "LucX-UI will manage xui-dns-allow for 127.0.0.1:5355 before geoip:private; the adapter will not write this rule itself"
                )
        elif local_servers or any(
            isinstance(s, dict) and s.get("address") == "127.0.0.1" and str(s.get("port")) == "5355"
            for s in servers
        ):
            plan.warnings.append(
                "No geoip:private block rule exists; LucX-UI will not generate xui-dns-allow because no such exception is needed by its save hook"
            )
    except IntegrationError as exc:
        plan.blockers.append(str(exc))

    return plan


def _is_subsequence(old: list, new: list) -> bool:
    cursor = 0
    for item in new:
        if cursor < len(old) and canonical(old[cursor]) == canonical(item):
            cursor += 1
    return cursor == len(old)


def parse_api_response(body: bytes) -> dict:
    try:
        envelope = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise IntegrationError("Panel API returned invalid JSON") from None
    if not isinstance(envelope, dict) or envelope.get("success") is not True:
        raise IntegrationError("Panel API reported an unsuccessful request")
    return envelope


class PanelAPI:
    def __init__(self, base_url: str, token: str, timeout: float = 15.0, allow_insecure_http: bool = False):
        parsed = urlsplit(base_url)
        if parsed.scheme not in {"https", "http"} or not parsed.netloc:
            raise IntegrationError("--base-url must be an absolute http(s) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise IntegrationError("--base-url must not contain credentials, query, or fragment")
        if parsed.scheme == "http" and not allow_insecure_http:
            try:
                loopback = ipaddress.ip_address(parsed.hostname).is_loopback
            except ValueError:
                loopback = parsed.hostname in {"localhost"}
            if not loopback:
                raise IntegrationError("Plain HTTP is refused for non-loopback hosts; use HTTPS or --allow-insecure-http")
        self.root = urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))
        self.token = token
        self.timeout = timeout

    def _post(self, suffix: str, fields: dict[str, str] | None = None) -> dict:
        url = self.root + "/panel/api/xray/" + suffix
        data = urlencode(fields or {}).encode("utf-8")
        request = Request(
            url,
            data=data,
            method="POST",
            headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "lucx-ui-doh-api/" + VERSION,
            },
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            raise IntegrationError(f"Panel API HTTP error ({exc.code}); response body suppressed") from None
        except (URLError, TimeoutError, OSError):
            raise IntegrationError("Could not reach the panel API; network details suppressed") from None
        if len(body) > MAX_RESPONSE_BYTES:
            raise IntegrationError("Panel API response exceeded the size limit")
        return parse_api_response(body)

    def get_snapshot(self) -> dict:
        envelope = self._post("")
        payload = envelope.get("obj")
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                raise IntegrationError("Panel returned an invalid xray settings payload") from None
        if not isinstance(payload, dict):
            raise IntegrationError("Panel response does not contain the xray settings object")
        raw_config = payload.get("xraySetting")
        if isinstance(raw_config, str):
            try:
                raw_config = json.loads(raw_config)
            except json.JSONDecodeError:
                raise IntegrationError("Panel returned invalid xraySetting JSON") from None
        if not isinstance(raw_config, dict):
            raise IntegrationError("Panel response does not contain an xraySetting object")
        test_url = payload.get("outboundTestUrl")
        if not isinstance(test_url, str) or not test_url.strip():
            raise IntegrationError("Panel did not return outboundTestUrl; refusing to overwrite panel metadata")
        return {"xraySetting": raw_config, "outboundTestUrl": test_url}

    def update(self, config: dict, outbound_test_url: str) -> None:
        fields = {
            "xraySetting": json.dumps(config, ensure_ascii=False, separators=(",", ":")),
            "outboundTestUrl": outbound_test_url,
        }
        self._post("update", fields)


def _default_backup_dir() -> Path:
    return Path.home() / ".local" / "state" / "lucx-ui-doh" / "backups"


def _write_private_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    fd, tmp_name = tempfile.mkstemp(prefix=".doh-backup-", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def create_backup(snapshot: dict, backup_dir: Path) -> Path:
    backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(backup_dir, 0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = backup_dir / f"lucx-doh-{stamp}-{secrets.token_hex(3)}.json"
    data = {
        "format": 1,
        "tool_version": VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "before": snapshot,
        "after": None,
        "state": "before-update",
    }
    _write_private_json(path, data)
    return path


def load_backup(path: Path) -> dict:
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            raise IntegrationError("Backup permissions are broader than 0600; refusing to read it")
        data = json.loads(path.read_text(encoding="utf-8"))
    except IntegrationError:
        raise
    except (OSError, json.JSONDecodeError):
        raise IntegrationError("Cannot read backup file") from None
    if not isinstance(data, dict) or data.get("format") != 1:
        raise IntegrationError("Unsupported or invalid backup file")
    if not isinstance(data.get("before"), dict):
        raise IntegrationError("Backup does not contain a valid pre-update snapshot")
    return data


def confirm_restart(action: str, approved_flag: bool) -> None:
    print()
    print("WARNING: submitting DNS changes through the LucX-UI API can cause a full Xray process restart")
    print("when Xray is running. This tool will not restart Xray directly.")
    if approved_flag:
        return
    if not sys.stdin.isatty():
        raise IntegrationError(f"Non-interactive apply requires --approve-restart for {action}")
    expected = "APPLY" if action == "apply" else "ROLLBACK"
    entered = input(f"Type {expected} to continue: ").strip()
    if entered != expected:
        raise IntegrationError("Operator confirmation did not match; no API update was sent")


def print_plan(plan: Plan) -> None:
    if plan.changes:
        print("Proposed additions:")
        for change in plan.changes:
            print("  + " + change)
    else:
        print("No DNS integration additions are required.")
    for warning in plan.warnings:
        print("  NOTE: " + warning)
    for blocker in plan.blockers:
        print("  BLOCK: " + blocker)
    if plan.blockers:
        print("Result: NOT SAFE TO APPLY automatically")
    elif plan.changes:
        print("Result: additive plan ready")
    else:
        print("Result: already integrated; no update or restart required")


def _snapshot_equal(a: dict, b: dict) -> bool:
    return (
        canonical(a.get("xraySetting")) == canonical(b.get("xraySetting"))
        and a.get("outboundTestUrl") == b.get("outboundTestUrl")
    )


def command_check_or_plan(args, client: PanelAPI) -> int:
    snapshot = client.get_snapshot()
    plan = build_plan(snapshot["xraySetting"])
    print("Source: LucX-UI panel API")
    print("Mode: CHECK / READ-ONLY FROM ADAPTER")
    print("SQLite and runtime Xray files are not opened.")
    print_plan(plan)
    return 2 if plan.blockers else 0


def command_apply(args, client: PanelAPI) -> int:
    snapshot = client.get_snapshot()
    plan = build_plan(snapshot["xraySetting"])
    print_plan(plan)
    if plan.blockers:
        return 2
    if not plan.changes:
        print("No API update sent; Xray was not restarted.")
        return 0

    confirm_restart("apply", args.approve_restart)
    backup_path = create_backup(snapshot, Path(args.backup_dir).expanduser())
    print("Private backup created (mode 0600):", backup_path)

    api_error = None
    try:
        client.update(plan.proposed, snapshot["outboundTestUrl"])
    except IntegrationError as exc:
        api_error = str(exc)

    try:
        after = client.get_snapshot()
    except IntegrationError:
        print("ERROR: read-back verification could not be completed.")
        print("The pre-update backup is preserved; do not retry blindly.")
        print("Backup:", backup_path)
        if api_error:
            print("API update result: " + api_error)
        return 2

    backup_data = load_backup(backup_path)
    backup_data["after"] = after
    backup_data["state"] = "update-attempted"
    _write_private_json(backup_path, backup_data)

    expected = plan.expected_saved
    if canonical(after["xraySetting"]) != canonical(expected):
        print("ERROR: panel read-back differs from the predicted additive result.")
        print("No automatic rollback was attempted.")
        print("Review the panel state; guarded rollback is available only while the current template still matches the saved after-snapshot.")
        print("Backup:", backup_path)
        if api_error:
            print("API update result: " + api_error)
        return 2

    backup_data["state"] = "applied-and-verified"
    _write_private_json(backup_path, backup_data)
    if api_error:
        print("ERROR: panel returned an update error although read-back matches the proposed configuration.")
        print("Check panel/Xray status before taking further action.")
        print("Backup:", backup_path)
        return 2

    print("PASS: panel API read-back matches the predicted additive configuration.")
    print("Existing outbounds, DNS entries, and user routing rules were preserved by the predicted transformation.")
    print("Backup:", backup_path)
    print("Check Xray status in LucX-UI; a running core may have been fully restarted by the panel.")
    return 0


def command_rollback(args, client: PanelAPI) -> int:
    backup_path = Path(args.backup).expanduser()
    backup_data = load_backup(backup_path)
    after = backup_data.get("after")
    if not isinstance(after, dict):
        raise IntegrationError("Backup has no verified after-snapshot; guarded rollback is unavailable")
    current = client.get_snapshot()
    if not _snapshot_equal(current, after):
        raise IntegrationError(
            "Current panel settings differ from the backup after-snapshot; rollback refused to avoid overwriting later changes"
        )

    before = backup_data["before"]
    confirm_restart("rollback", args.approve_restart)
    try:
        client.update(before["xraySetting"], before["outboundTestUrl"])
    except IntegrationError as exc:
        print("ERROR: panel reported a rollback update error: " + str(exc))
        print("The backup remains available:", backup_path)
        return 2

    restored = client.get_snapshot()
    expected = panel_normalize_dns_allow_rules(before["xraySetting"])
    if canonical(restored["xraySetting"]) != canonical(expected):
        print("ERROR: rollback read-back differs from the expected panel-normalized pre-update configuration.")
        print("No further update was sent. Backup:", backup_path)
        return 2

    backup_data["state"] = "rolled-back"
    backup_data["rollback_snapshot"] = restored
    _write_private_json(backup_path, backup_data)
    print("PASS: guarded rollback verified through the panel API.")
    print("The panel may have fully restarted Xray while restoring DNS settings.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Safe additive DoH integration for LucX-UI using its panel API"
    )
    parser.add_argument("--base-url", required=True, help="Panel origin plus any web base path; do not append /panel/api")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--allow-insecure-http", action="store_true", help="Allow non-loopback HTTP (not recommended)")
    parser.add_argument(
        "--backup-dir",
        default=str(_default_backup_dir()),
        help="Local directory for 0600 backups (default: user state directory)",
    )
    parser.add_argument(
        "--approve-restart",
        action="store_true",
        help="Explicitly approve the full Xray restart that the panel API may perform",
    )
    parser.add_argument("action", choices=("check", "plan", "apply", "rollback"))
    parser.add_argument("--backup", help="Backup file required for rollback")
    args = parser.parse_args()

    if args.action == "rollback" and not args.backup:
        parser.error("rollback requires --backup")

    if not sys.stdin.isatty():
        print("ERROR: API token must be entered through a TTY with hidden input.", file=sys.stderr)
        return 2
    token = getpass.getpass("LucX-UI Bearer API token (hidden): ").strip()
    if not token:
        print("ERROR: empty API token", file=sys.stderr)
        return 2

    try:
        client = PanelAPI(
            args.base_url,
            token,
            timeout=args.timeout,
            allow_insecure_http=args.allow_insecure_http,
        )
        if args.action in {"check", "plan"}:
            return command_check_or_plan(args, client)
        if args.action == "apply":
            return command_apply(args, client)
        return command_rollback(args, client)
    except IntegrationError as exc:
        print("ERROR:", exc, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nInterrupted; no additional action was taken.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
