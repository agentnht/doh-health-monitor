"""Pure Xray DNS-path inventory and additive planning.

This module has no panel/API/SQLite side effects. It treats existing objects as
reusable only when their behavior matches the requested local DoH endpoint.
Conflicting user objects are preserved and reported, never rewritten.
"""
from __future__ import annotations

import argparse
import copy
import ipaddress
import json
import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any

DNS_ADDRESS = "127.0.0.1"
DNS_PORT = 5355
DNS_OUT_TEMPLATE = {
    "tag": "dns-out",
    "protocol": "dns",
    "settings": {
        "rewriteNetwork": "udp",
        "rewriteAddress": DNS_ADDRESS,
        "rewritePort": DNS_PORT,
    },
}
DNS_SERVER_TEMPLATE = {
    "address": DNS_ADDRESS,
    "port": DNS_PORT,
    "domains": [],
    "skipFallback": False,
}
DNS_ROUTE_RULE_TEMPLATE = {
    "enabled": True,
    "network": "tcp,udp",
    "port": "53",
    "type": "field",
}


@dataclass
class DNSPlan:
    proposed: dict[str, Any]
    changes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    outbound_tag: str | None = None
    outbound_created: bool = False
    routing_rule_tag: str | None = None
    routing_rule_created: bool = False
    dns_server_created: bool = False


def _object_list(
    parent: dict[str, Any],
    key: str,
    description: str,
    *,
    create: bool = True,
) -> list[dict[str, Any]]:
    if key not in parent and create:
        parent[key] = []
    value = parent.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ValueError(f"Invalid {description}: expected an array of objects")
    return value


def _tokens(value: Any) -> set[str]:
    if isinstance(value, str):
        return {part.strip().lower() for part in value.split(",") if part.strip()}
    if isinstance(value, list):
        return {str(part).strip().lower() for part in value if str(part).strip()}
    return set()


def _port_contains_53(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value == 53
    if not isinstance(value, str) or not value.strip():
        return False
    for part in value.split(","):
        token = part.strip()
        if not token:
            continue
        if "-" in token:
            left, sep, right = token.partition("-")
            if not sep:
                return True
            try:
                start, end = int(left), int(right)
            except ValueError:
                return True  # Unknown selector: conservatively treat as overlap.
            if start <= 53 <= end:
                return True
        else:
            try:
                if int(token) == 53:
                    return True
            except ValueError:
                return True
    return False


def _network_intersects_dns(value: Any) -> bool:
    if value in (None, "", []):
        return True  # Xray's omitted network selector is not a TCP/UDP exclusion.
    networks = _tokens(value)
    if not networks:
        return True
    return bool(networks.intersection({"tcp", "udp"})) or not networks.issubset(
        {"tcp", "udp", "quic"}
    )


def rule_may_match_port53(rule: dict[str, Any]) -> bool:
    """Conservative TCP/UDP port-53 overlap test for routing-order analysis."""
    if rule.get("enabled") is False:
        return False
    if "port" not in rule or not _port_contains_53(rule.get("port")):
        return False
    return _network_intersects_dns(rule.get("network"))


def _global_port53_rule(rule: dict[str, Any]) -> bool:
    if rule.get("enabled") is False or rule.get("type", "field") != "field":
        return False
    if not _port_contains_53(rule.get("port")):
        return False
    port = rule.get("port")
    if isinstance(port, str) and port.strip() != "53":
        return False
    if isinstance(port, bool) or (isinstance(port, int) and port != 53):
        return False
    networks = _tokens(rule.get("network"))
    if networks and networks != {"tcp", "udp"}:
        return False
    allowed = {
        "type", "ruleTag", "enabled", "network", "port",
        "outboundTag", "balancerTag", "remarks", "comment",
    }
    has_outbound = isinstance(rule.get("outboundTag"), str) and bool(rule.get("outboundTag"))
    has_balancer = isinstance(rule.get("balancerTag"), str) and bool(rule.get("balancerTag"))
    # Xray gives outboundTag precedence if both are present.
    return (has_outbound or has_balancer) and not any(
        key not in allowed for key in rule
    )


def _global_protocol_port53_rule(rule: dict[str, Any]) -> bool:
    """Whether an unscoped rule captures at least one DNS transport on port 53."""
    if not rule_may_match_port53(rule) or rule.get("type", "field") != "field":
        return False
    allowed = {
        "type", "ruleTag", "enabled", "network", "port",
        "outboundTag", "balancerTag", "remarks", "comment",
    }
    if any(key not in allowed for key in rule):
        return False
    networks = _tokens(rule.get("network"))
    return not networks or bool(networks.intersection({"tcp", "udp"}))


def _global_port53_overlap(rule: dict[str, Any]) -> bool:
    """Whether a rule globally covers TCP+UDP port 53, including ranges."""
    if not rule_may_match_port53(rule) or rule.get("type", "field") != "field":
        return False
    networks = _tokens(rule.get("network", "tcp,udp"))
    if networks and not {"tcp", "udp"}.issubset(networks):
        return False
    allowed = {
        "type", "ruleTag", "enabled", "network", "port",
        "outboundTag", "balancerTag", "remarks", "comment",
    }
    return not any(key not in allowed for key in rule)


def _outbound_matches_dns_endpoint(item: dict[str, Any]) -> bool:
    """Return true only when the outbound's effective DNS behavior is the local plugin."""
    if item.get("protocol") != "dns":
        return False
    settings = item.get("settings")
    if not isinstance(settings, dict):
        return False
    # Do not reuse an outbound with unmodeled routing/transport fields. Known
    # DNS filtering options are checked below; unrelated behavioral settings
    # make its effective behavior uncertain.
    allowed_top_level = {
        "tag", "protocol", "settings", "sendThrough", "streamSettings",
        "proxySettings", "mux", "userLevel",
    }
    if set(item) - allowed_top_level:
        return False
    allowed_settings = {
        "rewriteNetwork", "rewriteAddress", "rewritePort",
        "rules", "blockTypes", "nonIPQuery", "userLevel",
    }
    if set(settings) - allowed_settings:
        return False
    if settings.get("rewriteAddress") != DNS_ADDRESS:
        return False
    try:
        rewrite_port = int(settings.get("rewritePort"))
    except (TypeError, ValueError):
        return False
    if rewrite_port != DNS_PORT:
        return False
    rewrite_network = settings.get("rewriteNetwork")
    if rewrite_network is not None and str(rewrite_network).lower() not in {"tcp", "udp"}:
        return False

    # DNS-outbound rules can hijack, drop, or synthesize selected answers.
    # Such an outbound is not a general replacement for this integration path.
    dns_rules = settings.get("rules", [])
    if not isinstance(dns_rules, list):
        return False
    for rule in dns_rules:
        if not isinstance(rule, dict) or rule.get("action") != "direct":
            return False
        # A direct rule restricted by qType/domain is only a partial match;
        # the DNS outbound's fallback would handle the remaining queries
        # differently. Do not treat a restricted rule as a general DoH path.
        qtype = rule.get("qType", rule.get("qtype"))
        domain = rule.get("domain")
        if qtype not in (None, "", []) or domain not in (None, "", []):
            return False
        if set(rule) - {"action", "rCode"}:
            return False
    if settings.get("blockTypes"):
        return False
    if settings.get("nonIPQuery") not in (None, "", "direct"):
        return False

    # A proxy chain or transport override can change where the DNS connection
    # actually goes even though the rewrite endpoint fields look correct.
    if item.get("proxySettings") or item.get("streamSettings") or item.get("mux"):
        return False
    send_through = item.get("sendThrough")
    if send_through:
        try:
            if not ipaddress.ip_address(str(send_through)).is_loopback:
                return False
        except ValueError:
            return False
    return True


def _unique_tag(
    preferred: str,
    used: set[str],
    forbidden_prefixes: tuple[str, ...] = (),
) -> str | None:
    """Choose a globally unused tag that cannot be captured by a balancer selector."""
    bases = (
        preferred,
        preferred + "-doh-health-monitor",
        "doh-health-monitor-" + preferred,
        "xray-" + preferred,
        "custom-" + preferred,
    )
    prefixes = tuple(prefix for prefix in forbidden_prefixes if prefix)
    if any(not prefix for prefix in forbidden_prefixes):
        return None
    for base in bases:
        if base not in used and not any(base.startswith(prefix) for prefix in prefixes):
            return base
    for base in bases:
        for suffix in range(2, 1000):
            candidate = f"{base}-{suffix}"
            if candidate not in used and not any(candidate.startswith(prefix) for prefix in prefixes):
                return candidate
    return None


def _server_endpoint(server: Any) -> tuple[str, int] | None:
    if isinstance(server, str):
        # Accept bare IPv4/IPv6 addresses, bracketed IPv6 host:port, and
        # ordinary IPv4 host:port without confusing an IPv6 literal's colons.
        if server.startswith("[") and "]:" in server:
            close = server.index("]:")
            host, port_text = server[1:close], server[close + 2:]
        elif server.count(":") == 1:
            host, port_text = server.rsplit(":", 1)
        else:
            host, port_text = server.strip("[]"), "53"
        try:
            return str(ipaddress.ip_address(host.strip("[]"))), int(port_text)
        except (ValueError, TypeError):
            return None
    if isinstance(server, dict):
        address = server.get("address")
        if not isinstance(address, str):
            return None
        # Some Xray templates encode an explicit port in address rather than
        # a separate port member. Recognize both forms without broad matching.
        explicit_port = server.get("port")
        if address.startswith("[") and "]:" in address and explicit_port is None:
            close = address.index("]:")
            port_value: Any = address[close + 2:]
            address = address[1:close]
        elif address.count(":") == 1 and explicit_port is None:
            host, embedded_port = address.rsplit(":", 1)
            address = host
            port_value = embedded_port
        else:
            address = address.strip("[]")
            port_value = 53 if explicit_port is None else explicit_port
        try:
            return str(ipaddress.ip_address(address)), int(port_value)
        except (ValueError, TypeError):
            return None
    return None


def _server_is_general(server: Any) -> bool:
    """Whether a local DNS server entry is an unrestricted fallback candidate."""
    if isinstance(server, str):
        return True
    if not isinstance(server, dict):
        return False
    if server.get("domains") not in (None, [], ""):
        return False
    if server.get("skipFallback") is True:
        return False
    # These fields can restrict which query results the server may return or
    # which address family is queried; preserve such entries as scoped objects.
    strategy = server.get("queryStrategy")
    if strategy not in (None, "", "UseIP"):
        return False
    for key in ("expectedIPs", "expectIPs", "unexpectedIPs"):
        if server.get(key) not in (None, [], ""):
            return False
    return True


def _rule_may_match_loopback_dns_without_port(rule: dict[str, Any]) -> bool:
    """Whether a no-port rule could catch the rewritten 127.0.0.1:53 traffic."""
    if rule.get("enabled") is False or "port" in rule:
        return False
    if rule.get("type", "field") != "field":
        return True
    # Domain-only rules cannot match the rewritten literal loopback destination.
    if "domain" in rule and not any(
        key in rule for key in ("ip", "source", "sourcePort", "inboundTag", "user", "attrs")
    ):
        return False
    ip_values = rule.get("ip")
    if isinstance(ip_values, list) and ip_values:
        for value in ip_values:
            if not isinstance(value, str):
                return True
            lowered = value.lower()
            if lowered in {"geoip:private", "geoip:loopback"}:
                return True
            try:
                if ipaddress.ip_address(value) == ipaddress.ip_address(DNS_ADDRESS):
                    return True
            except ValueError:
                try:
                    if ipaddress.ip_address(DNS_ADDRESS) in ipaddress.ip_network(value, strict=False):
                        return True
                except ValueError:
                    return True
        return False
    # A rule with no destination selector, or another selector type, may be broad.
    return True


def _validate_outbound_tag_index(
    outbounds: list[dict[str, Any]],
    balancers: list[dict[str, Any]],
    inbounds: list[dict[str, Any]],
    api_tag: str | None,
    dns_tags: list[tuple[str, str]],
    routing_tags: list[tuple[str, str]],
) -> tuple[dict[str, dict[str, Any]], set[str], list[str]]:
    """Index target namespaces and reserve every existing tag for new names."""
    index: dict[str, dict[str, Any]] = {}
    used: set[str] = set()
    blockers: list[str] = []

    # Routing references are typed (inboundTag vs outboundTag vs balancerTag),
    # so identical text across different namespaces is not itself a conflict.
    # Generated names are still globally unique across every namespace.
    for item in inbounds:
        tag = item.get("tag")
        if isinstance(tag, str) and tag:
            used.add(tag)

    for item in outbounds:
        tag = item.get("tag")
        if not isinstance(tag, str) or not tag:
            continue
        used.add(tag)
        if tag in index:
            blockers.append(f"Duplicate outbound tag {tag!r}; outboundTag references are ambiguous")
        else:
            index[tag] = item

    balancer_tags: set[str] = set()
    for item in balancers:
        tag = item.get("tag")
        if not isinstance(tag, str) or not tag:
            continue
        used.add(tag)
        if tag in balancer_tags:
            blockers.append(f"Duplicate balancer tag {tag!r}; balancerTag references are ambiguous")
        balancer_tags.add(tag)

    if isinstance(api_tag, str) and api_tag:
        # api.tag aliases the panel API inbound tag; reserve, do not double-count.
        used.add(api_tag)
    for _namespace, tag in dns_tags + routing_tags:
        if tag:
            used.add(tag)

    return index, used, blockers

def _resolve_balancer_dns_targets(
    balancer_tag: str,
    balancers: list[dict[str, Any]],
    outbound_index: dict[str, dict[str, Any]],
) -> tuple[list[str], str | None]:
    """Resolve a balancer only when every selected outbound reaches local DoH."""
    matches = [item for item in balancers if item.get("tag") == balancer_tag]
    if len(matches) != 1:
        return [], f"Balancer tag {balancer_tag!r} is missing or ambiguous"
    selector = matches[0].get("selector", [])
    if isinstance(selector, str):
        selector = [selector]
    if not isinstance(selector, list) or not selector or any(
        not isinstance(value, str) or not value for value in selector
    ):
        return [], f"Balancer {balancer_tag!r} has no valid selector list"
    selected = [
        tag for tag in outbound_index
        if any(tag.startswith(prefix) for prefix in selector)
    ]
    fallback = matches[0].get("fallbackTag")
    if fallback:
        if not isinstance(fallback, str) or fallback not in outbound_index:
            return [], f"Balancer {balancer_tag!r} has a missing fallbackTag"
        if fallback not in selected:
            selected.append(fallback)
    if not selected:
        return [], f"Balancer {balancer_tag!r} selects no configured outbounds"
    incompatible = [
        tag for tag in selected
        if not _outbound_matches_dns_endpoint(outbound_index[tag])
    ]
    if incompatible:
        return [], (
            f"Balancer {balancer_tag!r} selects outbound(s) that do not all resolve to "
            f"{DNS_ADDRESS}:{DNS_PORT}: {', '.join(incompatible)}"
        )
    return selected, None


def build_dns_plan(original: dict[str, Any]) -> DNSPlan:
    """Analyze current Xray settings and add only the missing local DoH path."""
    if not isinstance(original, dict):
        raise ValueError("Xray config root must be an object")
    cfg = copy.deepcopy(original)
    plan = DNSPlan(proposed=cfg)

    outbounds = _object_list(cfg, "outbounds", "outbounds")
    routing = cfg.get("routing")
    if routing is None:
        routing = {}
        cfg["routing"] = routing
    if not isinstance(routing, dict):
        plan.blockers.append("routing must be an object")
        plan.proposed = copy.deepcopy(original)
        return plan
    rules = _object_list(routing, "rules", "routing.rules")
    balancers = _object_list(routing, "balancers", "routing.balancers", create=False)

    # Reserve tags across all namespaces before selecting generated identifiers.
    inbounds = cfg.get("inbounds", [])
    if not isinstance(inbounds, list) or any(not isinstance(item, dict) for item in inbounds):
        plan.blockers.append("inbounds must be an array of objects")
        inbounds = []
    api_section = cfg.get("api", {})
    api_tag = api_section.get("tag") if isinstance(api_section, dict) else None
    dns_section = cfg.get("dns", {})
    dns_tags: list[tuple[str, str]] = []
    if isinstance(dns_section, dict):
        dns_tag = dns_section.get("tag")
        if isinstance(dns_tag, str) and dns_tag:
            dns_tags.append(("dns", dns_tag))
        existing_servers = dns_section.get("servers", [])
        if isinstance(existing_servers, list):
            for server in existing_servers:
                if isinstance(server, dict):
                    server_tag = server.get("tag")
                    if isinstance(server_tag, str) and server_tag:
                        dns_tags.append(("dns server", server_tag))
    routing_tags: list[tuple[str, str]] = []
    for rule in rules:
        for key in ("tag", "ruleTag"):
            value = rule.get(key)
            if isinstance(value, str) and value:
                routing_tags.append((f"routing rule {key}", value))
        # Reserve references too, even when currently dangling. Otherwise a
        # generated outbound could accidentally make a user's broken reference
        # begin resolving and silently change unrelated routing behavior.
        for key in ("inboundTag", "outboundTag", "balancerTag"):
            value = rule.get(key)
            values = [value] if isinstance(value, str) else value if isinstance(value, list) else []
            for tag in values:
                if isinstance(tag, str) and tag:
                    routing_tags.append((f"routing rule {key} reference", tag))

    # Balancer fallbackTag is a reference, not a definition, but must still be
    # reserved from generated names.
    for balancer in balancers:
        fallback = balancer.get("fallbackTag")
        if isinstance(fallback, str) and fallback:
            routing_tags.append(("balancer fallbackTag reference", fallback))

    outbound_index, used_tags, tag_blockers = _validate_outbound_tag_index(
        outbounds,
        balancers,
        inbounds,
        api_tag if isinstance(api_tag, str) else None,
        dns_tags,
        routing_tags,
    )
    plan.blockers.extend(tag_blockers)

    balancer_selectors = tuple(
        selector
        for owner in (balancers, [cfg.get("observatory", {})], [cfg.get("burstObservatory", {})])
        for item in owner
        if isinstance(item, dict)
        for selector in (
            item.get("selector", item.get("subjectSelector", []))
            if isinstance(item.get("selector", item.get("subjectSelector", [])), list)
            else [item.get("selector", item.get("subjectSelector"))]
        )
        if isinstance(selector, str)
    )

    reverse = cfg.get("reverse", {})
    if isinstance(reverse, dict):
        for key in ("bridges", "portals"):
            entries = reverse.get(key, [])
            if isinstance(entries, list):
                for entry in entries:
                    if isinstance(entry, dict):
                        tag = entry.get("tag")
                        if isinstance(tag, str) and tag:
                            used_tags.add(tag)

    route_matches = [
        rule for rule in rules
        if _global_port53_rule(rule)
    ]

    chosen_tag: str | None = None
    compatible = {
        tag: item for tag, item in outbound_index.items()
        if _outbound_matches_dns_endpoint(item)
    }

    broad_compatible_routes: list[tuple[int, str]] = []
    partial_global_routes: list[tuple[int, set[str], str]] = []
    if not route_matches:
        # A globally scoped route that owns only TCP or UDP still intercepts
        # that transport before any later fallback. Reuse it only when it
        # already sends that transport to the local DNS service.
        for index, rule in enumerate(rules):
            if not _global_protocol_port53_rule(rule):
                continue
            if _global_port53_rule(rule) or _global_port53_overlap(rule):
                continue
            networks = _tokens(rule.get("network"))
            covered = networks.intersection({"tcp", "udp"})
            if not covered:
                continue
            target = rule.get("outboundTag")
            balancer = rule.get("balancerTag")
            resolved = None
            if isinstance(target, str):
                if target in compatible:
                    resolved = target
                else:
                    plan.blockers.append(
                        f"Existing global {','.join(sorted(covered))} port-53 rule at routing.rules[{index}] targets incompatible outbound {target!r}"
                    )
            elif isinstance(balancer, str):
                selected, error = _resolve_balancer_dns_targets(balancer, balancers, outbound_index)
                if error is None and selected:
                    # A new fallback uses a concrete compatible outbound,
                    # not a newly introduced balancerTag.
                    resolved = selected[0]
                else:
                    plan.blockers.append(
                        f"Existing global single-transport rule at routing.rules[{index}] does not have a compatible DNS balancer: {error}"
                    )
            else:
                plan.blockers.append(
                    f"Existing global {','.join(sorted(covered))} port-53 rule at routing.rules[{index}] has no valid outboundTag or balancerTag"
                )
            if resolved is not None:
                partial_global_routes.append((index, covered, resolved))

        # A broader port range that includes both TCP and UDP port 53 shadows
        # any later fallback. Reuse it only when its target is fully compatible.
        for index, rule in enumerate(rules):
            if not _global_port53_overlap(rule) or _global_port53_rule(rule):
                continue
            target = rule.get("outboundTag")
            balancer = rule.get("balancerTag")
            if isinstance(target, str):
                if target in compatible:
                    broad_compatible_routes.append((index, target))
                else:
                    plan.blockers.append(
                        f"Existing broad routing rule at routing.rules[{index}] uses incompatible outboundTag {target!r}; a new port-53 fallback would be shadowed and its balancerTag, if any, is not selected by Xray"
                    )
            elif isinstance(balancer, str):
                selected, error = _resolve_balancer_dns_targets(balancer, balancers, outbound_index)
                if error:
                    plan.blockers.append(
                        f"Existing broad routing rule at routing.rules[{index}] also matches port 53 but its balancer is not DNS-compatible: {error}"
                    )
                elif selected:
                    broad_compatible_routes.append((index, selected[0]))
            else:
                plan.blockers.append(
                    f"Existing broad routing rule at routing.rules[{index}] also matches port 53 but does not target a compatible local DNS outbound; adding a fallback would be shadowed"
                )

    route_path_covered = bool(route_matches)
    if route_matches:
        route = route_matches[0]
        route_index = rules.index(route)
        earlier_broad = [
            index for index, rule in enumerate(rules[:route_index])
            if index > 0 and _rule_may_match_loopback_dns_without_port(rule)
        ]
        if earlier_broad:
            plan.blockers.append(
                "An earlier broad routing rule can intercept rewritten loopback DNS before the existing port-53 route; manual review required"
            )
        # An earlier global range such as 53,443 also shadows an exact
        # port-53 rule. It is safe only when that earlier rule selects the
        # same compatible direct outbound or an entirely compatible balancer.
        for index, earlier in enumerate(rules[:route_index]):
            if not (
                _global_protocol_port53_rule(earlier)
                and not _global_port53_rule(earlier)
            ):
                continue
            earlier_target = earlier.get("outboundTag")
            earlier_balancer = earlier.get("balancerTag")
            resolved_target = None
            if isinstance(earlier_target, str):
                if earlier_target in compatible:
                    resolved_target = earlier_target
            elif isinstance(earlier_balancer, str):
                _selected, resolve_error = _resolve_balancer_dns_targets(
                    earlier_balancer, balancers, outbound_index
                )
                if resolve_error is None and _selected:
                    resolved_target = _selected[0]
            if resolved_target is None:
                plan.blockers.append(
                    f"Earlier global port-53-overlap rule at routing.rules[{index}] "
                    "shadows the exact port-53 route with an incompatible target"
                )
        resolved_route_targets: list[str] = []
        for route_index_in_list, existing_route in enumerate(route_matches):
            target_tag = existing_route.get("outboundTag")
            balancer_tag = existing_route.get("balancerTag")
            # Xray prioritizes outboundTag when both fields are present.
            if target_tag:
                if target_tag not in outbound_index:
                    plan.blockers.append(
                        f"Existing global port-53 rule references missing outbound tag {target_tag!r}"
                    )
                elif not _outbound_matches_dns_endpoint(outbound_index[target_tag]):
                    plan.blockers.append(
                        f"Existing global port-53 rule targets {target_tag!r}, whose outbound does not resolve to 127.0.0.1:5355; it will not be changed"
                    )
                else:
                    resolved_route_targets.append(target_tag)
            elif balancer_tag:
                _selected, error = _resolve_balancer_dns_targets(
                    balancer_tag, balancers, outbound_index
                )
                if error:
                    plan.blockers.append(
                        f"Existing global port-53 rule uses an incompatible balancer: {error}"
                    )
                else:
                    resolved_route_targets.append(_selected[0])
            else:
                plan.blockers.append(
                    f"Existing global port-53 rule #{route_index_in_list + 1} has no outboundTag or balancerTag"
                )

        if resolved_route_targets:
            # Different tags may still represent the same verified local DNS
            # behavior. Preserve all existing rules and reuse the first route;
            # do not add another catch-all rule for an already-covered path.
            chosen_tag = resolved_route_targets[0]
            plan.warnings.append(
                f"Existing global TCP/UDP port-53 route already provides the local DNS path via {chosen_tag!r}"
            )
            if len(route_matches) > 1:
                plan.warnings.append(
                    "Multiple global port-53 rules already exist; all were verified as compatible and are preserved unchanged"
                )
            if len(compatible) > 1:
                plan.warnings.append(
                    "Additional compatible DNS outbounds exist; existing route targets are reused and other outbounds are preserved"
                )
    else:
        scoped_targets: set[str] = set()
        scoped_target_order: list[str] = []
        for index, rule in enumerate(rules):
            if not rule_may_match_port53(rule):
                continue
            if rule.get("type", "field") != "field":
                plan.blockers.append(
                    f"routing.rules[{index}] uses an unsupported rule type for port-53 DNS traffic"
                )
                continue
            # Global rules are analyzed separately so TCP-only/UDP-only
            # ownership is not confused with an inbound-scoped exception.
            if _global_protocol_port53_rule(rule):
                continue
            target = rule.get("outboundTag")
            balancer = rule.get("balancerTag")
            if isinstance(target, str):
                if target in compatible:
                    scoped_targets.add(target)
                    if target not in scoped_target_order:
                        scoped_target_order.append(target)
            elif isinstance(balancer, str):
                selected, resolve_error = _resolve_balancer_dns_targets(
                    balancer, balancers, outbound_index
                )
                if resolve_error is None and selected:
                    resolved_target = selected[0]
                    scoped_targets.add(resolved_target)
                    if resolved_target not in scoped_target_order:
                        scoped_target_order.append(resolved_target)

        broad_targets = {target for _index, target in broad_compatible_routes}
        covered_transports = {
            protocol
            for _index, transports, _target in partial_global_routes
            for protocol in transports
        }
        route_path_covered = False
        if broad_targets:
            chosen_tag = min(broad_compatible_routes, key=lambda item: item[0])[1]
            route_path_covered = True
            plan.warnings.append(
                "One or more existing broad port-range rules already route TCP/UDP port 53 to compatible local DNS outbounds; all are preserved unchanged"
            )
            if len(broad_targets) > 1:
                plan.warnings.append(
                    "Multiple equivalent broad routes use different compatible outbound tags; the earliest route is the effective one"
                )
        elif {"tcp", "udp"}.issubset(covered_transports):
            route_path_covered = True
            plan.warnings.append(
                "Existing global TCP-only/UDP-only rules already cover both DNS transports through compatible local DNS targets; both rules are preserved"
            )
        elif partial_global_routes:
            chosen_tag = min(partial_global_routes, key=lambda item: item[0])[2]
            plan.warnings.append(
                "An existing global single-transport port-53 route is reused; the generated fallback will complete the other DNS transport"
            )
        elif scoped_targets:
            # Every member was independently verified to perform the same
            # local DNS operation. Reuse the first matching existing policy
            # target and preserve all scoped rules without rewriting them.
            # Keep the first compatible target in routing order. For a
            # balancer rule this is the resolved outbound tag, not balancerTag.
            chosen_tag = scoped_target_order[0]
            if len(scoped_targets) > 1:
                plan.warnings.append(
                    "Scoped port-53 rules use multiple equivalent local DNS targets; the first is reused for the global fallback"
                )
        elif compatible:
            # These are distinct tags but verified-equivalent DNS endpoints.
            # Reuse the first existing outbound rather than create a duplicate.
            chosen_tag = next(iter(compatible))
            if len(compatible) > 1:
                plan.warnings.append(
                    "Multiple compatible local DNS outbounds exist without a selecting route; the first is reused and all are preserved"
                )

    if chosen_tag is None and not plan.blockers and not route_path_covered:
        new_tag = _unique_tag("dns-out", used_tags, balancer_selectors)
        if new_tag is None:
            plan.blockers.append(
                "No safe unique DNS outbound tag is available outside existing balancer selector prefixes"
            )
        else:
            outbound = copy.deepcopy(DNS_OUT_TEMPLATE)
            outbound["tag"] = new_tag
            outbounds.append(outbound)
            used_tags.add(new_tag)
            chosen_tag = new_tag
            plan.outbound_created = True
            plan.changes.append(
                f"ADD outbounds[{new_tag}] (DNS outbound to {DNS_ADDRESS}:{DNS_PORT})"
            )

    plan.outbound_tag = chosen_tag

    # Reuse a general DNS server for the endpoint; do not widen a domain-scoped
    # entry by editing it, and do not create a duplicate alongside a scoped one.
    dns = cfg.get("dns")
    if dns is None:
        dns = {}
        cfg["dns"] = dns
    if not isinstance(dns, dict):
        plan.blockers.append("dns must be an object")
        plan.proposed = copy.deepcopy(original)
        plan.changes.clear()
        plan.outbound_created = False
        return plan
    servers = dns.get("servers", [])
    if not isinstance(servers, list) or any(not isinstance(item, (dict, str)) for item in servers):
        plan.blockers.append("dns.servers must be an array of objects or address strings")
        plan.proposed = copy.deepcopy(original)
        plan.changes.clear()
        plan.outbound_created = False
        return plan
    endpoint_matches = [
        item for item in servers
        if _server_endpoint(item) == (DNS_ADDRESS, DNS_PORT)
    ]
    general_matches = [item for item in endpoint_matches if _server_is_general(item)]
    if general_matches:
        plan.warnings.append("One or more existing general DNS server entries target 127.0.0.1:5355; all are reused unchanged")
        if len(general_matches) > 1:
            plan.warnings.append(
                "Duplicate general DNS server entries already exist; they are preserved and no additional entry is added"
            )
    elif endpoint_matches:
        plan.blockers.append(
            "127.0.0.1:5355 exists only as a scoped DNS server; adding a general entry could change DNS selection"
        )
    else:
        servers.append(copy.deepcopy(DNS_SERVER_TEMPLATE))
        dns["servers"] = servers
        plan.dns_server_created = True
        plan.changes.append("ADD dns.servers entry 127.0.0.1:5355")

    # Reuse an exact global route when it exists. Otherwise insert a new route
    # after narrower port-53 rules, but before generic rules that could swallow
    # the rewritten loopback DNS traffic. Existing rules are never moved.
    if not route_matches and not broad_compatible_routes and chosen_tag is not None and not route_path_covered:
        scoped_indexes = [
            index for index, rule in enumerate(rules)
            if rule_may_match_port53(rule)
        ]
        last_scoped = max(scoped_indexes, default=0)
        broad_indexes = [
            index for index, rule in enumerate(rules)
            if index > 0 and _rule_may_match_loopback_dns_without_port(rule)
        ]
        first_broad = min(broad_indexes, default=len(rules))
        insert_at = 0 if not rules else max(1, last_scoped + 1)
        if insert_at > first_broad:
            plan.blockers.append(
                "Existing routing order has a broad rule before the position needed for a safe port-53 route; manual review required"
            )
        else:
            used_rule_tags = set(used_tags)
            rule_tag = _unique_tag("doh-health-monitor-dns-port53", used_rule_tags)
            if rule_tag is None:
                plan.blockers.append("No unique routing ruleTag is available")
                rule_tag = None
            new_rule = copy.deepcopy(DNS_ROUTE_RULE_TEMPLATE)
            if rule_tag is not None:
                new_rule["outboundTag"] = chosen_tag
                new_rule["ruleTag"] = rule_tag
                rules.insert(insert_at, new_rule)
                plan.routing_rule_tag = rule_tag
                plan.routing_rule_created = True
                plan.changes.append(
                    f"ADD global TCP/UDP port-53 rule -> {chosen_tag} at routing.rules[{insert_at}] (ruleTag {rule_tag})"
                )
                if scoped_indexes:
                    plan.warnings.append(
                        "Existing scoped port-53 rules are preserved before the new global rule; their selected traffic keeps its configured routing"
                    )

    # Every port-53 rule target must resolve to exactly one existing outbound
    # or balancer. Unrelated rules are inventoried but not rewritten.
    for index, rule in enumerate(rules):
        if not rule_may_match_port53(rule):
            continue
        outbound_tag = rule.get("outboundTag")
        balancer_tag = rule.get("balancerTag")
        # Xray uses outboundTag first when both are supplied; only inspect
        # balancerTag when outboundTag is absent.
        if outbound_tag and outbound_tag not in outbound_index:
            # The newly generated target is already included in outbound_index only
            # when created after inventory; account for it explicitly.
            if outbound_tag != chosen_tag or not plan.outbound_created:
                plan.blockers.append(
                    f"routing.rules[{index}] references missing outbound tag {outbound_tag!r}"
                )
        elif not outbound_tag and balancer_tag and not any(item.get("tag") == balancer_tag for item in balancers):
            plan.blockers.append(
                f"routing.rules[{index}] references missing balancer tag {balancer_tag!r}"
            )
        elif not outbound_tag and not balancer_tag:
            plan.blockers.append(
                f"routing.rules[{index}] matches DNS port 53 but has no outboundTag or balancerTag"
            )

    if plan.blockers:
        # Do not present a partially viable proposal as executable.
        plan.proposed = copy.deepcopy(original)
        plan.changes.clear()
        plan.outbound_created = False
        plan.routing_rule_created = False
        plan.dns_server_created = False
        plan.routing_rule_tag = None
        plan.outbound_tag = None
    return plan

def main(argv: list[str] | None = None) -> int:
    """Read-only runtime/template check entry point used by the shell checker."""
    parser = argparse.ArgumentParser(
        description="Analyze an Xray config for the local DoH DNS path without writing it"
    )
    parser.add_argument("--check-config", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        config = json.loads(args.check_config.read_text(encoding="utf-8"))
        plan = build_dns_plan(config)
    except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
        print(f"ERROR: cannot analyze Xray config: {exc}", file=sys.stderr)
        return 2

    for warning in plan.warnings:
        print(f"NOTICE: {warning}")
    if plan.blockers:
        for blocker in plan.blockers:
            print(f"ERROR: {blocker}", file=sys.stderr)
        return 2
    if plan.changes:
        for change in plan.changes:
            print(f"MISSING: {change}")
        print("ERROR: Xray DNS path is incomplete; no changes were made.", file=sys.stderr)
        return 1

    print(
        f"PASS: existing Xray DNS routing and resolver configuration covers "
        f"TCP/UDP DNS to {DNS_ADDRESS}:{DNS_PORT}; no changes are required."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
