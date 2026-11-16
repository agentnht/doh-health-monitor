#!/usr/bin/env python3
"""Tests for the additive LucX-UI panel API integration adapter."""

from __future__ import annotations

import copy
import importlib.util
import json
import socket
import subprocess
import struct
import os
import stat
import sqlite3
import threading
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

ROOT = __import__("pathlib").Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "lucx-ui-doh-api.py"
spec = importlib.util.spec_from_file_location("lucx_ui_doh_api", SCRIPT)
api_tool = importlib.util.module_from_spec(spec)
assert spec and spec.loader
import sys
sys.modules[spec.name] = api_tool
spec.loader.exec_module(api_tool)


def base_config():
    return {
        "api": {"tag": "api"},
        "log": {"loglevel": "warning"},
        "outbounds": [
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "proxy", "protocol": "socks", "settings": {"servers": [{"address": "proxy.invalid"}]}},
            {"tag": "WARP", "protocol": "wireguard", "settings": {"secretKey": "fixture-only"}},
            {"tag": "psiphon-out", "protocol": "socks", "settings": {"servers": []}},
            {"tag": "awg-out", "protocol": "freedom", "settings": {"domainStrategy": "UseIP"}},
        ],
        "routing": {
            "rules": [
                {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
                {"ip": ["geoip:private"], "outboundTag": "blocked", "type": "field"},
                {"domain": ["example.org"], "outboundTag": "proxy", "type": "field"},
            ]
        },
        "policy": {"levels": {"0": {"handshake": 4}}},
    }


def add_complete_dns(config):
    cfg = copy.deepcopy(config)
    cfg["outbounds"].append(copy.deepcopy(api_tool.DNS_OUT))
    cfg["dns"] = {
        "servers": [
            {"address": "127.0.0.1", "port": 5355, "domains": [], "skipFallback": False}
        ],
        "queryStrategy": "UseIP",
    }
    cfg["routing"]["rules"].insert(1, copy.deepcopy(api_tool.DNS_PORT_RULE))
    cfg = api_tool.panel_normalize_dns_allow_rules(cfg)
    return cfg


class TemporaryDNSFinalRuleTests(unittest.TestCase):
    class FakePanel:
        def __init__(self, config):
            self.state = {
                "xraySetting": copy.deepcopy(config),
                "outboundTestUrl": "https://example.invalid/",
            }
            self.updates = 0

        def read_state(self):
            return copy.deepcopy(self.state)

        def update(self, config, outbound_test_url):
            self.state = {
                "xraySetting": api_tool.panel_normalize_dns_allow_rules(copy.deepcopy(config)),
                "outboundTestUrl": outbound_test_url,
            }
            self.updates += 1

    def test_missing_rule_is_added_then_removed_from_latest_live_config(self):
        config = base_config()
        unrelated = {"action": "block", "network": "tcp", "port": "25", "ip": ["192.0.2.1"]}
        config["outbounds"][0]["settings"]["finalRules"] = [copy.deepcopy(unrelated)]
        client = self.FakePanel(config)

        api_tool._add_temporary_dns_final_rule(client)
        current = api_tool._temporary_final_rules(client.state["xraySetting"])
        self.assertEqual(current, [unrelated, api_tool.TEMP_DNS_FINAL_RULE])

        self.assertTrue(api_tool._remove_temporary_dns_final_rule(client))
        current = api_tool._temporary_final_rules(client.state["xraySetting"])
        self.assertEqual(current, [unrelated])
        self.assertEqual(client.updates, 2)

    def test_allow_is_inserted_before_first_matching_private_block(self):
        config = base_config()
        unrelated = {"action": "block", "network": "tcp", "port": "25", "ip": ["192.0.2.1"]}
        private_block = {"action": "block", "ip": ["geoip:private"]}
        later = {"action": "block", "network": "tcp", "port": "443", "ip": ["192.0.2.1"]}
        config["outbounds"][0]["settings"]["finalRules"] = [unrelated, private_block, later]
        client = self.FakePanel(config)

        api_tool._add_temporary_dns_final_rule(client)
        rules = api_tool._temporary_final_rules(client.state["xraySetting"])
        self.assertEqual(rules, [unrelated, api_tool.TEMP_DNS_FINAL_RULE, private_block, later])
        self.assertTrue(api_tool._temporary_dns_allow_precedes_blocks(rules))

    def test_existing_dns_allow_is_moved_before_private_block(self):
        config = base_config()
        private_block = {"action": "block", "ip": ["geoip:private"]}
        broad_allow = {"action": "allow"}
        dns_allow = copy.deepcopy(api_tool.TEMP_DNS_FINAL_RULE)
        config["outbounds"][0]["settings"]["finalRules"] = [
            private_block, broad_allow, dns_allow,
        ]
        client = self.FakePanel(config)

        api_tool._add_temporary_dns_final_rule(client)

        rules = api_tool._temporary_final_rules(client.state["xraySetting"])
        self.assertEqual(rules, [dns_allow, private_block, broad_allow])
        self.assertTrue(api_tool._temporary_dns_allow_precedes_blocks(rules))
        self.assertEqual(client.updates, 1)

    def test_integrate_planner_never_rewrites_a_matching_final_rule(self):
        config = base_config()
        existing = copy.deepcopy(api_tool.TEMP_DNS_FINAL_RULE)
        config["outbounds"][0]["settings"]["finalRules"] = [existing]

        plan = api_tool.build_plan(config)

        self.assertFalse(plan.blockers)
        self.assertIn(existing, plan.proposed["outbounds"][0]["settings"]["finalRules"])

    def test_duplicate_exact_rules_are_not_deleted_ambiguously(self):
        config = base_config()
        config["outbounds"][0]["settings"]["finalRules"] = [
            copy.deepcopy(api_tool.TEMP_DNS_FINAL_RULE),
            copy.deepcopy(api_tool.TEMP_DNS_FINAL_RULE),
        ]
        self.assertEqual(api_tool._temporary_final_rule_count(config), 2)


class RemovePlannerTests(unittest.TestCase):
    def test_removes_only_objects_selected_by_the_integrate_plan(self):
        config = add_complete_dns(base_config())
        config["outbounds"].append({
            "tag": "other-local-resolver",
            "protocol": "dns",
            "settings": {
                "rewriteNetwork": "udp",
                "rewriteAddress": "127.0.0.1",
                "rewritePort": 5355,
            },
        })

        plan = api_tool.build_remove_plan(config)

        self.assertFalse(plan.plan_blocked)
        self.assertEqual(plan.route_indexes, [1])
        self.assertEqual(plan.outbound_tags, ["dns-out"])
        self.assertEqual(plan.dns_server_indexes, [0])
        self.assertTrue(any(item.get("tag") == "other-local-resolver" for item in config["outbounds"]))

    def test_preserves_planned_outbound_and_dns_server_used_by_unrelated_rule(self):
        config = add_complete_dns(base_config())
        user_rule = {
            "type": "field", "domain": ["internal.example"], "outboundTag": "dns-out"
        }
        config["routing"]["rules"].append(user_rule)

        plan = api_tool.build_remove_plan(config)

        self.assertEqual(plan.route_indexes, [1])
        self.assertEqual(plan.outbound_tags, [])
        self.assertEqual(plan.dns_server_indexes, [])
        self.assertTrue(any("routing.rules[5].outboundTag" in item for item in plan.blockers))

    def test_preserves_outbound_referenced_by_balancer_and_observatory(self):
        config = add_complete_dns(base_config())
        config["routing"]["balancers"] = [{"tag": "dns-balancer", "selector": ["dns-out"]}]
        config["observatory"] = {"subjectSelector": ["dns-out"]}

        plan = api_tool.build_remove_plan(config)

        self.assertEqual(plan.route_indexes, [1])
        self.assertEqual(plan.outbound_tags, [])
        self.assertEqual(plan.dns_server_indexes, [])
        self.assertTrue(any("routing.balancers[0]" in item for item in plan.blockers))
        self.assertTrue(any("observatory.subjectSelector" in item for item in plan.blockers))

    def test_preserves_dns_server_referenced_by_dns_rule(self):
        config = add_complete_dns(base_config())
        config["dns"]["servers"][0]["tag"] = "local-doh"
        config["dns"]["rules"] = [{
            "type": "field", "domain": ["internal.example"], "server": "local-doh"
        }]

        plan = api_tool.build_remove_plan(config)

        self.assertEqual(plan.dns_server_indexes, [])
        self.assertTrue(any("dns.rules[0].server" in item for item in plan.blockers))

    def test_remove_does_not_inspect_or_modify_diagnostic_final_rules(self):
        class FakePanel:
            def __init__(self, config):
                self.state = {
                    "xraySetting": copy.deepcopy(config),
                    "outboundTestUrl": "https://example.invalid/",
                }

            def read_state(self):
                return copy.deepcopy(self.state)

            def update(self, config, outbound_test_url):
                self.state = {
                    "xraySetting": api_tool.panel_normalize_dns_allow_rules(copy.deepcopy(config)),
                    "outboundTestUrl": outbound_test_url,
                }

        config = add_complete_dns(base_config())
        direct = next(item for item in config["outbounds"] if item.get("tag") == "direct")
        diagnostic_rule = copy.deepcopy(api_tool.TEMP_DNS_FINAL_RULE)
        direct["settings"]["finalRules"] = [
            diagnostic_rule,
            {"action": "block", "ip": ["geoip:private"]},
        ]
        client = FakePanel(config)

        plan = api_tool.build_remove_plan(config)
        self.assertEqual(plan.route_indexes, [1])
        self.assertEqual(plan.outbound_tags, ["dns-out"])
        self.assertEqual(plan.dns_server_indexes, [0])
        self.assertFalse(hasattr(plan, "direct_final_rule_indexes"))

        result = api_tool.command_remove(SimpleNamespace(), client)

        self.assertEqual(result, 0)
        direct_after = next(
            item for item in client.state["xraySetting"]["outbounds"]
            if item.get("tag") == "direct"
        )
        self.assertEqual(
            direct_after["settings"]["finalRules"],
            [diagnostic_rule, {"action": "block", "ip": ["geoip:private"]}],
        )

    def test_blocking_scoped_dns_endpoint_stops_remove_planning(self):
        config = add_complete_dns(base_config())
        config["dns"]["servers"][0]["domains"] = ["domain:example.org"]

        plan = api_tool.build_remove_plan(config)

        self.assertTrue(plan.plan_blocked)
        self.assertEqual(plan.route_indexes, [])
        self.assertEqual(plan.outbound_tags, [])
        self.assertEqual(plan.dns_server_indexes, [])

    def test_finds_general_string_dns_server_entry(self):
        config = add_complete_dns(base_config())
        config["dns"]["servers"] = ["127.0.0.1:5355"]

        plan = api_tool.build_remove_plan(config)

        self.assertEqual(plan.dns_server_indexes, [0])

    def test_ambiguous_outbound_tag_blocks_remove_instead_of_guessing(self):
        config = add_complete_dns(base_config())
        duplicate = copy.deepcopy(config["outbounds"][-1])
        config["outbounds"].append(duplicate)

        plan = api_tool.build_remove_plan(config)

        self.assertTrue(plan.plan_blocked)
        self.assertEqual(plan.route_indexes, [])
        self.assertEqual(plan.outbound_tags, [])
        self.assertEqual(plan.dns_server_indexes, [])

    def test_stale_route_with_missing_outbound_is_not_claimed_by_remove_plan(self):
        config = base_config()
        config["routing"]["rules"].insert(1, copy.deepcopy(api_tool.DNS_PORT_RULE))

        plan = api_tool.build_remove_plan(config)

        self.assertTrue(plan.plan_blocked)
        self.assertEqual(plan.route_indexes, [])
        self.assertEqual(plan.outbound_tags, [])
        self.assertEqual(plan.dns_server_indexes, [])

    def test_remove_applies_one_plan_and_preserves_external_resources(self):
        class FakePanel:
            def __init__(self, config):
                self.state = {
                    "xraySetting": copy.deepcopy(config),
                    "outboundTestUrl": "https://example.invalid/",
                }
                self.updates = []
                self.reads = 0

            def read_state(self):
                self.reads += 1
                return copy.deepcopy(self.state)

            def update(self, config, outbound_test_url):
                self.updates.append(copy.deepcopy(config))
                self.state = {
                    "xraySetting": api_tool.panel_normalize_dns_allow_rules(copy.deepcopy(config)),
                    "outboundTestUrl": outbound_test_url,
                }

        config = add_complete_dns(base_config())
        user_rule = {
            "type": "field", "domain": ["internal.example"], "outboundTag": "dns-out"
        }
        config["routing"]["rules"].append(user_rule)
        client = FakePanel(config)

        result = api_tool.command_remove(
            SimpleNamespace(), client
        )

        self.assertEqual(result, 0)
        final = client.state["xraySetting"]
        self.assertTrue(any(item.get("tag") == "dns-out" for item in final["outbounds"]))
        self.assertIn(user_rule, final["routing"]["rules"])
        self.assertEqual(len(final["dns"]["servers"]), 1)
        self.assertFalse(any(api_tool._global_port53_rule(item) for item in final["routing"]["rules"]))
        self.assertEqual(len(client.updates), 1)
        self.assertEqual(client.reads, 2)  # one plan read plus one verified read-back

    def test_remove_preserves_direct_but_deletes_unshared_loopback_allow(self):
        class FakePanel:
            def __init__(self, config):
                self.state = {
                    "xraySetting": copy.deepcopy(config),
                    "outboundTestUrl": "https://example.invalid/",
                }

            def read_state(self):
                return copy.deepcopy(self.state)

            def update(self, config, outbound_test_url):
                self.state = {
                    "xraySetting": api_tool.panel_normalize_dns_allow_rules(copy.deepcopy(config)),
                    "outboundTestUrl": outbound_test_url,
                }

        config = add_complete_dns(base_config())
        expected_final_rules = [
            copy.deepcopy(api_tool.TEMP_DNS_FINAL_RULE),
            {"action": "block", "ip": ["geoip:private"]},
            {"action": "allow"},
        ]
        direct = next(item for item in config["outbounds"] if item.get("tag") == "direct")
        direct["settings"]["finalRules"] = copy.deepcopy(expected_final_rules)
        client = FakePanel(config)

        result = api_tool.command_remove(SimpleNamespace(), client)

        self.assertEqual(result, 0)
        final = client.state["xraySetting"]
        direct_after = next(item for item in final["outbounds"] if item.get("tag") == "direct")
        self.assertEqual(direct_after["protocol"], "freedom")
        self.assertEqual(
            direct_after["settings"]["finalRules"],
            expected_final_rules,
        )
        self.assertFalse(any(item.get("tag") == "dns-out" for item in final["outbounds"]))
        self.assertEqual(final["dns"]["servers"], [])
        self.assertFalse(any(api_tool._global_port53_rule(item) for item in final["routing"]["rules"]))
        self.assertFalse(any(
            item.get("ruleTag") == api_tool.DNS_ALLOW_TAG
            for item in final["routing"]["rules"]
        ))

    def test_remove_does_not_mutate_when_desired_plan_is_blocked(self):
        class FakePanel:
            def __init__(self, config):
                self.state = {
                    "xraySetting": copy.deepcopy(config),
                    "outboundTestUrl": "https://example.invalid/",
                }
                self.updates = []

            def read_state(self):
                return copy.deepcopy(self.state)

            def update(self, config, outbound_test_url):
                self.updates.append(copy.deepcopy(config))

        config = base_config()
        config["routing"]["rules"].insert(1, copy.deepcopy(api_tool.DNS_PORT_RULE))
        client = FakePanel(config)

        result = api_tool.command_remove(SimpleNamespace(), client)

        self.assertEqual(result, 2)
        self.assertEqual(client.updates, [])


class IntegrateOrchestrationTests(unittest.TestCase):
    class FakePanel:
        def __init__(self, config):
            self.state = {
                "xraySetting": copy.deepcopy(config),
                "outboundTestUrl": "https://example.invalid/",
            }
            self.reads = 0

        def read_state(self):
            self.reads += 1
            return copy.deepcopy(self.state)

    def _args(self):
        return SimpleNamespace(
            plugin_status_url="http://127.0.0.1:18765/status",
        )

    def test_integrate_cleans_up_diagnostic_tunnel_after_successful_self_test(self):
        client = self.FakePanel(base_config())
        with patch.object(api_tool, "discover_temporary_leftovers", return_value=[]), \
             patch.object(api_tool, "confirm_restart"), \
             patch.object(api_tool, "_apply_panel_update", return_value=client.state), \
             patch.object(api_tool, "ensure_diagnostic_tunnel") as create, \
             patch.object(api_tool, "test_diagnostic_tunnel") as test, \
             patch.object(api_tool, "cleanup_temporary_leftovers") as cleanup:
            self.assertEqual(api_tool.command_integrate(self._args(), client), 0)

        create.assert_called_once_with(self._args(), client)
        test.assert_called_once_with(self._args(), client)
        cleanup.assert_called_once_with(client)
        self.assertEqual(client.reads, 1)

    def test_integrate_tests_and_cleans_up_existing_diagnostic_tunnel(self):
        client = self.FakePanel(base_config())
        existing = [{"inbound_id": 10, "port": 15353}]
        with patch.object(api_tool, "discover_temporary_leftovers", return_value=existing), \
             patch.object(api_tool, "confirm_restart"), \
             patch.object(api_tool, "_apply_panel_update", return_value=client.state), \
             patch.object(api_tool, "ensure_diagnostic_tunnel") as create, \
             patch.object(api_tool, "test_diagnostic_tunnel") as test, \
             patch.object(api_tool, "cleanup_temporary_leftovers") as cleanup:
            self.assertEqual(api_tool.command_integrate(self._args(), client), 0)

        create.assert_not_called()
        test.assert_called_once_with(self._args(), client)
        cleanup.assert_called_once_with(client)

    def test_integrate_attempts_cleanup_after_failed_self_test(self):
        client = self.FakePanel(base_config())
        with patch.object(api_tool, "discover_temporary_leftovers", return_value=[]), \
             patch.object(api_tool, "confirm_restart"), \
             patch.object(api_tool, "_apply_panel_update", return_value=client.state), \
             patch.object(api_tool, "ensure_diagnostic_tunnel"), \
             patch.object(api_tool, "test_diagnostic_tunnel", side_effect=api_tool.IntegrationError("UDP failed")), \
             patch.object(api_tool, "cleanup_temporary_leftovers") as cleanup:
            with self.assertRaisesRegex(api_tool.IntegrationError, "self-test failed"):
                api_tool.command_integrate(self._args(), client)
        cleanup.assert_called_once_with(client)

    def test_integrate_reports_test_and_cleanup_failures_separately(self):
        client = self.FakePanel(base_config())
        with patch.object(api_tool, "discover_temporary_leftovers", return_value=[]), \
             patch.object(api_tool, "confirm_restart"), \
             patch.object(api_tool, "_apply_panel_update", return_value=client.state), \
             patch.object(api_tool, "ensure_diagnostic_tunnel"), \
             patch.object(api_tool, "test_diagnostic_tunnel", side_effect=api_tool.IntegrationError("UDP failed")), \
             patch.object(api_tool, "cleanup_temporary_leftovers", side_effect=api_tool.IntegrationError("inbound retained")) as cleanup:
            with self.assertRaisesRegex(api_tool.IntegrationError, "cleanup also failed"):
                api_tool.command_integrate(self._args(), client)
        cleanup.assert_called_once_with(client)


class SharedPlannerCLITests(unittest.TestCase):
    def _run(self, config):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json") as handle:
            json.dump(config, handle)
            handle.flush()
            return subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "xray_dns_planner.py"),
                    "--check-config",
                    handle.name,
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

    def test_complete_config_passes_read_only_runtime_check(self):
        config = add_complete_dns(base_config())
        before = copy.deepcopy(config)

        result = self._run(config)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS:", result.stdout)
        self.assertEqual(config, before)

    def test_incomplete_config_reports_missing_items_without_writing(self):
        config = base_config()
        before = copy.deepcopy(config)

        result = self._run(config)

        self.assertEqual(result.returncode, 1)
        self.assertIn("MISSING:", result.stdout)
        self.assertIn("no changes were made", result.stderr)
        self.assertEqual(config, before)


class AdditivePlannerTests(unittest.TestCase):
    def test_missing_outbounds_and_routing_rules_arrays_are_created(self):
        original = {
            "api": {"tag": "api"},
            "routing": {},
            "dns": {"servers": []},
        }

        # This case exercises generic DNS planning with no LucX-UI API
        # rule in the fixture; production API apply keeps that gate enabled.
        plan = api_tool.build_plan(original, require_api_rule=False)

        self.assertFalse(plan.blockers)
        self.assertTrue(plan.changes)
        self.assertTrue(plan.proposed["outbounds"])
        self.assertTrue(plan.proposed["routing"]["rules"])
        self.assertFalse(original.get("outbounds"))
        self.assertNotIn("rules", original["routing"])

    def test_clean_template_adds_only_dns_items_and_panel_managed_allow(self):
        original = base_config()
        plan = api_tool.build_plan(original)

        self.assertEqual(plan.blockers, [])
        self.assertEqual(len(plan.changes), 4)
        self.assertTrue(any("PANEL-MANAGED" in item for item in plan.changes))
        self.assertEqual(plan.proposed["outbounds"][-1], api_tool.DNS_OUT)
        self.assertEqual(plan.proposed["dns"]["servers"], [api_tool.DNS_SERVER])
        rules = plan.proposed["routing"]["rules"]
        self.assertEqual(rules[0], original["routing"]["rules"][0])
        self.assertEqual(rules[1], api_tool.DNS_PORT_RULE)
        self.assertEqual(rules[2:], original["routing"]["rules"][1:])
        saved_rules = plan.expected_saved["routing"]["rules"]
        self.assertEqual(saved_rules[0], original["routing"]["rules"][0])
        self.assertEqual(saved_rules[1], api_tool.DNS_PORT_RULE)
        allow = next(x for x in saved_rules if x.get("ruleTag") == "xui-dns-allow")
        self.assertEqual(allow["ip"], ["127.0.0.1"])
        self.assertEqual(allow["port"], "5355")
        self.assertEqual(allow["outboundTag"], "direct")

    def test_complete_template_is_idempotent(self):
        original = add_complete_dns(base_config())
        plan = api_tool.build_plan(original)
        self.assertEqual(plan.blockers, [])
        self.assertEqual(plan.changes, [])
        self.assertEqual(plan.proposed, original)
        self.assertEqual(plan.expected_saved, original)

    def test_adds_only_missing_elements(self):
        original = base_config()
        original["outbounds"].append(copy.deepcopy(api_tool.DNS_OUT))
        original["routing"]["rules"].insert(1, copy.deepcopy(api_tool.DNS_PORT_RULE))
        plan = api_tool.build_plan(original)
        self.assertEqual(plan.blockers, [])
        self.assertIn("ADD dns.servers entry 127.0.0.1:5355", plan.changes)
        self.assertTrue(any("PANEL-MANAGED" in item for item in plan.changes))
        self.assertEqual(
            len([x for x in plan.proposed["outbounds"] if x.get("tag") == "dns-out"]),
            1,
        )
        self.assertEqual(
            sum(1 for x in plan.proposed["routing"]["rules"] if api_tool._global_port53_rule(x)),
            1,
        )

    def test_existing_global_port53_rule_is_not_duplicated(self):
        original = add_complete_dns(base_config())
        plan = api_tool.build_plan(original)
        self.assertFalse(plan.blockers)
        self.assertFalse(any("port 53" in item for item in plan.changes))

    def test_reuses_dns_outbound_with_a_nonstandard_tag(self):
        original = base_config()
        outbound = copy.deepcopy(api_tool.DNS_OUT)
        outbound["tag"] = "local-doh-resolver"
        original["outbounds"].append(outbound)
        route = copy.deepcopy(api_tool.DNS_PORT_RULE)
        route["outboundTag"] = "local-doh-resolver"
        original["routing"]["rules"].insert(1, route)

        plan = api_tool.build_plan(original)

        self.assertFalse(plan.blockers)
        self.assertFalse(any(item.get("tag") == "dns-out" for item in plan.proposed["outbounds"]))
        self.assertEqual(
            [item for item in plan.proposed["outbounds"] if item["tag"] == "local-doh-resolver"],
            [outbound],
        )
        self.assertFalse(any(item.get("tag") == "dns-out" for item in plan.proposed["outbounds"]))
        self.assertEqual(
            [item for item in plan.proposed["routing"]["rules"] if api_tool._global_port53_rule(item)],
            [route],
        )

    def test_reuses_dns_outbound_with_tcp_or_preserved_transport(self):
        for network in ("tcp", None):
            with self.subTest(rewriteNetwork=network):
                original = base_config()
                outbound = copy.deepcopy(api_tool.DNS_OUT)
                outbound["tag"] = "custom-local-dns"
                if network is None:
                    outbound["settings"].pop("rewriteNetwork", None)
                else:
                    outbound["settings"]["rewriteNetwork"] = network
                original["outbounds"].append(outbound)
                route = copy.deepcopy(api_tool.DNS_PORT_RULE)
                route["outboundTag"] = "custom-local-dns"
                original["routing"]["rules"].insert(1, route)

                plan = api_tool.build_plan(original)

                self.assertFalse(plan.blockers)
                self.assertEqual(
                    [item for item in plan.proposed["outbounds"] if item.get("tag") == "custom-local-dns"],
                    [outbound],
                )
                self.assertFalse(any(
                    item.get("tag") == "dns-out" for item in plan.proposed["outbounds"]
                ))

    def test_existing_conflicting_dns_outbound_gets_a_unique_new_tag(self):
        original = base_config()
        occupied = copy.deepcopy(api_tool.DNS_OUT)
        occupied["settings"]["rewriteAddress"] = "9.9.9.9"
        original["outbounds"].append(occupied)

        plan = api_tool.build_plan(original)

        self.assertFalse(plan.blockers)
        self.assertEqual(original["outbounds"][-1], occupied)
        added = plan.proposed["outbounds"][-1]
        self.assertEqual(added["tag"], "dns-out-doh-health-monitor")
        global_rule = next(item for item in plan.proposed["routing"]["rules"] if api_tool._global_port53_rule(item))
        self.assertEqual(global_rule["outboundTag"], added["tag"])

    def test_new_outbound_and_rule_tags_skip_collisions(self):
        original = base_config()
        occupied = copy.deepcopy(api_tool.DNS_OUT)
        occupied["settings"]["rewriteAddress"] = "9.9.9.9"
        original["outbounds"].append(occupied)
        original["routing"]["rules"].append({
            "type": "field",
            "port": "443",
            "outboundTag": "proxy",
            "ruleTag": "doh-health-monitor-dns-port53",
        })

        plan = api_tool.build_plan(original)

        self.assertFalse(plan.blockers)
        added = plan.proposed["outbounds"][-1]
        self.assertEqual(added["tag"], "dns-out-doh-health-monitor")
        new_rule = next(item for item in plan.proposed["routing"]["rules"] if api_tool._global_port53_rule(item))
        self.assertEqual(new_rule["outboundTag"], added["tag"])
        self.assertNotEqual(new_rule["ruleTag"], "doh-health-monitor-dns-port53")
        self.assertTrue(new_rule["ruleTag"].startswith("doh-health-monitor-dns-port53-"))
        all_outbound_tags = [item.get("tag") for item in plan.proposed["outbounds"] if item.get("tag")]
        self.assertEqual(len(all_outbound_tags), len(set(all_outbound_tags)))
        all_rule_tags = [item.get("ruleTag") for item in plan.proposed["routing"]["rules"] if item.get("ruleTag")]
        self.assertEqual(len(all_rule_tags), len(set(all_rule_tags)))

    def test_new_outbound_tag_avoids_existing_balancer_selector_prefixes(self):
        original = base_config()
        occupied = copy.deepcopy(api_tool.DNS_OUT)
        occupied["settings"]["rewriteAddress"] = "9.9.9.9"
        original["outbounds"].append(occupied)
        original["routing"]["balancers"] = [
            {"tag": "dns-balancer", "selector": ["dns"]}
        ]

        plan = api_tool.build_plan(original)

        self.assertFalse(plan.blockers)
        added = plan.proposed["outbounds"][-1]
        self.assertEqual(added["tag"], "doh-health-monitor-dns-out")
        self.assertFalse(added["tag"].startswith("dns"))
        new_rule = next(item for item in plan.proposed["routing"]["rules"] if api_tool._global_port53_rule(item))
        self.assertEqual(new_rule["outboundTag"], added["tag"])

    def test_reuses_global_dns_balancer_when_every_selected_outbound_is_compatible(self):
        original = base_config()
        first = copy.deepcopy(api_tool.DNS_OUT)
        first["tag"] = "local-doh-a"
        second = copy.deepcopy(api_tool.DNS_OUT)
        second["tag"] = "local-doh-b"
        original["outbounds"].extend([first, second])
        original["routing"]["balancers"] = [{
            "tag": "local-doh-balancer",
            "selector": ["local-doh-"],
            "fallbackTag": "local-doh-a",
        }]
        original["routing"]["rules"].insert(1, {
            "type": "field",
            "network": "tcp,udp",
            "port": "53",
            "balancerTag": "local-doh-balancer",
        })

        plan = api_tool.build_plan(original)

        self.assertFalse(plan.blockers)
        self.assertFalse(any(
            item.get("tag") == "dns-out" for item in plan.proposed["outbounds"]
        ))
        self.assertEqual(
            sum(1 for item in plan.proposed["routing"]["rules"] if api_tool._global_port53_rule(item)),
            1,
        )
        self.assertEqual(plan.proposed["routing"]["rules"][1]["balancerTag"], "local-doh-balancer")
        self.assertFalse(any("ADD global TCP/UDP port-53" in item for item in plan.changes))

    def test_reuses_compatible_scoped_dns_balancer_and_uses_direct_outbound_fallback(self):
        original = base_config()
        first = copy.deepcopy(api_tool.DNS_OUT)
        first["tag"] = "local-doh-a"
        second = copy.deepcopy(api_tool.DNS_OUT)
        second["tag"] = "local-doh-b"
        original["outbounds"].extend([first, second])
        original["routing"]["balancers"] = [{
            "tag": "local-doh-balancer",
            "selector": ["local-doh-"],
            "fallbackTag": "local-doh-a",
        }]
        scoped = {
            "type": "field",
            "network": "udp",
            "port": "53",
            "inboundTag": ["vless-in"],
            "balancerTag": "local-doh-balancer",
        }
        original["routing"]["rules"].insert(1, scoped)

        plan = api_tool.build_plan(original)

        self.assertFalse(plan.blockers)
        self.assertEqual(plan.proposed["routing"]["rules"][1], scoped)
        global_rule = next(
            item for item in plan.proposed["routing"]["rules"]
            if api_tool._global_port53_rule(item)
        )
        self.assertEqual(global_rule["outboundTag"], "local-doh-a")
        self.assertNotIn("balancerTag", global_rule)

    def test_scoped_dns_balancer_with_missing_reference_is_blocked(self):
        original = base_config()
        original["routing"]["rules"].insert(1, {
            "type": "field",
            "network": "udp",
            "port": "53",
            "inboundTag": ["vless-in"],
            "balancerTag": "missing-balancer",
        })

        plan = api_tool.build_plan(original)

        self.assertTrue(any("references missing balancer tag" in item for item in plan.blockers))
        self.assertEqual(plan.proposed, original)

    def test_partial_global_balancer_route_generates_direct_outbound_fallback(self):
        original = base_config()
        first = copy.deepcopy(api_tool.DNS_OUT)
        first["tag"] = "local-doh-a"
        second = copy.deepcopy(api_tool.DNS_OUT)
        second["tag"] = "local-doh-b"
        original["outbounds"].extend([first, second])
        original["routing"]["balancers"] = [{
            "tag": "local-doh-balancer",
            "selector": ["local-doh-"],
            "fallbackTag": "local-doh-a",
        }]
        tcp_rule = {
            "type": "field",
            "network": "tcp",
            "port": "53",
            "balancerTag": "local-doh-balancer",
        }
        original["routing"]["rules"].insert(1, tcp_rule)

        plan = api_tool.build_plan(original)

        self.assertFalse(plan.blockers)
        self.assertEqual(plan.proposed["routing"]["rules"][1], tcp_rule)
        fallback = next(
            item for item in plan.proposed["routing"]["rules"]
            if api_tool._global_port53_rule(item)
        )
        self.assertEqual(fallback["outboundTag"], "local-doh-a")
        self.assertNotIn("balancerTag", fallback)

    def test_earlier_tcp_only_compatible_route_and_exact_global_route_are_both_reused(self):
        original = base_config()
        original["outbounds"].append(copy.deepcopy(api_tool.DNS_OUT))
        original["dns"] = {"servers": [copy.deepcopy(api_tool.DNS_SERVER)]}
        tcp_out = copy.deepcopy(api_tool.DNS_OUT)
        tcp_out["tag"] = "local-doh-tcp"
        original["outbounds"].append(tcp_out)
        original["routing"]["rules"].insert(1, {
            "type": "field",
            "network": "tcp",
            "port": "53",
            "outboundTag": "local-doh-tcp",
        })
        original["routing"]["rules"].insert(2, copy.deepcopy(api_tool.DNS_PORT_RULE))

        plan = api_tool.build_plan(original)

        self.assertFalse(plan.blockers)
        self.assertFalse(any(
            "ADD global TCP/UDP port-53" in change
            for change in plan.changes
        ))

    def test_global_dns_balancer_with_incompatible_fallback_is_blocked(self):
        original = base_config()
        compatible = copy.deepcopy(api_tool.DNS_OUT)
        compatible["tag"] = "local-doh-a"
        incompatible = copy.deepcopy(api_tool.DNS_OUT)
        incompatible["tag"] = "other-dns"
        incompatible["settings"]["rewriteAddress"] = "9.9.9.9"
        original["outbounds"].extend([compatible, incompatible])
        original["routing"]["balancers"] = [{
            "tag": "local-doh-balancer",
            "selector": ["local-doh-"],
            "fallbackTag": "other-dns",
        }]
        original["routing"]["rules"].insert(1, {
            "type": "field",
            "network": "tcp,udp",
            "port": "53",
            "balancerTag": "local-doh-balancer",
        })

        plan = api_tool.build_plan(original)

        self.assertTrue(any("incompatible balancer" in item for item in plan.blockers))
        self.assertEqual(plan.proposed, original)

    def test_dns_outbound_with_non_direct_query_rule_is_not_reused(self):
        original = base_config()
        occupied = copy.deepcopy(api_tool.DNS_OUT)
        occupied["tag"] = "dns-out"
        occupied["settings"]["rules"] = [{
            "action": "drop",
            "domain": ["domain:example.net"],
        }]
        original["outbounds"].append(occupied)

        plan = api_tool.build_plan(original)

        self.assertFalse(plan.blockers)
        added = plan.proposed["outbounds"][-1]
        self.assertNotEqual(added["tag"], "dns-out")
        self.assertEqual(
            next(item for item in plan.proposed["outbounds"] if item["tag"] == "dns-out"),
            occupied,
        )

    def test_dns_outbound_with_scoped_direct_query_rule_is_not_reused(self):
        original = base_config()
        occupied = copy.deepcopy(api_tool.DNS_OUT)
        occupied["tag"] = "local-dns"
        occupied["settings"]["rules"] = [{
            "action": "direct",
            "qType": 1,
            "domain": ["domain:example.net"],
        }]
        original["outbounds"].append(occupied)

        plan = api_tool.build_plan(original)

        self.assertFalse(plan.blockers)
        self.assertEqual(
            next(item for item in plan.proposed["outbounds"] if item.get("tag") == "local-dns"),
            occupied,
        )
        self.assertNotEqual(plan.proposed["outbounds"][-1]["tag"], "local-dns")
        route = next(item for item in plan.proposed["routing"]["rules"] if api_tool._global_port53_rule(item))
        self.assertEqual(route["outboundTag"], plan.proposed["outbounds"][-1]["tag"])

    def test_generated_outbound_skips_dangling_outbound_tag_references(self):
        original = base_config()
        original["routing"]["rules"].append({
            "type": "field",
            "port": "443",
            "outboundTag": "dns-out",
        })

        plan = api_tool.build_plan(original)

        self.assertFalse(plan.blockers)
        generated = next(
            item["tag"] for item in plan.proposed["outbounds"]
            if item.get("protocol") == "dns"
        )
        self.assertNotEqual(generated, "dns-out")
        self.assertTrue(generated.startswith("dns-out-"))
        dns_rule = next(
            item for item in plan.proposed["routing"]["rules"]
            if api_tool._global_port53_rule(item)
        )
        self.assertEqual(dns_rule["outboundTag"], generated)

    def test_generated_outbound_avoids_observatory_subject_selector_prefixes(self):
        original = base_config()
        occupied = copy.deepcopy(api_tool.DNS_OUT)
        occupied["settings"]["rewriteAddress"] = "9.9.9.9"
        original["outbounds"].append(occupied)
        original["observatory"] = {"subjectSelector": ["dns"]}

        plan = api_tool.build_plan(original)

        self.assertFalse(plan.blockers)
        generated = plan.proposed["outbounds"][-1]["tag"]
        self.assertFalse(generated.startswith("dns"))

    def test_generated_outbound_skips_dangling_balancer_fallback_reference(self):
        original = base_config()
        occupied = copy.deepcopy(api_tool.DNS_OUT)
        occupied["settings"]["rewriteAddress"] = "9.9.9.9"
        original["outbounds"].append(occupied)
        original["routing"]["balancers"] = [{
            "tag": "user-balancer",
            "selector": ["proxy"],
            "fallbackTag": "dns-out",
        }]

        plan = api_tool.build_plan(original)

        self.assertFalse(plan.blockers)
        generated = plan.proposed["outbounds"][-1]["tag"]
        self.assertNotEqual(generated, "dns-out")

    def test_multiple_equivalent_dns_outbounds_without_a_selecting_rule_reuse_first(self):
        original = base_config()
        first = copy.deepcopy(api_tool.DNS_OUT)
        first["tag"] = "doh-one"
        second = copy.deepcopy(api_tool.DNS_OUT)
        second["tag"] = "doh-two"
        original["outbounds"].extend([first, second])

        plan = api_tool.build_plan(original)

        self.assertFalse(plan.blockers)
        self.assertFalse(any(item.get("tag") == "dns-out" for item in plan.proposed["outbounds"]))
        route = next(item for item in plan.proposed["routing"]["rules"] if api_tool._global_port53_rule(item))
        self.assertEqual(route["outboundTag"], "doh-one")
        self.assertEqual(
            [item for item in plan.proposed["outbounds"] if item.get("tag") in {"doh-one", "doh-two"}],
            [first, second],
        )
        self.assertTrue(any("Multiple compatible local DNS outbounds exist" in item for item in plan.warnings))

    def test_api_tag_is_an_alias_for_its_inbound_tag(self):
        original = base_config()
        original["inbounds"] = [{"tag": "api", "protocol": "dokodemo-door"}]

        plan = api_tool.build_plan(original)

        self.assertFalse(plan.blockers)
        self.assertEqual(plan.proposed["inbounds"], original["inbounds"])

    def test_duplicate_existing_inbound_tags_are_reserved_but_not_rewritten(self):
        original = base_config()
        original["inbounds"] = [
            {"tag": "dns-out"},
            {"tag": "dns-out"},
        ]

        plan = api_tool.build_plan(original)

        self.assertFalse(plan.blockers)
        self.assertEqual(plan.proposed["inbounds"], original["inbounds"])
        generated = next(
            item["tag"] for item in plan.proposed["outbounds"]
            if item.get("protocol") == "dns"
        )
        self.assertNotEqual(generated, "dns-out")
        global_rule = next(
            item for item in plan.proposed["routing"]["rules"]
            if api_tool._global_port53_rule(item)
        )
        self.assertEqual(global_rule["outboundTag"], generated)

    def test_generated_outbound_tag_skips_inbound_api_and_rule_tags(self):
        original = base_config()
        occupied = copy.deepcopy(api_tool.DNS_OUT)
        occupied["settings"]["rewriteAddress"] = "9.9.9.9"
        original["outbounds"].append(occupied)
        original["inbounds"] = [{"tag": "dns-out-doh-health-monitor"}]
        original["api"] = {"tag": "doh-health-monitor-dns-out"}
        original["routing"]["rules"].append({
            "type": "field",
            "port": "443",
            "outboundTag": "proxy",
            "ruleTag": "xray-dns-out",
        })

        plan = api_tool.build_plan(original)

        self.assertFalse(plan.blockers)
        generated = plan.proposed["outbounds"][-1]["tag"]
        self.assertNotIn(
            generated,
            {
                original["inbounds"][0]["tag"],
                original["api"]["tag"],
                original["routing"]["rules"][-1]["ruleTag"],
            },
        )
        self.assertEqual(
            next(rule for rule in plan.proposed["routing"]["rules"] if api_tool._global_port53_rule(rule))["outboundTag"],
            generated,
        )

    def test_generated_tags_skip_dns_app_and_nameserver_tags(self):
        original = base_config()
        occupied = copy.deepcopy(api_tool.DNS_OUT)
        occupied["settings"]["rewriteAddress"] = "9.9.9.9"
        original["outbounds"].append(occupied)
        original["dns"] = {
            "tag": "dns-out-doh-health-monitor",
            "servers": [{"address": "127.0.0.1", "port": 5355, "tag": "doh-health-monitor-dns-out"}],
        }

        plan = api_tool.build_plan(original)

        self.assertFalse(plan.blockers)
        generated = plan.proposed["outbounds"][-1]["tag"]
        self.assertNotIn(generated, {
            original["dns"]["tag"],
            original["dns"]["servers"][0]["tag"],
        })
        route = next(item for item in plan.proposed["routing"]["rules"] if api_tool._global_port53_rule(item))
        self.assertEqual(route["outboundTag"], generated)

    def test_cross_namespace_outbound_and_nameserver_tag_text_is_reserved_not_rewritten(self):
        original = base_config()
        original["outbounds"].append(copy.deepcopy(api_tool.DNS_OUT))
        original["dns"] = {
            "servers": [{
                "address": "127.0.0.1",
                "port": 5355,
                "tag": "dns-out",
            }]
        }

        plan = api_tool.build_plan(original)

        self.assertFalse(plan.blockers)
        self.assertEqual(plan.proposed["dns"]["servers"], original["dns"]["servers"])
        self.assertEqual(
            [item for item in plan.proposed["outbounds"] if item.get("tag") == "dns-out"],
            [api_tool.DNS_OUT],
        )

    def test_duplicate_existing_routing_rule_tags_are_reserved_without_rewriting_rules(self):
        original = base_config()
        original["routing"]["rules"][1]["ruleTag"] = "same-rule"
        original["routing"]["rules"][2]["ruleTag"] = "same-rule"

        plan = api_tool.build_plan(original)

        self.assertFalse(plan.blockers)
        retained_rules = [
            rule for rule in plan.proposed["routing"]["rules"]
            if not api_tool._global_port53_rule(rule)
        ]
        self.assertEqual(retained_rules, original["routing"]["rules"])
        generated = next(
            rule for rule in plan.proposed["routing"]["rules"]
            if api_tool._global_port53_rule(rule)
        )
        self.assertNotEqual(generated["ruleTag"], "same-rule")

    def test_generated_rule_tag_skips_existing_outbound_tag(self):
        original = base_config()
        original["outbounds"].append({
            "tag": "doh-health-monitor-dns-port53",
            "protocol": "blackhole",
            "settings": {},
        })

        plan = api_tool.build_plan(original)

        self.assertFalse(plan.blockers)
        generated = next(
            rule["ruleTag"] for rule in plan.proposed["routing"]["rules"]
            if rule.get("outboundTag") == "dns-out" and str(rule.get("port")) == "53"
        )
        self.assertNotEqual(generated, "doh-health-monitor-dns-port53")

    def test_duplicate_balancer_tags_are_rejected_as_ambiguous(self):
        original = base_config()
        original["routing"]["balancers"] = [
            {"tag": "dns-balancer", "selector": ["dns"]},
            {"tag": "dns-balancer", "selector": ["local"]},
        ]

        plan = api_tool.build_plan(original)

        self.assertTrue(any("Duplicate balancer tag 'dns-balancer'" in item for item in plan.blockers))
        self.assertEqual(plan.proposed, original)

    def test_duplicate_outbound_tags_are_rejected_as_ambiguous(self):
        original = base_config()
        duplicate = copy.deepcopy(original["outbounds"][1])
        original["outbounds"].append(duplicate)

        plan = api_tool.build_plan(original)

        self.assertTrue(any("Duplicate outbound tag 'proxy'" in item for item in plan.blockers))
        self.assertEqual(plan.proposed, original)

    def test_multiple_equivalent_global_port53_rules_are_preserved_without_new_rule(self):
        original = base_config()
        first = copy.deepcopy(api_tool.DNS_OUT)
        first["tag"] = "doh-one"
        second = copy.deepcopy(api_tool.DNS_OUT)
        second["tag"] = "doh-two"
        original["outbounds"].extend([first, second])
        route_one = copy.deepcopy(api_tool.DNS_PORT_RULE)
        route_one["outboundTag"] = "doh-one"
        route_two = copy.deepcopy(api_tool.DNS_PORT_RULE)
        route_two["outboundTag"] = "doh-two"
        route_two["ruleTag"] = "dns-rule-two"
        original["routing"]["rules"][1:1] = [route_one, route_two]

        plan = api_tool.build_plan(original)

        self.assertFalse(plan.blockers)
        self.assertEqual(plan.proposed["routing"]["rules"][1:3], [route_one, route_two])
        self.assertFalse(any(
            "ADD global TCP/UDP port-53" in item for item in plan.changes
        ))
        self.assertTrue(any("Multiple global port-53 rules already exist" in item for item in plan.warnings))

    def test_existing_global_route_with_missing_outbound_reference_is_blocked(self):
        original = base_config()
        route = copy.deepcopy(api_tool.DNS_PORT_RULE)
        route["outboundTag"] = "missing-dns"
        original["routing"]["rules"].insert(1, route)

        plan = api_tool.build_plan(original)

        self.assertTrue(any("references missing outbound tag" in item for item in plan.blockers))
        self.assertEqual(plan.proposed, original)

    def test_earlier_global_port_range_shadowing_exact_dns_route_is_blocked(self):
        original = base_config()
        original["outbounds"].append(copy.deepcopy(api_tool.DNS_OUT))
        original["dns"] = {"servers": [copy.deepcopy(api_tool.DNS_SERVER)]}
        original["routing"]["rules"].insert(1, {
            "type": "field",
            "network": "tcp,udp",
            "port": "53,443",
            "outboundTag": "proxy",
        })
        original["routing"]["rules"].insert(2, copy.deepcopy(api_tool.DNS_PORT_RULE))

        plan = api_tool.build_plan(original)

        self.assertTrue(any("shadows the exact port-53 route" in item for item in plan.blockers))
        self.assertEqual(plan.proposed, original)

    def test_earlier_global_port_range_is_reused_when_it_targets_same_dns_outbound(self):
        original = base_config()
        original["outbounds"].append(copy.deepcopy(api_tool.DNS_OUT))
        original["dns"] = {"servers": [copy.deepcopy(api_tool.DNS_SERVER)]}
        broad = {
            "type": "field",
            "network": "tcp,udp,quic",
            "port": "53,443",
            "outboundTag": "dns-out",
        }
        original["routing"]["rules"].insert(1, broad)
        original["routing"]["rules"].insert(2, copy.deepcopy(api_tool.DNS_PORT_RULE))

        plan = api_tool.build_plan(original)

        self.assertFalse(plan.blockers)
        self.assertTrue(any(
            "Existing global TCP/UDP port-53 route already provides the local DNS path via"
            in item
            for item in plan.warnings
        ))
        self.assertEqual(plan.proposed["routing"]["rules"][1], broad)

    def test_xray_outbound_tag_precedes_balancer_tag_when_both_are_present(self):
        original = base_config()
        compatible = copy.deepcopy(api_tool.DNS_OUT)
        compatible["tag"] = "local-doh"
        original["outbounds"].append(compatible)
        original["routing"]["balancers"] = [{
            "tag": "incompatible-balancer",
            "selector": ["proxy"],
            "fallbackTag": "proxy",
        }]
        route = copy.deepcopy(api_tool.DNS_PORT_RULE)
        route["outboundTag"] = "local-doh"
        route["balancerTag"] = "incompatible-balancer"
        original["routing"]["rules"].insert(1, route)

        plan = api_tool.build_plan(original)

        self.assertFalse(plan.blockers)
        self.assertEqual(plan.proposed["routing"]["rules"][1], route)
        self.assertFalse(any(
            "ADD global TCP/UDP port-53" in change
            for change in plan.changes
        ))

    def test_existing_global_route_shadowed_by_earlier_broad_rule_is_blocked(self):
        original = add_complete_dns(base_config())
        rules = original["routing"]["rules"]
        route = next(item for item in rules if api_tool._global_port53_rule(item))
        rules.remove(route)
        rules.insert(1, {"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"})
        rules.insert(2, route)

        plan = api_tool.build_plan(original)

        self.assertTrue(any("earlier broad routing rule" in item for item in plan.blockers))

    def test_global_tcp_only_rule_is_reused_and_udp_fallback_is_added(self):
        original = base_config()
        outbound = copy.deepcopy(api_tool.DNS_OUT)
        outbound["tag"] = "existing-local-dns"
        original["outbounds"].append(outbound)
        tcp_rule = {
            "type": "field",
            "network": "tcp",
            "port": "53",
            "outboundTag": "existing-local-dns",
        }
        original["routing"]["rules"].insert(1, tcp_rule)

        plan = api_tool.build_plan(original)

        self.assertFalse(plan.blockers)
        self.assertEqual(plan.proposed["routing"]["rules"][1], tcp_rule)
        fallback = next(
            item for item in plan.proposed["routing"]["rules"]
            if api_tool._global_port53_rule(item)
        )
        self.assertEqual(fallback["outboundTag"], "existing-local-dns")
        self.assertEqual(fallback["network"], "tcp,udp")
        self.assertFalse(any(
            item.get("tag") == "dns-out" for item in plan.proposed["outbounds"]
        ))

    def test_global_tcp_only_rule_to_an_incompatible_target_blocks_apply(self):
        original = base_config()
        original["routing"]["rules"].insert(1, {
            "type": "field",
            "network": "tcp",
            "port": "53",
            "outboundTag": "proxy",
        })

        plan = api_tool.build_plan(original)

        self.assertTrue(any("global tcp port-53 rule" in item for item in plan.blockers))
        self.assertEqual(plan.proposed, original)

    def test_existing_global_tcp_and_udp_only_routes_cover_dns_without_new_route(self):
        original = base_config()
        tcp_out = copy.deepcopy(api_tool.DNS_OUT)
        tcp_out["tag"] = "local-dns-tcp"
        udp_out = copy.deepcopy(api_tool.DNS_OUT)
        udp_out["tag"] = "local-dns-udp"
        original["outbounds"].extend([tcp_out, udp_out])
        original["dns"] = {"servers": [copy.deepcopy(api_tool.DNS_SERVER)]}
        tcp_rule = {
            "type": "field",
            "network": "tcp",
            "port": "53",
            "outboundTag": "local-dns-tcp",
        }
        udp_rule = {
            "type": "field",
            "network": "udp",
            "port": "53",
            "outboundTag": "local-dns-udp",
        }
        original["routing"]["rules"][1:1] = [tcp_rule, udp_rule]

        plan = api_tool.build_plan(original)

        self.assertFalse(plan.blockers)
        self.assertEqual(plan.proposed["routing"]["rules"][1:3], [tcp_rule, udp_rule])
        self.assertFalse(any(
            api_tool._global_port53_rule(item)
            for item in plan.proposed["routing"]["rules"]
        ))
        self.assertFalse(any(
            "ADD global TCP/UDP port-53" in change
            for change in plan.changes
        ))
        self.assertFalse(any(
            item.get("tag") == "dns-out"
            for item in plan.proposed["outbounds"]
        ))

    def test_scoped_dns_rule_is_preserved_before_global_fallback(self):
        original = base_config()
        scoped = {
            "type": "field",
            "network": "udp",
            "port": "53",
            "inboundTag": ["vless-in"],
            "outboundTag": "proxy",
        }
        original["routing"]["rules"].insert(1, scoped)

        plan = api_tool.build_plan(original)

        self.assertFalse(plan.blockers)
        self.assertEqual(plan.proposed["routing"]["rules"][1], scoped)
        self.assertEqual(plan.proposed["routing"]["rules"][2]["outboundTag"], "dns-out")
        self.assertTrue(any("scoped port-53 rules are preserved" in item for item in plan.warnings))

    def test_scoped_udp_port53_rule_does_not_replace_global_rule(self):
        original = base_config()
        original["routing"]["rules"].insert(
            1,
            {
                "type": "field",
                "network": "udp",
                "port": "53",
                "inboundTag": ["vless-in"],
                "outboundTag": "proxy",
            },
        )
        plan = api_tool.build_plan(original)
        self.assertFalse(plan.blockers)
        self.assertEqual(plan.proposed["routing"]["rules"][1], original["routing"]["rules"][1])
        self.assertEqual(plan.proposed["routing"]["rules"][2], {
            **api_tool.DNS_PORT_RULE,
            "outboundTag": plan.proposed["routing"]["rules"][2]["outboundTag"],
        })

    def test_global_port53_rule_to_other_outbound_is_blocked(self):
        original = base_config()
        original["routing"]["rules"].insert(
            1,
            {"type": "field", "network": "tcp,udp", "port": "53", "outboundTag": "proxy"},
        )
        plan = api_tool.build_plan(original)
        self.assertTrue(any("does not resolve to 127.0.0.1:5355" in x for x in plan.blockers))
        self.assertEqual(
            sum(1 for x in plan.proposed["routing"]["rules"] if api_tool._global_port53_rule(x)),
            1,
        )

    def test_combined_global_port_range_that_shadows_port53_is_blocked(self):
        original = base_config()
        original["routing"]["rules"].insert(
            1,
            {
                "type": "field",
                "network": "tcp,udp",
                "port": "53,443",
                "outboundTag": "proxy",
            },
        )
        plan = api_tool.build_plan(original)
        self.assertTrue(any("fallback would be shadowed" in item for item in plan.blockers))
        self.assertEqual(plan.proposed, original)

    def test_existing_unmanaged_legacy_allow_rule_that_panel_would_adopt_is_blocked(self):
        original = base_config()
        original["routing"]["rules"].insert(
            1,
            {
                "type": "field",
                "ip": ["127.0.0.1"],
                "port": "5355",
                "outboundTag": "direct",
            },
        )
        plan = api_tool.build_plan(original)
        self.assertTrue(any("rewrite or remove an existing routing rule" in x for x in plan.blockers))

    def test_existing_global_port53_rule_after_domain_rule_is_reused(self):
        original = base_config()
        original["outbounds"].append(copy.deepcopy(api_tool.DNS_OUT))
        original["dns"] = {"servers": [copy.deepcopy(api_tool.DNS_SERVER)]}
        rules = original["routing"]["rules"]
        domain_rule = {"type": "field", "domain": ["example.net"], "outboundTag": "proxy"}
        rules.insert(1, domain_rule)
        route = copy.deepcopy(api_tool.DNS_PORT_RULE)
        rules.insert(2, route)  # domain-only rule cannot match rewritten loopback IP
        plan = api_tool.build_plan(original)
        self.assertFalse(plan.blockers)
        self.assertFalse(any("ADD global TCP/UDP port-53" in item for item in plan.changes))

    def test_missing_or_misordered_api_rule_is_blocked(self):
        missing = base_config()
        missing["routing"]["rules"] = missing["routing"]["rules"][1:]
        self.assertTrue(any("api-inbound" in x for x in api_tool.build_plan(missing).blockers))

        moved = base_config()
        moved["routing"]["rules"].append(moved["routing"]["rules"].pop(0))
        self.assertTrue(any("api-inbound" in x for x in api_tool.build_plan(moved).blockers))

    def test_panel_qtype_normalization_side_effect_is_blocked(self):
        original = add_complete_dns(base_config())
        dns_out = next(x for x in original["outbounds"] if x.get("tag") == "dns-out")
        dns_out["settings"]["rules"] = [{"qType": 0, "server": "9.9.9.9"}]
        plan = api_tool.build_plan(original)
        self.assertTrue(any("numeric DNS qType 0" in x for x in plan.blockers))

    def test_existing_dns_out_conflict_is_not_rewritten(self):
        original = base_config()
        conflicting = copy.deepcopy(api_tool.DNS_OUT)
        conflicting["settings"]["rewritePort"] = 5356
        original["outbounds"].append(conflicting)
        before = copy.deepcopy(original)
        plan = api_tool.build_plan(original)
        self.assertFalse(plan.blockers)
        self.assertEqual(plan.proposed["outbounds"][:len(before["outbounds"])], before["outbounds"])
        added = plan.proposed["outbounds"][-1]
        self.assertEqual(added["tag"], "dns-out-doh-health-monitor")
        self.assertEqual(added["settings"]["rewritePort"], 5355)
        self.assertEqual(plan.proposed["routing"]["rules"][1]["outboundTag"], added["tag"])

    def test_existing_scoped_local_dns_server_is_not_duplicated_or_replaced(self):
        original = base_config()
        original["dns"] = {
            "servers": [
                {
                    "address": "127.0.0.1",
                    "port": 5355,
                    "domains": ["geosite:category-ru"],
                    "skipFallback": False,
                }
            ]
        }
        plan = api_tool.build_plan(original)
        self.assertTrue(any("exists only as a scoped DNS server" in x for x in plan.blockers))
        self.assertEqual(len(plan.proposed["dns"]["servers"]), 1)

    def test_local_dns_server_object_with_embedded_port_is_reused(self):
        original = base_config()
        server = {"address": "127.0.0.1:5355", "domains": [], "skipFallback": False}
        original["dns"] = {"servers": [server]}

        plan = api_tool.build_plan(original)

        self.assertFalse(plan.blockers)
        self.assertFalse(any(
            "ADD dns.servers" in change for change in plan.changes
        ))
        self.assertEqual(plan.proposed["dns"]["servers"], [server])

    def test_ipv6_dns_server_without_port_is_not_misparsed_as_embedded_port(self):
        self.assertEqual(
            api_tool._server_endpoint({"address": "2001:db8::1"}),
            ("2001:db8::1", 53),
        )
        self.assertEqual(
            api_tool._server_endpoint("2001:db8::1"),
            ("2001:db8::1", 53),
        )
        self.assertEqual(
            api_tool._server_endpoint("[2001:db8::1]:5355"),
            ("2001:db8::1", 5355),
        )
    def test_local_dns_server_with_query_or_ip_filters_is_not_reused_as_general(self):
        variants = [
            {"queryStrategy": "UseIPv4"},
            {"expectedIPs": ["geoip:private"]},
            {"unexpectedIPs": ["geoip:private"]},
        ]
        for extra in variants:
            with self.subTest(extra=extra):
                original = base_config()
                server = copy.deepcopy(api_tool.DNS_SERVER)
                server.update(extra)
                original["dns"] = {"servers": [server]}

                plan = api_tool.build_plan(original)

                self.assertTrue(any(
                    "exists only as a scoped DNS server" in item
                    for item in plan.blockers
                ))
                self.assertEqual(plan.proposed["dns"]["servers"], [server])

    def test_duplicate_general_local_dns_servers_are_reused_without_adding_another(self):
        original = base_config()
        duplicate_servers = [
            copy.deepcopy(api_tool.DNS_SERVER),
            copy.deepcopy(api_tool.DNS_SERVER),
        ]
        original["dns"] = {"servers": duplicate_servers}

        plan = api_tool.build_plan(original)

        self.assertFalse(plan.blockers)
        self.assertEqual(plan.proposed["dns"]["servers"], duplicate_servers)
        self.assertTrue(any("Duplicate general DNS server entries already exist" in x for x in plan.warnings))
        self.assertFalse(any("ADD dns.servers" in item for item in plan.changes))

    def test_panel_owned_custom_allow_rule_is_not_silently_removed(self):
        original = base_config()
        original["dns"] = {"servers": [copy.deepcopy(api_tool.DNS_SERVER)]}
        original["routing"]["rules"].insert(
            1,
            {
                "type": "field",
                "ruleTag": "xui-dns-allow",
                "ip": ["192.168.1.2"],
                "port": "5000",
                "outboundTag": "direct",
            },
        )
        plan = api_tool.build_plan(original)
        self.assertTrue(any("rewrite or remove an existing routing rule" in x for x in plan.blockers))

    def test_existing_legacy_managed_rule_is_not_rewritten(self):
        original = base_config()
        original["dns"] = {"servers": [copy.deepcopy(api_tool.DNS_SERVER)]}
        original["routing"]["rules"].insert(
            1,
            {
                "type": "field",
                "ip": ["127.0.0.1"],
                "port": "5355",
                "outboundTag": "direct",
            },
        )
        plan = api_tool.build_plan(original)
        self.assertTrue(any("rewrite or remove an existing routing rule" in x for x in plan.blockers))

    def test_missing_direct_outbound_with_private_block_is_blocked(self):
        original = base_config()
        original["outbounds"] = [x for x in original["outbounds"] if x.get("tag") != "direct"]
        plan = api_tool.build_plan(original)
        self.assertTrue(any("exactly one direct outbound" in x for x in plan.blockers))

    def test_all_non_dns_outbounds_and_user_rules_are_preserved(self):
        original = base_config()
        before_outbounds = copy.deepcopy(original["outbounds"])
        before_rules = copy.deepcopy(original["routing"]["rules"])
        plan = api_tool.build_plan(original)
        self.assertFalse(plan.blockers)
        retained = [x for x in plan.proposed["outbounds"] if x.get("tag") != "dns-out"]
        self.assertEqual(retained, before_outbounds)
        retained_rules = [
            x for x in plan.proposed["routing"]["rules"]
            if not api_tool._global_port53_rule(x)
        ]
        self.assertEqual(retained_rules, before_rules)
        self.assertEqual(plan.proposed["policy"], original["policy"])
        self.assertEqual(plan.proposed["log"], original["log"])

    def test_dns_server_address_string_is_recognized(self):
        original = base_config()
        original["dns"] = {"servers": ["127.0.0.1:5355"]}
        plan = api_tool.build_plan(original)
        self.assertFalse(plan.blockers)
        self.assertFalse(any("dns.servers" in x for x in plan.changes))

    def test_dns_server_private_endpoint_parser(self):
        self.assertEqual(api_tool._split_ip_address("127.0.0.1:5355"), ("127.0.0.1", 5355))
        self.assertEqual(api_tool._split_ip_address("https://1.1.1.1/dns-query"), ("1.1.1.1", 443))
        self.assertIsNone(api_tool._split_ip_address("https://cloudflare-dns.com/dns-query"))


class PanelEndpointDiscoveryTests(unittest.TestCase):
    def _write_panel_db(self, path, values):
        connection = sqlite3.connect(path)
        try:
            connection.execute("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT)")
            connection.executemany(
                "INSERT INTO settings(key, value) VALUES (?, ?)",
                list(values.items()),
            )
            connection.commit()
        finally:
            connection.close()

    def test_detects_tls_port_path_and_domain(self):
        with tempfile.TemporaryDirectory() as directory:
            db = __import__("pathlib").Path(directory) / "x-ui.db"
            self._write_panel_db(db, {
                "webPort": "33976",
                "webBasePath": "/private-panel-path/",
                "webCertFile": "/cert/fullchain.pem",
                "webKeyFile": "/cert/privkey.pem",
                "webDomain": "panel.example.test",
            })
            with patch.object(api_tool, "_panel_tls_is_enabled", return_value=True):
                endpoint = api_tool.detect_panel_endpoint(
                    db, runtime_env={}, panel_cwd=__import__("pathlib").Path(directory)
                )
            self.assertEqual(endpoint.base_url, "https://127.0.0.1:33976/private-panel-path")
            self.assertEqual(endpoint.host_header, "panel.example.test:33976")
            self.assertEqual(endpoint.tls_server_name, "panel.example.test")
            self.assertIsNone(endpoint.tls_verify_ip)

    def test_detects_ip_san_certificate_and_uses_separate_sni_and_ip_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = __import__("pathlib").Path(directory)
            db = root / "x-ui.db"
            self._write_panel_db(db, {
                "webPort": "33976",
                "webBasePath": "/",
                "webCertFile": "/cert/fullchain.pem",
                "webKeyFile": "/cert/privkey.pem",
            })
            with (
                patch.object(api_tool, "_panel_tls_is_enabled", return_value=True),
                patch.object(
                    api_tool.ssl._ssl,
                    "_test_decode_cert",
                    return_value={"subjectAltName": [("IP Address", "130.49.178.137")]},
                ),
            ):
                endpoint = api_tool.detect_panel_endpoint(db, runtime_env={}, panel_cwd=root)
            self.assertEqual(endpoint.base_url, "https://127.0.0.1:33976")
            self.assertEqual(endpoint.tls_server_name, "localhost")
            self.assertEqual(endpoint.tls_verify_ip, "130.49.178.137")

    def test_detects_http_when_panel_has_no_tls_certificate(self):
        with tempfile.TemporaryDirectory() as directory:
            db = __import__("pathlib").Path(directory) / "x-ui.db"
            self._write_panel_db(db, {"webPort": "33976", "webBasePath": "/"})
            endpoint = api_tool.detect_panel_endpoint(
                db, runtime_env={}, panel_cwd=__import__("pathlib").Path(directory)
            )
            self.assertEqual(endpoint.base_url, "http://127.0.0.1:33976")
            self.assertIsNone(endpoint.tls_server_name)
            self.assertIsNone(endpoint.tls_verify_ip)

    def test_tls_configuration_does_not_silently_fall_back_to_http(self):
        with self.assertRaisesRegex(api_tool.IntegrationError, "refusing HTTP fallback"):
            api_tool._panel_tls_is_enabled("/missing/cert.pem", "", __import__("pathlib").Path("/"))

    def test_runtime_xui_port_overrides_database_port(self):
        with tempfile.TemporaryDirectory() as directory:
            db = __import__("pathlib").Path(directory) / "x-ui.db"
            self._write_panel_db(db, {"webPort": "33976", "webBasePath": "/"})
            endpoint = api_tool.detect_panel_endpoint(
                db, runtime_env={"XUI_PORT": "4455"}, panel_cwd=__import__("pathlib").Path(directory)
            )
            self.assertEqual(endpoint.base_url, "http://127.0.0.1:4455")

    def test_invalid_runtime_port_falls_back_to_database(self):
        with tempfile.TemporaryDirectory() as directory:
            db = __import__("pathlib").Path(directory) / "x-ui.db"
            self._write_panel_db(db, {"webPort": "33976", "webBasePath": "/"})
            endpoint = api_tool.detect_panel_endpoint(
                db, runtime_env={"XUI_PORT": "not-a-port"}, panel_cwd=__import__("pathlib").Path(directory)
            )
            self.assertEqual(endpoint.base_url, "http://127.0.0.1:33976")

    def test_endpoint_discovery_refuses_relative_path_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            db = __import__("pathlib").Path(directory) / "x-ui.db"
            self._write_panel_db(db, {"webPort": "33976", "webBasePath": "/foo/../bar/"})
            with self.assertRaisesRegex(api_tool.IntegrationError, "relative path segment"):
                api_tool.detect_panel_endpoint(db, runtime_env={}, panel_cwd=__import__("pathlib").Path(directory))

    def test_postgres_requires_explicit_base_url(self):
        with self.assertRaisesRegex(api_tool.IntegrationError, "PostgreSQL"):
            api_tool.detect_panel_endpoint(runtime_env={"XUI_DB_TYPE": "postgres"})

    def test_discovery_does_not_modify_sqlite_database(self):
        with tempfile.TemporaryDirectory() as directory:
            db = __import__("pathlib").Path(directory) / "x-ui.db"
            self._write_panel_db(db, {"webPort": "33976", "webBasePath": "/hidden/"})
            before = db.read_bytes()
            api_tool.detect_panel_endpoint(db, runtime_env={}, panel_cwd=__import__("pathlib").Path(directory))
            self.assertEqual(db.read_bytes(), before)


class PluginPreflightTests(unittest.TestCase):
    def test_detects_ipv4_and_ipv6_loopback_listeners(self):
        self.assertTrue(api_tool.listener_output_has_loopback_port(
            "LISTEN 0 128 127.0.0.1:5355 0.0.0.0:*", 5355
        ))
        self.assertTrue(api_tool.listener_output_has_loopback_port(
            "UNCONN 0 0 [::1]:5355 [::]:*", 5355
        ))

    def test_rejects_non_loopback_listener(self):
        self.assertFalse(api_tool.listener_output_has_loopback_port(
            "LISTEN 0 128 0.0.0.0:5355 0.0.0.0:*", 5355
        ))
        self.assertFalse(api_tool.listener_output_has_loopback_port(
            "LISTEN 0 128 127.0.0.1:5356 0.0.0.0:*", 5355
        ))

    def test_status_endpoint_requires_json_object(self):
        self.assertEqual(api_tool.validate_plugin_status(b'{"ok":true}'), {"ok": True})
        with self.assertRaises(api_tool.IntegrationError):
            api_tool.validate_plugin_status(b"not-json")
        with self.assertRaises(api_tool.IntegrationError):
            api_tool.validate_plugin_status(b"[]")

    def test_inactive_service_stops_before_status_api_or_panel_api(self):
        completed = [
            SimpleNamespace(returncode=0, stdout="loaded"),
            SimpleNamespace(returncode=3, stdout=""),
        ]
        with patch.object(api_tool.shutil, "which", side_effect=lambda name: "/usr/bin/" + name), \
             patch.object(api_tool.subprocess, "run", side_effect=completed), \
             patch.object(api_tool, "urlopen") as urlopen:
            with self.assertRaisesRegex(api_tool.IntegrationError, "installed but not active"):
                api_tool.check_plugin_health(
                    api_tool.DEFAULT_PLUGIN_SERVICE,
                    api_tool.DEFAULT_PLUGIN_STATUS_URL,
                    5355,
                )
            urlopen.assert_not_called()


class PanelAPITests(unittest.TestCase):
    def test_ip_san_verification_requires_exact_ip_san_not_cn(self):
        api_tool.verify_certificate_ip_san(
            {"subjectAltName": [("IP Address", "130.49.178.137")]},
            "130.49.178.137",
        )
        with self.assertRaises(api_tool.ssl.CertificateError):
            api_tool.verify_certificate_ip_san(
                {"subject": ((("commonName", "130.49.178.137"),),)},
                "130.49.178.137",
            )
        with self.assertRaises(api_tool.ssl.CertificateError):
            api_tool.verify_certificate_ip_san(
                {"subjectAltName": [("IP Address", "130.49.178.138")]},
                "130.49.178.137",
            )

    def test_ip_tls_handler_keeps_chain_validation_enabled(self):
        handler = api_tool._PanelSNIHTTPSHandler("localhost", verify_ip="130.49.178.137")
        self.assertFalse(handler._context.check_hostname)
        self.assertEqual(handler._context.verify_mode, api_tool.ssl.CERT_REQUIRED)

    def test_ip_tls_handler_passes_custom_context_to_https_connection(self):
        handler = api_tool._PanelSNIHTTPSHandler("localhost", verify_ip="130.49.178.137")
        request = api_tool.Request("https://127.0.0.1:33976/panel/api/xray/")
        captured = {}

        def capture_do_open(connection_factory, req, **kwargs):
            captured["connection_factory"] = connection_factory
            captured["request"] = req
            captured.update(kwargs)
            return object()

        handler.do_open = capture_do_open
        handler.https_open(request)

        self.assertIs(captured["request"], request)
        self.assertIs(captured["context"], handler._context)
        self.assertNotIn("check_hostname", captured)
        self.assertFalse(captured["context"].check_hostname)
        self.assertEqual(captured["context"].verify_mode, api_tool.ssl.CERT_REQUIRED)

    def setUp(self):
        self.state = {
            "config": base_config(),
            "outboundTestUrl": "https://example.invalid/204",
            "authorization": [],
            "host_headers": [],
            "posted_form": [],
            "inbounds": [],
            "next_inbound_id": 1,
            "inbound_payloads": [],
        }
        state = self.state

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                return

            def _send(self, value):
                body = json.dumps(value).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                state["authorization"].append(self.headers.get("Authorization"))
                state["host_headers"].append(self.headers.get("Host"))
                if self.path == "/nested/panel/api/inbounds/list":
                    self._send({"success": True, "msg": "", "obj": state["inbounds"]})
                else:
                    self.send_error(404)

            def do_POST(self):
                state["authorization"].append(self.headers.get("Authorization"))
                state["host_headers"].append(self.headers.get("Host"))
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length).decode()
                if self.path == "/nested/panel/api/inbounds/add":
                    payload = json.loads(raw)
                    state["inbound_payloads"].append(payload)
                    created = dict(payload)
                    created.update({"id": state["next_inbound_id"], "tag": "in-test"})
                    state["next_inbound_id"] += 1
                    state["inbounds"].append(created)
                    self._send({"success": True, "msg": "", "obj": created})
                elif self.path.startswith("/nested/panel/api/inbounds/del/"):
                    inbound_id = int(self.path.rsplit("/", 1)[1])
                    state["inbounds"] = [x for x in state["inbounds"] if x["id"] != inbound_id]
                    self._send({"success": True, "msg": "", "obj": inbound_id})
                elif self.path == "/nested/panel/api/xray/":
                    payload = {
                        "xraySetting": state["config"],
                        "outboundTestUrl": state["outboundTestUrl"],
                        "inboundTags": ["api", "vless-in"],
                    }
                    self._send({"success": True, "msg": "", "obj": json.dumps(payload)})
                elif self.path == "/nested/panel/api/xray/update":
                    form = parse_qs(raw)
                    state["posted_form"].append(form)
                    state["config"] = json.loads(form["xraySetting"][0])
                    state["outboundTestUrl"] = form["outboundTestUrl"][0]
                    self._send({"success": True, "msg": "", "obj": None})
                else:
                    self.send_error(404)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}/nested"
        self.client = api_tool.PanelAPI(self.base_url, "test-token", timeout=3)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_get_parses_nested_json_string_and_preserves_metadata(self):
        snapshot = self.client.read_state()
        self.assertEqual(snapshot["xraySetting"], self.state["config"])
        self.assertEqual(snapshot["outboundTestUrl"], "https://example.invalid/204")
        self.assertEqual(self.state["authorization"], ["Bearer test-token"])

    def test_configured_host_header_is_sent_to_local_panel(self):
        client = api_tool.PanelAPI(
            self.base_url, "test-token", timeout=3, host_header="panel.example.invalid:12345"
        )
        client.read_state()
        self.assertEqual(self.state["host_headers"], ["panel.example.invalid:12345"])

    def test_update_uses_exact_panel_route_and_preserves_outbound_test_url(self):
        config = base_config()
        config["outbounds"].append(copy.deepcopy(api_tool.DNS_OUT))
        self.client.update(config, "https://example.invalid/204")
        self.assertEqual(self.state["config"], config)
        self.assertEqual(self.state["outboundTestUrl"], "https://example.invalid/204")
        self.assertEqual(self.state["authorization"][-1], "Bearer test-token")
        self.assertIn("xraySetting", self.state["posted_form"][-1])
        self.assertIn("outboundTestUrl", self.state["posted_form"][-1])

    def test_inbound_api_lists_creates_and_deletes_only_by_numeric_id(self):
        inbound = {
            "remark": "doh-route-test-unit",
            "protocol": "tunnel",
            "listen": "127.0.0.1",
            "port": 15353,
            "settings": json.dumps({
                "rewriteAddress": "127.0.0.1",
                "rewritePort": 53,
                "allowedNetwork": "tcp,udp",
                "followRedirect": False,
                "portMap": {},
            }),
            "enable": True,
        }
        created = self.client.add_inbound(inbound)
        self.assertEqual(created["id"], 1)
        self.assertEqual(self.client.list_inbounds()[0]["remark"], "doh-route-test-unit")
        self.client.delete_inbound(created["id"])
        self.assertEqual(self.client.list_inbounds(), [])
        self.assertEqual(self.state["inbound_payloads"], [inbound])
        self.assertTrue(all(x == "Bearer test-token" for x in self.state["authorization"]))

    def test_delete_inbound_refuses_invalid_ids_without_api_request(self):
        before = len(self.state["authorization"])
        for invalid in (0, -1, True, "1", None):
            with self.subTest(invalid=invalid):
                with self.assertRaises(api_tool.IntegrationError):
                    self.client.delete_inbound(invalid)
        self.assertEqual(len(self.state["authorization"]), before)

    def test_add_inbound_rejects_non_tunnel_protocol(self):
        with self.assertRaisesRegex(api_tool.IntegrationError, "Only a Tunnel"):
            self.client.add_inbound({"protocol": "vless"})
        self.assertEqual(self.state["authorization"], [])

    def test_non_loopback_plain_http_requires_explicit_override(self):
        with self.assertRaises(api_tool.IntegrationError):
            api_tool.PanelAPI("http://panel.example.invalid", "secret")
        allowed = api_tool.PanelAPI(
            "http://panel.example.invalid", "secret", allow_insecure_http=True
        )
        self.assertTrue(allowed.root.startswith("http://"))




class TemporaryTunnelSafetyTests(unittest.TestCase):
    def test_port_selection_skips_panel_reservations_and_live_sockets(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            occupied = listener.getsockname()[1]
            chosen = api_tool.choose_temporary_tunnel_port(
                [{"listen": "127.0.0.1", "port": 15353}],
                candidates=(15353, occupied, 15354),
            )
        self.assertEqual(chosen, 15354)

    def test_port_selection_refuses_when_all_candidates_reserved(self):
        with self.assertRaises(api_tool.IntegrationError):
            api_tool.choose_temporary_tunnel_port(
                [{"listen": "0.0.0.0", "port": 15353}],
                candidates=(15353,),
            )

    def test_temporary_tunnel_is_loopback_and_dns_only(self):
        inbound = api_tool.build_temporary_tunnel(15353, "a1b2c3d4e5f60718")
        self.assertEqual(inbound["protocol"], "tunnel")
        self.assertEqual(inbound["listen"], "127.0.0.1")
        self.assertEqual(inbound["port"], 15353)
        self.assertTrue(inbound["remark"].startswith(api_tool.TUNNEL_REMARK_PREFIX))
        settings = json.loads(inbound["settings"])
        self.assertEqual(settings["rewriteAddress"], "127.0.0.1")
        self.assertEqual(settings["rewritePort"], 53)
        self.assertEqual(settings["allowedNetwork"], "tcp,udp")

    def test_temporary_tunnel_verification_rejects_identity_changes(self):
        expected = api_tool.build_temporary_tunnel(15353, "a1b2c3d4e5f60718")
        actual = dict(expected, id=7, tag="inbound-7")
        self.assertEqual(
            api_tool.verify_temporary_tunnel([actual], expected, 7)["id"], 7
        )
        actual["port"] = 15354
        with self.assertRaises(api_tool.IntegrationError):
            api_tool.verify_temporary_tunnel([actual], expected, 7)

    def test_cleanup_is_idempotent_and_deletes_only_verified_id(self):
        expected = api_tool.build_temporary_tunnel(15353, "a1b2c3d4e5f60718")
        created = dict(expected, id=7, tag="inbound-7")

        class FakeClient:
            def __init__(self):
                self.inbounds = [created]
                self.deleted = []

            def list_inbounds(self):
                return copy.deepcopy(self.inbounds)

            def delete_inbound(self, inbound_id):
                self.deleted.append(inbound_id)
                self.inbounds = [x for x in self.inbounds if x["id"] != inbound_id]

        client = FakeClient()
        api_tool.cleanup_temporary_tunnel(client, expected, 7)
        api_tool.cleanup_temporary_tunnel(client, expected, 7)
        self.assertEqual(client.deleted, [7])
        self.assertEqual(client.inbounds, [])

    def test_cleanup_refuses_same_remark_under_a_different_id(self):
        expected = api_tool.build_temporary_tunnel(15353, "a1b2c3d4e5f60718")
        replacement = dict(expected, id=8, tag="inbound-8")
        class FakeClient:
            def list_inbounds(self):
                return [replacement]
            def delete_inbound(self, _inbound_id):
                self.fail("must not delete an inbound with a different ID")
        with self.assertRaisesRegex(api_tool.IntegrationError, "different ID"):
            api_tool.cleanup_temporary_tunnel(FakeClient(), expected, 7)

    def test_cleanup_refuses_to_delete_replaced_inbound(self):
        expected = api_tool.build_temporary_tunnel(15353, "a1b2c3d4e5f60718")
        replacement = dict(expected, id=7, remark="operator-owned")
        class FakeClient:
            def list_inbounds(self):
                return [replacement]
            def delete_inbound(self, _inbound_id):
                self.fail("must not delete an inbound whose identity changed")
        with self.assertRaises(api_tool.IntegrationError):
            api_tool.cleanup_temporary_tunnel(FakeClient(), expected, 7)




class DnsTunnelProbeTests(unittest.TestCase):
    def test_dns_query_packet_is_a_single_recursive_a_question(self):
        query_id, packet = api_tool._dns_query_packet("example.com")
        self.assertEqual(struct.unpack("!HHHHHH", packet[:12]), (query_id, 0x0100, 1, 0, 0, 0))
        self.assertTrue(packet.endswith(b"\x00\x01\x00\x01"))

    def test_dns_parser_requires_matching_positive_a_answer(self):
        query_id, query = api_tool._dns_query_packet("example.com")
        question_end = api_tool._skip_dns_name(query, 12) + 4
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("93.184.216.34")
        response = struct.pack("!HHHHHH", query_id, 0x8180, 1, 1, 0, 0) + query[12:question_end] + answer
        self.assertEqual(api_tool._parse_dns_a_response(response, query_id), ["93.184.216.34"])

    def test_dns_parser_rejects_empty_noerror_answer(self):
        query_id, query = api_tool._dns_query_packet("example.com")
        question_end = api_tool._skip_dns_name(query, 12) + 4
        response = struct.pack("!HHHHHH", query_id, 0x8180, 1, 0, 0, 0) + query[12:question_end]
        with self.assertRaisesRegex(api_tool.IntegrationError, "no positive A record"):
            api_tool._parse_dns_a_response(response, query_id)

    def test_dns_parser_rejects_rcode_error(self):
        query_id, query = api_tool._dns_query_packet("example.com")
        question_end = api_tool._skip_dns_name(query, 12) + 4
        response = struct.pack("!HHHHHH", query_id, 0x8183, 1, 0, 0, 0) + query[12:question_end]
        with self.assertRaisesRegex(api_tool.IntegrationError, "RCODE"):
            api_tool._parse_dns_a_response(response, query_id)

    def test_tunnel_probe_passes_when_udp_and_tcp_answers_succeed_without_counter_checks(self):
        with patch.object(
            api_tool, "query_dns_a",
            side_effect=[["93.184.216.34"], ["93.184.216.35"]],
        ) as query:
            api_tool.run_tunnel_dns_self_test(15353, "http://127.0.0.1:18765/status")
        self.assertEqual(query.call_count, 2)
        self.assertEqual(query.call_args_list[0].kwargs, {"tcp": False, "name": "example.com"})
        self.assertEqual(query.call_args_list[1].kwargs, {"tcp": True, "name": "www.example.com"})

    def test_udp_probe_failure_is_reported_separately_and_stops_before_tcp(self):
        with patch.object(
            api_tool, "query_dns_a",
            side_effect=api_tool.IntegrationError("UDP response timeout"),
        ) as query:
            with self.assertRaisesRegex(
                api_tool.IntegrationError,
                r"UDP Tunnel DNS self-test failed at 127\.0\.0\.1:15353: UDP response timeout",
            ):
                api_tool.run_tunnel_dns_self_test(15353, "http://127.0.0.1:18765/status")
        query.assert_called_once_with("127.0.0.1", 15353, tcp=False, name="example.com")

    def test_tcp_probe_failure_is_reported_separately_after_udp_passes(self):
        with patch.object(
            api_tool, "query_dns_a",
            side_effect=[["93.184.216.34"], api_tool.IntegrationError("TCP response timeout")],
        ) as query:
            with self.assertRaisesRegex(
                api_tool.IntegrationError,
                r"TCP Tunnel DNS self-test failed at 127\.0\.0\.1:15353: TCP response timeout",
            ):
                api_tool.run_tunnel_dns_self_test(15353, "http://127.0.0.1:18765/status")
        self.assertEqual(query.call_count, 2)
        self.assertEqual(query.call_args_list[0].kwargs, {"tcp": False, "name": "example.com"})
        self.assertEqual(query.call_args_list[1].kwargs, {"tcp": True, "name": "www.example.com"})

    def test_query_dns_a_reports_udp_receive_timeout_with_endpoint(self):
        with patch.object(api_tool.socket, "socket") as socket_factory:
            connection = socket_factory.return_value.__enter__.return_value
            connection.recvfrom.side_effect = TimeoutError("timed out")
            with self.assertRaisesRegex(
                api_tool.IntegrationError,
                r"UDP DNS self-test timed out waiting for a response from 127\.0\.0\.1:15353",
            ):
                api_tool.query_dns_a("127.0.0.1", 15353, tcp=False)

    def test_query_dns_a_reports_tcp_connect_timeout_with_endpoint(self):
        with patch.object(api_tool.socket, "create_connection", side_effect=TimeoutError("timed out")):
            with self.assertRaisesRegex(
                api_tool.IntegrationError,
                r"TCP DNS self-test timed out connecting to 127\.0\.0\.1:15353",
            ):
                api_tool.query_dns_a("127.0.0.1", 15353, tcp=True)



class TemporaryTunnelOrchestrationTests(unittest.TestCase):
    class FakeClient:
        def __init__(self, existing_rule=False):
            config = base_config()
            if existing_rule:
                config["outbounds"][0]["settings"]["finalRules"] = [
                    copy.deepcopy(api_tool.TEMP_DNS_FINAL_RULE)
                ]
            self.state = {
                "xraySetting": config,
                "outboundTestUrl": "https://example.invalid/",
            }
            self.inbounds = []
            self.next_id = 1
            self.deleted = []
            self.updates = 0

        def read_state(self):
            return copy.deepcopy(self.state)

        def update(self, config, outbound_test_url):
            self.state = {
                "xraySetting": api_tool.panel_normalize_dns_allow_rules(copy.deepcopy(config)),
                "outboundTestUrl": outbound_test_url,
            }
            self.updates += 1

        def list_inbounds(self):
            return copy.deepcopy(self.inbounds)

        def add_inbound(self, payload):
            created = copy.deepcopy(payload)
            created["id"] = self.next_id
            created["tag"] = f"temporary-{self.next_id}"
            self.next_id += 1
            self.inbounds.append(created)
            return copy.deepcopy(created)

        def delete_inbound(self, inbound_id):
            self.deleted.append(inbound_id)
            self.inbounds = [item for item in self.inbounds if item.get("id") != inbound_id]

    def _args(self):
        return SimpleNamespace(
            plugin_status_url="http://127.0.0.1:18765/status",
        )

    def test_create_retains_tunnel_and_added_rule_without_running_test_or_cleanup(self):
        client = self.FakeClient()
        with patch.object(api_tool, "choose_temporary_tunnel_port", return_value=15353), \
             patch.object(api_tool, "wait_for_tunnel_listeners"), \
             patch.object(api_tool, "confirm_restart"), \
             patch.object(api_tool, "run_tunnel_dns_self_test") as probe:
            self.assertEqual(api_tool.ensure_diagnostic_tunnel(self._args(), client), 0)

        self.assertEqual(len(client.inbounds), 1)
        self.assertEqual(client.inbounds[0]["port"], 15353)
        self.assertEqual(client.deleted, [])
        self.assertEqual(
            api_tool._temporary_final_rule_count(client.state["xraySetting"]), 1
        )
        probe.assert_not_called()

    def test_test_only_probes_existing_tunnel_and_never_mutates_or_deletes(self):
        client = self.FakeClient()
        expected = api_tool.build_temporary_tunnel(15353, "a1b2c3d4e5f60718", rule_mode="added")
        inbound = copy.deepcopy(expected)
        inbound.update({"id": 7, "tag": "temporary-7"})
        client.inbounds = [inbound]
        direct = next(item for item in client.state["xraySetting"]["outbounds"] if item.get("tag") == "direct")
        direct["settings"]["finalRules"] = [copy.deepcopy(api_tool.TEMP_DNS_FINAL_RULE)]
        before_state = client.read_state()
        before_inbounds = client.list_inbounds()

        with patch.object(api_tool, "run_tunnel_dns_self_test") as probe:
            self.assertEqual(api_tool.test_diagnostic_tunnel(self._args(), client), 0)

        probe.assert_called_once_with(15353, self._args().plugin_status_url)
        self.assertEqual(client.read_state(), before_state)
        self.assertEqual(client.list_inbounds(), before_inbounds)
        self.assertEqual(client.deleted, [])

    def test_cleanup_removes_reused_rule_even_with_panel_dns_allow_route(self):
        client = self.FakeClient(existing_rule=True)
        expected = api_tool.build_temporary_tunnel(15353, "a1b2c3d4e5f60718", rule_mode="reused")
        inbound = copy.deepcopy(expected)
        inbound.update({"id": 10, "tag": "temporary-10"})
        client.inbounds = [inbound]
        client.state["xraySetting"]["routing"]["rules"].append({
            "type": "field",
            "ip": ["127.0.0.1"],
            "port": "5355",
            "outboundTag": "direct",
            "ruleTag": "xui-dns-allow",
        })

        with patch.object(api_tool, "wait_for_tunnel_port_closed"):
            api_tool.cleanup_temporary_leftovers(client)

        self.assertEqual(client.inbounds, [])
        self.assertEqual(api_tool._temporary_final_rule_count(client.state["xraySetting"]), 0)
        # Cleanup must not mistake the panel route for ownership of the finalRule.
        # Panel normalization may independently reconcile its routing rules.

    def test_cleanup_preserves_rule_for_external_direct_route_to_diagnostic_endpoint(self):
        client = self.FakeClient(existing_rule=True)
        expected = api_tool.build_temporary_tunnel(15353, "a1b2c3d4e5f60718", rule_mode="reused")
        inbound = copy.deepcopy(expected)
        inbound.update({"id": 10, "tag": "temporary-10"})
        client.inbounds = [inbound]
        client.state["xraySetting"]["routing"]["rules"].append({
            "type": "field",
            "ip": ["127.0.0.1"],
            "port": "5355",
            "network": "tcp,udp",
            "outboundTag": "direct",
            "ruleTag": "external-dns-consumer",
        })

        with patch.object(api_tool, "wait_for_tunnel_port_closed"):
            api_tool.cleanup_temporary_leftovers(client)

        self.assertEqual(client.inbounds, [])
        self.assertEqual(api_tool._temporary_final_rule_count(client.state["xraySetting"]), 1)

    def test_cleanup_removes_rule_when_direct_route_cannot_match_final_rule_endpoint(self):
        client = self.FakeClient(existing_rule=True)
        expected = api_tool.build_temporary_tunnel(15353, "a1b2c3d4e5f60718", rule_mode="reused")
        inbound = copy.deepcopy(expected)
        inbound.update({"id": 10, "tag": "temporary-10"})
        client.inbounds = [inbound]
        client.state["xraySetting"]["routing"]["rules"].append({
            "type": "field",
            "ip": ["203.0.113.10"],
            "port": "443",
            "outboundTag": "direct",
        })

        with patch.object(api_tool, "wait_for_tunnel_port_closed"):
            api_tool.cleanup_temporary_leftovers(client)

        self.assertEqual(client.inbounds, [])
        self.assertEqual(api_tool._temporary_final_rule_count(client.state["xraySetting"]), 0)

    def test_cleanup_removes_rule_when_direct_route_targets_loopback_on_other_port(self):
        client = self.FakeClient(existing_rule=True)
        expected = api_tool.build_temporary_tunnel(15353, "a1b2c3d4e5f60718", rule_mode="reused")
        inbound = copy.deepcopy(expected)
        inbound.update({"id": 10, "tag": "temporary-10"})
        client.inbounds = [inbound]
        client.state["xraySetting"]["routing"]["rules"].append({
            "type": "field",
            "ip": ["127.0.0.1"],
            "port": "5353",
            "outboundTag": "direct",
        })

        with patch.object(api_tool, "wait_for_tunnel_port_closed"):
            api_tool.cleanup_temporary_leftovers(client)

        self.assertEqual(client.inbounds, [])
        self.assertEqual(api_tool._temporary_final_rule_count(client.state["xraySetting"]), 0)

    def test_cleanup_preserves_inbound_referenced_by_non_diagnostic_route(self):
        client = self.FakeClient(existing_rule=False)
        expected = api_tool.build_temporary_tunnel(15353, "a1b2c3d4e5f60718", rule_mode="added")
        inbound = copy.deepcopy(expected)
        inbound.update({"id": 10, "tag": "temporary-10"})
        client.inbounds = [inbound]
        client.state["xraySetting"]["routing"]["rules"].append({
            "type": "field", "inboundTag": ["temporary-10"], "outboundTag": "proxy"
        })

        api_tool.cleanup_temporary_leftovers(client)

        self.assertEqual([item["id"] for item in client.inbounds], [10])
        self.assertEqual(api_tool._temporary_final_rule_count(client.state["xraySetting"]), 0)

    def test_duplicate_final_rules_do_not_block_safe_inbound_cleanup(self):
        client = self.FakeClient(existing_rule=True)
        client.state["xraySetting"]["outbounds"][0]["settings"]["finalRules"].append(
            copy.deepcopy(api_tool.TEMP_DNS_FINAL_RULE)
        )
        expected = api_tool.build_temporary_tunnel(15353, "a1b2c3d4e5f60718", rule_mode="reused")
        inbound = copy.deepcopy(expected)
        inbound.update({"id": 10, "tag": "temporary-10"})
        client.inbounds = [inbound]

        with patch.object(api_tool, "wait_for_tunnel_port_closed"):
            api_tool.cleanup_temporary_leftovers(client)

        self.assertEqual(client.inbounds, [])
        self.assertEqual(api_tool._temporary_final_rule_count(client.state["xraySetting"]), 2)

    def test_create_repairs_misordered_existing_dns_allow(self):
        client = self.FakeClient(existing_rule=True)
        direct = next(item for item in client.state["xraySetting"]["outbounds"] if item.get("tag") == "direct")
        direct["settings"]["finalRules"] = [
            {"action": "block", "ip": ["geoip:private"]},
            {"action": "allow"},
            copy.deepcopy(api_tool.TEMP_DNS_FINAL_RULE),
        ]
        with patch.object(api_tool, "choose_temporary_tunnel_port", return_value=15353), \
             patch.object(api_tool, "wait_for_tunnel_listeners"), \
             patch.object(api_tool, "confirm_restart"):
            self.assertEqual(api_tool.ensure_diagnostic_tunnel(self._args(), client), 0)

        rules = api_tool._temporary_final_rules(client.state["xraySetting"])
        self.assertEqual(rules[0], api_tool.TEMP_DNS_FINAL_RULE)
        self.assertEqual(rules[1]["ip"], ["geoip:private"])
        self.assertEqual(rules[2], {"action": "allow"})
        self.assertEqual(len(client.inbounds), 1)
        self.assertEqual(client.deleted, [])

    def test_create_refuses_to_create_a_second_diagnostic_tunnel(self):
        client = self.FakeClient()
        expected = api_tool.build_temporary_tunnel(15353, "a1b2c3d4e5f60718", rule_mode="reused")
        inbound = copy.deepcopy(expected)
        inbound.update({"id": 11, "tag": "temporary-11"})
        client.inbounds = [inbound]
        with self.assertRaisesRegex(api_tool.IntegrationError, "already exists"):
            api_tool.ensure_diagnostic_tunnel(self._args(), client)
        self.assertEqual(len(client.inbounds), 1)
        self.assertEqual(client.deleted, [])

    def test_test_refuses_rule_behind_block_without_sending_dns_packet(self):
        client = self.FakeClient(existing_rule=True)
        expected = api_tool.build_temporary_tunnel(15353, "a1b2c3d4e5f60718", rule_mode="reused")
        inbound = copy.deepcopy(expected)
        inbound.update({"id": 12, "tag": "temporary-12"})
        client.inbounds = [inbound]
        direct = next(item for item in client.state["xraySetting"]["outbounds"] if item.get("tag") == "direct")
        direct["settings"]["finalRules"] = [
            {"action": "block", "ip": ["geoip:private"]},
            copy.deepcopy(api_tool.TEMP_DNS_FINAL_RULE),
        ]
        with patch.object(api_tool, "run_tunnel_dns_self_test") as probe:
            with self.assertRaisesRegex(api_tool.IntegrationError, "before blocking finalRules"):
                api_tool.test_diagnostic_tunnel(self._args(), client)
        probe.assert_not_called()
        self.assertEqual(client.deleted, [])


class RestartNoticeTests(unittest.TestCase):
    def test_panel_change_prints_restart_notice(self):
        for action in ("integrate", "remove"):
            with self.subTest(action=action), patch("builtins.print") as output:
                api_tool.confirm_restart(action)
            printed = " ".join(str(call.args[0]) for call in output.call_args_list if call.args)
            self.assertIn("may automatically restart the Xray process", printed)

    def test_unknown_panel_action_is_rejected(self):
        with self.assertRaisesRegex(api_tool.IntegrationError, "Unknown panel directive"):
            api_tool.confirm_restart("unknown")


class PanelCredentialTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = __import__("pathlib").Path(self.temp.name)
        self.expected_uid = os.geteuid()

    def tearDown(self):
        self.temp.cleanup()

    def _write_private(self, path, content):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        path.chmod(0o600)
        return path

    def test_reads_installer_token_without_sourcing_shell_file(self):
        token = "a" * 48
        path = self._write_private(
            self.root / "install-result.env",
            "XUI_USERNAME=operator\nXUI_API_TOKEN=" + token + "\n",
        )
        self.assertEqual(
            api_tool.load_installer_api_token(path, expected_uid=self.expected_uid),
            token,
        )

    def test_rejects_insecure_installer_credential_permissions(self):
        token = "b" * 48
        path = self._write_private(
            self.root / "install-result.env",
            "XUI_API_TOKEN=" + token + "\n",
        )
        path.chmod(0o644)
        with self.assertRaises(api_tool.IntegrationError):
            api_tool.load_installer_api_token(path, expected_uid=self.expected_uid)

    def test_saved_token_round_trip_is_private(self):
        token = "c" * 48
        path = self.root / "private" / "panel-auth.json"
        api_tool.save_panel_api_token(path, token, expected_uid=self.expected_uid)
        self.assertEqual(
            api_tool.load_saved_panel_api_token(path, expected_uid=self.expected_uid),
            token,
        )
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)

    def test_mints_dedicated_token_and_does_not_print_secret(self):
        token = "d" * 48
        help_result = SimpleNamespace(
            stdout="-getApiToken -tokenName -tokenScope",
            returncode=0,
        )
        mint_result = SimpleNamespace(
            stdout="API token created\napiToken: " + token + "\n",
            returncode=0,
        )
        auth_file = self.root / "auth" / "panel-auth.json"
        with patch.object(
            api_tool.subprocess, "run", side_effect=[help_result, mint_result]
        ) as run, patch("builtins.print") as output:
            actual = api_tool.mint_panel_api_token(
                __import__("pathlib").Path("/usr/local/x-ui/x-ui"),
                auth_file,
            )
        self.assertEqual(actual, token)
        self.assertEqual(run.call_count, 2)
        command = run.call_args_list[1].args[0]
        self.assertEqual(command[2:], [
            "-getApiToken",
            "-tokenName",
            api_tool.PANEL_AUTH_TOKEN_NAME,
            "-tokenScope",
            "admin",
        ])
        self.assertNotIn(token, repr(output.call_args_list))
        self.assertEqual(
            api_tool.load_saved_panel_api_token(
                auth_file, expected_uid=self.expected_uid
            ),
            token,
        )

    def test_saved_token_is_reused_without_running_panel_cli(self):
        token = "e" * 48
        auth_file = self.root / "auth" / "panel-auth.json"
        api_tool.save_panel_api_token(
            auth_file, token, expected_uid=self.expected_uid
        )
        missing_installer_file = self.root / "missing-install-result.env"
        with patch.object(api_tool, "detect_panel_cli") as detect:
            result = api_tool.resolve_panel_api_token(
                auth_file,
                installer_file=missing_installer_file,
                environ={},
            )
        self.assertEqual(result, token)
        detect.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)