#!/usr/bin/env python3
"""Tests for the additive LucX-UI panel API integration adapter."""

from __future__ import annotations

import copy
import importlib.util
import json
import threading
import unittest
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


class AdditivePlannerTests(unittest.TestCase):
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
        self.assertEqual(plan.proposed["routing"]["rules"][1], api_tool.DNS_PORT_RULE)
        self.assertEqual(plan.proposed["routing"]["rules"][2], original["routing"]["rules"][1])

    def test_global_port53_rule_to_other_outbound_is_blocked(self):
        original = base_config()
        original["routing"]["rules"].insert(
            1,
            {"type": "field", "network": "tcp,udp", "port": "53", "outboundTag": "proxy"},
        )
        plan = api_tool.build_plan(original)
        self.assertTrue(any("routes to another outbound" in x for x in plan.blockers))
        self.assertEqual(
            sum(1 for x in plan.proposed["routing"]["rules"] if api_tool._global_port53_rule(x)),
            1,
        )

    def test_combined_port_range_is_not_mistaken_for_exact_port53_rule(self):
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
        self.assertFalse(plan.blockers)
        self.assertEqual(plan.proposed["routing"]["rules"][1], api_tool.DNS_PORT_RULE)
        self.assertEqual(plan.proposed["routing"]["rules"][2], original["routing"]["rules"][1])

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

    def test_existing_global_port53_rule_below_user_rule_is_blocked(self):
        original = base_config()
        original["routing"]["rules"].insert(1, {"type": "field", "domain": ["example.net"], "outboundTag": "proxy"})
        original["routing"]["rules"].insert(2, copy.deepcopy(api_tool.DNS_PORT_RULE))
        plan = api_tool.build_plan(original)
        self.assertTrue(any("not immediately after" in x for x in plan.blockers))

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
        self.assertTrue(any("will not be overwritten" in x for x in plan.blockers))
        self.assertEqual(plan.proposed["outbounds"], before["outbounds"])

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
        self.assertTrue(any("domain-scoped" in x for x in plan.blockers))
        self.assertEqual(len(plan.proposed["dns"]["servers"]), 1)

    def test_duplicate_local_dns_servers_are_blocked(self):
        original = base_config()
        original["dns"] = {"servers": [copy.deepcopy(api_tool.DNS_SERVER), copy.deepcopy(api_tool.DNS_SERVER)]}
        plan = api_tool.build_plan(original)
        self.assertTrue(any("Multiple DNS server" in x for x in plan.blockers))

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
            if x != api_tool.DNS_PORT_RULE
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


class XrayVersionTests(unittest.TestCase):
    def test_parses_standard_xray_version_output(self):
        self.assertEqual(
            api_tool.parse_xray_version("Xray 25.10.3 (Xray, Penetrates Everything.) Custom"),
            "25.10.3",
        )

    def test_parses_version_with_v_prefix(self):
        self.assertEqual(api_tool.parse_xray_version("Xray v1.8.24"), "1.8.24")

    def test_rejects_unrelated_or_unparseable_output(self):
        self.assertIsNone(api_tool.parse_xray_version("x-ui 3.11.0-lucx.357"))
        self.assertIsNone(api_tool.parse_xray_version("Xray version unavailable"))

    def test_unlisted_version_is_not_assumed_verified(self):
        self.assertFalse(api_tool.xray_version_is_verified("0.0.0-test"))

    def test_remote_panel_api_url_is_not_allowed_by_cli_policy(self):
        self.assertFalse(api_tool.panel_api_is_local("https://panel.example.com"))
        self.assertTrue(api_tool.panel_api_is_local("http://127.0.0.1:2053/base"))
        self.assertTrue(api_tool.panel_api_is_local("http://localhost:2053"))


class PanelAPITests(unittest.TestCase):
    def setUp(self):
        self.state = {
            "config": base_config(),
            "outboundTestUrl": "https://example.invalid/204",
            "authorization": [],
            "posted_form": [],
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

            def do_POST(self):
                state["authorization"].append(self.headers.get("Authorization"))
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length).decode()
                if self.path == "/nested/panel/api/xray/":
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
        snapshot = self.client.get_snapshot()
        self.assertEqual(snapshot["xraySetting"], self.state["config"])
        self.assertEqual(snapshot["outboundTestUrl"], "https://example.invalid/204")
        self.assertEqual(self.state["authorization"], ["Bearer test-token"])

    def test_update_uses_exact_panel_route_and_preserves_outbound_test_url(self):
        config = base_config()
        config["outbounds"].append(copy.deepcopy(api_tool.DNS_OUT))
        self.client.update(config, "https://example.invalid/204")
        self.assertEqual(self.state["config"], config)
        self.assertEqual(self.state["outboundTestUrl"], "https://example.invalid/204")
        self.assertEqual(self.state["authorization"][-1], "Bearer test-token")
        self.assertIn("xraySetting", self.state["posted_form"][-1])
        self.assertIn("outboundTestUrl", self.state["posted_form"][-1])

    def test_non_loopback_plain_http_requires_explicit_override(self):
        with self.assertRaises(api_tool.IntegrationError):
            api_tool.PanelAPI("http://panel.example.invalid", "secret")
        allowed = api_tool.PanelAPI(
            "http://panel.example.invalid", "secret", allow_insecure_http=True
        )
        self.assertTrue(allowed.root.startswith("http://"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
