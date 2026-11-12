#!/usr/bin/env python3
"""Tests for the additive LucX-UI panel API integration adapter."""

from __future__ import annotations

import copy
import importlib.util
import json
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

    def test_unlisted_xray_version_is_informational_and_does_not_prompt(self):
        with (
            patch.object(api_tool, "find_xray_binary", return_value="/usr/bin/xray"),
            patch.object(api_tool, "read_xray_version", return_value="0.0.0-test"),
            patch.object(api_tool, "detect_panel_version", return_value="3.11.0-test"),
            patch.object(api_tool, "read_tty_confirmation") as confirm,
        ):
            self.assertEqual(api_tool.check_xray_compatibility(), "0.0.0-test")
        confirm.assert_not_called()

    def test_missing_xray_binary_does_not_block_api_compatibility_checks(self):
        with (
            patch.object(
                api_tool, "find_xray_binary",
                side_effect=api_tool.IntegrationError("Xray executable was not detected"),
            ),
            patch.object(api_tool, "detect_panel_version", return_value=None),
            patch.object(api_tool, "read_tty_confirmation") as confirm,
        ):
            self.assertIsNone(api_tool.check_xray_compatibility())
        confirm.assert_not_called()

    def test_verified_xray_version_is_still_reported(self):
        version = next(iter(api_tool.VERIFIED_XRAY_VERSIONS), "99.0.0-test")
        with (
            patch.object(api_tool, "find_xray_binary", return_value="/usr/bin/xray"),
            patch.object(api_tool, "read_xray_version", return_value=version),
            patch.object(api_tool, "detect_panel_version", return_value=None),
        ):
            self.assertEqual(api_tool.check_xray_compatibility(), version)

    def test_remote_panel_api_url_is_not_allowed_by_cli_policy(self):
        self.assertFalse(api_tool.panel_api_is_local("https://panel.example.com"))
        self.assertTrue(api_tool.panel_api_is_local("http://127.0.0.1:2053/base"))
        self.assertTrue(api_tool.panel_api_is_local("http://localhost:2053"))


class BackupCleanupTests(unittest.TestCase):
    def test_verified_backup_cleanup_removes_file(self):
        with tempfile.TemporaryDirectory() as directory:
            backup = __import__("pathlib").Path(directory) / "backup.json"
            backup.write_text("private snapshot", encoding="utf-8")
            self.assertTrue(api_tool.remove_verified_backup(backup))
            self.assertFalse(backup.exists())

    def test_verified_backup_cleanup_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            backup = __import__("pathlib").Path(directory) / "already-removed.json"
            self.assertFalse(api_tool.remove_verified_backup(backup))


class ApplyBackupLifecycleTests(unittest.TestCase):
    def test_apply_retains_snapshot_after_verified_readback_for_delayed_rollback(self):
        initial = base_config()
        plan = api_tool.build_plan(initial)

        class FakeClient:
            def __init__(self):
                self.config = copy.deepcopy(initial)

            def get_snapshot(self):
                return {
                    "xraySetting": copy.deepcopy(self.config),
                    "outboundTestUrl": "https://example.invalid/204",
                }

            def update(self, config, _test_url):
                self.config = copy.deepcopy(plan.expected_saved)

        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(
                approve_restart=True,
                backup_dir=directory,
            )
            self.assertEqual(api_tool.command_apply(args, FakeClient()), 0)
            backups = list(__import__("pathlib").Path(directory).iterdir())
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)
            saved = api_tool.load_backup(backups[0])
            self.assertEqual(saved["state"], "applied-and-verified")
            self.assertEqual(saved["before"]["xraySetting"], initial)
            self.assertEqual(saved["after"]["xraySetting"], plan.expected_saved)

    def test_apply_retains_snapshot_when_readback_does_not_match(self):
        initial = base_config()
        plan = api_tool.build_plan(initial)

        class FakeClient:
            def __init__(self):
                self.calls = 0

            def get_snapshot(self):
                self.calls += 1
                config = initial if self.calls == 1 else {"unexpected": True}
                return {
                    "xraySetting": copy.deepcopy(config),
                    "outboundTestUrl": "https://example.invalid/204",
                }

            def update(self, _config, _test_url):
                return None

        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(
                approve_restart=True,
                backup_dir=directory,
            )
            self.assertEqual(api_tool.command_apply(args, FakeClient()), 2)
            backups = list(__import__("pathlib").Path(directory).iterdir())
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)


class RollbackLifecycleTests(unittest.TestCase):
    def _make_applied_backup(self, directory, before, after):
        path = api_tool.create_backup(
            {
                "xraySetting": copy.deepcopy(before),
                "outboundTestUrl": "https://example.invalid/204",
            },
            __import__("pathlib").Path(directory),
        )
        saved = api_tool.load_backup(path)
        saved["after"] = {
            "xraySetting": copy.deepcopy(after),
            "outboundTestUrl": "https://example.invalid/204",
        }
        saved["state"] = "applied-and-verified"
        api_tool._write_private_json(path, saved)
        return path

    def test_delayed_rollback_restores_before_snapshot_and_removes_backup(self):
        before = base_config()
        after = api_tool.build_plan(before).expected_saved

        class FakeClient:
            def __init__(self):
                self.config = copy.deepcopy(after)
                self.update_calls = 0

            def get_snapshot(self):
                return {
                    "xraySetting": copy.deepcopy(self.config),
                    "outboundTestUrl": "https://example.invalid/204",
                }

            def update(self, config, _test_url):
                self.update_calls += 1
                self.config = copy.deepcopy(config)

        with tempfile.TemporaryDirectory() as directory:
            backup = self._make_applied_backup(directory, before, after)
            client = FakeClient()
            args = SimpleNamespace(backup=str(backup), approve_restart=True)
            self.assertEqual(api_tool.command_rollback(args, client), 0)
            self.assertEqual(client.update_calls, 1)
            self.assertEqual(
                api_tool.canonical(client.config),
                api_tool.canonical(api_tool.panel_normalize_dns_allow_rules(before)),
            )
            self.assertFalse(backup.exists())

    def test_rollback_refuses_later_panel_changes_and_keeps_backup(self):
        before = base_config()
        after = api_tool.build_plan(before).expected_saved

        class FakeClient:
            def __init__(self):
                self.config = copy.deepcopy(after)
                self.config["log"]["loglevel"] = "debug"
                self.update_calls = 0

            def get_snapshot(self):
                return {
                    "xraySetting": copy.deepcopy(self.config),
                    "outboundTestUrl": "https://example.invalid/204",
                }

            def update(self, _config, _test_url):
                self.update_calls += 1

        with tempfile.TemporaryDirectory() as directory:
            backup = self._make_applied_backup(directory, before, after)
            client = FakeClient()
            args = SimpleNamespace(backup=str(backup), approve_restart=True)
            with self.assertRaisesRegex(
                api_tool.IntegrationError, "differ from the backup after-snapshot"
            ):
                api_tool.command_rollback(args, client)
            self.assertEqual(client.update_calls, 0)
            self.assertTrue(backup.exists())

    def test_rollback_keeps_backup_when_readback_verification_fails(self):
        before = base_config()
        after = api_tool.build_plan(before).expected_saved

        class FakeClient:
            def __init__(self):
                self.config = copy.deepcopy(after)
                self.update_calls = 0
                self.reads = 0

            def get_snapshot(self):
                self.reads += 1
                config = after if self.reads == 1 else {"unexpected": True}
                return {
                    "xraySetting": copy.deepcopy(config),
                    "outboundTestUrl": "https://example.invalid/204",
                }

            def update(self, _config, _test_url):
                self.update_calls += 1

        with tempfile.TemporaryDirectory() as directory:
            backup = self._make_applied_backup(directory, before, after)
            client = FakeClient()
            args = SimpleNamespace(backup=str(backup), approve_restart=True)
            self.assertEqual(api_tool.command_rollback(args, client), 2)
            self.assertEqual(client.update_calls, 1)
            self.assertTrue(backup.exists())



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
    def setUp(self):
        self.state = {
            "config": base_config(),
            "outboundTestUrl": "https://example.invalid/204",
            "authorization": [],
            "host_headers": [],
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
                state["host_headers"].append(self.headers.get("Host"))
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

    def test_configured_host_header_is_sent_to_local_panel(self):
        client = api_tool.PanelAPI(
            self.base_url, "test-token", timeout=3, host_header="panel.example.invalid:12345"
        )
        client.get_snapshot()
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

    def test_non_loopback_plain_http_requires_explicit_override(self):
        with self.assertRaises(api_tool.IntegrationError):
            api_tool.PanelAPI("http://panel.example.invalid", "secret")
        allowed = api_tool.PanelAPI(
            "http://panel.example.invalid", "secret", allow_insecure_http=True
        )
        self.assertTrue(allowed.root.startswith("http://"))



class TTYConfirmationTests(unittest.TestCase):
    def test_confirmation_uses_separate_non_seekable_tty_streams(self):
        from unittest.mock import mock_open

        tty_out = mock_open()
        tty_in = mock_open(read_data="RISK\n")
        with patch("builtins.open", side_effect=[tty_out.return_value, tty_in.return_value]) as mocked_open:
            answer = api_tool.read_tty_confirmation("Type RISK: ")

        self.assertEqual(answer, "RISK")
        self.assertEqual(
            [call.args[:2] for call in mocked_open.call_args_list],
            [("/dev/tty", "w"), ("/dev/tty", "r")],
        )
        tty_out.return_value.write.assert_called_once_with("Type RISK: ")
        tty_out.return_value.flush.assert_called_once()



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