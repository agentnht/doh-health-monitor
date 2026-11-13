#!/usr/bin/env python3
"""Unit and synthetic-SQLite lifecycle tests for the DoH integration tools."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DRY_RUN = ROOT / "scripts" / "doh-integration-dry-run.py"
STAGING = ROOT / "scripts" / "doh-integration-staging.py"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


planner = load_module(DRY_RUN, "doh_integration_dry_run")
staging = load_module(STAGING, "doh_integration_staging")


def sample_config() -> dict:
    return {
        "log": {"loglevel": "warning"},
        "outbounds": [
            {
                "tag": "dns-out",
                "protocol": "dns",
                "settings": {
                    "rewriteNetwork": "udp",
                    "rewriteAddress": "127.0.0.1",
                    "rewritePort": 5355,
                },
                "targetStrategy": "ForceIPv4",
                "sendThrough": "127.0.0.1",
            },
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "dns-doqd", "protocol": "dns", "settings": {}},
            {"tag": "custom-out", "protocol": "blackhole", "settings": {}},
        ],
        "dns": {
            "servers": [
                {
                    "address": "127.0.0.1",
                    "port": 5355,
                    "domains": [],
                    "skipFallback": False,
                },
                {"address": "9.9.9.9", "port": 53},
            ]
        },
        "routing": {
            "rules": [
                {
                    "enabled": True,
                    "network": "tcp,udp",
                    "outboundTag": "dns-out",
                    "port": "53",
                    "type": "field",
                },
                {
                    "ip": ["127.0.0.1"],
                    "outboundTag": "direct",
                    "port": "5355",
                    "ruleTag": "xui-dns-allow",
                    "type": "field",
                },
                {"ip": ["geoip:private"], "outboundTag": "blocked", "type": "field"},
                {"domain": ["example.org"], "outboundTag": "custom-out", "type": "field"},
            ]
        },
        "policy": {"levels": {"0": {"handshake": 4}}},
    }


def write_db(path: Path, config: dict) -> None:
    con = sqlite3.connect(path)
    try:
        con.execute("CREATE TABLE settings (id INTEGER PRIMARY KEY, key TEXT UNIQUE, value TEXT)")
        con.execute(
            "INSERT INTO settings(key, value) VALUES (?, ?)",
            ("xrayTemplateConfig", json.dumps(config, ensure_ascii=False)),
        )
        con.commit()
    finally:
        con.close()


def read_db_config(path: Path) -> dict:
    con = sqlite3.connect(path)
    try:
        row = con.execute(
            "SELECT value FROM settings WHERE key='xrayTemplateConfig'"
        ).fetchone()
        if row is None:
            raise AssertionError("xrayTemplateConfig is missing")
        return json.loads(row[0])
    finally:
        con.close()


class TransformTests(unittest.TestCase):
    def setUp(self):
        self.original = sample_config()

    def test_unchanged_config_has_no_changes(self):
        proposed, changes = planner.transform(copy.deepcopy(self.original))
        self.assertEqual(proposed, self.original)
        self.assertEqual(changes, [])

    def test_missing_dns_out_and_route_are_added_without_removing_dns_doqd(self):
        cfg = copy.deepcopy(self.original)
        cfg["outbounds"] = [x for x in cfg["outbounds"] if x.get("tag") != "dns-out"]
        cfg["routing"]["rules"] = [
            item for item in cfg["routing"]["rules"]
            if item.get("outboundTag") != "dns-out" or str(item.get("port")) != "53"
        ]
        proposed, changes = planner.transform(cfg)
        added = next(x for x in proposed["outbounds"] if x.get("tag") == "dns-out")
        self.assertEqual(added["settings"]["rewritePort"], 5355)
        self.assertTrue(any(x.get("tag") == "dns-doqd" for x in proposed["outbounds"]))
        self.assertTrue(any("ADD outbounds[dns-out]" in change for change in changes))

    def test_wrong_rewrite_port_conflict_is_not_rewritten(self):
        cfg = copy.deepcopy(self.original)
        cfg["outbounds"][0]["settings"]["rewritePort"] = 9999
        before = copy.deepcopy(cfg)
        with self.assertRaisesRegex(RuntimeError, "does not resolve to 127.0.0.1:5355"):
            planner.transform(cfg)
        self.assertEqual(cfg, before)

    def test_scoped_dns_server_is_not_widened_or_rewritten(self):
        cfg = copy.deepcopy(self.original)
        cfg["dns"]["servers"][0]["domains"] = ["geosite:category-ru"]
        before = copy.deepcopy(cfg)
        with self.assertRaisesRegex(RuntimeError, "exists only as a scoped DNS server"):
            planner.transform(cfg)
        self.assertEqual(cfg, before)

    def test_missing_dns_server_is_added_without_replacing_other_servers(self):
        cfg = copy.deepcopy(self.original)
        cfg["dns"]["servers"] = [x for x in cfg["dns"]["servers"] if x.get("port") != 5355]
        other_servers = copy.deepcopy(cfg["dns"]["servers"])
        proposed, changes = planner.transform(cfg)
        self.assertEqual(
            [x for x in proposed["dns"]["servers"] if x.get("port") != 5355],
            other_servers,
        )
        self.assertTrue(changes)

    def test_disabled_port53_rule_is_preserved_and_active_fallback_is_added(self):
        cfg = copy.deepcopy(self.original)
        cfg["routing"]["rules"][0]["enabled"] = False
        disabled_before = copy.deepcopy(cfg["routing"]["rules"][0])
        proposed, changes = planner.transform(cfg)
        self.assertEqual(proposed["routing"]["rules"][0], disabled_before)
        active = [
            item for item in proposed["routing"]["rules"]
            if item.get("enabled") is True and str(item.get("port")) == "53"
        ]
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["outboundTag"], "dns-out")
        self.assertTrue(changes)

    def test_missing_allow_rule_is_added_before_private_block(self):
        cfg = copy.deepcopy(self.original)
        cfg["routing"]["rules"] = [
            x for x in cfg["routing"]["rules"] if x.get("ruleTag") != "xui-dns-allow"
        ]
        before = [copy.deepcopy(x) for x in cfg["routing"]["rules"]]
        proposed, changes = planner.transform(cfg)
        rules = proposed["routing"]["rules"]
        self.assertEqual(
            [x for x in rules if x.get("ruleTag") != "xui-dns-allow"], before
        )
        allow_i = next(i for i, x in enumerate(rules) if x.get("ruleTag") == "xui-dns-allow")
        private_i = next(i for i, x in enumerate(rules) if "geoip:private" in x.get("ip", []))
        self.assertLess(allow_i, private_i)
        self.assertTrue(changes)

    def test_panel_rule_reordering_conflict_is_reported_without_rewrite(self):
        cfg = copy.deepcopy(self.original)
        rules = cfg["routing"]["rules"]
        allow = next(x for x in rules if x.get("ruleTag") == "xui-dns-allow")
        rules.remove(allow)
        rules.append(allow)
        before = copy.deepcopy(cfg)
        with self.assertRaisesRegex(RuntimeError, "rewrite or remove an existing routing rule"):
            planner.transform(cfg)
        self.assertEqual(cfg, before)

    def test_conflicting_input_is_not_mutated(self):
        cfg = copy.deepcopy(self.original)
        cfg["outbounds"][0]["settings"]["rewritePort"] = 9999
        before = json.dumps(cfg, sort_keys=True)
        with self.assertRaises(RuntimeError):
            planner.transform(cfg)
        self.assertEqual(json.dumps(cfg, sort_keys=True), before)

    def test_duplicate_dns_out_is_rejected(self):
        cfg = copy.deepcopy(self.original)
        cfg["outbounds"].append(copy.deepcopy(cfg["outbounds"][0]))
        with self.assertRaises(RuntimeError):
            planner.transform(cfg)

    def test_duplicate_local_dns_server_is_rejected(self):
        cfg = copy.deepcopy(self.original)
        cfg["dns"]["servers"].append(copy.deepcopy(cfg["dns"]["servers"][0]))
        with self.assertRaises(RuntimeError):
            planner.transform(cfg)

    def test_duplicate_allow_rule_is_rejected(self):
        cfg = copy.deepcopy(self.original)
        cfg["routing"]["rules"].append(copy.deepcopy(cfg["routing"]["rules"][1]))
        with self.assertRaises(RuntimeError):
            planner.transform(cfg)

    def test_conflicting_port53_outbound_is_rejected(self):
        cfg = copy.deepcopy(self.original)
        cfg["routing"]["rules"][0]["outboundTag"] = "custom-out"
        with self.assertRaises(RuntimeError):
            planner.transform(cfg)

    def test_partial_port53_rule_is_preserved_and_global_fallback_is_added(self):
        cfg = copy.deepcopy(self.original)
        scoped = copy.deepcopy(cfg["routing"]["rules"][0])
        scoped["network"] = "udp"
        cfg["routing"]["rules"][0] = scoped
        proposed, changes = planner.transform(cfg)
        self.assertEqual(proposed["routing"]["rules"][0], scoped)
        routes = [
            item for item in proposed["routing"]["rules"]
            if item.get("enabled") is True and str(item.get("port")) == "53"
        ]
        self.assertEqual(len(routes), 2)
        self.assertTrue(any(item.get("network") == "tcp,udp" for item in routes))
        self.assertTrue(changes)

    def test_untagged_local_allow_candidate_is_rejected(self):
        cfg = copy.deepcopy(self.original)
        cfg["routing"]["rules"][1].pop("ruleTag")
        with self.assertRaises(RuntimeError):
            planner.transform(cfg)

    def test_idempotency_after_repairs(self):
        mutations = []
        cfg = copy.deepcopy(self.original)
        cfg["outbounds"] = [x for x in cfg["outbounds"] if x.get("tag") != "dns-out"]
        cfg["routing"]["rules"] = [
            rule for rule in cfg["routing"]["rules"]
            if rule.get("outboundTag") != "dns-out"
        ]
        mutations.append(cfg)

        cfg = copy.deepcopy(self.original)
        cfg["dns"]["servers"] = [x for x in cfg["dns"]["servers"] if x.get("port") != 5355]
        mutations.append(cfg)

        cfg = copy.deepcopy(self.original)
        cfg["routing"]["rules"] = [x for x in cfg["routing"]["rules"] if x.get("ruleTag") != "xui-dns-allow"]
        mutations.append(cfg)

        cfg = copy.deepcopy(self.original)
        cfg["routing"]["rules"][0]["enabled"] = False
        mutations.append(cfg)

        for broken in mutations:
            fixed, first_changes = planner.transform(broken)
            repeated, second_changes = planner.transform(fixed)
            self.assertTrue(first_changes)
            self.assertEqual(second_changes, [])
            self.assertEqual(repeated, fixed)

    def test_unrelated_settings_and_routing_are_preserved(self):
        cfg = copy.deepcopy(self.original)
        proposed, changes = planner.transform(cfg)
        self.assertEqual(proposed, cfg)
        self.assertEqual(changes, [])
        self.assertEqual(proposed["policy"], cfg["policy"])


class StagingLifecycleTests(unittest.TestCase):
    def run_cli(self, *args, expected=0):
        result = subprocess.run(
            [sys.executable, str(STAGING), *map(str, args), "--helper", str(DRY_RUN)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        self.assertEqual(result.returncode, expected, result.stdout)
        return result.stdout

    def test_clone_apply_verify_rollback_on_synthetic_db(self):
        with tempfile.TemporaryDirectory(prefix="doh-stage-test-") as td:
            root = Path(td)
            source = root / "source.db"
            stage_db = root / "stage.db"
            write_db(source, sample_config())

            clone_output = self.run_cli(
                "--action", "clone", "--source-db", source,
                "--staging-db", stage_db,
            )
            self.assertIn("Staging copy created", clone_output)
            self.assertEqual(os.stat(stage_db).st_mode & 0o777, 0o600)

            # Remove the previous local DNS integration objects only in the
            # staging copy. The shared planner must add the missing path without
            # rewriting or claiming ownership of unrelated objects.
            con = sqlite3.connect(stage_db)
            try:
                cfg = read_db_config(stage_db)
                cfg["outbounds"] = [
                    item for item in cfg["outbounds"] if item.get("tag") != "dns-out"
                ]
                cfg["routing"]["rules"] = [
                    rule for rule in cfg["routing"]["rules"]
                    if rule.get("outboundTag") != "dns-out"
                    or str(rule.get("port")) != "53"
                ]
                con.execute(
                    "UPDATE settings SET value=? WHERE key='xrayTemplateConfig'",
                    (json.dumps(cfg),),
                )
                con.commit()
            finally:
                con.close()

            apply_output = self.run_cli(
                "--action", "apply", "--staging-db", stage_db,
            )
            self.assertIn("PASS: staging write and read-back verification succeeded", apply_output)
            self.assertTrue(Path(str(stage_db) + ".before").is_file())
            self.assertTrue(any(
                item.get("tag") == "dns-out"
                and item.get("settings", {}).get("rewritePort") == 5355
                for item in read_db_config(stage_db)["outbounds"]
            ))

            verify_output = self.run_cli(
                "--action", "verify", "--staging-db", stage_db,
            )
            self.assertIn("already matches the target", verify_output)

            rollback_output = self.run_cli(
                "--action", "rollback", "--staging-db", stage_db,
            )
            self.assertIn("staging database restored", rollback_output)
            self.assertFalse(any(
                item.get("tag") == "dns-out"
                and item.get("settings", {}).get("rewritePort") == 5355
                for item in read_db_config(stage_db)["outbounds"]
            ))

            post_rollback = self.run_cli(
                "--action", "dry-run", "--staging-db", stage_db,
            )
            self.assertIn("ADD outbounds[dns-out]", post_rollback)
            self.assertEqual(read_db_config(source)["outbounds"][0]["settings"]["rewritePort"], 5355)

            cleanup_output = self.run_cli(
                "--action", "cleanup", "--staging-db", stage_db,
            )
            self.assertIn("Removed temporary staging artifact", cleanup_output)
            self.assertFalse(stage_db.exists())
            self.assertFalse(Path(str(stage_db) + ".before").exists())
            self.assertTrue(source.is_file())

    def test_refuses_staging_inside_etc_xui(self):
        with self.assertRaises(RuntimeError):
            staging.resolve_stage_path("/etc/x-ui/not-a-staging-file.db")

    def test_refuses_staging_symlink(self):
        with tempfile.TemporaryDirectory(prefix="doh-stage-link-") as td:
            root = Path(td)
            target = root / "target.db"
            link = root / "stage.db"
            target.touch()
            link.symlink_to(target)
            with self.assertRaises(RuntimeError):
                staging.resolve_stage_path(str(link))

    def test_refuses_source_and_stage_same_path(self):
        with tempfile.TemporaryDirectory(prefix="doh-same-path-") as td:
            path = Path(td) / "same.db"
            path.touch()
            with self.assertRaises(RuntimeError):
                staging.ensure_not_same_file(path, path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
