#!/usr/bin/env python3
"""Read-only planner for the LucX-UI / DoH Health Monitor Xray integration.

The script reads either a JSON fixture or xrayTemplateConfig from SQLite in
read-only mode. It never writes files, database records, panel settings, or
runtime Xray configuration.
"""

from __future__ import annotations

import argparse
import difflib
import importlib.util
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

DB_DEFAULT = "/etc/x-ui/x-ui.db"
SETTING_KEY = "xrayTemplateConfig"

_API_PLANNER = None


def _load_api_planner():
    """Load the production planner so dry-run and apply share identical decisions."""
    global _API_PLANNER
    if _API_PLANNER is not None:
        return _API_PLANNER
    api_path = Path(__file__).resolve().with_name("lucx-ui-doh-api.py")
    spec = importlib.util.spec_from_file_location("doh_dry_run_api_planner", api_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot load the shared LucX-UI DNS planner")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    _API_PLANNER = module
    return module


def transform(original: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Use the same semantic plan as apply; this function remains read-only."""
    plan = _load_api_planner().build_plan(original, require_api_rule=False)
    if plan.blockers:
        raise RuntimeError("; ".join(plan.blockers))
    # expected_saved includes only the panel's modeled normalization of its
    # own DNS exception; this makes the offline view match API apply/read-back.
    return plan.expected_saved, plan.changes


def load_config(args: argparse.Namespace) -> dict[str, Any]:
    if args.config:
        config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    else:
        db_path = Path(args.db).expanduser().resolve()
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
