#!/usr/bin/env python3
"""Staging-only SQLite writer for DoH/Xray integration.

This script never writes to /etc/x-ui/x-ui.db and never contacts the panel API,
Xray, systemd, or the network. It can clone the live DB read-only into a staging
file, then dry-run/apply/verify/rollback changes in that staging file only.

Requires the tested transform() function in doh-integration-dry-run.py.
"""

from __future__ import annotations

import argparse
import difflib
import importlib.util
import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any

LIVE_DB = Path("/etc/x-ui/x-ui.db").resolve()
DEFAULT_SOURCE = "/etc/x-ui/x-ui.db"
SETTING_KEY = "xrayTemplateConfig"


def load_transform(helper_path: Path):
    if not helper_path.is_file():
        raise RuntimeError(f"Transform helper not found: {helper_path}")
    spec = importlib.util.spec_from_file_location("doh_dry_run_helper", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load helper: {helper_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    transform = getattr(module, "transform", None)
    if not callable(transform):
        raise RuntimeError("Helper does not export callable transform(original)")
    return transform


def sqlite_uri(path: Path, mode: str) -> str:
    return f"{path.resolve().as_uri()}?mode={mode}"


def connect_readonly(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(sqlite_uri(path, "ro"), uri=True, timeout=10)


def check_database(path: Path) -> None:
    con = connect_readonly(path)
    try:
        rows = con.execute("PRAGMA quick_check").fetchall()
        if rows != [("ok",)]:
            raise RuntimeError(f"SQLite quick_check failed for {path}: {rows!r}")
    finally:
        con.close()


def get_template(con: sqlite3.Connection) -> str:
    row = con.execute(
        "SELECT value FROM settings WHERE key=?", (SETTING_KEY,)
    ).fetchone()
    if row is None or not isinstance(row[0], str):
        raise RuntimeError(f"{SETTING_KEY} is missing or is not text")
    return row[0]


def resolve_stage_path(path_text: str) -> Path:
    path = Path(path_text).expanduser().resolve()
    try:
        path.relative_to(Path("/etc/x-ui").resolve())
    except ValueError:
        pass
    else:
        raise RuntimeError("Refusing staging path inside /etc/x-ui")
    if path == LIVE_DB:
        raise RuntimeError("Refusing to use the live panel database as staging DB")
    return path


def ensure_not_same_file(a: Path, b: Path) -> None:
    if a.resolve() == b.resolve():
        raise RuntimeError("Source and staging paths must be different")
    if a.exists() and b.exists() and os.path.samefile(a, b):
        raise RuntimeError("Source and staging paths refer to the same file")


def create_empty_private_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)


def backup_to_new_file(source: Path, destination: Path) -> None:
    if not source.is_file():
        raise RuntimeError(f"Database does not exist: {source}")
    if destination.exists():
        raise RuntimeError(f"Refusing to overwrite existing file: {destination}")
    create_empty_private_file(destination)
    src = dst = None
    try:
        src = connect_readonly(source)
        dst = sqlite3.connect(str(destination), timeout=10)
        src.backup(dst)
        dst.commit()
        dst.close()
        dst = None
        src.close()
        src = None
        os.chmod(destination, 0o600)
        check_database(destination)
    except Exception:
        if dst is not None:
            dst.close()
        if src is not None:
            src.close()
        try:
            destination.unlink()
        except FileNotFoundError:
            pass
        raise


def restore_from_backup(backup: Path, destination: Path) -> None:
    if not backup.is_file() or not destination.is_file():
        raise RuntimeError("Rollback requires both the .before backup and staging DB")
    src = connect_readonly(backup)
    dst = sqlite3.connect(str(destination), timeout=10)
    try:
        src.backup(dst)
        dst.commit()
    finally:
        dst.close()
        src.close()
    os.chmod(destination, 0o600)
    check_database(destination)


def read_config(path: Path) -> tuple[str, dict[str, Any]]:
    con = connect_readonly(path)
    try:
        raw = get_template(con)
    finally:
        con.close()
    config = json.loads(raw)
    if not isinstance(config, dict):
        raise RuntimeError("xrayTemplateConfig root must be a JSON object")
    return raw, config


def print_diff(before: dict[str, Any], after: dict[str, Any]) -> None:
    a = json.dumps(before, indent=2, ensure_ascii=False).splitlines(keepends=True)
    b = json.dumps(after, indent=2, ensure_ascii=False).splitlines(keepends=True)
    sys.stdout.writelines(difflib.unified_diff(
        a, b, fromfile="staging-current", tofile="staging-proposed"
    ))


def action_clone(source: Path, stage: Path, transform) -> int:
    ensure_not_same_file(source, stage)
    backup_to_new_file(source, stage)
    try:
        _, config = read_config(stage)
        _, changes = transform(config)
    except Exception:
        # Keep the clone for inspection if the source template is unexpected.
        raise
    print(f"Staging copy created: {stage}")
    print("Source opened read-only; no live database records were modified.")
    if changes:
        print("The copied template has proposed corrections:")
        for change in changes:
            print(f" - {change}")
    else:
        print("Copied xrayTemplateConfig already matches the target.")
    print("File permissions: 0600")
    return 0


def action_dry_run(stage: Path, transform, verify_only: bool = False) -> int:
    _, current = read_config(stage)
    proposed, changes = transform(current)
    check_database(stage)
    if not changes: 
        print("OK: staging configuration already matches the target.")
        print("No changes proposed; no database records were modified.")
        return 0
    print("Proposed changes:")
    for change in changes:
        print(f" - {change}")
    print("\n--- STAGING DIFF ---")
    print_diff(current, proposed)
    print("\nNo database records were modified.")
    return 2 if verify_only else 0


def action_apply(stage: Path, transform) -> int:
    before_raw, before_config = read_config(gstage)
    proposed, changes = transform(before_config)
    check_database(stage)

    if not changes:
        print("OK: no changes needed. Staging database was not written.")
        return 0

    backup = Path(str(stage) + ".before")
    backup_to_new_file(stage, backup)
    print(f"Pre-write snapshot: {backup}")

    con = sqlite3.connect(str(stage), timeout=10)
    committed = False
    try:
        con.execute("BEGIN IMMEDIATE")
        current_raw = get_template(con)
        if current_raw != before_raw:
            raise RuntimeError(
                "Staging DB changed after inspection; refusing stale write"
            )

        current_config = json.loads(current_raw)
        current_proposed, current_changes = transform(current_config)
        if not current_changes:
            con.rollback()
            print("No changes remain; staging database was not written.")
            return 0

        new_raw = json.dumps(
            current_proposed, ensure_ascii=False, separators=(",", ":")
        )
        cursor = con.execute(
            "UPDATE settings SET value=? WHERE key=? AND value=?",
            (new_raw, SETTING_KEY, current_raw),
        )
        if cursor.rowcount != 1:
            raise RuntimeError(
                "Conditional update did not affect exactly one settings row"
            )
        con.commit()
        committed = True
    except Exception:
        if con.in_transaction:
            con.rollback()
        con.close()
        raise
    else:
        con.close()

    try:
        check_database(stage)
        _, verified = read_config(stage)
        if verified != proposed:
            raise RuntimeError("Post-write verification differs from proposal")
        print("PASS: staging write and read-back verification succeeded.")
        print("Only the staging database was modified.")
        print(f"Rollback snapshot retained at: {backup}")
        return 0
    except Exception:
        if committed and backup.is_file():
            restore_from_backup(backup, stage)
            print("Automatic rollback from the pre-write snapshot completed.")
        raise


def action_rollback(stage: Path) -> int:
    backup = Path(str(stage) + ".before")
    restore_from_backup(backup, stage)
    print(f"PASStage database restored from {backup}")
    print("The live panel database was not touched.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Staging-only writer; never writes the live LucX-UI database."
    )
    parser.add_argument(
        "--action", required=True,
        choices=("clone", "dry-run", "verify", "apply", "rollback"),
    )
    parser.add_argument("--staging-db", required=True)
    parser.add_argument("--source-db", default=DEFAULT_SOURCE)
    parser.add_argument(
        "--helper",
        default=str(Path(__file__).resolve().with_name("doh-integration-dry-run.py")),
        help="Path to the tested helper containing transform()",
    )
    args = parser.parse_args()

    try:
        stage = resolve_stage_path(args.staging_db)
        source = Path(args.source_db).expanduser().resolve()
        ensure_not_same_file(source, stage)

        if args.action == "clone":
            if stage.exists():
                raise RuntimeError(
                    f"Staging file already exists; refusing overwrite: {stage}"
                )
        else:
            if not stage.is_file():
                raise RuntimeError(f"Staging DB not found: {stage}; clone it first")

        transform = load_transform(Path(args.helper).expanduser().resolve())

        if args.action == "clone":
            return action_clone(source, stage, transform)
        if args.action == "dry-run":
            return action_dry_run(stage, transform)
        if args.action == "verify":
            return action_dry_run(stage, transform, verify_only=True)
        if args.action == "apply":
            return action_apply(stage, transform)
        if args.action == "rollback":
            return action_rollback(stage)
        raise RuntimeError("Unsupported action")

    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
