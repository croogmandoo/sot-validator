"""Read-only curation audit-chain verification subcommands (`audit verify`, `audit head`)."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sqlite3
from typing import Any, Optional

from sot_validator.cli._common import INPUT_ERRORS, _input_error
from sot_validator.curation import CurationStore, verify_audit_chain
from sot_validator.curation.store import _validate_anchor

_ANCHOR_PATTERN = re.compile(r"([0-9]+):([0-9a-f]{64})")
_DB_ERRORS = (*INPUT_ERRORS, sqlite3.DatabaseError)

_UNCHAINED_MESSAGE = (
    "unchained: audit log has no prev_hash/entry_hash columns (legacy schema); "
    "migrate it by opening the database once with the curation tooling "
    "(`curate` / `serve`), then re-run"
)


def _parse_anchor(raw: str) -> tuple[int, str]:
    match = _ANCHOR_PATTERN.fullmatch(raw)
    if match is None:
        raise ValueError("expected <entry_count>:<64 lowercase hex head hash>")
    return _validate_anchor((int(match.group(1)), match.group(2)))


def _printable(value: Any) -> str:
    return "".join(
        ch if ch.isprintable() else ch.encode("unicode_escape").decode("ascii")
        for ch in str(value)
    )


def _open_audit_store(path: Path) -> tuple[CurationStore, bool]:
    """Open ``path`` read-only and return the store plus whether its audit log is hash-chained."""
    store = CurationStore.open_read_only(path)
    try:
        conn = store._conn
        table = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'audit_log'"
        ).fetchone()
        if table is None:
            raise ValueError("not a curation database (no audit_log table)")
        columns = {
            str(row[1]) for row in conn.execute("PRAGMA table_info(audit_log)").fetchall()
        }
    except BaseException:
        store.close()
        raise
    return store, {"prev_hash", "entry_hash"} <= columns


def _entry_id_at(store: CurationStore, index: Optional[int]) -> Optional[str]:
    if index is None or index < 0:
        return None
    row = store._conn.execute(
        "SELECT entry_id FROM audit_log ORDER BY seq ASC LIMIT 1 OFFSET ?", (index,)
    ).fetchone()
    return None if row is None else str(row["entry_id"])


def cmd_audit_verify(args: argparse.Namespace) -> int:
    anchor: Optional[tuple[int, str]] = None
    if getattr(args, "anchor", None) is not None:
        try:
            anchor = _parse_anchor(args.anchor)
        except ValueError as exc:
            return _input_error("--anchor", args.anchor, exc)

    try:
        store, chained = _open_audit_store(Path(args.curation_db))
    except _DB_ERRORS as exc:
        return _input_error("--curation-db", args.curation_db, exc)
    with store:
        if not chained:
            print(_UNCHAINED_MESSAGE)
            return 1
        try:
            report = verify_audit_chain(store, anchor)
        except _DB_ERRORS as exc:
            return _input_error("--curation-db", args.curation_db, exc)
        if report.ok:
            print(f"ok: audit chain intact ({report.entries_checked} entries)")
            return 0
        try:
            entry_id = _entry_id_at(store, report.broken_index)
        except _DB_ERRORS as exc:
            return _input_error("--curation-db", args.curation_db, exc)
    label = f"entry {report.broken_index}"
    if entry_id is not None:
        label += f" ({_printable(entry_id)})"
    print(f"broken: {label} {report.reason}")
    return 1


def cmd_audit_head(args: argparse.Namespace) -> int:
    try:
        store, chained = _open_audit_store(Path(args.curation_db))
    except _DB_ERRORS as exc:
        return _input_error("--curation-db", args.curation_db, exc)
    with store:
        if not chained:
            print(_UNCHAINED_MESSAGE)
            return 1
        try:
            count, head_hash = store.export_chain_head()
        except sqlite3.DatabaseError as exc:
            return _input_error("--curation-db", args.curation_db, exc)
        except ValueError as exc:
            print(f"broken: {_printable(exc)}")
            return 1
    print(f"{count}:{head_hash}")
    return 0


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the `audit` command group and its `verify` / `head` subcommands."""
    # 27. audit (Phase 15)
    audit_parser = subparsers.add_parser(
        "audit",
        help="Verify the curation audit-log hash chain read-only (never migrates or writes the database).",
    )
    audit_subparsers = audit_parser.add_subparsers(dest="audit_command", required=True)

    verify_parser = audit_subparsers.add_parser(
        "verify",
        help="Walk the audit-log hash chain and report the first break (exit 0 intact, 1 broken or unchained).",
    )
    verify_parser.add_argument(
        "--curation-db",
        type=Path,
        required=True,
        help="Curation SQLite database to verify (opened read-only).",
    )
    verify_parser.add_argument(
        "--anchor",
        type=str,
        default=None,
        help="External anchor COUNT:HASH, as printed by `audit head`, the chain must still match.",
    )
    verify_parser.set_defaults(func=cmd_audit_verify)

    head_parser = audit_subparsers.add_parser(
        "head",
        help="Print the audit-log chain head as COUNT:HASH for use as a later `audit verify --anchor`.",
    )
    head_parser.add_argument(
        "--curation-db",
        type=Path,
        required=True,
        help="Curation SQLite database to read (opened read-only).",
    )
    head_parser.set_defaults(func=cmd_audit_head)
