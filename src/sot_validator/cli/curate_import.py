"""Bulk CSV curation import subcommand (`curate-import`): read-only preview, confirm-token apply."""

from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
import sqlite3
import sys
from typing import Any, Optional

from sot_validator.cli._common import INPUT_ERRORS, _load_single_site_snapshot
from sot_validator.cli.audit import _open_audit_store, _printable
from sot_validator.curation import (
    BulkApplyRefused,
    CsvPatchRow,
    CurationStore,
    PatchCsvError,
    PatchPreview,
    apply_patches,
    parse_patch_csv,
    preview_patches,
)
from sot_validator.models import Site
from sot_validator.signals.base import normalize_utc_datetime

_STORE_ERRORS = (sqlite3.DatabaseError, ValueError)


def _import_error(message: str) -> int:
    print(f"error: {' '.join(message.split())}", file=sys.stderr)
    return 2


def _input_error(flag: str, value: Any, exc: BaseException) -> int:
    # Like _common._input_error, but control characters in the value and reason are escaped.
    reason = f"missing field {exc}" if isinstance(exc, KeyError) else str(exc)
    return _import_error(
        f"{flag} {_printable(value)}: {_printable(reason or type(exc).__name__)}"
    )


def _cell(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True)


def _mode_error(args: argparse.Namespace) -> Optional[str]:
    if not args.preview and not args.apply:
        return "curate-import needs a mode: pass --preview or --apply --confirm-token TOKEN"
    if args.preview and args.apply:
        return "--preview and --apply cannot be combined; preview first, then apply"
    if args.apply and args.confirm_token is None:
        return "--apply needs --confirm-token TOKEN from a --preview of the same CSV"
    if args.preview and args.confirm_token is not None:
        return "--confirm-token is only used with --apply; --preview never writes"
    return None


def _print_preview(preview: PatchPreview) -> None:
    for row in preview.rows:
        print(
            f"row {row.row_number}: {row.status} {_printable(row.record_type)} "
            f"{_cell(row.record_id)} {_cell(row.field)}: "
            f"{_cell(row.old_value)} -> {_cell(row.new_value)} "
            f"reason {_cell(row.reason)} detail {_cell(row.detail)}"
        )
    print(
        " ".join(
            f"{status}: {preview.counts.get(status, 0)}"
            for status in ("change", "no_op", "conflict", "invalid")
        )
    )
    print(f"can_apply: {'true' if preview.can_apply else 'false'}")
    print(f"confirm_token: {preview.confirm_token}")


def _run_preview(
    args: argparse.Namespace, db_path: Path, site: Site, patches: list[CsvPatchRow]
) -> int:
    try:
        store, _ = _open_audit_store(db_path)
    except _STORE_ERRORS as exc:
        return _input_error("--curation-db", db_path, exc)
    with store:
        try:
            preview = preview_patches(store, site, patches, args.as_of)
        except _STORE_ERRORS as exc:
            return _input_error("--curation-db", db_path, exc)
    if args.json:
        print(json.dumps(preview.to_dict(), indent=2))
    else:
        _print_preview(preview)
    return 0


def _run_apply(
    args: argparse.Namespace, db_path: Path, site: Site, csv_text: str
) -> int:
    # Refuse a non-curation SQLite file before CurationStore() could create tables in it.
    try:
        check_store, _ = _open_audit_store(db_path)
    except _STORE_ERRORS as exc:
        return _input_error("--curation-db", db_path, exc)
    check_store.close()

    try:
        store = CurationStore(db_path)
    except _STORE_ERRORS as exc:
        return _input_error("--curation-db", db_path, exc)
    try:
        patches = parse_patch_csv(io.StringIO(csv_text))
        preview = preview_patches(store, site, patches, args.as_of)
        result = apply_patches(store, preview, args.actor, args.confirm_token)
    except BulkApplyRefused as exc:
        return _import_error(_printable(exc))
    except _STORE_ERRORS as exc:
        return _input_error("--curation-db", db_path, exc)
    finally:
        store.close()

    applied = len(result.entries)
    if args.json:
        print(json.dumps({"batch_id": result.batch_id, "applied": applied}))
    else:
        print(f"applied {applied} rows: batch_id {_printable(result.batch_id)}")
    return 0


def cmd_curate_import(args: argparse.Namespace) -> int:
    mode_error = _mode_error(args)
    if mode_error is not None:
        return _import_error(mode_error)

    db_path = Path(args.curation_db)
    if db_path.suffix.lower() == ".json":
        return _import_error(
            f"--curation-db {_printable(db_path)}: JSON curation files are not supported "
            "by curate-import; use a SQLite curation database"
        )
    for flag, path in (
        ("--curation-db", db_path),
        ("--snapshot", Path(args.snapshot)),
        ("--csv", Path(args.csv)),
    ):
        if not path.exists():
            return _import_error(f"{flag} {_printable(path)}: path does not exist")

    if args.as_of is not None:
        try:
            normalize_utc_datetime(args.as_of, field_name="as_of")
        except (ValueError, TypeError) as exc:
            return _input_error("--as-of", args.as_of, exc)

    try:
        site = _load_single_site_snapshot(
            Path(args.snapshot), args, default_to_fixtures=False
        )
    except INPUT_ERRORS as exc:
        return _input_error("--snapshot", args.snapshot, exc)

    csv_path = Path(args.csv)
    try:
        csv_text = csv_path.read_text(encoding="utf-8", newline="")
    except (OSError, UnicodeDecodeError) as exc:
        return _input_error("--csv", csv_path, exc)
    try:
        patches = parse_patch_csv(io.StringIO(csv_text))
    except PatchCsvError as exc:
        lines = [f"error: --csv {_printable(csv_path)}: invalid patch CSV"]
        lines.extend(f"row {row}: {_printable(message)}" for row, message in exc.errors)
        print("\n".join(lines), file=sys.stderr)
        return 2

    if args.preview:
        return _run_preview(args, db_path, site, patches)
    return _run_apply(args, db_path, site, csv_text)


def register(subparsers: argparse._SubParsersAction) -> None:
    """Register the `curate-import` subcommand."""
    # 18b. curate-import
    import_parser = subparsers.add_parser(
        "curate-import",
        help="Preview a bulk patch CSV against the curation DB read-only, or apply it with its confirm token.",
        description=(
            "Bulk-import field edits from a patch CSV into an existing SQLite curation database. "
            "--preview opens the database read-only, prints every row's diff and a confirm token, "
            "and writes nothing. --apply --confirm-token TOKEN rebuilds the preview and writes the "
            "change rows in one transaction only if the token still matches. JSON curation files "
            "are not supported, and a missing database is never created."
        ),
    )
    import_parser.add_argument(
        "--curation-db",
        type=Path,
        required=True,
        help="Existing SQLite CurationStore database. JSON curation files are not supported.",
    )
    import_parser.add_argument(
        "--snapshot",
        type=Path,
        required=True,
        help="Site JSON snapshot file or SnapshotStore directory the CSV edits apply to.",
    )
    import_parser.add_argument(
        "--csv",
        type=Path,
        required=True,
        help="Patch CSV with columns record_type, record_id, field, new_value, reason.",
    )
    import_parser.add_argument(
        "--preview",
        action="store_true",
        help="Print the per-row diff, status counts, and confirm token; never writes.",
    )
    import_parser.add_argument(
        "--apply",
        action="store_true",
        help="Write the change rows; requires --confirm-token from a --preview of the same CSV.",
    )
    import_parser.add_argument(
        "--confirm-token",
        type=str,
        default=None,
        help="Confirm token printed by --preview; only used with --apply.",
    )
    import_parser.add_argument(
        "--as-of",
        type=str,
        default=None,
        help="Optional ISO-8601 UTC time the CSV was prepared; records changed after it are conflicts.",
    )
    import_parser.add_argument(
        "--actor",
        type=str,
        default="cli-operator",
        help="Operator identifier recorded in the audit log (default: cli-operator).",
    )
    import_parser.add_argument(
        "--json",
        action="store_true",
        help="Print the preview or apply result as JSON.",
    )
    import_parser.set_defaults(func=cmd_curate_import)
