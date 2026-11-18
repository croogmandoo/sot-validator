"""CLI tests for `sot-validator history-migrate`."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3

import pytest

from sot_validator.cli import main
from sot_validator.history import HISTORY_SCHEMA_VERSION, HistoryStore
from sot_validator.models import ValidationClassification, ValidationResult

FLEET_TOML = """
[[sites]]
site_id = "SITE-001"
name = "HQ"
block = "10.1.0.0/16"
active_subnets = ["10.1.10.0/24"]
"""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _history_db(tmp_path: Path, version: int | None = None) -> Path:
    db_path = tmp_path / "history.db"
    with HistoryStore(db_path) as store:
        store.record_run(
            [
                ValidationResult(
                    item_type="IPAddress",
                    item_id="ip-1",
                    site_id="SITE-001",
                    name="ip-1",
                    classification=ValidationClassification.CONFIRMED_ACTIVE,
                    confidence=0.9,
                    rationale="test",
                )
            ],
            run_id="r1",
            recorded_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
    if version is not None:
        conn = sqlite3.connect(str(db_path))
        conn.execute(f"PRAGMA user_version = {version}")
        conn.commit()
        conn.close()
    return db_path


def _user_version(path: Path) -> int:
    conn = sqlite3.connect(str(path))
    try:
        return int(conn.execute("PRAGMA user_version").fetchone()[0])
    finally:
        conn.close()


def _runs(path: Path) -> list[tuple]:
    conn = sqlite3.connect(str(path))
    try:
        return conn.execute("SELECT * FROM validation_runs ORDER BY run_seq").fetchall()
    finally:
        conn.close()


def _migrate(capsys, *args: str) -> tuple[int, str, str]:
    rc = main(["history-migrate", *args])
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


def _assert_single_error_line(err: str) -> None:
    lines = err.strip().splitlines()
    assert len(lines) == 1
    assert lines[0].startswith("error: ")
    assert "Traceback" not in err


def test_schema_version_is_one():
    # The fixtures below assume one migration; revisit them when another is added.
    assert HISTORY_SCHEMA_VERSION == 1


def test_dry_run_on_current_db(tmp_path, capsys):
    db_path = _history_db(tmp_path)
    before = _sha256(db_path)
    rc, out, err = _migrate(capsys, "--db-path", str(db_path))
    assert rc == 0, err
    assert json.loads(out) == {
        "db_path": str(db_path),
        "current_version": 1,
        "target_version": 1,
        "pending": [],
        "dry_run": True,
        "final_version": 1,
    }
    assert _sha256(db_path) == before


def test_dry_run_on_unversioned_db(tmp_path, capsys):
    db_path = _history_db(tmp_path, version=0)
    before = _sha256(db_path)
    rc, out, err = _migrate(capsys, "--db-path", str(db_path))
    assert rc == 0, err
    report = json.loads(out)
    assert report["current_version"] == 0
    assert report["pending"] == [1]
    assert report["dry_run"] is True
    assert report["final_version"] == 0
    assert _sha256(db_path) == before


def test_apply_migrates_unversioned_db_and_is_idempotent(tmp_path, capsys):
    db_path = _history_db(tmp_path, version=0)
    runs_before = _runs(db_path)
    assert len(runs_before) == 1
    rc, out, err = _migrate(capsys, "--db-path", str(db_path), "--apply")
    assert rc == 0, err
    report = json.loads(out)
    assert report["dry_run"] is False
    assert report["pending"] == [1]
    assert report["final_version"] == 1
    assert _user_version(db_path) == 1
    assert _runs(db_path) == runs_before

    after = _sha256(db_path)
    rc, out, err = _migrate(capsys, "--db-path", str(db_path), "--apply")
    assert rc == 0, err
    report = json.loads(out)
    assert report["pending"] == []
    assert report["dry_run"] is False
    assert report["final_version"] == 1
    assert _sha256(db_path) == after


def test_apply_on_empty_sqlite_file(tmp_path, capsys):
    db_path = tmp_path / "empty.db"
    db_path.write_bytes(b"")
    rc, out, err = _migrate(capsys, "--db-path", str(db_path), "--apply")
    assert rc == 0, err
    assert json.loads(out)["final_version"] == 1
    assert _user_version(db_path) == 1


@pytest.mark.parametrize("apply", [False, True])
def test_newer_schema_refused(tmp_path, capsys, apply):
    db_path = _history_db(tmp_path, version=99)
    before = _sha256(db_path)
    rc, out, err = _migrate(capsys, "--db-path", str(db_path), *(["--apply"] if apply else []))
    assert rc == 2
    assert out == ""
    _assert_single_error_line(err)
    assert "schema version 99 is newer than the highest version this code supports (1)" in err
    assert _sha256(db_path) == before


@pytest.mark.parametrize("apply", [False, True])
def test_missing_path_is_not_created(tmp_path, capsys, apply):
    db_path = tmp_path / "sub" / "history.db"
    rc, _, err = _migrate(capsys, "--db-path", str(db_path), *(["--apply"] if apply else []))
    assert rc == 2
    _assert_single_error_line(err)
    assert not db_path.exists()
    assert not db_path.parent.exists()


def test_json_path_refused(tmp_path, capsys):
    db_path = tmp_path / "history.json"
    db_path.write_text("{}", encoding="utf-8")
    before = _sha256(db_path)
    rc, _, err = _migrate(capsys, "--db-path", str(db_path), "--apply")
    assert rc == 2
    _assert_single_error_line(err)
    assert "JSON history files are not supported by history-migrate" in err
    assert _sha256(db_path) == before


@pytest.mark.parametrize("apply", [False, True])
def test_non_sqlite_file_refused(tmp_path, capsys, apply):
    db_path = tmp_path / "history.db"
    db_path.write_text("not a database\n" * 50, encoding="utf-8")
    before = _sha256(db_path)
    rc, _, err = _migrate(capsys, "--db-path", str(db_path), *(["--apply"] if apply else []))
    assert rc == 2
    _assert_single_error_line(err)
    assert _sha256(db_path) == before


def test_unrelated_sqlite_refused(tmp_path, capsys):
    db_path = tmp_path / "other.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE unrelated (x INTEGER)")
    conn.commit()
    conn.close()
    before = _sha256(db_path)
    rc, _, err = _migrate(capsys, "--db-path", str(db_path), "--apply")
    assert rc == 2
    _assert_single_error_line(err)
    assert "not a history database" in err
    assert _sha256(db_path) == before
    assert _user_version(db_path) == 0


def test_global_config_does_not_change_behaviour(tmp_path, capsys):
    db_path = _history_db(tmp_path, version=0)
    config = tmp_path / "fleet.toml"
    config.write_text(FLEET_TOML, encoding="utf-8")
    rc_plain, out_plain, _ = _migrate(capsys, "--db-path", str(db_path))
    rc = main(["--config", str(config), "history-migrate", "--db-path", str(db_path)])
    captured = capsys.readouterr()
    assert (rc, captured.out, captured.err) == (rc_plain, out_plain, "")
    assert rc == 0
