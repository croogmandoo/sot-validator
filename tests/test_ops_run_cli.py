"""CLI tests for the run lock, run manifest and exit-code contract on `run` and `campaign`."""

from __future__ import annotations

import dataclasses
from datetime import datetime
import json
import logging
import multiprocessing
import os
from pathlib import Path
import re

import pytest

from sot_validator.campaign import CampaignOrchestrator
from sot_validator.classifier import ClassificationEngine
from sot_validator.cli import build_parser, main
from sot_validator.cli import core as cli_core
from sot_validator.models import ValidationClassification
from sot_validator.ops import MANIFEST_FILENAME, RunLock, RunManifest, file_sha256, tool_version

JOIN_TIMEOUT = 20
LOCK_NAME = ".sot-validator.lock"
SENTINEL = "SENTINEL123"
COMMANDS = ("run", "campaign")

RUN_REPORTS = {
    "validation_results.json",
    "validation_report.json",
    "validation_report.csv",
    "validation_summary.md",
    "remediation_action_plan.json",
}
CAMPAIGN_REPORTS = {"campaign_summary.json", "campaign_alerts.json"}

_original_classify_site = ClassificationEngine.classify_site


def _hold_lock(path: str, acquired, release) -> None:
    with RunLock(path):
        acquired.set()
        release.wait(JOIN_TIMEOUT)


def _dead_pid() -> int:
    ctx = multiprocessing.get_context("spawn")
    proc = ctx.Process(target=int)
    proc.start()
    proc.join(JOIN_TIMEOUT)
    return proc.pid


def _argv(command: str, out: Path, *extra: str) -> list[str]:
    if command == "run":
        return ["run", "--fixtures", "--output-dir", str(out), *extra]
    return [
        "campaign",
        "--fixtures",
        "--num-sites",
        "4",
        "--campaign-id",
        "c1",
        "--output-dir",
        str(out),
        *extra,
    ]


def _error_lines(err: str) -> list[str]:
    return [line for line in err.splitlines() if line.strip()]


def _assert_one_error(err: str) -> str:
    lines = _error_lines(err)
    assert len(lines) == 1, err
    assert lines[0].startswith("error: ")
    assert "Traceback" not in err
    return lines[0]


def _manifest(out: Path) -> dict:
    return json.loads((out / MANIFEST_FILENAME).read_text(encoding="utf-8"))


def _snapshot(out: Path) -> dict[str, tuple[int, bytes]]:
    return {
        p.name: (p.stat().st_mtime_ns, p.read_bytes())
        for p in out.iterdir()
        if p.is_file() and p.name != LOCK_NAME
    }


def _patch_classify(monkeypatch, per_site):
    """Route `classify_site` through `per_site(site, results)` for every site."""

    def fake(self, site, *args, **kwargs):
        return per_site(site, _original_classify_site(self, site, *args, **kwargs))

    monkeypatch.setattr(ClassificationEngine, "classify_site", fake)


def _reclassify(results, classification):
    return [dataclasses.replace(r, classification=classification) for r in results]


def _all_active(site, results):
    return _reclassify(results, ValidationClassification.CONFIRMED_ACTIVE)


class _HeldLock:
    def __init__(self, path: Path) -> None:
        ctx = multiprocessing.get_context("spawn")
        self.acquired, self.release = ctx.Event(), ctx.Event()
        self.child = ctx.Process(
            target=_hold_lock, args=(str(path), self.acquired, self.release)
        )

    def __enter__(self):
        self.child.start()
        assert self.acquired.wait(JOIN_TIMEOUT), "child never took the lock"
        return self.child

    def __exit__(self, *exc_info) -> None:
        self.release.set()
        self.child.join(JOIN_TIMEOUT)
        if self.child.is_alive():
            self.child.kill()
            self.child.join(JOIN_TIMEOUT)


# --- Exit 4: lock contention ---------------------------------------------------


@pytest.mark.parametrize("command", COMMANDS)
def test_exit_4_lock_held_writes_nothing(command, tmp_path, capsys):
    out = tmp_path / "out"
    out.mkdir()
    with _HeldLock(out / LOCK_NAME) as child:
        rc = main(_argv(command, out))
    assert rc == 4
    line = _assert_one_error(capsys.readouterr().err)
    assert str(child.pid) in line
    assert [p.name for p in out.iterdir()] == [LOCK_NAME]


@pytest.mark.parametrize("command", COMMANDS)
def test_exit_4_leaves_previous_manifest_and_reports_unchanged(command, tmp_path, capsys):
    out = tmp_path / "out"
    assert main(_argv(command, out)) == 1
    before = _snapshot(out)
    assert MANIFEST_FILENAME in before
    capsys.readouterr()
    with _HeldLock(out / LOCK_NAME):
        rc = main(_argv(command, out))
    assert rc == 4
    _assert_one_error(capsys.readouterr().err)
    assert _snapshot(out) == before


# --- Stale and symlinked locks -------------------------------------------------


@pytest.mark.parametrize("command", COMMANDS)
def test_stale_lock_reclaimed_and_manifest_written(command, tmp_path, caplog):
    out = tmp_path / "out"
    out.mkdir()
    dead = _dead_pid()
    (out / LOCK_NAME).write_text(
        json.dumps({"pid": dead, "started_at": "2026-11-16T02:00:00+00:00"})
    )
    with caplog.at_level(logging.WARNING, logger="sot_validator"):
        rc = main(_argv(command, out))
    assert rc in (0, 1)
    messages = [r.getMessage() for r in caplog.records]
    assert any(
        "reclaiming stale run lock" in m and f"dead pid {dead}" in m for m in messages
    )
    assert (out / MANIFEST_FILENAME).exists()
    assert (out / LOCK_NAME).read_bytes() == b""


@pytest.mark.parametrize("command", COMMANDS)
def test_symlinked_lock_file_exits_3_and_target_untouched(command, tmp_path, capsys):
    out = tmp_path / "out"
    target = tmp_path / "target"
    target.write_bytes(b"keep\n")
    link = tmp_path / "run.lock"
    link.symlink_to(target)
    rc = main(_argv(command, out, "--lock-file", str(link)))
    assert rc == 3
    line = _assert_one_error(capsys.readouterr().err)
    assert line.startswith(f"error: cannot open run lock {link}: ")
    assert target.read_bytes() == b"keep\n"
    assert not (out / MANIFEST_FILENAME).exists()


@pytest.mark.parametrize("command", COMMANDS)
def test_missing_custom_lock_parent_exits_3(command, tmp_path, capsys):
    out = tmp_path / "out"
    lock = tmp_path / "missing" / "run.lock"
    assert main(_argv(command, out, "--lock-file", str(lock))) == 3
    _assert_one_error(capsys.readouterr().err)
    assert not lock.parent.exists()
    assert not (out / MANIFEST_FILENAME).exists()


@pytest.mark.parametrize("command", COMMANDS)
def test_custom_lock_file_is_used(command, tmp_path, capsys):
    out = tmp_path / "out"
    lock = tmp_path / "custom.lock"
    with _HeldLock(lock):
        assert main(_argv(command, out, "--lock-file", str(lock))) == 4
    _assert_one_error(capsys.readouterr().err)
    assert main(_argv(command, out, "--lock-file", str(lock))) == 1
    assert not (out / LOCK_NAME).exists()


# --- Manifest contents ---------------------------------------------------------


def _assert_common_manifest(data: dict) -> None:
    assert set(data) == {
        "run_id",
        "started_at",
        "finished_at",
        "tool_version",
        "config_sha256",
        "sites",
        "output_files",
        "failure_reason",
    }
    started = datetime.fromisoformat(data["started_at"])
    finished = datetime.fromisoformat(data["finished_at"])
    assert started.tzinfo is not None and finished >= started
    assert data["tool_version"] == tool_version()
    for path in data["output_files"]:
        assert Path(path).is_file(), path
    assert MANIFEST_FILENAME not in {Path(p).name for p in data["output_files"]}


def test_run_manifest_contents(tmp_path):
    out = tmp_path / "out"
    html_copy = tmp_path / "elsewhere" / "dash.html"
    rc = main(_argv("run", out, "--html-output", str(html_copy)))
    assert rc == 1
    data = _manifest(out)
    _assert_common_manifest(data)
    assert re.fullmatch(r"run-[0-9a-f]{32}", data["run_id"])
    assert data["config_sha256"] is None
    assert data["failure_reason"] is None
    assert data["sites"] == [
        {"site_id": f"site-00{i}", "status": "ok", "reason": None} for i in (1, 2, 3)
    ]
    expected = {str(out / name) for name in RUN_REPORTS | {"validation_dashboard.html"}}
    expected.add(str(html_copy))
    assert set(data["output_files"]) == expected
    assert len(data["output_files"]) == len(expected)


def test_run_ids_are_unique_per_run(tmp_path):
    out = tmp_path / "out"
    main(_argv("run", out))
    first = _manifest(out)["run_id"]
    main(_argv("run", out))
    assert _manifest(out)["run_id"] != first


def test_campaign_manifest_contents(tmp_path):
    out = tmp_path / "out"
    rc = main(_argv("campaign", out, "--webhook-format", "slack", "--html-dashboard"))
    assert rc == 1
    data = _manifest(out)
    _assert_common_manifest(data)
    assert data["run_id"] == "c1"
    assert data["config_sha256"] is None
    assert data["failure_reason"] is None
    assert data["sites"] == [
        {"site_id": f"site-00{i}", "status": "ok", "reason": None} for i in (1, 2, 3, 4)
    ]
    expected = {
        str(out / name)
        for name in CAMPAIGN_REPORTS
        | {"campaign_webhook_payload.json", "validation_dashboard.html"}
    }
    assert set(data["output_files"]) == expected
    assert len(data["output_files"]) == len(expected)


def test_campaign_custom_alerts_file_listed_and_history_db_not(tmp_path):
    out = tmp_path / "out"
    alerts = tmp_path / "alerts" / "a.json"
    db = tmp_path / "history.db"
    rc = main(
        _argv("campaign", out, "--alerts-file", str(alerts), "--history-db", str(db))
    )
    assert rc == 1
    assert db.exists()
    assert set(_manifest(out)["output_files"]) == {
        str(out / "campaign_summary.json"),
        str(alerts),
    }


@pytest.mark.parametrize("command", COMMANDS)
def test_config_sha256_from_fleet_config_path(command, tmp_path):
    out = tmp_path / "out"
    config = tmp_path / "fleet.toml"
    config.write_text("[fleet]\nname = 'x'\n", encoding="utf-8")
    args = build_parser().parse_args(_argv(command, out))
    args.fleet_config_path = config
    assert args.func(args) == 1
    assert _manifest(out)["config_sha256"] == file_sha256(config)


@pytest.mark.parametrize("command", COMMANDS)
def test_config_sha256_from_global_config_flag(command, tmp_path):
    out = tmp_path / "out"
    config = tmp_path / "fleet.toml"
    config.write_text(
        '[[sites]]\nsite_id = "site-001"\nname = "HQ"\nblock = "10.1.0.0/16"\n'
        'active_subnets = ["10.1.10.0/24"]\n',
        encoding="utf-8",
    )
    assert main(["--config", str(config), *_argv(command, out)]) == 1
    data = _manifest(out)
    assert data["config_sha256"] == file_sha256(config)
    assert [s["site_id"] for s in data["sites"]] == ["site-001"]


# --- Secret-free reasons ---------------------------------------------------------


def test_run_site_failure_reason_is_class_name(tmp_path, monkeypatch):
    def per_site(site, results):
        if site.site_id == "site-002":
            raise RuntimeError(f"password={SENTINEL}")
        return results

    _patch_classify(monkeypatch, per_site)
    out = tmp_path / "out"
    assert main(_argv("run", out)) == 2
    text = (out / MANIFEST_FILENAME).read_text(encoding="utf-8")
    assert SENTINEL not in text
    sites = {s["site_id"]: s for s in json.loads(text)["sites"]}
    assert sites["site-002"] == {
        "site_id": "site-002",
        "status": "failed",
        "reason": "RuntimeError",
    }
    assert sites["site-001"]["status"] == sites["site-003"]["status"] == "ok"
    report = json.loads((out / "validation_report.json").read_text(encoding="utf-8"))
    assert set(report["summary"]["by_site"]) == {"site-001", "site-003"}


def test_campaign_failure_reason_is_class_name(tmp_path, monkeypatch, capsys):
    def boom(self, *args, **kwargs):
        raise RuntimeError(f"password={SENTINEL}\nsecond line")

    monkeypatch.setattr(CampaignOrchestrator, "run", boom)
    out = tmp_path / "out"
    assert main(_argv("campaign", out)) == 3
    line = _assert_one_error(capsys.readouterr().err)
    assert line == f"error: campaign failed: RuntimeError: password={SENTINEL} second line"
    text = (out / MANIFEST_FILENAME).read_text(encoding="utf-8")
    assert SENTINEL not in text
    data = json.loads(text)
    assert data["failure_reason"] == "RuntimeError"
    assert data["sites"] == []
    assert data["output_files"] == []


# --- Exit codes ------------------------------------------------------------------


@pytest.mark.parametrize("command", COMMANDS)
def test_exit_0_when_everything_confirmed_active(command, tmp_path, monkeypatch):
    _patch_classify(monkeypatch, _all_active)
    out = tmp_path / "out"
    assert main(_argv(command, out)) == 0
    data = _manifest(out)
    assert data["failure_reason"] is None
    assert {s["status"] for s in data["sites"]} == {"ok"}


@pytest.mark.parametrize("command", COMMANDS)
def test_exit_1_with_fixture_findings(command, tmp_path):
    out = tmp_path / "out"
    assert main(_argv(command, out)) == 1
    assert {s["status"] for s in _manifest(out)["sites"]} == {"ok"}


def test_exit_2_campaign_quarantined_and_committed(tmp_path, monkeypatch):
    def per_site(site, results):
        if site.site_id == "site-002":
            return _reclassify(results, ValidationClassification.UNREACHABLE_NEEDS_REVIEW)
        return _all_active(site, results)

    _patch_classify(monkeypatch, per_site)
    out = tmp_path / "out"
    assert main(_argv("campaign", out)) == 2
    sites = {s["site_id"]: s for s in _manifest(out)["sites"]}
    assert sites["site-002"] == {
        "site_id": "site-002",
        "status": "failed",
        "reason": "outage suspected",
    }
    assert [sites[f"site-00{i}"]["status"] for i in (1, 3, 4)] == ["ok"] * 3


def test_campaign_circuit_breaker_skips_are_skipped(tmp_path, monkeypatch):
    def per_site(site, results):
        return _reclassify(results, ValidationClassification.UNREACHABLE_NEEDS_REVIEW)

    _patch_classify(monkeypatch, per_site)
    out = tmp_path / "out"
    assert main(_argv("campaign", out, "--cohort-size", "1")) == 2
    sites = _manifest(out)["sites"]
    assert sites == [
        {"site_id": "site-001", "status": "failed", "reason": "outage suspected"},
        {"site_id": "site-002", "status": "failed", "reason": "outage suspected"},
        {"site_id": "site-003", "status": "skipped", "reason": "circuit breaker"},
        {"site_id": "site-004", "status": "skipped", "reason": "circuit breaker"},
    ]


def test_exit_3_run_all_sites_failed(tmp_path, monkeypatch, capsys):
    def per_site(site, results):
        raise ValueError(f"token={SENTINEL}")

    _patch_classify(monkeypatch, per_site)
    out = tmp_path / "out"
    assert main(_argv("run", out)) == 3
    assert capsys.readouterr().err == ""
    text = (out / MANIFEST_FILENAME).read_text(encoding="utf-8")
    assert SENTINEL not in text
    data = json.loads(text)
    assert data["failure_reason"] is None
    assert [s["status"] for s in data["sites"]] == ["failed"] * 3
    assert {s["reason"] for s in data["sites"]} == {"ValueError"}


def test_exit_3_campaign_all_sites_quarantined(tmp_path, monkeypatch):
    def per_site(site, results):
        return _reclassify(results, ValidationClassification.UNREACHABLE_NEEDS_REVIEW)

    _patch_classify(monkeypatch, per_site)
    out = tmp_path / "out"
    assert main(_argv("campaign", out, "--max-consecutive-aborted-sites", "10")) == 3
    assert {s["status"] for s in _manifest(out)["sites"]} == {"failed"}


def test_exit_3_run_extraction_error(tmp_path, monkeypatch, capsys):
    def boom(*args, **kwargs):
        raise OSError(f"cannot reach https://user:{SENTINEL}@sot.example/\n")

    monkeypatch.setattr(cli_core, "_extract_sites", boom)
    out = tmp_path / "out"
    assert main(_argv("run", out)) == 3
    line = _assert_one_error(capsys.readouterr().err)
    assert line.startswith("error: run failed: OSError: cannot reach ")
    text = (out / MANIFEST_FILENAME).read_text(encoding="utf-8")
    assert SENTINEL not in text
    data = json.loads(text)
    assert data["failure_reason"] == "OSError"
    assert data["sites"] == [] and data["output_files"] == []


def test_exit_3_run_report_error_keeps_progress(tmp_path, monkeypatch, capsys):
    def boom(*args, **kwargs):
        raise RuntimeError(SENTINEL)

    monkeypatch.setattr(cli_core, "generate_all_reports", boom)
    out = tmp_path / "out"
    assert main(_argv("run", out)) == 3
    _assert_one_error(capsys.readouterr().err)
    data = _manifest(out)
    assert data["failure_reason"] == "RuntimeError"
    assert [s["status"] for s in data["sites"]] == ["ok"] * 3
    assert data["output_files"] == [str(out / "validation_results.json")]


@pytest.mark.parametrize("command", COMMANDS)
def test_exit_3_manifest_write_failure(command, tmp_path, monkeypatch, capsys):
    def boom(self, output_dir):
        raise OSError("disk full")

    monkeypatch.setattr(RunManifest, "write", boom)
    out = tmp_path / "out"
    assert main(_argv(command, out)) == 3
    line = _assert_one_error(capsys.readouterr().err)
    assert line == f"error: {command} failed: OSError: disk full"
    assert (out / LOCK_NAME).read_bytes() == b""


@pytest.mark.parametrize("command", COMMANDS)
def test_lock_released_on_keyboard_interrupt(command, tmp_path, monkeypatch):
    def interrupt(self, *args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(ClassificationEngine, "classify_site", interrupt)
    out = tmp_path / "out"
    with pytest.raises(KeyboardInterrupt):
        main(_argv(command, out))
    with RunLock(out / LOCK_NAME) as lock:
        assert lock.held
        assert json.loads((out / LOCK_NAME).read_text())["pid"] == os.getpid()
