"""Tests for the unattended run lock, run manifest and exit-code contract."""

from __future__ import annotations

from datetime import datetime, timezone
import fcntl
import hashlib
import json
import logging
import multiprocessing
import os
from pathlib import Path

import pytest

from sot_validator.config import SecretValue
from sot_validator.observability import REDACTION_MASK
from sot_validator.ops import (
    MANIFEST_FILENAME,
    ExitCode,
    RunLock,
    RunLockHeld,
    RunManifest,
    SiteStatus,
    file_sha256,
    select_exit_code,
    tool_version,
)
from sot_validator.ops import runner

JOIN_TIMEOUT = 20


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


def _manifest(**overrides) -> RunManifest:
    values = dict(
        run_id="run-42",
        started_at=datetime(2026, 11, 17, 2, 0, tzinfo=timezone.utc),
        finished_at=datetime(2026, 11, 17, 2, 30, tzinfo=timezone.utc),
        tool_version="0.1.0",
        config_sha256=None,
        sites=[SiteStatus("site-001", "ok"), SiteStatus("site-002", "skipped", "out of batch")],
        output_files=[Path("/var/lib/sot-validator/output/validation_report.json")],
    )
    values.update(overrides)
    return RunManifest(**values)


def test_contention_between_processes(tmp_path):
    lock_path = tmp_path / "run.lock"
    ctx = multiprocessing.get_context("spawn")
    acquired, release = ctx.Event(), ctx.Event()
    child = ctx.Process(target=_hold_lock, args=(str(lock_path), acquired, release))
    child.start()
    try:
        assert acquired.wait(JOIN_TIMEOUT), "child never took the lock"
        with pytest.raises(RunLockHeld) as info:
            RunLock(lock_path).acquire()
        assert info.value.pid == child.pid
        assert str(child.pid) in str(info.value)
        assert str(lock_path) in str(info.value)
        assert info.value.started_at and info.value.started_at in str(info.value)
    finally:
        release.set()
        child.join(JOIN_TIMEOUT)
        if child.is_alive():
            child.kill()
            child.join(JOIN_TIMEOUT)
    assert child.exitcode == 0
    assert lock_path.exists()
    assert lock_path.read_bytes() == b""
    with RunLock(lock_path) as lock:
        assert lock.held
        assert json.loads(lock_path.read_text())["pid"] == os.getpid()
    assert lock_path.read_bytes() == b""


def test_lock_held_with_unknown_holder(tmp_path):
    lock_path = tmp_path / "run.lock"
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(RunLockHeld) as info:
            RunLock(lock_path).acquire()
        assert info.value.pid is None
        assert info.value.started_at is None
        assert "unknown holder" in str(info.value)
    finally:
        os.close(fd)


def test_stale_lock_reclaimed_with_warning(tmp_path, caplog):
    lock_path = tmp_path / "run.lock"
    dead = _dead_pid()
    lock_path.write_text(json.dumps({"pid": dead, "started_at": "2026-11-16T02:00:00+00:00"}))
    with caplog.at_level(logging.WARNING, logger="sot_validator"):
        with RunLock(lock_path):
            assert json.loads(lock_path.read_text())["pid"] == os.getpid()
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any(str(dead) in r.getMessage() for r in warnings)
    assert any("2026-11-16T02:00:00+00:00" in r.getMessage() for r in warnings)


def test_live_pid_record_taken_silently(tmp_path, caplog):
    lock_path = tmp_path / "run.lock"
    lock_path.write_text(json.dumps({"pid": os.getppid(), "started_at": "x"}))
    with caplog.at_level(logging.WARNING, logger="sot_validator"):
        with RunLock(lock_path):
            pass
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_garbage_record_does_not_block(tmp_path, caplog):
    lock_path = tmp_path / "run.lock"
    lock_path.write_text('{"pid": "false", "started_at": 1}')
    with caplog.at_level(logging.WARNING, logger="sot_validator"):
        with RunLock(lock_path):
            assert json.loads(lock_path.read_text())["pid"] == os.getpid()
    assert not caplog.records


def test_release_when_not_held_is_noop(tmp_path):
    lock = RunLock(tmp_path / "run.lock")
    lock.release()
    lock.acquire()
    lock.release()
    lock.release()
    assert (tmp_path / "run.lock").read_bytes() == b""


def test_manifest_write_round_trip(tmp_path):
    path = _manifest().write(tmp_path)
    assert path == tmp_path / MANIFEST_FILENAME
    data = json.loads(path.read_text())
    assert set(data) == {
        "run_id",
        "started_at",
        "finished_at",
        "tool_version",
        "config_sha256",
        "sites",
        "output_files",
    }
    assert data["started_at"] == "2026-11-17T02:00:00+00:00"
    assert data["sites"][1] == {"site_id": "site-002", "status": "skipped", "reason": "out of batch"}
    assert data["output_files"] == ["/var/lib/sot-validator/output/validation_report.json"]
    assert [p.name for p in tmp_path.iterdir()] == [MANIFEST_FILENAME]


def test_manifest_naive_datetime_rejected():
    with pytest.raises(ValueError):
        _manifest(started_at=datetime(2026, 11, 17, 2, 0)).to_dict()
    with pytest.raises(ValueError):
        _manifest(finished_at=datetime(2026, 11, 17, 2, 0)).to_dict()


def test_manifest_unfinished_and_arbitrary_reason():
    class Opaque:
        def __str__(self) -> str:
            return "opaque-thing"

    data = _manifest(finished_at=None, sites=[SiteStatus("s", "failed", Opaque())]).to_dict()
    assert data["finished_at"] is None
    assert data["sites"][0]["reason"] == "opaque-thing"
    json.dumps(data)


def _fail_replace(*args, **kwargs):
    raise OSError("simulated replace failure")


def test_manifest_write_failure_leaves_no_file(tmp_path, monkeypatch):
    monkeypatch.setattr(runner.os, "replace", _fail_replace)
    with pytest.raises(OSError, match="simulated"):
        _manifest().write(tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_manifest_write_failure_keeps_previous(tmp_path, monkeypatch):
    first = _manifest().write(tmp_path)
    before = first.read_bytes()
    monkeypatch.setattr(runner.os, "replace", _fail_replace)
    with pytest.raises(OSError):
        _manifest(run_id="run-43").write(tmp_path)
    assert first.read_bytes() == before
    assert [p.name for p in tmp_path.iterdir()] == [MANIFEST_FILENAME]


def test_manifest_redaction_and_config_hash(tmp_path):
    config = tmp_path / "fleet.toml"
    config_bytes = b'[sot]\npassword = "config-file-secret-contents"\n'
    config.write_bytes(config_bytes)
    out = tmp_path / "out"
    out.mkdir()
    manifest = _manifest(
        config_sha256=file_sha256(config),
        sites=[
            SiteStatus("site-001", "failed", SecretValue("hunter2-secret-value", "f.toml", "vcenters[0]", "password")),
            SiteStatus("site-002", "failed", {"password": "pw-secret-value", "note": "x"}),
            SiteStatus("site-003", "ok", {"detail": {"api_token": "tok-secret-value"}}),
        ],
    )
    text = manifest.write(out).read_text()
    for secret in ("hunter2-secret-value", "pw-secret-value", "tok-secret-value"):
        assert secret not in text
    assert "config-file-secret-contents" not in text
    data = json.loads(text)
    assert data["config_sha256"] == hashlib.sha256(config_bytes).hexdigest()
    assert data["sites"][0]["reason"] == REDACTION_MASK
    assert data["sites"][1]["reason"] == {"password": REDACTION_MASK, "note": "x"}
    assert data["sites"][2]["reason"]["detail"]["api_token"] == REDACTION_MASK


@pytest.mark.parametrize(
    ("statuses", "kwargs", "expected"),
    [
        (["ok", "ok"], {}, ExitCode.SUCCESS),
        ([], {}, ExitCode.SUCCESS),
        (["skipped"], {}, ExitCode.SUCCESS),
        (["skipped", "skipped"], {"actionable_findings": True}, ExitCode.ACTIONABLE),
        (["ok", "skipped"], {"actionable_findings": True}, ExitCode.ACTIONABLE),
        (["ok", "failed"], {"actionable_findings": True}, ExitCode.PARTIAL),
        (["skipped", "failed"], {}, ExitCode.PARTIAL),
        (["failed", "failed"], {}, ExitCode.FAILED),
        (["ok"], {"run_failed": True}, ExitCode.FAILED),
        ([], {"lock_held": True, "run_failed": True}, ExitCode.LOCK_HELD),
        (["failed"], {"lock_held": True}, ExitCode.LOCK_HELD),
    ],
)
def test_select_exit_code(statuses, kwargs, expected):
    assert select_exit_code(statuses, **kwargs) is expected
    sites = [SiteStatus(f"s{i}", status) for i, status in enumerate(statuses)]
    assert select_exit_code(iter(sites), **kwargs) is expected


def test_exit_code_values():
    assert [int(code) for code in ExitCode] == [0, 1, 2, 3, 4]
    assert [code.name for code in ExitCode] == [
        "SUCCESS",
        "ACTIONABLE",
        "PARTIAL",
        "FAILED",
        "LOCK_HELD",
    ]


def test_select_exit_code_rejects_string_flags_and_bad_status():
    with pytest.raises(TypeError):
        select_exit_code(["ok"], actionable_findings="false")
    with pytest.raises(TypeError):
        select_exit_code(["ok"], lock_held=0)
    with pytest.raises(ValueError):
        select_exit_code(["ok", "FAILED"])


@pytest.mark.parametrize("status", ["", "OK", "error", None])
def test_site_status_rejects_invalid(status):
    with pytest.raises(ValueError):
        SiteStatus("site-001", status)


def test_file_sha256_and_tool_version(tmp_path):
    payload = os.urandom(200_000)
    target = tmp_path / "blob"
    target.write_bytes(payload)
    assert file_sha256(target) == hashlib.sha256(payload).hexdigest()
    assert isinstance(tool_version(), str) and tool_version()


def test_tool_version_unknown_without_metadata(monkeypatch):
    def missing(name):
        raise runner.importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(runner.importlib.metadata, "version", missing)
    assert tool_version() == "unknown"
