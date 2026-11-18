"""CLI tests for the root `--log-format`, `--log-level` and `--metrics-file` flags."""

from __future__ import annotations

import json
import logging
import multiprocessing
from pathlib import Path
import re

import pytest

from sot_validator.cli import _observability, main
from sot_validator.cli import core as cli_core

JOIN_TIMEOUT = 20
LOCK_NAME = ".sot-validator.lock"
HANDLER_MARKER = "_sot_validator_observability"
RECLAIM = "reclaiming stale run lock"
SECRET_VARS = ("SOT_VCENTER_PASSWORD", "SOT_SNMP_COMMUNITY", "SOT_PROXMOX_TOKEN_SECRET")
SENTINEL = "sentinel-Zq7-secret-value"
# `run` and `campaign` exit 1 (actionable) because the fixtures hold stale and unreachable records.
FIXTURE_RC = {"validate": 0, "run": 1, "campaign": 1}
STARTER_METRICS = (
    "sot_run_last_success_timestamp_seconds",
    "sot_run_duration_seconds",
    "sot_site_status",
    "sot_records_total",
    "sot_collector_errors_total",
    "sot_probe_duration_seconds",
)

SECRETS_CONFIG = """
[[sites]]
site_id = "site-001"
name = "HQ"
block = "10.1.0.0/16"
active_subnets = ["10.1.10.0/24"]

[[vcenters]]
name = "vc1"
host = "vc1.example.invalid"
username = "reader"
password = "${env:SOT_VCENTER_PASSWORD}"

[[snmp_profiles]]
name = "default"
community = "${env:SOT_SNMP_COMMUNITY}"

[[proxmox]]
name = "pve"
host = "pve.example.invalid"
token_id = "reader@pve!ro"
token_secret = "${env:SOT_PROXMOX_TOKEN_SECRET}"
"""


@pytest.fixture(autouse=True)
def _restore_sot_logger():
    logger = logging.getLogger("sot_validator")
    level = logger.level
    handlers = list(logger.handlers)
    yield
    for handler in list(logger.handlers):
        if handler not in handlers:
            logger.removeHandler(handler)
            handler.close()
    logger.setLevel(level)


def _dead_pid() -> int:
    ctx = multiprocessing.get_context("spawn")
    proc = ctx.Process(target=int)
    proc.start()
    proc.join(JOIN_TIMEOUT)
    return proc.pid


def _argv(command: str, out: Path) -> list[str]:
    if command == "run":
        return ["run", "--fixtures", "--output-dir", str(out)]
    if command == "validate":
        return ["validate", "--fixtures", "--output-dir", str(out)]
    return ["campaign", "--fixtures", "--campaign-id", "c1", "--output-dir", str(out)]


def _stale_lock(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / LOCK_NAME).write_text(
        json.dumps({"pid": _dead_pid(), "started_at": "2026-11-16T02:00:00+00:00"})
    )


def _run(capsys, *argv: str) -> tuple[int, str, str]:
    rc = main(list(argv))
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


def _observability_handlers() -> list[logging.Handler]:
    return [
        h for h in logging.getLogger("sot_validator").handlers if getattr(h, HANDLER_MARKER, False)
    ]


def _samples(text: str, name: str) -> dict[str, float]:
    samples = {}
    for line in text.splitlines():
        if line.startswith(f"{name} ") or line.startswith(f"{name}{{"):
            key, value = line.rsplit(" ", 1)
            samples[key] = float(value)
    return samples


def _assert_help_and_type(text: str) -> None:
    for name in STARTER_METRICS:
        assert re.search(rf"^# HELP {name} ", text, re.M), name
        assert re.search(rf"^# TYPE {name} ", text, re.M), name


def _single_error(err: str) -> str:
    lines = [line for line in err.splitlines() if line.strip()]
    assert len(lines) == 1, err
    assert lines[0].startswith("error: ")
    assert "Traceback" not in err
    return lines[0]


# --- logging -----------------------------------------------------------------------------


def test_json_format_lines_have_required_keys(tmp_path, capsys):
    out = tmp_path / "out"
    _stale_lock(out)
    rc, _, err = _run(capsys, "--log-format", "json", *_argv("run", out))
    assert rc == FIXTURE_RC["run"]
    records = []
    for line in err.splitlines():
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    assert records
    for record in records:
        assert {"ts", "level", "logger", "msg", "run_id", "site_id"} <= set(record)
    assert any(r["level"] == "WARNING" and RECLAIM in r["msg"] for r in records)


def test_text_format_reclaim_warning_is_one_line(tmp_path, capsys):
    out = tmp_path / "out"
    _stale_lock(out)
    rc, _, err = _run(capsys, "--log-format", "text", *_argv("run", out))
    assert rc == FIXTURE_RC["run"]
    lines = [line for line in err.splitlines() if RECLAIM in line]
    assert len(lines) == 1, err
    assert "WARNING" in lines[0] and "sot_validator." in lines[0]


@pytest.mark.parametrize(("level", "shown"), [("error", False), ("WARNING", True)])
def test_log_level_filters_reclaim_warning(tmp_path, capsys, level, shown):
    out = tmp_path / "out"
    _stale_lock(out)
    rc, _, err = _run(capsys, "--log-level", level, *_argv("run", out))
    assert rc == FIXTURE_RC["run"]
    assert (RECLAIM in err) is shown
    assert len(_observability_handlers()) == 1


def test_no_flags_leave_logging_untouched(tmp_path, capsys):
    logger = logging.getLogger("sot_validator")
    level = logger.level
    rc, plain_out, _ = _run(capsys, *_argv("run", tmp_path / "a"))
    assert rc == FIXTURE_RC["run"]
    assert _observability_handlers() == []
    assert logger.level == level
    assert not list((tmp_path / "a").glob("*.prom"))
    rc, metrics_out, _ = _run(
        capsys, "--metrics-file", str(tmp_path / "m.prom"), *_argv("run", tmp_path / "b")
    )
    assert rc == FIXTURE_RC["run"]
    assert _observability_handlers() == []

    def _strip_dir(text: str, name: str) -> str:
        return text.replace(str(tmp_path / name), "<out>")

    assert _strip_dir(plain_out, "a") == _strip_dir(metrics_out, "b")


@pytest.mark.parametrize("flags", [["--log-format", "xml"], ["--log-level", "verbose"]])
def test_bad_log_values_exit_2(tmp_path, capsys, flags):
    metrics = tmp_path / "m.prom"
    with pytest.raises(SystemExit) as excinfo:
        main([*flags, "--metrics-file", str(metrics), *_argv("run", tmp_path / "out")])
    assert excinfo.value.code == 2
    assert "invalid choice" in capsys.readouterr().err
    assert not metrics.exists()


def test_root_flags_rejected_after_subcommand(tmp_path, capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["run", "--fixtures", "--metrics-file", str(tmp_path / "m.prom")])
    assert excinfo.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err


# --- metrics -----------------------------------------------------------------------------


@pytest.mark.parametrize("command", ["run", "campaign"])
def test_metrics_after_run_and_campaign(tmp_path, capsys, command):
    out = tmp_path / "out"
    metrics = out / "m.prom"
    out.mkdir()
    rc, _, err = _run(capsys, "--metrics-file", str(metrics), *_argv(command, out))
    assert rc == FIXTURE_RC[command], err
    text = metrics.read_text(encoding="utf-8")
    _assert_help_and_type(text)
    assert _samples(text, "sot_run_duration_seconds")["sot_run_duration_seconds"] > 0
    last = _samples(text, "sot_run_last_success_timestamp_seconds")
    assert last["sot_run_last_success_timestamp_seconds"] != 0
    assert "sot_collector_errors_total{" not in text

    manifest = json.loads((out / "run_manifest.json").read_text(encoding="utf-8"))
    ok_sites = [s["site_id"] for s in manifest["sites"] if s["status"] == "ok"]
    assert ok_sites
    status = _samples(text, "sot_site_status")
    for site in ok_sites:
        assert status[f'sot_site_status{{site="{site}",status="ok"}}'] == 1
    assert len([k for k in status if k.endswith('status="ok"}')]) == len(ok_sites)

    if command == "run":
        written = json.loads((out / "validation_results.json").read_text(encoding="utf-8"))
        results = written["results"]
    else:
        summary = json.loads((out / "campaign_summary.json").read_text(encoding="utf-8"))
        results = summary["committed_validation_results"]
    assert results
    assert sum(_samples(text, "sot_records_total").values()) == len(results)
    assert not list(out.glob("*.tmp")) and not list(out.glob(".*.tmp"))


def test_non_run_command_has_no_site_series(tmp_path, capsys):
    metrics = tmp_path / "m.prom"
    rc, _, err = _run(capsys, "--metrics-file", str(metrics), *_argv("validate", tmp_path / "out"))
    assert rc == 0, err
    text = metrics.read_text(encoding="utf-8")
    _assert_help_and_type(text)
    assert _samples(text, "sot_run_duration_seconds")["sot_run_duration_seconds"] > 0
    last = _samples(text, "sot_run_last_success_timestamp_seconds")
    assert last["sot_run_last_success_timestamp_seconds"] != 0
    assert "sot_site_status{" not in text
    assert "sot_records_total{" not in text
    assert not list(tmp_path.glob(".*.tmp"))


def test_missing_metrics_dir_gives_one_error(tmp_path, capsys):
    metrics = tmp_path / "missing-dir" / "m.prom"
    rc, _, err = _run(capsys, "--metrics-file", str(metrics), *_argv("validate", tmp_path / "out"))
    assert rc == 3
    line = _single_error(err)
    assert line.startswith(f"error: cannot write metrics file {metrics}: ")
    assert not metrics.exists()
    assert not metrics.parent.exists()


def test_write_failure_keeps_handler_exit_code_and_existing_file(tmp_path, capsys, monkeypatch):
    metrics = tmp_path / "m.prom"
    metrics.write_bytes(b"previous\n")

    def _fail(path, registry):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(_observability, "write_textfile", _fail)
    rc, _, err = _run(capsys, "--metrics-file", str(metrics), *_argv("run", tmp_path / "out"))
    assert rc == FIXTURE_RC["run"]
    assert _single_error(err) == f"error: cannot write metrics file {metrics}: Permission denied"
    assert metrics.read_bytes() == b"previous\n"


def test_write_failure_after_raise_reraises(tmp_path, capsys, monkeypatch):
    metrics = tmp_path / "m.prom"

    def _fail(path, registry):
        raise OSError("boom")

    def _boom(args):
        raise RuntimeError("handler exploded")

    monkeypatch.setattr(_observability, "write_textfile", _fail)
    monkeypatch.setattr(cli_core, "cmd_validate", _boom)
    with pytest.raises(RuntimeError, match="handler exploded"):
        main(["--metrics-file", str(metrics), *_argv("validate", tmp_path / "out")])
    assert _single_error(capsys.readouterr().err) == (
        f"error: cannot write metrics file {metrics}: OSError"
    )


def test_no_metrics_file_on_config_error(tmp_path, capsys):
    metrics = tmp_path / "m.prom"
    bad = tmp_path / "bad.toml"
    bad.write_text("[policy\n", encoding="utf-8")
    rc, _, err = _run(
        capsys, "--metrics-file", str(metrics), "--config", str(bad), *_argv("validate", tmp_path / "out")
    )
    assert rc == 2
    _single_error(err)
    assert not metrics.exists()


def test_no_metrics_file_on_threshold_conflict(tmp_path, capsys):
    metrics = tmp_path / "m.prom"
    cfg = tmp_path / "fleet.toml"
    cfg.write_text("[policy]\nlast_seen_stale_after_days = 10.0\n", encoding="utf-8")
    rc, _, err = _run(
        capsys,
        "--metrics-file",
        str(metrics),
        "--config",
        str(cfg),
        *_argv("validate", tmp_path / "out"),
        "--active-within-days",
        "40",
    )
    assert rc == 2
    _single_error(err)
    assert not metrics.exists()


def test_last_success_unset_when_handler_returns_2(tmp_path, capsys, monkeypatch):
    metrics = tmp_path / "m.prom"
    monkeypatch.setattr(cli_core, "cmd_validate", lambda args: 2)
    rc, _, _ = _run(capsys, "--metrics-file", str(metrics), *_argv("validate", tmp_path / "out"))
    assert rc == 2
    text = metrics.read_text(encoding="utf-8")
    assert re.search(r"^sot_run_last_success_timestamp_seconds 0$", text, re.M)
    assert _samples(text, "sot_run_duration_seconds")["sot_run_duration_seconds"] >= 0


@pytest.mark.parametrize("exc", [RuntimeError("handler exploded"), SystemExit(5)])
def test_last_success_unset_and_reraised_when_handler_raises(tmp_path, monkeypatch, exc):
    metrics = tmp_path / "m.prom"

    def _boom(args):
        raise exc

    monkeypatch.setattr(cli_core, "cmd_validate", _boom)
    with pytest.raises(type(exc)) as excinfo:
        main(["--metrics-file", str(metrics), *_argv("validate", tmp_path / "out")])
    assert excinfo.value is exc
    text = metrics.read_text(encoding="utf-8")
    assert re.search(r"^sot_run_last_success_timestamp_seconds 0$", text, re.M)
    _assert_help_and_type(text)


# --- secrets -----------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", ["json", "text"])
@pytest.mark.parametrize("command", ["run", "campaign"])
def test_secret_sentinel_never_logged_or_written(tmp_path, capsys, monkeypatch, fmt, command):
    for name in SECRET_VARS:
        monkeypatch.setenv(name, SENTINEL)
    cfg = tmp_path / "fleet.toml"
    cfg.write_text(SECRETS_CONFIG, encoding="utf-8")
    out = tmp_path / "out"
    _stale_lock(out)
    metrics = tmp_path / "m.prom"
    rc, stdout, err = _run(
        capsys,
        "--log-level",
        "DEBUG",
        "--log-format",
        fmt,
        "--metrics-file",
        str(metrics),
        "--config",
        str(cfg),
        *_argv(command, out),
    )
    assert rc == FIXTURE_RC[command], err
    assert RECLAIM in err
    assert SENTINEL not in stdout
    assert SENTINEL not in err
    assert SENTINEL not in metrics.read_text(encoding="utf-8")
