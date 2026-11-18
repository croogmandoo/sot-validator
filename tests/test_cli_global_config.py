"""CLI tests for the global `sot-validator --config` flag (flag > config file > built-in default)."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from typing import Any

import pytest

from sot_validator.cli import _common, discovery, main
from sot_validator.cli._config import default_site_ids
from sot_validator.config import load_config
from sot_validator.history import HistoryStore
from sot_validator.models import ValidationClassification, ValidationResult

EXAMPLE_PATH = Path(__file__).resolve().parents[1] / "examples" / "sot-validator.example.toml"
FIXTURE_SITES = ["site-001", "site-002", "site-003"]
SECRET_VARS = ("SOT_VCENTER_PASSWORD", "SOT_SNMP_COMMUNITY", "SOT_PROXMOX_TOKEN_SECRET")
SENTINEL = "sentinel-Zq7-secret-value"
NOW = "2026-04-11T00:00:00Z"

SITE_001 = """
[[sites]]
site_id = "site-001"
name = "HQ"
block = "10.1.0.0/16"
active_subnets = ["10.1.10.0/24"]
"""

SITE_003 = """
[[sites]]
site_id = "site-003"
name = "Branch"
block = "10.3.0.0/16"
active_subnets = ["10.3.10.0/24"]
"""

SECRETS = """
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


def _config(tmp_path: Path, policy: str = "", body: str = SITE_001, name: str = "fleet.toml") -> Path:
    path = tmp_path / name
    path.write_text((f"[policy]\n{policy}\n" if policy else "") + body, encoding="utf-8")
    return path


def _run(capsys, *argv: str) -> tuple[int, str, str]:
    rc = main(list(argv))
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


def _single_error(err: str) -> str:
    lines = err.strip().splitlines()
    assert len(lines) == 1, err
    assert lines[0].startswith("error: ")
    assert "Traceback" not in err
    return lines[0]


def _result_sites(out_dir: Path) -> set[str]:
    payload = json.loads((out_dir / "validation_results.json").read_text(encoding="utf-8"))
    return {result["site_id"] for result in payload["results"]}


@pytest.fixture
def engine_thresholds(monkeypatch) -> list[dict[str, float]]:
    """Record the thresholds handed to ClassificationPolicy and the AD collector."""
    calls: list[dict[str, float]] = []
    real_policy = _common.ClassificationPolicy
    real_ad = _common._load_ad_collector

    def policy(**kwargs: Any):
        calls.append({"source": "policy", **kwargs})
        return real_policy(**kwargs)

    def ad_collector(path, *, active_within_days, stale_after_days, evaluation_time):
        calls.append(
            {"source": "ad", "active_within_days": active_within_days, "stale_after_days": stale_after_days}
        )
        return real_ad(
            path,
            active_within_days=active_within_days,
            stale_after_days=stale_after_days,
            evaluation_time=evaluation_time,
        )

    monkeypatch.setattr(_common, "ClassificationPolicy", policy)
    monkeypatch.setattr(_common, "_load_ad_collector", ad_collector)
    return calls


# --- recency thresholds ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("flags", "policy", "expected"),
    [
        pytest.param([], None, (7.0, 30.0), id="built-in"),
        pytest.param(["--active-within-days", "3", "--stale-after-days", "20"], None, (3.0, 20.0), id="flag-only"),
        pytest.param([], "last_seen_active_within_days = 2.0\nlast_seen_stale_after_days = 10.0", (2.0, 10.0), id="config-only"),
        pytest.param(
            ["--active-within-days", "5", "--stale-after-days", "12"],
            "last_seen_active_within_days = 2.0\nlast_seen_stale_after_days = 10.0",
            (5.0, 12.0),
            id="flag-wins",
        ),
        pytest.param(
            ["--stale-after-days", "15"],
            "last_seen_active_within_days = 2.0\nlast_seen_stale_after_days = 10.0",
            (2.0, 15.0),
            id="mixed",
        ),
    ],
)
@pytest.mark.parametrize("command", ["validate", "run", "campaign"])
def test_recency_thresholds_reach_engine(tmp_path, capsys, engine_thresholds, command, flags, policy, expected):
    prefix = ["--config", str(_config(tmp_path, policy))] if policy is not None else []
    rc, _, err = _run(capsys, *prefix, command, "--fixtures", "--output-dir", str(tmp_path / "out"), *flags)
    assert rc == 0, err
    assert engine_thresholds
    for call in engine_thresholds:
        assert (call["active_within_days"], call["stale_after_days"]) == expected
    assert {call["source"] for call in engine_thresholds} == {"policy", "ad"}


def test_threshold_conflict_with_config_exits_2(tmp_path, capsys):
    cfg = _config(tmp_path, "last_seen_active_within_days = 2.0\nlast_seen_stale_after_days = 10.0")
    out = tmp_path / "out3"
    rc, stdout, err = _run(
        capsys, "--config", str(cfg), "validate", "--fixtures", "--active-within-days", "40", "--output-dir", str(out)
    )
    assert rc == 2
    line = _single_error(err)
    assert "40.0" in line and "10.0" in line and str(cfg) in line
    assert stdout == ""
    assert not out.exists()


def test_threshold_conflict_from_stale_flag_below_config_active(tmp_path, capsys):
    cfg = _config(tmp_path, "last_seen_active_within_days = 5.0\nlast_seen_stale_after_days = 10.0")
    out = tmp_path / "out"
    rc, _, err = _run(capsys, "--config", str(cfg), "run", "--fixtures", "--stale-after-days", "1", "--output-dir", str(out))
    assert rc == 2
    assert "5.0" in _single_error(err)
    assert not out.exists()


# --- target sites ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("use_config", "flags", "expected"),
    [
        pytest.param(False, [], FIXTURE_SITES, id="built-in"),
        pytest.param(False, ["--site-ids", "site-002"], ["site-002"], id="flag-only"),
        pytest.param(True, [], ["site-001"], id="config-only"),
        pytest.param(True, ["--site-ids", "site-002"], ["site-002"], id="site-ids-wins"),
        pytest.param(True, ["--all-sites"], FIXTURE_SITES, id="all-sites-wins"),
    ],
)
@pytest.mark.parametrize("command", ["validate", "run"])
def test_target_sites(tmp_path, capsys, command, use_config, flags, expected):
    prefix = ["--config", str(_config(tmp_path))] if use_config else []
    out = tmp_path / "out"
    rc, _, err = _run(capsys, *prefix, command, "--fixtures", "--output-dir", str(out), *flags)
    assert rc == 0, err
    assert _result_sites(out) == set(expected)


def test_config_sites_feed_resolved_site_commands(tmp_path, capsys):
    cfg = _config(tmp_path, body=SITE_003)
    out = tmp_path / "camp"
    rc, _, err = _run(capsys, "--config", str(cfg), "campaign", "--fixtures", "--output-dir", str(out))
    assert rc == 0, err
    summary = json.loads((out / "campaign_summary.json").read_text(encoding="utf-8"))
    assert "site-003" in json.dumps(summary)
    assert "site-001" not in json.dumps(summary)


def test_single_site_commands_ignore_config_sites(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = _config(tmp_path, body=SITE_003)
    plain, configured = tmp_path / "plain.json", tmp_path / "configured.json"
    assert main(["topology", "--fixtures", "--output-json", str(plain)]) == 0
    assert main(["--config", str(cfg), "topology", "--fixtures", "--output-json", str(configured)]) == 0
    capsys.readouterr()
    assert json.loads(configured.read_text(encoding="utf-8"))["site_id"] == "site-001"
    assert plain.read_bytes() == configured.read_bytes()


def test_default_site_ids_keep_file_order_and_yield_to_flags(tmp_path):
    config = load_config(_config(tmp_path, body=SITE_003 + SITE_001))
    args = argparse.Namespace(fleet_config=config, site_ids=None, all_sites=False)
    assert default_site_ids(args) == ["site-003", "site-001"]
    assert default_site_ids(argparse.Namespace(fleet_config=config, site_ids=[""], all_sites=False)) is None
    assert default_site_ids(argparse.Namespace(fleet_config=config, site_ids=None, all_sites=True)) is None
    assert default_site_ids(argparse.Namespace(site_ids=None, all_sites=False)) is None


# --- quarantine --min-consecutive-stale-runs ---------------------------------------------


@pytest.fixture
def results_file(tmp_path, capsys) -> Path:
    out = tmp_path / "val"
    assert main(["validate", "--fixtures", "--output-dir", str(out)]) == 0
    capsys.readouterr()
    return out / "validation_results.json"


@pytest.mark.parametrize(
    ("flags", "policy", "expected"),
    [
        pytest.param([], None, 3, id="built-in"),
        pytest.param(["--min-consecutive-stale-runs", "5"], None, 5, id="flag-only"),
        pytest.param([], "quarantine_min_stale_runs = 4", 4, id="config-only"),
        pytest.param(["--min-consecutive-stale-runs", "6"], "quarantine_min_stale_runs = 4", 6, id="flag-wins"),
    ],
)
def test_quarantine_min_consecutive_stale_runs(tmp_path, capsys, monkeypatch, results_file, flags, policy, expected):
    monkeypatch.chdir(tmp_path)
    prefix = ["--config", str(_config(tmp_path, policy))] if policy is not None else []
    manifest = tmp_path / "manifest.json"
    rc, _, err = _run(capsys, *prefix, "quarantine", "--results-file", str(results_file), "--output", str(manifest), *flags)
    assert rc == 0, err
    policy_out = json.loads(manifest.read_text(encoding="utf-8"))["policy"]
    assert policy_out["min_consecutive_stale_runs"] == expected


# --- history --min-consecutive-stale -----------------------------------------------------


@pytest.mark.parametrize(
    ("flags", "policy", "expected"),
    [
        pytest.param([], None, 0, id="built-in"),
        pytest.param(["--min-consecutive-stale", "2"], None, 2, id="flag-only"),
        pytest.param([], "quarantine_min_stale_runs = 4", 4, id="config-only"),
        pytest.param(["--min-consecutive-stale", "1"], "quarantine_min_stale_runs = 4", 1, id="flag-wins"),
    ],
)
def test_history_min_consecutive_stale(tmp_path, capsys, monkeypatch, flags, policy, expected):
    seen: list[int] = []
    real = HistoryStore.list_streaks

    def list_streaks(self, *args: Any, **kwargs: Any):
        seen.append(kwargs["min_consecutive_stale"])
        return real(self, *args, **kwargs)

    monkeypatch.setattr(HistoryStore, "list_streaks", list_streaks)
    prefix = ["--config", str(_config(tmp_path, policy))] if policy is not None else []
    rc, _, err = _run(capsys, *prefix, "history", "--db-path", str(tmp_path / "h.db"), *flags)
    assert rc == 0, err
    assert seen == [expected]


def test_history_streak_filter_uses_config_on_real_streaks(tmp_path, capsys):
    db_path = _stale_history(tmp_path, runs=3)
    summary = tmp_path / "summary.json"
    base = ["history", "--db-path", str(db_path), "--drift-output", str(summary)]

    assert main(base) == 0
    assert json.loads(summary.read_text(encoding="utf-8"))["total_streaks"] == 1
    assert main(["--config", str(_config(tmp_path, "quarantine_min_stale_runs = 4")), *base]) == 0
    assert json.loads(summary.read_text(encoding="utf-8"))["total_streaks"] == 0
    assert main(["--config", str(_config(tmp_path, "quarantine_min_stale_runs = 3")), *base]) == 0
    assert json.loads(summary.read_text(encoding="utf-8"))["total_streaks"] == 1
    capsys.readouterr()


# --- discover --max-concurrency ----------------------------------------------------------


@pytest.mark.parametrize(
    ("flags", "policy", "expected"),
    [
        pytest.param([], None, 128, id="built-in"),
        pytest.param(["--max-concurrency", "16"], None, 16, id="flag-only"),
        pytest.param([], "max_concurrent_probes_per_site = 8", 8, id="config-only"),
        pytest.param([], "", 32, id="config-loader-default"),
        pytest.param(["--max-concurrency", "20"], "max_concurrent_probes_per_site = 8", 20, id="flag-wins"),
    ],
)
def test_discover_max_concurrency(tmp_path, capsys, monkeypatch, flags, policy, expected):
    seen: list[int] = []
    real = discovery.DiscoveryConfig

    def config_spy(**kwargs: Any):
        seen.append(kwargs["max_concurrency"])
        return real(**kwargs)

    monkeypatch.setattr(discovery, "DiscoveryConfig", config_spy)
    if policy is None:
        prefix = []
    elif policy:
        prefix = ["--config", str(_config(tmp_path, policy))]
    else:
        prefix = ["--config", str(_config(tmp_path))]
    rc, _, err = _run(
        capsys,
        *prefix,
        "discover",
        "--cidr",
        "10.1.0.0/16",
        "--site-id",
        "site-001",
        "--fixtures",
        "--output",
        str(tmp_path / "site.json"),
        *flags,
    )
    assert rc == 0, err
    assert seen == [expected]


# --- no --config keeps today's behaviour --------------------------------------------------


@pytest.mark.parametrize("command", ["validate", "run"])
def test_without_config_results_match_built_in_defaults(tmp_path, capsys, command):
    plain, explicit = tmp_path / "plain", tmp_path / "explicit"
    assert main([command, "--fixtures", "--output-dir", str(plain)]) == 0
    assert main(
        [command, "--fixtures", "--output-dir", str(explicit), "--active-within-days", "7.0", "--stale-after-days", "30.0", "--all-sites"]
    ) == 0
    capsys.readouterr()
    assert (plain / "validation_results.json").read_bytes() == (explicit / "validation_results.json").read_bytes()
    assert _result_sites(plain) == set(FIXTURE_SITES)


def test_handler_works_on_namespace_main_never_resolved(tmp_path, engine_thresholds):
    from sot_validator.cli import build_parser

    args = build_parser().parse_args(["validate", "--fixtures", "--output-dir", str(tmp_path / "out")])
    assert args.active_within_days is None and not hasattr(args, "fleet_config")
    assert args.func(args) == 0
    assert {(c["active_within_days"], c["stale_after_days"]) for c in engine_thresholds} == {(7.0, 30.0)}


# --- config errors -----------------------------------------------------------------------


def test_invalid_config_exits_2_before_dispatch(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = _config(tmp_path, "quarantine_min_stale_runs = 0", name="bad.toml")
    out = tmp_path / "out2"
    rc, stdout, err = _run(capsys, "--config", str(cfg), "run", "--fixtures", "--output-dir", str(out))
    assert rc == 2
    line = _single_error(err)
    assert str(cfg) in line and "[policy]" in line and "quarantine_min_stale_runs" in line
    assert stdout == ""
    assert not out.exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["bad.toml"]


def test_missing_config_file_exits_2(tmp_path, capsys):
    missing = tmp_path / "nope.toml"
    rc, _, err = _run(capsys, "--config", str(missing), "validate", "--fixtures", "--output-dir", str(tmp_path / "o"))
    assert rc == 2
    assert str(missing) in _single_error(err)
    assert not (tmp_path / "o").exists()


def test_bad_toml_exits_2_with_one_line(tmp_path, capsys):
    cfg = tmp_path / "broken.toml"
    cfg.write_text("[policy\nx = \n", encoding="utf-8")
    rc, _, err = _run(capsys, "--config", str(cfg), "history", "--db-path", str(tmp_path / "h.db"))
    assert rc == 2
    assert "invalid TOML" in _single_error(err)
    assert not (tmp_path / "h.db").exists()


def test_global_config_is_rejected_after_subcommand(tmp_path, capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["validate", "--config", str(_config(tmp_path)), "--fixtures"])
    assert excinfo.value.code == 2
    capsys.readouterr()


# --- history-prune -----------------------------------------------------------------------


def _stale_history(tmp_path: Path, runs: int = 5) -> Path:
    db_path = tmp_path / "history.db"
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with HistoryStore(db_path) as store:
        for index in range(runs):
            store.record_run(
                [
                    ValidationResult(
                        item_type="IPAddress",
                        item_id="ip-1",
                        site_id="site-001",
                        name="ip-1",
                        classification=ValidationClassification.STALE_LIKELY_UNUSED,
                        confidence=0.9,
                        rationale="test",
                    )
                ],
                run_id=f"r{index + 1}",
                recorded_at=start + timedelta(days=10 * index),
            )
    return db_path


def _pruned_run_ids(out: str) -> list[str]:
    return json.loads(out)["run_ids"]


def test_history_prune_uses_global_config(tmp_path, capsys):
    db_path = _stale_history(tmp_path)
    cfg = _config(tmp_path, body="[retention]\nmax_runs_per_site = 2\n" + SITE_001)
    rc, out, err = _run(capsys, "--config", str(cfg), "history-prune", "--db-path", str(db_path), "--now", NOW)
    assert rc == 0, err
    own_rc, own_out, _ = _run(capsys, "history-prune", "--db-path", str(db_path), "--now", NOW, "--config", str(cfg))
    assert own_rc == 0
    assert _pruned_run_ids(out) == _pruned_run_ids(own_out)


def test_history_prune_own_config_wins(tmp_path, capsys):
    db_path = _stale_history(tmp_path)
    global_cfg = _config(tmp_path, body="[retention]\nmax_runs_per_site = 4\n" + SITE_001, name="global.toml")
    own_cfg = _config(tmp_path, body="[retention]\nmax_runs_per_site = 1\n" + SITE_001, name="own.toml")
    _, global_only, _ = _run(capsys, "--config", str(global_cfg), "history-prune", "--db-path", str(db_path), "--now", NOW)
    _, own_only, _ = _run(capsys, "history-prune", "--db-path", str(db_path), "--now", NOW, "--config", str(own_cfg))
    rc, both, err = _run(
        capsys, "--config", str(global_cfg), "history-prune", "--db-path", str(db_path), "--now", NOW, "--config", str(own_cfg)
    )
    assert rc == 0, err
    assert _pruned_run_ids(both) == _pruned_run_ids(own_only)
    assert _pruned_run_ids(both) != _pruned_run_ids(global_only)


def test_history_prune_without_any_config_exits_2(tmp_path, capsys):
    db_path = _stale_history(tmp_path)
    rc, out, err = _run(capsys, "history-prune", "--db-path", str(db_path), "--now", NOW)
    assert rc == 2
    assert out == ""
    assert "--config" in _single_error(err)


# --- secrets -----------------------------------------------------------------------------


def test_unset_secret_env_vars_still_run(tmp_path, capsys, monkeypatch):
    for name in SECRET_VARS:
        monkeypatch.delenv(name, raising=False)
    cfg = _config(tmp_path, body=SITE_001 + SECRETS)
    rc, _, err = _run(capsys, "--config", str(cfg), "validate", "--fixtures", "--output-dir", str(tmp_path / "out"))
    assert rc == 0, err
    rc, _, err = _run(capsys, "--config", str(EXAMPLE_PATH), "validate", "--fixtures", "--output-dir", str(tmp_path / "out4"))
    assert rc == 0, err


def test_secret_sentinel_never_printed(tmp_path, capsys, monkeypatch):
    for name in SECRET_VARS:
        monkeypatch.setenv(name, SENTINEL)
    cfg = _config(tmp_path, body="[retention]\nmax_runs_per_site = 2\n" + SITE_001 + SECRETS)
    bad = _config(tmp_path, "quarantine_min_stale_runs = 0", body=SITE_001 + SECRETS, name="bad.toml")
    db_path = _stale_history(tmp_path)
    runs = [
        ["--config", str(cfg), "validate", "--fixtures", "--output-dir", str(tmp_path / "v")],
        ["--config", str(cfg), "run", "--fixtures", "--output-dir", str(tmp_path / "r")],
        ["--config", str(cfg), "history-prune", "--db-path", str(db_path), "--now", NOW],
        ["--config", str(cfg), "history", "--db-path", str(db_path)],
        ["--config", str(cfg), "validate", "--fixtures", "--active-within-days", "99", "--output-dir", str(tmp_path / "c")],
        ["--config", str(bad), "validate", "--fixtures", "--output-dir", str(tmp_path / "b")],
        ["history-prune", "--db-path", str(db_path), "--now", NOW, "--config", str(bad)],
    ]
    codes = []
    for argv in runs:
        rc, out, err = _run(capsys, *argv)
        codes.append(rc)
        assert SENTINEL not in out
        assert SENTINEL not in err
    assert codes == [0, 0, 0, 0, 2, 2, 2]
    for path in tmp_path.rglob("*"):
        if path.is_file() and path.suffix != ".db":
            assert SENTINEL not in path.read_text(encoding="utf-8", errors="replace"), path
