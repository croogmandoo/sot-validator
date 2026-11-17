"""End-to-end CLI tests for `fleet-summary` (fleet site health scorecard over report JSON)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sot_validator.cli import main
from sot_validator.models import (
    Equipment,
    EquipmentCategory,
    IPAddress,
    NetworkDevice,
    Site,
    Subnet,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_CATALOG = REPO_ROOT / "examples" / "lifecycle-catalog.example.json"
SNMP_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "sot_samples" / "snmp" / "extreme_and_apc_walks.json"
EVAL_TIME = "2026-01-01T00:00:00Z"
OUTPUT_FILES = ("fleet-summary.md", "fleet-summary.html", "fleet-summary.json")


def _site_a() -> Site:
    return Site(
        site_id="site-001",
        name="Site 1",
        devices=[
            NetworkDevice(
                device_id="sw-01",
                site_id="site-001",
                hostname="sw01.site001.example.internal",
                management_ip="10.1.1.2",
            )
        ],
        subnets=[Subnet(subnet_id="sub-a1", site_id="site-001", cidr="10.1.1.0/24", vlan_id="10")],
        ip_addresses=[
            IPAddress(ip="10.1.1.2", subnet_id="sub-a1", assigned_object_type="device", assigned_object_id="sw-01"),
            IPAddress(ip="10.1.1.20", subnet_id="sub-a1", assigned_object_type="equipment", assigned_object_id="eq-a"),
            IPAddress(ip="10.1.1.20", subnet_id="sub-a1", assigned_object_type="equipment", assigned_object_id="eq-b"),
        ],
        equipment=[
            Equipment(equipment_id="eq-a", site_id="site-001", name="srv-a", assigned_ips=["10.1.1.20"]),
            Equipment(equipment_id="eq-b", site_id="site-001", name="srv-b", assigned_ips=["10.1.1.20"]),
        ],
    )


def _site_042() -> Site:
    return Site(
        site_id="site-042",
        name="Site 42",
        devices=[
            NetworkDevice(
                device_id="dev-042-sw01",
                site_id="site-042",
                hostname="sw01.site042.example.internal",
                management_ip="10.42.1.10",
            )
        ],
        equipment=[
            Equipment(
                equipment_id="eq-ups-01",
                site_id="site-042",
                name="ups-mdf-101",
                category=EquipmentCategory.UPS,
                assigned_ips=["10.42.30.10"],
            ),
        ],
    )


def _write(path: Path, payload: Any) -> Path:
    text = payload.to_json(indent=2) if isinstance(payload, Site) else json.dumps(payload, indent=2)
    path.write_text(text, encoding="utf-8")
    return path


def _cert(ip: str, cn: str, not_after: str) -> dict[str, Any]:
    return {
        "ip": ip,
        "port": 443,
        "subject_cn": cn,
        "san_dns_names": [cn],
        "issuer_dn": "CN=Corp Issuing CA,O=Example",
        "not_before": "2024-01-01T00:00:00Z",
        "not_after": not_after,
        "signature_algorithm": "sha256WithRSAEncryption",
        "key_type": "RSA",
        "key_bits": 2048,
    }


def _banners(tmp_path: Path) -> Path:
    return _write(
        tmp_path / "banners.json",
        {
            "banners": [
                {"ip": "10.1.1.2", "tls_certificates": [_cert("10.1.1.2", "wrong-name.example.internal", "2026-01-20T00:00:00Z")]},
                {"ip": "10.1.1.20", "tls_certificates": [_cert("10.1.1.20", "srv-a", "2025-06-01T00:00:00Z")]},
            ]
        },
    )


def _assert_one_line_error(capsys: pytest.CaptureFixture[str], *needles: str) -> None:
    err = capsys.readouterr().err
    lines = err.strip().splitlines()
    assert len(lines) == 1, err
    assert lines[0].startswith("error: ")
    assert "Traceback" not in err
    for needle in needles:
        assert needle in lines[0]


def _real_reports(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Run `quality`, `cert-report` and `firmware-check` and return their `--output-json` paths."""
    site_a = _write(tmp_path / "site-a.json", _site_a())
    site_042 = _write(tmp_path / "site-042.json", _site_042())
    q, c, f = tmp_path / "q.json", tmp_path / "c.json", tmp_path / "f.json"
    assert main(["quality", "--snapshot", str(site_a), "--snapshot", str(site_042), "--output-json", str(q)]) == 0
    assert main([
        "cert-report", "--fingerprints", str(_banners(tmp_path)), "--snapshot", str(site_a),
        "--evaluation-time", EVAL_TIME, "--output-json", str(c),
    ]) == 0
    assert main([
        "firmware-check", "--snapshot", str(site_a), "--snapshot", str(site_042), "--catalog", str(EXAMPLE_CATALOG),
        "--snmp-fixture", str(SNMP_FIXTURE), "--evaluation-time", EVAL_TIME, "--output-json", str(f),
    ]) == 0
    return q, c, f


def _quality_report(site_ids: list[str], findings: list[dict[str, Any]]) -> dict[str, Any]:
    return {"site_ids": site_ids, "rules": [], "cross_site": False, "total_findings": len(findings),
            "severity_counts": {}, "findings": findings}


def _cards(out: Path) -> list[dict[str, Any]]:
    return json.loads((out / "fleet-summary.json").read_text(encoding="utf-8"))


# --- happy paths -------------------------------------------------------------------------------

def test_all_three_real_reports(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    q, c, f = _real_reports(tmp_path)
    capsys.readouterr()
    out = tmp_path / "nested" / "out"
    argv = ["fleet-summary", "--quality", str(q), "--cert-report", str(c), "--firmware-check", str(f),
            "--output-dir", str(out)]
    assert main(argv) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    lines = captured.out.strip().splitlines()
    assert lines == [
        f"fleet-summary: 2 site(s) written to {out} (fleet-summary.md, fleet-summary.html, fleet-summary.json)"
    ]
    for name in OUTPUT_FILES:
        assert (out / name).is_file()
    cards = _cards(out)
    assert [card["site_id"] for card in cards] == ["site-001", "site-042"]
    for card in cards:
        assert card["inputs_present"] == ["quality", "certificates", "firmware"]
        assert card["trend"] == "new"
    site_001 = cards[0]
    assert site_001["quality_errors"] >= 1
    assert sum(site_001["cert_findings"].values()) >= 2
    assert cards[1]["firmware_devices"] == 2
    assert (out / "fleet-summary.html").read_text(encoding="utf-8").startswith("<!DOCTYPE html>")
    assert (out / "fleet-summary.md").read_text(encoding="utf-8").startswith("# Fleet Site Health Scorecard")


def test_single_quality_input_shows_no_data_columns(tmp_path: Path) -> None:
    q, _, _ = _real_reports(tmp_path)
    out = tmp_path / "out"
    assert main(["fleet-summary", "--quality", str(q), "--output-dir", str(out)]) == 0
    cards = _cards(out)
    assert cards and all(card["inputs_present"] == ["quality"] for card in cards)
    md = (out / "fleet-summary.md").read_text(encoding="utf-8")
    header = next(line for line in md.splitlines() if line.startswith("| Site |"))
    columns = [cell.strip() for cell in header.strip("|").split("|")]
    row = next(line for line in md.splitlines() if line.startswith("| site-001"))
    cells = dict(zip(columns, (cell.strip() for cell in row.strip("|").split("|"))))
    cert_col = next(name for name in columns if name.lower().startswith("cert"))
    firmware_col = next(name for name in columns if name.lower().startswith("firmware"))
    assert cells[cert_col] == "no data"
    assert cells[firmware_col] == "no data"


def test_zero_finding_sites_from_site_ids_and_site_flag(tmp_path: Path) -> None:
    q = _write(tmp_path / "q.json", _quality_report(
        ["site-001", "site-002"], [{"site_id": "site-001", "severity": "warning", "rule": "x"}]
    ))
    out = tmp_path / "out"
    assert main(["fleet-summary", "--quality", str(q), "--output-dir", str(out)]) == 0
    cards = {card["site_id"]: card for card in _cards(out)}
    assert sorted(cards) == ["site-001", "site-002"]
    assert cards["site-002"]["inputs_present"] == ["quality"]
    assert cards["site-002"]["health_score"] == 100.0

    out2 = tmp_path / "out2"
    assert main(["fleet-summary", "--quality", str(q), "--site", "site-009", "--output-dir", str(out2)]) == 0
    cards = {card["site_id"]: card for card in _cards(out2)}
    assert sorted(cards) == ["site-001", "site-002", "site-009"]
    assert cards["site-009"]["health_score"] == 100.0


def test_bare_list_quality_input_and_info_findings(tmp_path: Path) -> None:
    q = _write(tmp_path / "q.json", [{"site_id": "site-001", "severity": "info"}])
    out = tmp_path / "out"
    assert main(["fleet-summary", "--quality", str(q), "--output-dir", str(out)]) == 0
    [card] = _cards(out)
    assert card["site_id"] == "site-001" and card["health_score"] == 100.0


def _trend_quality(tmp_path: Path) -> Path:
    # Quality-only health scores: site-a 100, site-b 25 (3 warnings), site-c 75 (1 warning), site-d 100.
    findings = [{"site_id": "site-b", "severity": "warning"}] * 3 + [{"site_id": "site-c", "severity": "warning"}]
    return _write(tmp_path / "q.json", _quality_report(["site-a", "site-b", "site-c", "site-d"], findings))


@pytest.mark.parametrize("envelope", [False, True], ids=["bare-list", "scorecards-envelope"])
def test_previous_drives_trend(tmp_path: Path, envelope: bool) -> None:
    q = _trend_quality(tmp_path)
    previous_cards = [
        {"site_id": "site-a", "health_score": 80.0, "trend": "new"},
        {"site_id": "site-b", "health_score": 45.0, "trend": "stable"},
        {"site_id": "site-c", "health_score": 72.0},
        {"site_id": "site-zzz", "health_score": 50.0},
    ]
    prev = _write(tmp_path / "prev.json", {"scorecards": previous_cards} if envelope else previous_cards)
    out = tmp_path / "out"
    assert main(["fleet-summary", "--quality", str(q), "--previous", str(prev), "--output-dir", str(out)]) == 0
    cards = {card["site_id"]: card for card in _cards(out)}
    assert sorted(cards) == ["site-a", "site-b", "site-c", "site-d"]
    expected = {
        "site-a": (100.0, 80.0, "improving"),
        "site-b": (25.0, 45.0, "degrading"),
        "site-c": (75.0, 72.0, "stable"),
        "site-d": (100.0, None, "new"),
    }
    for site_id, (score, previous_score, trend) in expected.items():
        card = cards[site_id]
        assert (card["health_score"], card["previous_score"], card["trend"]) == (score, previous_score, trend)


def test_round_trip_previous_is_stable(tmp_path: Path) -> None:
    q, c, f = _real_reports(tmp_path)
    reports = ["--quality", str(q), "--cert-report", str(c), "--firmware-check", str(f)]
    run1, run2 = tmp_path / "run1", tmp_path / "run2"
    assert main(["fleet-summary", *reports, "--output-dir", str(run1)]) == 0
    assert main(["fleet-summary", *reports, "--previous", str(run1 / "fleet-summary.json"),
                 "--output-dir", str(run2)]) == 0
    first = {card["site_id"]: card for card in _cards(run1)}
    cards = _cards(run2)
    assert cards
    for card in cards:
        assert card["health_score"] is not None
        assert card["trend"] == "stable"
        assert card["previous_score"] == first[card["site_id"]]["health_score"]


def test_deterministic_output(tmp_path: Path) -> None:
    q, c, f = _real_reports(tmp_path)
    reports = ["--quality", str(q), "--cert-report", str(c), "--firmware-check", str(f)]

    def run(name: str, *extra: str) -> dict[str, bytes]:
        out = tmp_path / name
        assert main(["fleet-summary", *reports, *extra, "--output-dir", str(out)]) == 0
        return {file: (out / file).read_bytes() for file in OUTPUT_FILES}

    timed_a = run("timed-a", "--evaluation-time", EVAL_TIME)
    timed_b = run("timed-b", "--evaluation-time", EVAL_TIME)
    assert timed_a == timed_b
    assert "Generated at: 2026-01-01T00:00:00+00:00" in timed_a["fleet-summary.md"].decode("utf-8")
    assert b"2026-01-01T00:00:00+00:00" in timed_a["fleet-summary.html"]
    assert b"2026-01-01" not in timed_a["fleet-summary.json"]

    plain_a = run("plain-a")
    plain_b = run("plain-b")
    assert plain_a == plain_b
    assert "Generated at:" not in plain_a["fleet-summary.md"].decode("utf-8")
    assert b"Generated at:" not in plain_a["fleet-summary.html"]
    assert plain_a["fleet-summary.json"] == timed_a["fleet-summary.json"]
    assert plain_a["fleet-summary.json"].endswith(b"\n")


def test_inputs_are_not_modified(tmp_path: Path) -> None:
    q, c, f = _real_reports(tmp_path)
    before = {path: path.read_bytes() for path in (q, c, f)}
    assert main(["fleet-summary", "--quality", str(q), "--cert-report", str(c), "--firmware-check", str(f),
                 "--output-dir", str(tmp_path / "out")]) == 0
    assert {path: path.read_bytes() for path in (q, c, f)} == before


# --- errors ------------------------------------------------------------------------------------

def test_no_report_input_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "out"
    prev = _write(tmp_path / "prev.json", [])
    assert main(["fleet-summary", "--previous", str(prev), "--site", "site-001", "--output-dir", str(out)]) == 2
    _assert_one_line_error(capsys, "--quality", "--cert-report", "--firmware-check")
    assert not out.exists()
    assert main(["fleet-summary", "--output-dir", str(out)]) == 2
    _assert_one_line_error(capsys, "--quality", "--cert-report", "--firmware-check")
    assert not out.exists()


_MISSING = object()
_NO_SITE = {
    "--quality": {"findings": [{"severity": "error"}]},
    "--cert-report": {"findings": [{"severity": "error"}]},
    "--firmware-check": {"findings": [{"status": "compliant"}]},
    "--previous": {"scorecards": [{"health_score": 50.0, "trend": "new"}]},
}
_BAD_VALUE = {
    "--quality": {"findings": [{"site_id": "site-001", "severity": "critical"}]},
    "--cert-report": {"findings": [{"site_id": "site-001", "severity": "fatal"}]},
    "--firmware-check": {"findings": [{"site_id": "site-001", "status": "bogus"}]},
    "--previous": {"scorecards": [{"site_id": "site-001", "health_score": 50.0, "trend": "sideways"}]},
}
_BAD_CONTENT: dict[str, Any] = {
    "missing": _MISSING,
    "invalid-json": "{not json",
    "scalar": "42",
    "no-key": json.dumps({"other": []}),
}


def _bad_input_cases() -> list[Any]:
    cases = []
    for flag in ("--quality", "--cert-report", "--firmware-check", "--previous"):
        for name, content in _BAD_CONTENT.items():
            cases.append(pytest.param(flag, content, id=f"{flag[2:]}-{name}"))
        cases.append(pytest.param(flag, json.dumps(_NO_SITE[flag]), id=f"{flag[2:]}-no-site-id"))
        cases.append(pytest.param(flag, json.dumps(_BAD_VALUE[flag]), id=f"{flag[2:]}-bad-value"))
    extra = {
        "quality-site-ids-not-list": ("--quality", {"site_ids": "site-001", "findings": []}),
        "quality-site-ids-non-string": ("--quality", {"site_ids": ["site-001", 7], "findings": []}),
        "quality-empty-site-id": ("--quality", {"findings": [{"site_id": "  ", "severity": "error"}]}),
        "quality-non-string-severity": ("--quality", {"findings": [{"site_id": "s", "severity": ["error"]}]}),
        "cert-findings-not-list": ("--cert-report", {"findings": {"site_id": "s"}}),
        "firmware-site-id-number": ("--firmware-check", {"findings": [{"site_id": 1, "status": "compliant"}]}),
        "previous-score-out-of-range": ("--previous", [{"site_id": "s", "health_score": 150}]),
        "previous-score-string": ("--previous", [{"site_id": "s", "health_score": "90"}]),
        "previous-site-id-list": ("--previous", [{"site_id": ["s"], "health_score": 90}]),
    }
    for case_id, (flag, payload) in extra.items():
        cases.append(pytest.param(flag, json.dumps(payload), id=case_id))
    return cases


@pytest.mark.parametrize(("flag", "content"), _bad_input_cases())
def test_bad_input_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str], flag: str, content: Any) -> None:
    bad = tmp_path / "bad.json"
    if content is not _MISSING:
        bad.write_text(content, encoding="utf-8")
    good_quality = _write(tmp_path / "good-q.json", _quality_report(["site-001"], []))
    argv = ["fleet-summary", flag, str(bad)]
    if flag == "--previous":
        argv += ["--quality", str(good_quality)]
    out = tmp_path / "out"
    assert main([*argv, "--output-dir", str(out)]) == 2
    _assert_one_line_error(capsys, flag, str(bad))
    assert not out.exists()


def test_bad_input_after_good_inputs_writes_nothing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    q, c, _ = _real_reports(tmp_path)
    capsys.readouterr()
    out = tmp_path / "out"
    out.mkdir()
    bad = _write(tmp_path / "bad.json", {"findings": [{"site_id": "s", "status": "bogus"}]})
    argv = ["fleet-summary", "--quality", str(q), "--cert-report", str(c), "--firmware-check", str(bad),
            "--output-dir", str(out)]
    assert main(argv) == 2
    _assert_one_line_error(capsys, "--firmware-check")
    assert list(out.iterdir()) == []


@pytest.mark.parametrize("value", ["not-a-date", "2026-13-01", ""])
def test_bad_evaluation_time_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str], value: str) -> None:
    q = _write(tmp_path / "q.json", _quality_report(["site-001"], []))
    out = tmp_path / "out"
    assert main(["fleet-summary", "--quality", str(q), "--evaluation-time", value, "--output-dir", str(out)]) == 2
    _assert_one_line_error(capsys, "error: --evaluation-time")
    assert not out.exists()


@pytest.mark.parametrize("value", ["", "   "])
def test_empty_site_flag_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str], value: str) -> None:
    q = _write(tmp_path / "q.json", _quality_report(["site-001"], []))
    out = tmp_path / "out"
    assert main(["fleet-summary", "--quality", str(q), "--site", value, "--output-dir", str(out)]) == 2
    _assert_one_line_error(capsys, "error: --site")
    assert not out.exists()
