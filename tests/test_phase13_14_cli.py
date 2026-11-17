"""End-to-end CLI tests for Phases 13-14 (`quality`, `cert-report`, `firmware-check`, and package exports)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import sot_validator
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


def _site_a(*, duplicate_ip: bool = True) -> Site:
    ip_addresses = [
        IPAddress(ip="10.1.1.2", subnet_id="sub-a1", assigned_object_type="device", assigned_object_id="sw-01"),
        IPAddress(ip="10.1.1.20", subnet_id="sub-a1", assigned_object_type="equipment", assigned_object_id="eq-a"),
    ]
    if duplicate_ip:
        ip_addresses.append(
            IPAddress(ip="10.1.1.20", subnet_id="sub-a1", assigned_object_type="equipment", assigned_object_id="eq-b")
        )
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
        ip_addresses=ip_addresses,
        equipment=[
            Equipment(equipment_id="eq-a", site_id="site-001", name="srv-a", assigned_ips=["10.1.1.20"]),
            Equipment(equipment_id="eq-b", site_id="site-001", name="srv-b", assigned_ips=["10.1.1.20"]),
        ],
    )


def _site_b() -> Site:
    return Site(
        site_id="site-002",
        name="Site 2",
        subnets=[Subnet(subnet_id="sub-b1", site_id="site-002", cidr="10.2.1.0/24", vlan_id="10")],
        ip_addresses=[
            IPAddress(ip="10.1.1.20", subnet_id="sub-b1", assigned_object_type="equipment", assigned_object_id="eq-c"),
        ],
        equipment=[
            Equipment(equipment_id="eq-c", site_id="site-002", name="srv-c", assigned_ips=["10.1.1.20"]),
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
                equipment_id="eq-vm-01",
                site_id="site-042",
                name="vm-app-01",
                category=EquipmentCategory.VM,
                assigned_ips=["10.42.20.50"],
            ),
            Equipment(
                equipment_id="eq-ups-01",
                site_id="site-042",
                name="ups-mdf-101",
                category=EquipmentCategory.UPS,
                assigned_ips=["10.42.30.99", "10.42.30.10"],
            ),
        ],
    )


def _write(path: Path, payload: Any) -> Path:
    text = payload.to_json(indent=2) if isinstance(payload, Site) else json.dumps(payload, indent=2)
    path.write_text(text, encoding="utf-8")
    return path


def _cert(ip: str, cn: str, not_after: str, **extra: Any) -> dict[str, Any]:
    cert = {
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
    cert.update(extra)
    return cert


def _banners(tmp_path: Path) -> Path:
    return _write(
        tmp_path / "banners.json",
        {
            "banners": [
                {
                    "ip": "10.1.1.2",
                    "tls_certificates": [
                        _cert("10.1.1.2", "wrong-name.example.internal", "2026-01-20T00:00:00Z")
                    ],
                },
                {
                    "ip": "10.1.1.20",
                    "tls_certificates": [_cert("10.1.1.20", "srv-a", "2025-06-01T00:00:00Z")],
                },
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


# --- package exports -------------------------------------------------------------------------

def test_package_exports_phases_13_14() -> None:
    expected = (
        "DataQualityChecker",
        "QualityFinding",
        "VlanConsistencyAuditor",
        "VlanAuditResult",
        "DhcpScope",
        "FdbObservation",
        "CertificateInventory",
        "CertificateRecord",
        "CertificateFinding",
        "FirmwareComplianceChecker",
        "FirmwareFinding",
        "FirmwareInfo",
        "FirmwareObservation",
        "FirmwareParser",
        "LifecycleCatalog",
        "LifecycleEntry",
    )
    for name in expected:
        assert hasattr(sot_validator, name)
        assert name in sot_validator.__all__
    assert "VALID_SEVERITIES" not in sot_validator.__all__
    assert sot_validator.__all__ == sorted(sot_validator.__all__)
    assert len(sot_validator.__all__) == len(set(sot_validator.__all__))

    from sot_validator.lifecycle import LifecycleCatalog
    from sot_validator.quality import DataQualityChecker

    assert sot_validator.LifecycleCatalog is LifecycleCatalog
    assert sot_validator.DataQualityChecker is DataQualityChecker


# --- quality ---------------------------------------------------------------------------------

def test_quality_cross_site_findings_need_two_snapshots(tmp_path: Path) -> None:
    a = _write(tmp_path / "a.json", _site_a())
    b = _write(tmp_path / "b.json", _site_b())
    q_json, q_md = tmp_path / "out" / "q.json", tmp_path / "out" / "q.md"

    argv = ["quality", "--snapshot", str(a), "--snapshot", str(b), "--output-json", str(q_json), "--output-md", str(q_md)]
    assert main(argv) == 0
    report = json.loads(q_json.read_text(encoding="utf-8"))
    assert report["cross_site"] is True
    assert report["site_ids"] == ["site-001", "site-002"]
    assert list(report["rules"]) == list(sot_validator.quality.ALL_RULE_NAMES)
    assert set(report["severity_counts"]) == {"error", "warning", "info"}
    assert report["total_findings"] == len(report["findings"])
    cross = [f for f in report["findings"] if f["rule"] == "cross_site_duplicate_ip"]
    assert len(cross) == 1
    row = (
        f"| {cross[0]['site_id']} | cross_site_duplicate_ip | error | IPAddress | "
        f"{', '.join(cross[0]['record_ids'])} | {cross[0]['message']} |"
    )
    markdown = q_md.read_text(encoding="utf-8")
    assert markdown.startswith("# ")
    assert "| Site | Rule | Severity | Record Type | Records | Message |" in markdown
    assert row in markdown

    first_json, first_md = q_json.read_bytes(), q_md.read_bytes()
    assert main(argv) == 0
    assert q_json.read_bytes() == first_json
    assert q_md.read_bytes() == first_md

    single_json = tmp_path / "single.json"
    assert main(["quality", "--snapshot", str(a), "--output-json", str(single_json)]) == 0
    single = json.loads(single_json.read_text(encoding="utf-8"))
    assert single["cross_site"] is False
    assert single["site_ids"] == ["site-001"]
    assert not [f for f in single["findings"] if f["rule"].startswith("cross_site_")]


def test_quality_rules_and_disable_filters(tmp_path: Path) -> None:
    a = _write(tmp_path / "a.json", _site_a())
    only = tmp_path / "only.json"
    assert main(["quality", "--snapshot", str(a), "--rules", "duplicate_ip", "--output-json", str(only)]) == 0
    report = json.loads(only.read_text(encoding="utf-8"))
    assert report["rules"] == ["duplicate_ip"]
    assert report["findings"]
    assert {f["rule"] for f in report["findings"]} == {"duplicate_ip"}

    without = tmp_path / "without.json"
    assert main(["quality", "--snapshot", str(a), "--disable", "duplicate_ip", "--output-json", str(without)]) == 0
    report = json.loads(without.read_text(encoding="utf-8"))
    assert "duplicate_ip" not in report["rules"]
    assert not [f for f in report["findings"] if f["rule"] == "duplicate_ip"]

    combined = tmp_path / "combined.json"
    argv = [
        "quality", "--snapshot", str(a), "--rules", "duplicate_ip,duplicate_mac", "--rules", "orphan_reference",
        "--disable", "duplicate_mac", "--output-json", str(combined),
    ]
    assert main(argv) == 0
    assert json.loads(combined.read_text(encoding="utf-8"))["rules"] == ["duplicate_ip", "orphan_reference"]


@pytest.mark.parametrize("flag", ["--rules", "--disable"])
def test_quality_unknown_rule_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str], flag: str) -> None:
    a = _write(tmp_path / "a.json", _site_a())
    out = tmp_path / "q.json"
    assert main(["quality", "--snapshot", str(a), flag, "duplicate_ip,not_a_rule", "--output-json", str(out)]) == 2
    _assert_one_line_error(capsys, flag, "not_a_rule")
    assert not out.exists()


def test_quality_no_findings_markdown(tmp_path: Path) -> None:
    a = _write(tmp_path / "a.json", _site_a(duplicate_ip=False))
    md = tmp_path / "q.md"
    assert main(["quality", "--snapshot", str(a), "--rules", "duplicate_ip", "--output-md", str(md)]) == 0
    assert "No data-quality findings." in md.read_text(encoding="utf-8")


def test_quality_escapes_markdown_cells(tmp_path: Path) -> None:
    site = _site_a()
    site.site_id = "site|001\nx"
    for record in [*site.devices, *site.equipment, *site.subnets]:
        record.site_id = site.site_id
    a = _write(tmp_path / "a.json", site)
    md = tmp_path / "q.md"
    assert main(["quality", "--snapshot", str(a), "--rules", "duplicate_ip", "--output-md", str(md)]) == 0
    rows = [line for line in md.read_text(encoding="utf-8").splitlines() if "duplicate_ip" in line]
    assert rows and all("site\\|001 x" in row for row in rows)


@pytest.mark.parametrize(
    "content",
    [None, "{not json", '"just a string"', '{"site": {"site_id": "s", "name": "n", "devices": ["x"]}}',
     '{"site": {"name": "no id"}}'],
    ids=["missing", "bad-json", "bad-shape", "bad-record", "missing-field"],
)
def test_quality_bad_snapshot_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str], content: str | None) -> None:
    snapshot = tmp_path / "a.json"
    if content is not None:
        snapshot.write_text(content, encoding="utf-8")
    out = tmp_path / "q.json"
    assert main(["quality", "--snapshot", str(snapshot), "--output-json", str(out)]) == 2
    _assert_one_line_error(capsys, "--snapshot", str(snapshot))
    assert not out.exists()


# --- cert-report -----------------------------------------------------------------------------

def test_cert_report_with_snapshot(tmp_path: Path) -> None:
    site = _write(tmp_path / "site.json", _site_a())
    banners = _banners(tmp_path)
    c_json, c_md = tmp_path / "out" / "c.json", tmp_path / "out" / "c.md"
    argv = [
        "cert-report", "--fingerprints", str(banners), "--snapshot", str(site), "--evaluation-time", EVAL_TIME,
        "--output-json", str(c_json), "--output-md", str(c_md),
    ]
    assert main(argv) == 0
    report = json.loads(c_json.read_text(encoding="utf-8"))
    assert report["total_findings"] >= 2
    assert report["generated_at"] == "2026-01-01T00:00:00+00:00"
    assert {f["site_id"] for f in report["findings"]} == {"site-001"}
    by_ip = {f["ip"]: f for f in report["findings"]}
    assert "expired" in by_ip["10.1.1.20"]["issues"]
    assert any(issue.startswith("expiring_") for issue in by_ip["10.1.1.2"]["issues"])
    assert "hostname_mismatch" in by_ip["10.1.1.2"]["issues"]
    # srv-a is the equipment name at 10.1.1.20 and matches the certificate CN.
    assert "hostname_mismatch" not in by_ip["10.1.1.20"]["issues"]
    assert c_md.read_text(encoding="utf-8").startswith("# TLS Certificate Inventory")

    first_json, first_md = c_json.read_bytes(), c_md.read_bytes()
    assert main(argv) == 0
    assert c_json.read_bytes() == first_json
    assert c_md.read_bytes() == first_md


def test_cert_report_without_snapshot_uses_unknown_site(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    banners = _banners(tmp_path)
    assert main(["cert-report", "--fingerprints", str(banners), "--evaluation-time", EVAL_TIME]) == 0
    report = json.loads(capsys.readouterr().out)
    assert {f["site_id"] for f in report["findings"]} == {"unknown"}
    assert all("hostname_mismatch" not in f["issues"] for f in report["findings"])

    assert main(["cert-report", "--fingerprints", str(banners), "--site-id", "site-777", "--evaluation-time", EVAL_TIME]) == 0
    report = json.loads(capsys.readouterr().out)
    assert {f["site_id"] for f in report["findings"]} == {"site-777"}


def test_cert_report_hostname_prefers_device_then_equipment(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    site = _site_a()
    site.equipment.append(
        Equipment(equipment_id="eq-0", site_id="site-001", name="sw01.site001.example.internal", assigned_ips=["10.1.1.2"])
    )
    snapshot = _write(tmp_path / "site.json", site)
    banners = _write(
        tmp_path / "banners.json",
        [
            {"ip": "10.1.1.2", "tls_certificates": [_cert("10.1.1.2", "sw01.site001.example.internal", "2027-06-01T00:00:00Z")]},
            {"ip": "10.1.1.20", "tls_certificates": [_cert("10.1.1.20", "srv-b", "2027-06-01T00:00:00Z")]},
        ],
    )
    argv = ["cert-report", "--fingerprints", str(banners), "--snapshot", str(snapshot), "--evaluation-time", EVAL_TIME]
    assert main(argv) == 0
    report = json.loads(capsys.readouterr().out)
    # 10.1.1.2 matches the device hostname; 10.1.1.20 resolves to eq-a (srv-a), the lowest equipment_id.
    assert [(f["ip"], f["issues"]) for f in report["findings"]] == [("10.1.1.20", ["hostname_mismatch"])]


def test_cert_report_empty_banners_is_zero_findings(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    banners = _write(tmp_path / "banners.json", {"banners": [{"ip": "10.1.1.2"}]})
    assert main(["cert-report", "--fingerprints", str(banners), "--evaluation-time", EVAL_TIME]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["total_findings"] == 0


@pytest.mark.parametrize("warn_days", ["90,0", "abc", "-5", "90,,x", "", "3_0", "+30"])
def test_cert_report_bad_warn_days_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], warn_days: str
) -> None:
    banners = _banners(tmp_path)
    c_json, c_md = tmp_path / "c.json", tmp_path / "c.md"
    argv = ["cert-report", "--fingerprints", str(banners), f"--warn-days={warn_days}",
            "--output-json", str(c_json), "--output-md", str(c_md)]
    assert main(argv) == 2
    _assert_one_line_error(capsys, "--warn-days")
    assert not c_json.exists() and not c_md.exists()


def test_cert_report_custom_warn_days(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    banners = _banners(tmp_path)
    assert main(["cert-report", "--fingerprints", str(banners), "--warn-days", "20, 7", "--evaluation-time", EVAL_TIME]) == 0
    report = json.loads(capsys.readouterr().out)
    issues = {f["ip"]: f["issues"] for f in report["findings"]}
    assert "expiring_20d" in issues["10.1.1.2"]


@pytest.mark.parametrize("value", ["not-a-time", "2026-13-01", ""])
def test_cert_report_bad_evaluation_time_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str], value: str) -> None:
    banners = _banners(tmp_path)
    out = tmp_path / "c.json"
    assert main(["cert-report", "--fingerprints", str(banners), f"--evaluation-time={value}", "--output-json", str(out)]) == 2
    _assert_one_line_error(capsys, "--evaluation-time")
    assert not out.exists()


def test_cert_report_naive_evaluation_time_is_utc(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    banners = _banners(tmp_path)
    assert main(["cert-report", "--fingerprints", str(banners), "--evaluation-time", "2026-01-01T00:00:00"]) == 0
    assert json.loads(capsys.readouterr().out)["generated_at"] == "2026-01-01T00:00:00+00:00"


@pytest.mark.parametrize(
    "content",
    [None, "{not json", '{"other": []}', '[{"no_ip": true}]', '[{"ip": "10.1.1.2", "tls_certificates": [{"ip": "10.1.1.2", "port": 0}]}]'],
    ids=["missing", "bad-json", "no-banners-key", "missing-ip", "bad-cert"],
)
def test_cert_report_bad_fingerprints_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], content: str | None
) -> None:
    banners = tmp_path / "banners.json"
    if content is not None:
        banners.write_text(content, encoding="utf-8")
    out = tmp_path / "c.json"
    assert main(["cert-report", "--fingerprints", str(banners), "--output-json", str(out)]) == 2
    _assert_one_line_error(capsys, "--fingerprints", str(banners))
    assert not out.exists()


def test_cert_report_missing_snapshot_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    banners = _banners(tmp_path)
    out = tmp_path / "c.json"
    missing = tmp_path / "missing.json"
    assert main(["cert-report", "--fingerprints", str(banners), "--snapshot", str(missing), "--output-json", str(out)]) == 2
    _assert_one_line_error(capsys, "--snapshot", str(missing))
    assert not out.exists()


# --- firmware-check --------------------------------------------------------------------------

def test_firmware_check_with_and_without_snmp_fixture(tmp_path: Path) -> None:
    site = _write(tmp_path / "site.json", _site_042())
    f_json, f_md = tmp_path / "out" / "f.json", tmp_path / "out" / "f.md"
    argv = [
        "firmware-check", "--snapshot", str(site), "--catalog", str(EXAMPLE_CATALOG), "--snmp-fixture", str(SNMP_FIXTURE),
        "--evaluation-time", EVAL_TIME, "--output-json", str(f_json), "--output-md", str(f_md),
    ]
    assert main(argv) == 0
    report = json.loads(f_json.read_text(encoding="utf-8"))
    by_device = {f["device"]: f for f in report["findings"]}
    switch = by_device["sw01.site042.example.internal"]
    assert switch["vendor"] == "extreme"
    assert switch["version"] is not None
    assert switch["ip"] == "10.42.1.10"
    ups = by_device["ups-mdf-101"]
    assert ups["ip"] == "10.42.30.10"
    assert ups["vendor"] == "apc"
    assert "vm-app-01" not in by_device
    assert report["generated_at"] == "2026-01-01T00:00:00+00:00"
    assert f_md.read_text(encoding="utf-8").startswith("# Firmware Lifecycle Compliance")

    first_json, first_md = f_json.read_bytes(), f_md.read_bytes()
    assert main(argv) == 0
    assert f_json.read_bytes() == first_json
    assert f_md.read_bytes() == first_md

    plain = tmp_path / "plain.json"
    argv = ["firmware-check", "--snapshot", str(site), "--catalog", str(EXAMPLE_CATALOG), "--evaluation-time", EVAL_TIME,
            "--output-json", str(plain)]
    assert main(argv) == 0
    report = json.loads(plain.read_text(encoding="utf-8"))
    assert [(f["device"], f["status"]) for f in report["findings"]] == [("sw01.site042.example.internal", "unparsed")]


def test_firmware_check_multiple_snapshots_prints_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    a = _write(tmp_path / "a.json", _site_a())
    b = _write(tmp_path / "b.json", _site_042())
    argv = ["firmware-check", "--snapshot", str(a), "--snapshot", str(b), "--catalog", str(EXAMPLE_CATALOG),
            "--snmp-fixture", str(SNMP_FIXTURE), "--evaluation-time", EVAL_TIME]
    assert main(argv) == 0
    report = json.loads(capsys.readouterr().out)
    assert {f["site_id"] for f in report["findings"]} == {"site-001", "site-042"}


@pytest.mark.parametrize("content", [None, "{not json", '{"entries": "x"}'], ids=["missing", "bad-json", "bad-schema"])
def test_firmware_check_bad_catalog_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], content: str | None
) -> None:
    site = _write(tmp_path / "site.json", _site_042())
    catalog = tmp_path / "catalog.json"
    if content is not None:
        catalog.write_text(content, encoding="utf-8")
    f_json, f_md = tmp_path / "f.json", tmp_path / "f.md"
    argv = ["firmware-check", "--snapshot", str(site), "--catalog", str(catalog),
            "--output-json", str(f_json), "--output-md", str(f_md)]
    assert main(argv) == 2
    _assert_one_line_error(capsys, "--catalog", str(catalog))
    assert not f_json.exists() and not f_md.exists()


def test_firmware_check_missing_snapshot_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    missing = tmp_path / "missing.json"
    out = tmp_path / "f.json"
    argv = ["firmware-check", "--snapshot", str(missing), "--catalog", str(EXAMPLE_CATALOG), "--output-json", str(out)]
    assert main(argv) == 2
    _assert_one_line_error(capsys, "--snapshot", str(missing))
    assert not out.exists()


@pytest.mark.parametrize(
    "content",
    [None, "{not json", "[]", json.dumps({"snmp_profile": {"mode": "readwrite"}, "targets": {}}),
     json.dumps({"targets": {"t": {"ip_address": "10.42.1.10", "snmp_reachable": True, "oids": {"1.3.6.1.2.1.1.1.0": 42}}}})],
    ids=["missing", "bad-json", "not-object", "readwrite-mode", "non-string-sysdescr"],
)
def test_firmware_check_bad_snmp_fixture_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], content: str | None
) -> None:
    site = _write(tmp_path / "site.json", _site_042())
    fixture = tmp_path / "snmp.json"
    if content is not None:
        fixture.write_text(content, encoding="utf-8")
    out = tmp_path / "f.json"
    argv = ["firmware-check", "--snapshot", str(site), "--catalog", str(EXAMPLE_CATALOG),
            "--snmp-fixture", str(fixture), "--output-json", str(out)]
    assert main(argv) == 2
    _assert_one_line_error(capsys, "--snmp-fixture", str(fixture))
    assert not out.exists()


def test_firmware_check_unreachable_target_is_unparsed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    site = _write(tmp_path / "site.json", _site_042())
    fixture = _write(
        tmp_path / "snmp.json",
        {"targets": {
            "sw": {"ip_address": "10.42.1.10", "snmp_reachable": False,
                   "oids": {"1.3.6.1.2.1.1.1.0": "ExtremeXOS (X465-48W) version 31.7.1.4 by release-manager"}},
            "ups": {"ip_address": "10.42.30.10", "snmp_reachable": True, "oids": {"1.3.6.1.2.1.1.1.0": "   "}},
        }},
    )
    argv = ["firmware-check", "--snapshot", str(site), "--catalog", str(EXAMPLE_CATALOG),
            "--snmp-fixture", str(fixture), "--evaluation-time", EVAL_TIME]
    assert main(argv) == 0
    report = json.loads(capsys.readouterr().out)
    assert [(f["device"], f["status"]) for f in report["findings"]] == [("sw01.site042.example.internal", "unparsed")]


# --- stdout and read-only ---------------------------------------------------------------------

def test_commands_print_json_to_stdout_without_output_flags(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    a = _write(tmp_path / "a.json", _site_a())
    banners = _banners(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    for argv in (
        ["quality", "--snapshot", str(a)],
        ["cert-report", "--fingerprints", str(banners)],
        ["firmware-check", "--snapshot", str(a), "--catalog", str(EXAMPLE_CATALOG)],
    ):
        assert main(argv) == 0
        captured = capsys.readouterr()
        assert isinstance(json.loads(captured.out), dict)
        assert captured.err == ""
    assert list(work.iterdir()) == []
