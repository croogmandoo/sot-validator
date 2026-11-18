"""CLI tests for `reconcile --oui-dir/--exclude-randomized-macs` and `diff-scans --oui-dir`."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from sot_validator.cli import main
from sot_validator.models import IPAddress, Site, Subnet
from sot_validator.reconciliation import DISCREPANCY_CSV_COLUMNS

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES_DIR = REPO_ROOT / "tests" / "fixtures" / "sot_samples"
OUI_DIR = REPO_ROOT / "tests" / "fixtures" / "oui"
RECONCILE_OUTPUTS = (
    "reconciliation_report.json",
    "reconciliation_discrepancies.csv",
    "onboarding_template.csv",
    "onboarding_import.sql",
)


def _reconcile(out_dir: Path, *extra: str) -> int:
    return main(
        [
            "reconcile",
            "--csv-dir",
            str(SAMPLES_DIR / "csv"),
            "--vcenter-json",
            str(SAMPLES_DIR / "vcenter" / "vcenter_inventory.json"),
            "--snmp-fixture",
            str(SAMPLES_DIR / "snmp" / "extreme_and_apc_walks.json"),
            "--evaluation-time",
            "2026-11-11T09:00:00Z",
            "--output-dir",
            str(out_dir),
            *extra,
        ]
    )


def _bad_oui_dir(tmp_path: Path, kind: str) -> Path:
    if kind == "missing":
        return tmp_path / "does-not-exist"
    if kind == "file":
        path = tmp_path / "oui.csv"
        path.write_text((OUI_DIR / "oui.csv").read_text(encoding="utf-8"), encoding="utf-8")
        return path
    directory = tmp_path / kind
    directory.mkdir()
    if kind == "empty":
        (directory / "readme.txt").write_text("no csv here", encoding="utf-8")
    else:
        (directory / "oui.csv").write_text("Registry,Vendor\nMA-L,Foo\n", encoding="utf-8")
    return directory


BAD_KINDS = ("missing", "file", "empty", "headers")
BAD_REASONS = {
    "missing": "not an existing directory",
    "file": "not an existing directory",
    "empty": "directory contains no *.csv IEEE OUI files",
    "headers": "missing required headers",
}


# --- reconcile ------------------------------------------------------------------


def test_reconcile_oui_dir_annotates_report_and_csv(tmp_path: Path) -> None:
    out = tmp_path / "out"
    assert _reconcile(out, "--oui-dir", str(OUI_DIR)) == 0
    report = json.loads((out / "reconciliation_report.json").read_text(encoding="utf-8"))
    assert report["total_discrepancies"] == 16
    assert "excluded_randomized_mac_count" not in report
    for item in report["discrepancies"]:
        assert item["observed_mac"].startswith("00:50:56:")
        assert item["observed_mac_vendor"] == "VMware, Inc."
        assert item["observed_mac_class"] == "universal"
    with (out / "reconciliation_discrepancies.csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.reader(handle))
    assert tuple(rows[0]) == DISCREPANCY_CSV_COLUMNS + ("observed_mac_vendor", "observed_mac_class")
    assert all(row[-2:] == ["VMware, Inc.", "universal"] for row in rows[1:])

    plain = tmp_path / "plain"
    assert _reconcile(plain) == 0
    for name in ("onboarding_template.csv", "onboarding_import.sql"):
        assert (out / name).read_bytes() == (plain / name).read_bytes()


def test_reconcile_without_flags_keeps_existing_shape(tmp_path: Path) -> None:
    out = tmp_path / "out"
    assert _reconcile(out) == 0
    report = json.loads((out / "reconciliation_report.json").read_text(encoding="utf-8"))
    assert list(report) == [
        "generated_at",
        "total_discrepancies",
        "summary_by_type",
        "summary_by_site",
        "discrepancies",
    ]
    assert all(tuple(item) == DISCREPANCY_CSV_COLUMNS for item in report["discrepancies"])
    header = (out / "reconciliation_discrepancies.csv").read_text(encoding="utf-8").splitlines()[0]
    assert header == ",".join(DISCREPANCY_CSV_COLUMNS)


def test_reconcile_exclude_flag_alone_adds_only_exclusion_keys(tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    excl = tmp_path / "excl"
    assert _reconcile(plain) == 0
    assert _reconcile(excl, "--exclude-randomized-macs") == 0
    for name in RECONCILE_OUTPUTS[1:]:
        assert (excl / name).read_bytes() == (plain / name).read_bytes()
    plain_report = json.loads((plain / "reconciliation_report.json").read_text(encoding="utf-8"))
    excl_report = json.loads((excl / "reconciliation_report.json").read_text(encoding="utf-8"))
    assert excl_report["excluded_randomized_mac_count"] == 0
    assert excl_report["excluded_randomized_mac_discrepancies"] == []
    assert list(excl_report)[-2:] == [
        "excluded_randomized_mac_count",
        "excluded_randomized_mac_discrepancies",
    ]
    del excl_report["excluded_randomized_mac_count"]
    del excl_report["excluded_randomized_mac_discrepancies"]
    assert excl_report == plain_report
    assert all("observed_mac_vendor" not in item for item in excl_report["discrepancies"])


def test_reconcile_exclude_randomized_macs_end_to_end(tmp_path: Path) -> None:
    vc_data = json.loads(
        (SAMPLES_DIR / "vcenter" / "vcenter_inventory.json").read_text(encoding="utf-8")
    )
    template = next(vm for vm in vc_data["vms"] if vm["power_state"] == "poweredOn")
    for index, mac in enumerate(("02:00:00:00:42:01", "aa:9c:6c:00:42:02"), start=1):
        vm = json.loads(json.dumps(template))
        vm.update(
            vm_moref=f"vm-rnd-{index}",
            bios_uuid=f"42000042-0000-0000-0000-00000000aa0{index}",
            vm_name=f"rnd-vm-{index}",
            guest_hostname=f"rnd-vm-{index}.example.internal",
        )
        vm["nics"] = [
            {
                "nic_label": "Network adapter 1",
                "mac_address": mac,
                "ip_addresses": [f"10.42.10.24{index}"],
                "vlan_id": 10,
                "connected": True,
            }
        ]
        vc_data["vms"].append(vm)
    vc_file = tmp_path / "vcenter.json"
    vc_file.write_text(json.dumps(vc_data), encoding="utf-8")

    def run(out: Path, *extra: str) -> int:
        return main(
            [
                "reconcile",
                "--csv-dir",
                str(SAMPLES_DIR / "csv"),
                "--vcenter-json",
                str(vc_file),
                "--snmp-fixture",
                str(SAMPLES_DIR / "snmp" / "extreme_and_apc_walks.json"),
                "--evaluation-time",
                "2026-11-11T09:00:00Z",
                "--output-dir",
                str(out),
                *extra,
            ]
        )

    off = tmp_path / "off"
    on = tmp_path / "on"
    assert run(off) == 0
    assert run(on, "--oui-dir", str(OUI_DIR), "--exclude-randomized-macs") == 0
    off_report = json.loads((off / "reconciliation_report.json").read_text(encoding="utf-8"))
    on_report = json.loads((on / "reconciliation_report.json").read_text(encoding="utf-8"))
    excluded = on_report["excluded_randomized_mac_discrepancies"]
    assert on_report["excluded_randomized_mac_count"] == len(excluded) > 0
    assert {item["observed_mac"] for item in excluded} == {"02:00:00:00:42:01"}
    assert all(item["observed_mac_class"] == "locally_administered" for item in excluded)
    assert on_report["total_discrepancies"] == off_report["total_discrepancies"] - len(excluded)
    for name in RECONCILE_OUTPUTS[1:]:
        assert "02:00:00:00:42:01" in (off / name).read_text(encoding="utf-8")
        assert "02:00:00:00:42:01" not in (on / name).read_text(encoding="utf-8")
        assert "aa:9c:6c:00:42:02" in (on / name).read_text(encoding="utf-8")
    counted = {item["observed_mac"]: item for item in on_report["discrepancies"]}
    assert counted["aa:9c:6c:00:42:02"]["observed_mac_vendor"] == "Ubiquiti UniFi"


@pytest.mark.parametrize("kind", BAD_KINDS)
def test_reconcile_bad_oui_dir_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], kind: str
) -> None:
    bad = _bad_oui_dir(tmp_path, kind)
    out = tmp_path / "out"
    assert main(["reconcile", "--fixtures", "--output-dir", str(out), "--oui-dir", str(bad)]) == 2
    captured = capsys.readouterr()
    lines = captured.err.splitlines()
    assert len(lines) == 1
    assert lines[0].startswith(f"error: --oui-dir {bad}: ")
    assert BAD_REASONS[kind] in lines[0]
    assert captured.out == ""
    assert not (out / "reconciliation_report.json").exists()
    assert not out.exists()


# --- diff-scans -----------------------------------------------------------------


def _write_site(path: Path, macs: dict[str, str]) -> Path:
    site = Site(
        site_id="site-042",
        name="Site 42",
        subnets=[Subnet(subnet_id="sub-1", site_id="site-042", cidr="10.42.1.0/24")],
        ip_addresses=[
            IPAddress(ip=ip, subnet_id="sub-1", arp_mac=mac) for ip, mac in macs.items()
        ],
    )
    path.write_text(site.to_json(indent=2), encoding="utf-8")
    return path


def _diff_args(tmp_path: Path) -> list[str]:
    baseline = _write_site(
        tmp_path / "baseline.json",
        {"10.42.1.10": "00:50:56:00:00:10", "10.42.1.11": "00:04:96:00:00:11"},
    )
    current = _write_site(
        tmp_path / "current.json",
        {"10.42.1.10": "70:b3:d5:12:3a:bc", "10.42.1.12": "06:aa:bb:cc:dd:ee"},
    )
    return ["diff-scans", "--baseline", str(baseline), "--current", str(current)]


def test_diff_scans_oui_dir_annotates_json_markdown_and_alerts(tmp_path: Path) -> None:
    json_out = tmp_path / "drift.json"
    md_out = tmp_path / "drift.md"
    alert_out = tmp_path / "alert.json"
    alert_file = tmp_path / "alerts.json"
    alert_file.write_text(
        json.dumps([{"kind": "json_file", "destination": str(alert_out)}]), encoding="utf-8"
    )
    args = _diff_args(tmp_path) + ["--output-json", str(json_out), "--output-md", str(md_out)]
    assert main(args + ["--oui-dir", str(OUI_DIR), "--alert-file", str(alert_file)]) == 0
    report = json.loads(json_out.read_text(encoding="utf-8"))
    by_type = {event["event_type"]: event for event in report["events"]}
    assert by_type["MAC_ADDRESS_CHANGED"]["mac_annotations"] == {
        "previous": {"mac": "00:50:56:00:00:10", "vendor": "VMware, Inc.", "class": "universal"},
        "current": {"mac": "70:b3:d5:12:3a:bc", "vendor": "Tiny Block, Small Co", "class": "universal"},
    }
    assert by_type["NEW_HOST_JOINED"]["mac_annotations"] == {
        "current": {"mac": "06:aa:bb:cc:dd:ee", "vendor": None, "class": "locally_administered"},
    }
    assert by_type["HOST_WENT_OFFLINE"]["mac_annotations"] == {
        "previous": {
            "mac": "00:04:96:00:00:11",
            "vendor": "Extreme Networks Headquarters",
            "class": "universal",
        },
    }
    assert json.loads(alert_out.read_text(encoding="utf-8"))["events"] == report["events"]
    md = md_out.read_text(encoding="utf-8")
    assert "| Summary | MAC vendor |" in md
    assert "current: unknown (locally_administered) |" in md

    plain_json = tmp_path / "plain.json"
    plain_md = tmp_path / "plain.md"
    assert main(_diff_args(tmp_path) + ["--output-json", str(plain_json), "--output-md", str(plain_md)]) == 0
    plain = json.loads(plain_json.read_text(encoding="utf-8"))
    assert "mac_annotations" not in plain_json.read_text(encoding="utf-8")
    assert "MAC vendor" not in plain_md.read_text(encoding="utf-8")
    assert [e["event_id"] for e in plain["events"]] == [e["event_id"] for e in report["events"]]
    assert plain["summary_counts"] == report["summary_counts"]


@pytest.mark.parametrize("kind", BAD_KINDS)
def test_diff_scans_bad_oui_dir_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], kind: str
) -> None:
    bad = _bad_oui_dir(tmp_path, kind)
    json_out = tmp_path / "drift.json"
    alert_out = tmp_path / "alert.json"
    alert_file = tmp_path / "alerts.json"
    alert_file.write_text(
        json.dumps([{"kind": "json_file", "destination": str(alert_out)}]), encoding="utf-8"
    )
    args = _diff_args(tmp_path) + [
        "--output-json",
        str(json_out),
        "--alert-file",
        str(alert_file),
        "--oui-dir",
        str(bad),
    ]
    assert main(args) == 2
    captured = capsys.readouterr()
    lines = captured.err.splitlines()
    assert len(lines) == 1
    assert lines[0].startswith(f"error: --oui-dir {bad}: ")
    assert BAD_REASONS[kind] in lines[0]
    assert not json_out.exists()
    assert not alert_out.exists()


def test_diff_scans_bad_oui_dir_checked_before_snapshots(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(
        [
            "diff-scans",
            "--baseline",
            str(tmp_path / "A"),
            "--current",
            str(tmp_path / "B"),
            "--oui-dir",
            "/nonexistent",
        ]
    )
    assert rc == 2
    lines = capsys.readouterr().err.splitlines()
    assert len(lines) == 1 and lines[0].startswith("error: --oui-dir /nonexistent:")
