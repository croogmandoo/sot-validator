"""CLI tests for the read-only `vlan-audit` subcommand."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sot_validator import cli
from sot_validator.models import NetworkDevice, Port, Site, Subnet, VLAN
from sot_validator.quality import VALID_SEVERITIES, VLAN_RULE_NAMES

SITE_ID = "site-001"
REPORT_KEYS = {
    "site_id",
    "rules",
    "skipped_rules",
    "total_findings",
    "severity_counts",
    "findings",
}


def _site(site_id: str = SITE_ID) -> Site:
    return Site(
        site_id=site_id,
        name="Site 001",
        devices=[
            NetworkDevice(
                device_id="sw-01",
                site_id=site_id,
                hostname="sw-01-host",
                management_ip=None,
                role="switch",
                ports=[Port(port_id="sw-01-p1", device_id="sw-01", name="1:1", vlan_id="10")],
            )
        ],
        vlans=[
            VLAN(vlan_id="10", site_id=site_id, subnet_id="sub-10", cidr="10.1.10.0/24"),
            VLAN(vlan_id="20", site_id=site_id, subnet_id="sub-20", cidr="10.1.20.0/24"),
        ],
        subnets=[
            Subnet(subnet_id="sub-10", site_id=site_id, cidr="10.1.10.0/24", vlan_id="10"),
            Subnet(subnet_id="sub-20", site_id=site_id, cidr="10.1.20.0/24", vlan_id="20"),
        ],
    )


def _write(path: Path, payload: Any) -> Path:
    if isinstance(payload, Site):
        text = payload.to_json(indent=2)
    elif isinstance(payload, str):
        text = payload
    else:
        text = json.dumps(payload, indent=2)
    path.write_text(text, encoding="utf-8")
    return path


def _entry(vlan_id: str, *, device_id: str = "sw-01") -> dict[str, Any]:
    return {
        "device_id": device_id,
        "port_name": "1:1",
        "mac_address": "00:11:22:33:44:55",
        "vlan_id": vlan_id,
    }


def _access(vlan_id: str, *, device_id: str = "sw-01") -> dict[str, Any]:
    return {
        "device_id": device_id,
        "port_name": "1:1",
        "port_mode": "access",
        "learned_mac_count": 1,
        "vlan_ids": [vlan_id],
    }


def _observation(*vlans: str, **extra: Any) -> dict[str, Any]:
    return {
        "device_id": "sw-01",
        "observed_at": "2026-11-01T12:00:00Z",
        "entries": [_entry(v) for v in vlans],
        **extra,
    }


def _snapshot(tmp_path: Path, site: Site | None = None) -> Path:
    return _write(tmp_path / "site.json", site or _site())


def _run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    code = cli.main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], *flags: str
) -> dict[str, Any]:
    out = tmp_path / "out" / "vlan.json"
    code, _, err = _run(
        ["vlan-audit", "--snapshot", str(_snapshot(tmp_path)), *flags, "--output-json", str(out)],
        capsys,
    )
    assert code == 0, err
    return json.loads(out.read_text(encoding="utf-8"))


def _rules(report: dict[str, Any]) -> list[str]:
    return [finding["rule"] for finding in report["findings"]]


def _rule_inputs(tmp_path: Path, rule: str) -> list[str]:
    if rule == "vlan_undocumented":
        return ["--fdb", str(_write(tmp_path / "fdb.json", [_observation("10", "20", "30")]))]
    if rule == "vlan_unobserved":
        return ["--fdb", str(_write(tmp_path / "fdb.json", [_observation("10")]))]
    if rule == "subnet_vlan_mismatch":
        records = [{"ip": "10.1.10.5", "interface": "vlan20", "vlan_id": "20", "router_id": "rtr-01"}]
        return ["--router-arp", str(_write(tmp_path / "arp.json", records))]
    if rule == "access_port_vlan_mismatch":
        payload = {"observations": [_observation(port_classifications=[_access("20")])]}
        return ["--fdb", str(_write(tmp_path / "fdb.json", payload))]
    if rule == "dhcp_scope_without_subnet":
        scopes = [{"cidr": "10.1.99.0/24", "source": "dhcp-01"}]
        return ["--dhcp-scopes", str(_write(tmp_path / "scopes.json", scopes))]
    assert rule == "subnet_without_dhcp_scope"
    scopes = {"scopes": [{"cidr": "10.1.10.0/24", "observed_at": "2026-11-01T12:00:00Z"}]}
    return [
        "--dhcp-scopes",
        str(_write(tmp_path / "scopes.json", scopes)),
        "--dhcp-expected",
        str(_write(tmp_path / "expected.txt", "# DHCP subnets\n\n  sub-20  \n10.1.10.0/24\n")),
    ]


@pytest.mark.parametrize("rule", VLAN_RULE_NAMES)
def test_each_rule_fires_end_to_end(
    rule: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = _report(tmp_path, capsys, *_rule_inputs(tmp_path, rule))
    assert rule in _rules(report)
    assert rule in report["rules"]
    assert rule not in report["skipped_rules"]


def test_snapshot_only_skips_every_rule(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    report = _report(tmp_path, capsys)
    assert set(report) == REPORT_KEYS
    assert report["site_id"] == SITE_ID
    assert report["rules"] == []
    assert sorted(report["skipped_rules"]) == sorted(VLAN_RULE_NAMES)
    assert report["total_findings"] == 0
    assert report["findings"] == []
    assert report["severity_counts"] == {severity: 0 for severity in VALID_SEVERITIES}


def test_empty_input_files_count_as_not_supplied(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = _report(
        tmp_path,
        capsys,
        "--fdb", str(_write(tmp_path / "fdb.json", {"observations": []})),
        "--router-arp", str(_write(tmp_path / "arp.json", [])),
        "--dhcp-scopes", str(_write(tmp_path / "scopes.json", {"scopes": []})),
        "--dhcp-expected", str(_write(tmp_path / "expected.txt", "\n# nothing\n")),
    )
    assert report["rules"] == []
    assert sorted(report["skipped_rules"]) == sorted(VLAN_RULE_NAMES)


def test_two_fdb_files_are_joined(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    first = _write(tmp_path / "a.json", [_observation("10", "30")])
    second = _write(tmp_path / "b.json", {"observations": [_observation("20", "40")]})
    report = _report(tmp_path, capsys, "--fdb", str(first), "--fdb", str(second))
    undocumented = [f for f in report["findings"] if f["rule"] == "vlan_undocumented"]
    assert [f["evidence"]["vlan_id"] for f in undocumented] == ["30", "40"]
    assert "vlan_unobserved" not in _rules(report)


def test_map_ports_report_is_accepted_unchanged(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    map_ports = {
        "site_id": SITE_ID,
        "port_count": 2,
        "ports": [_access("30"), {**_access("10", device_id="sw-02"), "port_name": "1:2"}],
        "site": _site().to_dict(),
    }
    report = _report(tmp_path, capsys, "--fdb", str(_write(tmp_path / "ports.json", map_ports)))
    mismatch = [f for f in report["findings"] if f["rule"] == "access_port_vlan_mismatch"]
    assert len(mismatch) == 1
    assert mismatch[0]["record_ids"] == ["port:sw-01-p1", f"site:{SITE_ID}"]
    assert mismatch[0]["evidence"]["observed_vlan_ids"] == ["30"]
    unobserved = [f for f in report["findings"] if f["rule"] == "vlan_unobserved"]
    assert unobserved[0]["evidence"]["covered_switches"] == ["sw-01", "sw-02"]


def test_integer_vlan_ids_are_accepted(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    payload = {"ports": [{**_access("10"), "vlan_ids": [30]}]}
    report = _report(tmp_path, capsys, "--fdb", str(_write(tmp_path / "ports.json", payload)))
    mismatch = [f for f in report["findings"] if f["rule"] == "access_port_vlan_mismatch"]
    assert [f["evidence"]["observed_vlan_ids"] for f in mismatch] == [["30"]]


def test_arp_records_envelope_is_accepted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    payload = {
        "arp_records": [
            {
                "ip": "10.1.10.5",
                "interface": "vlan20",
                "vlan_id": "20",
                "observed_at": "2026-11-01T12:00:00Z",
            }
        ]
    }
    report = _report(tmp_path, capsys, "--router-arp", str(_write(tmp_path / "arp.json", payload)))
    assert "subnet_vlan_mismatch" in _rules(report)


@pytest.mark.parametrize("key", ["arp", "records"])
def test_other_router_arp_envelopes(
    key: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    payload = {key: [{"ip": "10.1.10.5", "interface": "vlan20", "vlan_id": "20"}]}
    report = _report(tmp_path, capsys, "--router-arp", str(_write(tmp_path / "arp.json", payload)))
    assert "subnet_vlan_mismatch" in _rules(report)


def test_dhcp_expected_json_list(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    scopes = _write(tmp_path / "scopes.json", [{"cidr": "10.1.10.0/24"}])
    expected = _write(tmp_path / "expected.JSON", ["10.1.20.0/24"])
    report = _report(tmp_path, capsys, "--dhcp-scopes", str(scopes), "--dhcp-expected", str(expected))
    missing = [f for f in report["findings"] if f["rule"] == "subnet_without_dhcp_scope"]
    assert [f["record_ids"][1] for f in missing] == ["subnet:sub-20"]


def test_dhcp_expected_text_digits_are_not_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    scopes = _write(tmp_path / "scopes.json", [{"cidr": "10.1.10.0/24"}])
    expected = _write(tmp_path / "expected.txt", "42\n")
    report = _report(tmp_path, capsys, "--dhcp-scopes", str(scopes), "--dhcp-expected", str(expected))
    assert "subnet_without_dhcp_scope" in report["rules"]
    assert "subnet_without_dhcp_scope" not in _rules(report)


@pytest.mark.parametrize("bom", ["", "﻿"], ids=["plain", "bom"])
def test_dhcp_expected_text_with_bom(
    bom: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    scopes = _write(tmp_path / "scopes.json", [{"cidr": "10.1.20.0/24"}])
    for first_line in ("10.1.10.0/24", "# DHCP subnets\nsub-10"):
        expected = _write(tmp_path / "expected.txt", f"{bom}{first_line}\n")
        report = _report(
            tmp_path, capsys, "--dhcp-scopes", str(scopes), "--dhcp-expected", str(expected)
        )
        missing = [f for f in report["findings"] if f["rule"] == "subnet_without_dhcp_scope"]
        assert [f["record_ids"][1] for f in missing] == ["subnet:sub-10"]


def _all_inputs(tmp_path: Path) -> list[str]:
    fdb = _write(
        tmp_path / "fdb.json",
        [_observation("10", "30", port_classifications=[_access("30")])],
    )
    arp = _write(tmp_path / "arp.json", {"arp": [{"ip": "10.1.10.5", "interface": "vlan40", "vlan_id": "40"}]})
    scopes = _write(tmp_path / "scopes.json", [{"cidr": "10.1.99.0/24"}])
    expected = _write(tmp_path / "expected.txt", "sub-10\nsub-20\n")
    return [
        "--snapshot", str(_snapshot(tmp_path)),
        "--fdb", str(fdb),
        "--router-arp", str(arp),
        "--dhcp-scopes", str(scopes),
        "--dhcp-expected", str(expected),
    ]


def test_output_is_byte_identical_across_runs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    inputs = _all_inputs(tmp_path)
    outputs = []
    for run in ("one", "two"):
        out_json, out_md = tmp_path / run / "v.json", tmp_path / run / "v.md"
        code, _, err = _run(
            ["vlan-audit", *inputs, "--output-json", str(out_json), "--output-md", str(out_md)],
            capsys,
        )
        assert code == 0, err
        outputs.append((out_json.read_bytes(), out_md.read_bytes()))
    assert outputs[0] == outputs[1]
    report = json.loads(outputs[0][0])
    assert report["rules"] == list(VLAN_RULE_NAMES)
    assert set(_rules(report)) == set(VLAN_RULE_NAMES)
    assert report["total_findings"] == len(report["findings"])
    assert sum(report["severity_counts"].values()) == report["total_findings"]


def test_input_files_are_unchanged(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    inputs = _all_inputs(tmp_path)
    paths = [Path(value) for flag, value in zip(inputs[::2], inputs[1::2])]
    before = {path: path.read_bytes() for path in paths}
    code, _, err = _run(
        ["vlan-audit", *inputs, "--output-json", str(tmp_path / "out.json")], capsys
    )
    assert code == 0, err
    assert {path: path.read_bytes() for path in paths} == before


def test_stdout_json_without_output_flags(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = _run(["vlan-audit", "--snapshot", str(_snapshot(tmp_path))], capsys)
    assert code == 0, err
    report = json.loads(out)
    assert set(report) == REPORT_KEYS
    assert report["site_id"] == SITE_ID


def test_markdown_with_findings_escapes_pipes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snapshot = _write(tmp_path / "site.json", _site("site|001"))
    fdb = _write(tmp_path / "fdb.json", [_observation("30")])
    out_md = tmp_path / "v.md"
    code, _, err = _run(
        ["vlan-audit", "--snapshot", str(snapshot), "--fdb", str(fdb), "--output-md", str(out_md)],
        capsys,
    )
    assert code == 0, err
    text = out_md.read_text(encoding="utf-8")
    assert text.startswith("# VLAN Consistency Audit\n")
    assert "- Site: site\\|001" in text
    assert "| Rule | Severity | Record Type | Records | Message |" in text
    assert "documented in the SoT for site site\\|001" in text
    assert "No VLAN consistency findings." not in text
    assert "- subnet_vlan_mismatch: no router ARP data supplied" in text


def test_markdown_without_findings(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out_md = tmp_path / "v.md"
    code, _, err = _run(
        ["vlan-audit", "--snapshot", str(_snapshot(tmp_path)), "--output-md", str(out_md)], capsys
    )
    assert code == 0, err
    text = out_md.read_text(encoding="utf-8")
    assert "# VLAN Consistency Audit" in text
    assert f"- Site: {SITE_ID}" in text
    assert "No VLAN consistency findings." in text
    assert "| Rule |" not in text
    skipped = [line.split(":")[0][2:] for line in text.split("## Skipped Rules\n\n")[1].split("\n\n")[0].splitlines()]
    assert skipped == list(VLAN_RULE_NAMES)


def test_markdown_lists_no_skipped_rules(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out_md = tmp_path / "v.md"
    code, _, err = _run(
        ["vlan-audit", *_all_inputs(tmp_path), "--output-md", str(out_md)], capsys
    )
    assert code == 0, err
    assert "## Skipped Rules\n\nNone.\n" in out_md.read_text(encoding="utf-8")


ERROR_CASES = [
    pytest.param("--snapshot", "missing.json", None, id="snapshot-missing"),
    pytest.param("--snapshot", "site.json", "site-id", id="snapshot-unknown-site-id"),
    pytest.param("--fdb", "fdb.json", [{"entries": []}], id="fdb-missing-device-id"),
    pytest.param(
        "--fdb", "fdb.json", [{"device_id": "sw-01", "observed_at": "yesterday"}],
        id="fdb-bad-observed-at",
    ),
    pytest.param("--fdb", "fdb.json", [{"device_id": "sw-01", "entries": {}}], id="fdb-entries-not-list"),
    pytest.param("--fdb", "fdb.json", [{"device_id": "sw-01", "source": False}], id="fdb-source-not-string"),
    pytest.param("--fdb", "fdb.json", {"ports": "x"}, id="fdb-map-ports-not-list"),
    pytest.param("--fdb", "fdb.json", {"entries": []}, id="fdb-wrong-shape"),
    pytest.param(
        "--fdb", "fdb.json", {"ports": [{**_access("10"), "vlan_ids": "10"}]},
        id="fdb-map-ports-vlan-ids-string",
    ),
    pytest.param(
        "--fdb", "fdb.json",
        {"observations": [_observation(port_classifications=[{**_access("10"), "vlan_ids": "10"}])]},
        id="fdb-observations-vlan-ids-string",
    ),
    pytest.param(
        "--fdb", "fdb.json", {"ports": [{**_access("10"), "vlan_ids": ["10", None]}]},
        id="fdb-vlan-ids-null-item",
    ),
    pytest.param(
        "--fdb", "fdb.json", {"ports": [{**_access("10"), "vlan_ids": [True]}]},
        id="fdb-vlan-ids-bool-item",
    ),
    pytest.param(
        "--fdb", "fdb.json", {"ports": [{**_access("10"), "vlan_ids": [["10"]]}]},
        id="fdb-vlan-ids-nested-list",
    ),
    pytest.param(
        "--fdb", "fdb.json", [{**_observation(), "entries": [{**_entry("10"), "vlan_id": [10]}]}],
        id="fdb-entry-vlan-id-list",
    ),
    pytest.param("--fdb", "fdb.json", ["not-an-object"], id="fdb-non-object"),
    pytest.param("--router-arp", "arp.json", "{not json", id="router-arp-invalid-json"),
    pytest.param("--router-arp", "arp.json", [{"ip": "10.1.10.999"}], id="router-arp-bad-ip"),
    pytest.param("--router-arp", "arp.json", {"rows": []}, id="router-arp-wrong-shape"),
    pytest.param("--dhcp-scopes", "scopes.json", [{"cidr": "10.1.300.0/24"}], id="dhcp-scopes-bad-cidr"),
    pytest.param("--dhcp-scopes", "scopes.json", [{"source": "dhcp-01"}], id="dhcp-scopes-missing-cidr"),
    pytest.param("--dhcp-expected", "expected.json", {"subnets": ["sub-10"]}, id="dhcp-expected-non-list"),
    pytest.param("--dhcp-expected", "expected.json", ["sub-10", 20], id="dhcp-expected-non-string"),
    pytest.param("--dhcp-expected", "missing.txt", None, id="dhcp-expected-missing"),
]


@pytest.mark.parametrize(("flag", "name", "payload"), ERROR_CASES)
def test_input_errors_print_one_line_and_write_nothing(
    flag: str,
    name: str,
    payload: Any,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / name
    argv = ["vlan-audit"]
    if flag == "--snapshot":
        if payload == "site-id":
            argv += ["--snapshot", str(_snapshot(tmp_path)), "--site-id", "site-999"]
        else:
            argv += ["--snapshot", str(path)]
    else:
        argv += ["--snapshot", str(_snapshot(tmp_path)), flag, str(path)]
        if payload is not None:
            _write(path, payload)
    out_json, out_md = tmp_path / "out" / "v.json", tmp_path / "out" / "v.md"
    code, out, err = _run([*argv, "--output-json", str(out_json), "--output-md", str(out_md)], capsys)
    assert code == 2
    assert out == ""
    lines = err.strip().splitlines()
    assert len(lines) == 1, err
    assert lines[0].startswith(f"error: {flag} {path}:")
    assert "Traceback" not in err
    if payload == "site-id":
        assert "site 'site-999' not found" in lines[0]
    assert not out_json.exists()
    assert not out_md.exists()
