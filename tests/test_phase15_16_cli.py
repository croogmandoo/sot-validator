"""End-to-end CLI tests for Phases 15-16 (`oui lookup`, `audit verify` / `head`, `power blast-radius` / `risk`)."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
import re
import sqlite3

import pytest

import sot_validator
from sot_validator.cli import main
from sot_validator.curation import CurationStore, ItemEditPatch, verify_audit_chain
from sot_validator.curation.store import GENESIS_HASH
from sot_validator.models import Equipment, EquipmentCategory, NetworkDevice, Site
from sot_validator.signals.ups_health import UpsHealthRecord, UpsHealthStatus
from sot_validator.topology import (
    PowerDependencyGraph,
    PowerFeed,
    generate_power_json_report,
    generate_power_markdown_report,
    generate_power_risk_json_report,
    generate_power_risk_markdown_report,
    rank_power_risk,
)
from sot_validator.topology.identifier import KNOWN_OUI_VENDORS
from test_audit_chain import _build_legacy_db

REPO_ROOT = Path(__file__).resolve().parents[1]
OUI_FIXTURES = REPO_ROOT / "tests" / "fixtures" / "oui"
SITE_ID = "site-077"


def _error_lines(err: str) -> list[str]:
    return [line for line in err.splitlines() if line.startswith("error:")]


def _assert_input_error(code: int, err: str, flag: str) -> None:
    assert code == 2
    lines = err.strip().splitlines()
    errors = _error_lines(err)
    assert len(errors) == 1, err
    assert flag in errors[0]
    assert "Traceback" not in err
    assert all(line.startswith(("error:", "warning:")) for line in lines)


# ---------------------------------------------------------------------------
# oui lookup
# ---------------------------------------------------------------------------


def test_oui_lookup_builtin_rows_in_input_order(capsys: pytest.CaptureFixture[str]) -> None:
    vendor, role = KNOWN_OUI_VENDORS["00:04:96"]
    argv = ["oui", "lookup", "00:04:96:00:00:01", "nope", "02:00:00:00:00:01", "01:00:5e:00:00:01"]
    assert main(argv) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].split("\t") == ["mac", "class", "vendor", "registry", "prefix_bits", "prefix"]
    rows = [line.split("\t") for line in lines[1:]]
    assert len(rows) == 4
    assert rows[0] == ["00:04:96:00:00:01", "universal", vendor, "builtin", "24", "000496"]
    assert rows[1] == ["nope", "invalid", "-", "-", "-", "-"]
    assert rows[2][1] == "locally_administered"
    assert rows[3][1] == "multicast"


def test_oui_lookup_json_builtin_fields(capsys: pytest.CaptureFixture[str]) -> None:
    vendor, role = KNOWN_OUI_VENDORS["00:04:96"]
    assert main(["oui", "lookup", "00-04-96-AA-BB-CC", "nope", "00-04-96-AA-BB-CC", "--json"]) == 0
    results = json.loads(capsys.readouterr().out)["results"]
    assert [r["input"] for r in results] == ["00-04-96-AA-BB-CC", "nope", "00-04-96-AA-BB-CC"]
    assert results[0] == {
        "input": "00-04-96-AA-BB-CC",
        "mac": "00:04:96:aa:bb:cc",
        "class": "universal",
        "vendor": vendor,
        "prefix": "000496",
        "prefix_bits": 24,
        "registry": "builtin",
        "role_hint": role,
    }
    assert results[1] == {
        "input": "nope",
        "mac": None,
        "class": "invalid",
        "vendor": None,
        "prefix": None,
        "prefix_bits": None,
        "registry": None,
        "role_hint": None,
    }
    assert results[2] == results[0]


def test_oui_lookup_rejects_ipv4_lookalike(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["oui", "lookup", "100.200.100.200", "--json"]) == 0
    (result,) = json.loads(capsys.readouterr().out)["results"]
    assert (result["class"], result["mac"], result["vendor"]) == ("invalid", None, None)


def test_oui_lookup_text_escapes_control_characters(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["oui", "lookup", "bad\tmac\nrow"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 2
    assert lines[1].split("\t")[:2] == ["bad\\tmac\\nrow", "invalid"]


def test_oui_lookup_csv_dir_json_is_deterministic(capsys: pytest.CaptureFixture[str]) -> None:
    argv = ["oui", "lookup", "70:b3:d5:12:34:56", "70:b3:d5:1f:00:00", "--oui-dir", str(OUI_FIXTURES), "--json"]
    assert main(argv) == 0
    first = capsys.readouterr().out
    assert main(argv) == 0
    second = capsys.readouterr().out
    assert first == second
    assert str(OUI_FIXTURES) not in first
    results = json.loads(first)["results"]
    assert isinstance(results, list)
    assert results[0]["registry"] == "MA-S"
    assert results[0]["prefix_bits"] == 36
    assert results[0]["prefix"] == "70b3d5123"
    assert results[1]["registry"] == "MA-M"
    assert results[1]["prefix_bits"] == 28


def test_oui_dir_is_not_recursive(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "oui.csv").write_text((OUI_FIXTURES / "oui.csv").read_text(encoding="utf-8"), encoding="utf-8")
    code = main(["oui", "lookup", "00:04:96:00:00:01", "--oui-dir", str(tmp_path)])
    _assert_input_error(code, capsys.readouterr().err, "--oui-dir")


@pytest.mark.parametrize("case", ["missing", "empty", "bad_headers", "file"])
def test_oui_dir_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str], case: str) -> None:
    target = tmp_path / "oui"
    if case == "empty":
        target.mkdir()
    elif case == "bad_headers":
        target.mkdir()
        (target / "oui.csv").write_text("Prefix,Vendor\n000496,Extreme\n", encoding="utf-8")
    elif case == "file":
        target.write_text("not a dir", encoding="utf-8")
    code = main(["oui", "lookup", "00:04:96:00:00:01", "--oui-dir", str(target)])
    captured = capsys.readouterr()
    _assert_input_error(code, captured.err, "--oui-dir")
    assert captured.out == ""


# ---------------------------------------------------------------------------
# audit verify / head
# ---------------------------------------------------------------------------


def _curation_db(path: Path, n_patches: int = 4) -> Path:
    store = CurationStore(path)
    for i in range(n_patches):
        store.upsert_patch(
            ItemEditPatch(target_type="NetworkDevice", target_id=f"dev-{i}", notes=f"note {i}"),
            actor="alice",
            reason="audit test",
        )
    store.close()
    return path


def _raw_exec(path: Path, *statements: str) -> None:
    conn = sqlite3.connect(str(path))
    with conn:
        for statement in statements:
            conn.execute(statement)
    conn.close()


def _entry_ids(path: Path) -> list[str]:
    conn = sqlite3.connect(str(path))
    try:
        return [row[0] for row in conn.execute("SELECT entry_id FROM audit_log ORDER BY seq")]
    finally:
        conn.close()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_audit_verify_intact(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = _curation_db(tmp_path / "c.db")
    assert main(["audit", "verify", "--curation-db", str(db)]) == 0
    out = capsys.readouterr().out
    assert out == "ok: audit chain intact (4 entries)\n"


def test_audit_verify_tampered_changes_is_hash_mismatch(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = _curation_db(tmp_path / "c.db")
    ids = _entry_ids(db)
    _raw_exec(db, """UPDATE audit_log SET changes_json = '{"notes": "forged"}' WHERE seq = 3""")
    assert main(["audit", "verify", "--curation-db", str(db)]) == 1
    assert capsys.readouterr().out == f"broken: entry 2 ({ids[2]}) hash_mismatch\n"


def test_audit_verify_deleted_row_is_gap(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = _curation_db(tmp_path / "c.db")
    ids = _entry_ids(db)
    _raw_exec(db, "DELETE FROM audit_log WHERE seq = 2")
    assert main(["audit", "verify", "--curation-db", str(db)]) == 1
    assert capsys.readouterr().out == f"broken: entry 1 ({ids[2]}) gap\n"


def test_audit_verify_swapped_rows_is_broken(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = _curation_db(tmp_path / "c.db")
    ids = _entry_ids(db)
    _raw_exec(
        db,
        "UPDATE audit_log SET seq = -1 WHERE seq = 2",
        "UPDATE audit_log SET seq = 2 WHERE seq = 3",
        "UPDATE audit_log SET seq = 3 WHERE seq = -1",
    )
    assert main(["audit", "verify", "--curation-db", str(db)]) == 1
    assert capsys.readouterr().out == f"broken: entry 1 ({ids[2]}) prev_link_broken\n"


def test_audit_head_and_anchor_round_trip(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = _curation_db(tmp_path / "c.db")
    assert main(["audit", "head", "--curation-db", str(db)]) == 0
    out = capsys.readouterr().out
    assert out.count("\n") == 1
    anchor = out.strip()
    assert re.fullmatch(r"\d+:[0-9a-f]{64}", anchor)
    assert int(anchor.split(":")[0]) == len(_entry_ids(db))

    assert main(["audit", "verify", "--curation-db", str(db), "--anchor", anchor]) == 0
    assert capsys.readouterr().out.startswith("ok:")

    count, head_hash = anchor.split(":")
    other = ("0" if head_hash[0] != "0" else "1") + head_hash[1:]
    assert main(["audit", "verify", "--curation-db", str(db), "--anchor", f"{count}:{other}"]) == 1
    out = capsys.readouterr().out
    assert "anchor_mismatch" in out
    assert f"entry {int(count) - 1} " in out


def test_audit_anchor_beyond_log_has_no_entry_id(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = _curation_db(tmp_path / "c.db", n_patches=2)
    assert main(["audit", "verify", "--curation-db", str(db), "--anchor", "9:" + "a" * 64]) == 1
    assert capsys.readouterr().out == "broken: entry 8 anchor_mismatch\n"


def test_audit_head_empty_log_prints_genesis(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = _curation_db(tmp_path / "c.db", n_patches=0)
    assert main(["audit", "head", "--curation-db", str(db)]) == 0
    assert capsys.readouterr().out == f"0:{GENESIS_HASH}\n"
    assert main(["audit", "verify", "--curation-db", str(db), "--anchor", f"0:{GENESIS_HASH}"]) == 0


def test_audit_head_without_entry_hash_is_broken(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = _curation_db(tmp_path / "c.db")
    _raw_exec(db, "UPDATE audit_log SET entry_hash = NULL WHERE seq = 4")
    assert main(["audit", "head", "--curation-db", str(db)]) == 1
    assert capsys.readouterr().out.startswith("broken: ")


@pytest.mark.parametrize(
    "anchor",
    ["garbage", "3:" + "A" * 64, "-1:" + "a" * 64, "3:" + "a" * 63, "0:" + "a" * 64, " 3:" + "a" * 64, "٣:" + "a" * 64],
)
def test_audit_bad_anchor_is_input_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], anchor: str
) -> None:
    db = _curation_db(tmp_path / "c.db")
    code = main(["audit", "verify", "--curation-db", str(db), "--anchor", anchor])
    captured = capsys.readouterr()
    _assert_input_error(code, captured.err, "--anchor")
    assert captured.out == ""


def test_audit_commands_leave_db_untouched(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = _curation_db(tmp_path / "c.db")
    before_hash = _sha256(db)
    before_listing = sorted(p.name for p in tmp_path.iterdir())
    assert main(["audit", "verify", "--curation-db", str(db)]) == 0
    assert main(["audit", "head", "--curation-db", str(db)]) == 0
    capsys.readouterr()
    assert _sha256(db) == before_hash
    assert sorted(p.name for p in tmp_path.iterdir()) == before_listing


def test_open_read_only_store_rejects_writes(tmp_path: Path) -> None:
    db = _curation_db(tmp_path / "c.db")
    before = _sha256(db)
    store = CurationStore.open_read_only(db)
    try:
        assert store.db_path == db
        assert verify_audit_chain(store).ok
        assert store.export_chain_head()[0] == 4
        with pytest.raises(sqlite3.DatabaseError):
            store.upsert_patch(ItemEditPatch(target_type="NetworkDevice", target_id="dev-x", notes="n"))
    finally:
        store.close()
    assert _sha256(db) == before


def test_open_read_only_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        CurationStore.open_read_only(tmp_path / "missing.db")
    assert not (tmp_path / "missing.db").exists()
    with pytest.raises(ValueError):
        CurationStore.open_read_only(tmp_path)


def test_open_read_only_does_not_migrate_legacy(tmp_path: Path) -> None:
    db = tmp_path / "legacy.db"
    _build_legacy_db(db, 3)
    before = _sha256(db)
    store = CurationStore.open_read_only(db)
    store.close()
    assert _sha256(db) == before


@pytest.mark.parametrize("command", ["verify", "head"])
def test_audit_legacy_db_is_not_migrated(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], command: str
) -> None:
    db = tmp_path / "legacy.db"
    _build_legacy_db(db, 3)
    before = _sha256(db)
    listing = sorted(p.name for p in tmp_path.iterdir())
    assert main(["audit", command, "--curation-db", str(db)]) == 1
    out = capsys.readouterr().out
    assert "migrat" in out
    assert out.count("\n") == 1
    assert _sha256(db) == before
    assert sorted(p.name for p in tmp_path.iterdir()) == listing
    conn = sqlite3.connect(str(db))
    try:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(audit_log)")}
    finally:
        conn.close()
    assert "prev_hash" not in columns


@pytest.mark.parametrize("command", ["verify", "head"])
@pytest.mark.parametrize("case", ["missing", "directory", "text", "json", "no_audit_table"])
def test_audit_db_input_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], command: str, case: str
) -> None:
    target = tmp_path / "c.db"
    if case == "directory":
        target.mkdir()
    elif case == "text":
        target.write_text("this is not sqlite\n" * 10, encoding="utf-8")
    elif case == "json":
        target = tmp_path / "curation.json"
        target.write_text(json.dumps({"patches": [], "audit_log": []}), encoding="utf-8")
    elif case == "no_audit_table":
        _raw_exec(target, "CREATE TABLE other (x INTEGER)")
    before = _sha256(target) if target.is_file() else None
    code = main(["audit", command, "--curation-db", str(target)])
    captured = capsys.readouterr()
    _assert_input_error(code, captured.err, "--curation-db")
    assert captured.out == ""
    if case == "missing":
        assert not target.exists()
    if before is not None:
        assert _sha256(target) == before
    if case == "no_audit_table":
        assert "not a curation database" in captured.err


# ---------------------------------------------------------------------------
# power blast-radius / risk
# ---------------------------------------------------------------------------


def _power_site() -> Site:
    def device(device_id: str, role: str) -> NetworkDevice:
        return NetworkDevice(device_id=device_id, site_id=SITE_ID, hostname=f"{device_id}.example.internal", role=role)

    def equipment(equipment_id: str, category: EquipmentCategory) -> Equipment:
        return Equipment(equipment_id=equipment_id, site_id=SITE_ID, name=equipment_id, category=category)

    return Site(
        site_id=SITE_ID,
        name="Site 077",
        devices=[device("rtr-01", "router"), device("core-01", "core-switch"), device("acc-01", "access-switch")],
        equipment=[
            equipment("UPS-A", EquipmentCategory.UPS),
            equipment("UPS-B", EquipmentCategory.UPS),
            equipment("UPS-C", EquipmentCategory.UPS),
        ],
    )


_FEEDS = [
    {"device_id": "rtr-01", "psu": "psu1", "source_id": "UPS-A", "source_type": "ups", "outlet": "1"},
    {"device_id": "rtr-01", "psu": "psu2", "source_id": "UPS-A", "source_type": "ups", "outlet": "2"},
    {"device_id": "core-01", "psu": "psu1", "source_id": "UPS-A", "source_type": "ups", "outlet": None},
    {"device_id": "core-01", "psu": "psu2", "source_id": "PDU-1", "source_type": "pdu", "outlet": None},
    {"device_id": "PDU-1", "psu": None, "source_id": "UPS-B", "source_type": "ups", "outlet": None},
    {"device_id": "acc-01", "psu": None, "source_id": "UPS-B", "source_type": "ups", "outlet": None},
]


def _graph() -> PowerDependencyGraph:
    return PowerDependencyGraph(PowerFeed(**feed) for feed in _FEEDS)


@pytest.fixture
def power_files(tmp_path: Path) -> dict[str, Path]:
    snapshot = tmp_path / "site.json"
    snapshot.write_text(json.dumps(_power_site().to_dict()), encoding="utf-8")
    power_map = tmp_path / "map.json"
    power_map.write_text(json.dumps({"feeds": _FEEDS}), encoding="utf-8")
    csv_map = tmp_path / "map.csv"
    with csv_map.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["device_id", "psu", "source_id", "source_type", "outlet"])
        writer.writeheader()
        for feed in _FEEDS:
            writer.writerow({key: value or "" for key, value in feed.items()})
    return {"snapshot": snapshot, "map": power_map, "csv": csv_map, "dir": tmp_path}


def test_power_blast_radius_all_ups(power_files: dict[str, Path], capsys: pytest.CaptureFixture[str]) -> None:
    out_json = power_files["dir"] / "o.json"
    out_md = power_files["dir"] / "o.md"
    argv = ["power", "blast-radius", "--snapshot", str(power_files["snapshot"]), "--power-map", str(power_files["map"]),
            "--output-json", str(out_json), "--output-md", str(out_md)]
    assert main(argv) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    site, graph = _power_site(), _graph()
    assert out_json.read_text(encoding="utf-8") == generate_power_json_report(site, graph)
    assert out_md.read_text(encoding="utf-8") == generate_power_markdown_report(site, graph)


def test_power_blast_radius_single_ups(power_files: dict[str, Path], capsys: pytest.CaptureFixture[str]) -> None:
    argv = ["power", "blast-radius", "--snapshot", str(power_files["snapshot"]), "--power-map", str(power_files["map"]),
            "--ups", "UPS-A"]
    assert main(argv) == 0
    report = json.loads(capsys.readouterr().out)
    assert [entry["source_id"] for entry in report["ups_blast_radius"]] == ["UPS-A"]
    full = json.loads(generate_power_json_report(_power_site(), _graph()))
    assert report["single_fed_critical"] == full["single_fed_critical"]
    assert report["false_redundancy"] == full["false_redundancy"]


def test_power_csv_map_matches_json_map(power_files: dict[str, Path], capsys: pytest.CaptureFixture[str]) -> None:
    base = ["power", "blast-radius", "--snapshot", str(power_files["snapshot"])]
    assert main(base + ["--power-map", str(power_files["map"])]) == 0
    from_json = capsys.readouterr().out
    assert main(base + ["--power-map", str(power_files["csv"])]) == 0
    assert capsys.readouterr().out == from_json


def test_power_risk_without_health_is_unknown(power_files: dict[str, Path], capsys: pytest.CaptureFixture[str]) -> None:
    out_md = power_files["dir"] / "risk.md"
    argv = ["power", "risk", "--snapshot", str(power_files["snapshot"]), "--power-map", str(power_files["map"]),
            "--output-json", str(power_files["dir"] / "risk.json"), "--output-md", str(out_md)]
    assert main(argv) == 0
    report = json.loads((power_files["dir"] / "risk.json").read_text(encoding="utf-8"))
    assert set(report) == {"site_id", "risk", "false_redundancy", "single_fed_critical"}
    assert report["risk"] and all(entry["health_unknown"] is True for entry in report["risk"])
    markdown = out_md.read_text(encoding="utf-8")
    assert markdown.startswith(f"# Power Risk Report: {SITE_ID}")
    assert "| Rank | UPS | Health | Severity | Score | Single-fed critical devices |" in markdown


def test_power_risk_with_health_matches_ranking(
    power_files: dict[str, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    records = [
        UpsHealthRecord(equipment_id="UPS-A", site_id=SITE_ID, name="UPS-A", status=UpsHealthStatus.CRITICAL,
                        needs_battery_replacement=True),
        UpsHealthRecord(equipment_id="UPS-B", site_id=SITE_ID, name="UPS-B", status=UpsHealthStatus.HEALTHY),
    ]
    health = power_files["dir"] / "ups.json"
    health.write_text(json.dumps({"records": [r.to_dict() for r in records], "total_units": 2}), encoding="utf-8")
    argv = ["power", "risk", "--snapshot", str(power_files["snapshot"]), "--power-map", str(power_files["map"]),
            "--ups-health", str(health), "--output-md", str(power_files["dir"] / "r.md")]
    assert main(argv) == 0
    capsys.readouterr()
    expected = rank_power_risk(_power_site(), records, _graph())
    assert expected[0].ups_id == "UPS-A" and expected[0].score > 0
    markdown = (power_files["dir"] / "r.md").read_text(encoding="utf-8")
    assert markdown == generate_power_risk_markdown_report(_power_site(), _graph(), records)
    argv[-2:] = ["--output-json", str(power_files["dir"] / "r.json")]
    assert main(argv) == 0
    report = json.loads((power_files["dir"] / "r.json").read_text(encoding="utf-8"))
    assert [(e["ups_id"], e["score"]) for e in report["risk"]] == [(e.ups_id, e.score) for e in expected]
    assert report["risk"][0]["health_unknown"] is False

    # A bare list is accepted too.
    health.write_text(json.dumps([r.to_dict() for r in records]), encoding="utf-8")
    assert main(argv) == 0
    assert json.loads((power_files["dir"] / "r.json").read_text(encoding="utf-8")) == report


def test_power_map_problems_are_warnings(power_files: dict[str, Path], capsys: pytest.CaptureFixture[str]) -> None:
    feeds = _FEEDS + [{"device_id": "ghost-99", "source_id": "UPS-C", "source_type": "ups"}]
    power_files["map"].write_text(json.dumps(feeds), encoding="utf-8")
    for command in ("blast-radius", "risk"):
        argv = ["power", command, "--snapshot", str(power_files["snapshot"]), "--power-map", str(power_files["map"])]
        assert main(argv) == 0
        captured = capsys.readouterr()
        warnings = captured.err.splitlines()
        assert len(warnings) == 1
        assert warnings[0].startswith(f"warning: power map row {len(feeds)}: ")
        assert "ghost-99" in warnings[0]
        json.loads(captured.out)


@pytest.mark.parametrize(
    "case",
    ["unknown_ups", "missing_snapshot", "bad_snapshot", "txt_map", "bad_source_type", "cycle", "missing_map", "bad_map_shape"],
)
def test_power_blast_radius_input_errors(
    power_files: dict[str, Path], capsys: pytest.CaptureFixture[str], case: str
) -> None:
    snapshot, power_map = power_files["snapshot"], power_files["map"]
    extra: list[str] = []
    flag = "--power-map"
    if case == "unknown_ups":
        extra, flag = ["--ups", "UPS-C"], "--ups"
    elif case == "missing_snapshot":
        snapshot, flag = power_files["dir"] / "nope.json", "--snapshot"
    elif case == "bad_snapshot":
        snapshot.write_text("{not json", encoding="utf-8")
        flag = "--snapshot"
    elif case == "txt_map":
        power_map = power_files["dir"] / "map.txt"
        power_map.write_text("x", encoding="utf-8")
    elif case == "bad_source_type":
        power_map.write_text(json.dumps([{"device_id": "rtr-01", "source_id": "UPS-A", "source_type": "generator"}]), encoding="utf-8")
    elif case == "cycle":
        power_map.write_text(json.dumps([
            {"device_id": "rtr-01", "source_id": "PDU-1", "source_type": "pdu"},
            {"device_id": "PDU-1", "source_id": "PDU-2", "source_type": "pdu"},
            {"device_id": "PDU-2", "source_id": "PDU-1", "source_type": "pdu"},
        ]), encoding="utf-8")
    elif case == "missing_map":
        power_map = power_files["dir"] / "absent.json"
    elif case == "bad_map_shape":
        power_map.write_text(json.dumps({"rows": []}), encoding="utf-8")
    argv = ["power", "blast-radius", "--snapshot", str(snapshot), "--power-map", str(power_map), *extra]
    code = main(argv)
    captured = capsys.readouterr()
    _assert_input_error(code, captured.err, flag)
    assert captured.out == ""
    if case == "unknown_ups":
        assert "UPS-A, UPS-B" in captured.err
    if case == "cycle":
        assert "cycle" in captured.err


def test_power_unknown_ups_with_no_ups_sources(power_files: dict[str, Path], capsys: pytest.CaptureFixture[str]) -> None:
    power_files["map"].write_text(
        json.dumps([{"device_id": "acc-01", "source_id": "MAINS", "source_type": "utility"}]), encoding="utf-8"
    )
    argv = ["power", "blast-radius", "--snapshot", str(power_files["snapshot"]), "--power-map", str(power_files["map"]),
            "--ups", "UPS-A"]
    code = main(argv)
    captured = capsys.readouterr()
    _assert_input_error(code, captured.err, "--ups")
    assert "no UPS sources" in captured.err


@pytest.mark.parametrize("content", ["{broken", json.dumps({"records": [{"equipment_id": "UPS-A"}]}), json.dumps({"records": "x"}), None])
def test_power_risk_bad_ups_health(
    power_files: dict[str, Path], capsys: pytest.CaptureFixture[str], content: str | None
) -> None:
    health = power_files["dir"] / "ups.json"
    if content is not None:
        health.write_text(content, encoding="utf-8")
    argv = ["power", "risk", "--snapshot", str(power_files["snapshot"]), "--power-map", str(power_files["map"]),
            "--ups-health", str(health)]
    code = main(argv)
    captured = capsys.readouterr()
    _assert_input_error(code, captured.err, "--ups-health")
    assert captured.out == ""


def test_power_commands_do_not_modify_inputs(power_files: dict[str, Path], capsys: pytest.CaptureFixture[str]) -> None:
    inputs = [power_files["snapshot"], power_files["map"]]
    before = [_sha256(path) for path in inputs]
    for command in ("blast-radius", "risk"):
        assert main(["power", command, "--snapshot", str(inputs[0]), "--power-map", str(inputs[1])]) == 0
    capsys.readouterr()
    assert [_sha256(path) for path in inputs] == before


# ---------------------------------------------------------------------------
# power report helpers
# ---------------------------------------------------------------------------


def test_power_report_ups_ids_none_matches_default() -> None:
    site, graph = _power_site(), _graph()
    assert generate_power_json_report(site, graph, ups_ids=None) == generate_power_json_report(site, graph)
    assert generate_power_markdown_report(site, graph, ups_ids=None) == generate_power_markdown_report(site, graph)


def test_power_report_ups_ids_filters_blast_radius_only() -> None:
    site, graph = _power_site(), _graph()
    full = json.loads(generate_power_json_report(site, graph))
    filtered = json.loads(generate_power_json_report(site, graph, ups_ids=["UPS-B"]))
    assert [entry["source_id"] for entry in filtered["ups_blast_radius"]] == ["UPS-B"]
    assert filtered["single_fed_critical"] == full["single_fed_critical"]
    assert filtered["false_redundancy"] == full["false_redundancy"]
    markdown = generate_power_markdown_report(site, graph, ups_ids=["UPS-B"])
    assert "### UPS UPS-B" in markdown and "### UPS UPS-A" not in markdown
    assert "## Site Summary" in markdown
    empty = generate_power_markdown_report(site, graph, ups_ids=[])
    assert "## UPS Blast Radius\n\nNone\n" in empty


def test_power_risk_report_helpers() -> None:
    site, graph = _power_site(), _graph()
    report = json.loads(generate_power_risk_json_report(site, graph, []))
    assert report["site_id"] == SITE_ID
    assert report["risk"] == [entry.to_dict() for entry in rank_power_risk(site, [], graph)]
    assert report["false_redundancy"] == ["rtr-01"]
    assert generate_power_risk_json_report(site, graph, []) == generate_power_risk_json_report(site, graph, [])

    markdown = generate_power_risk_markdown_report(site, graph, [])
    lines = markdown.splitlines()
    assert lines[0] == f"# Power Risk Report: {SITE_ID}"
    rows = [line for line in lines if line.startswith("| ") and not line.startswith("| Rank")]
    assert [row.split(" | ")[1] for row in rows] == [e.ups_id for e in rank_power_risk(site, [], graph)]
    assert "## False redundancy\n\n- rtr-01\n" in markdown
    # UPS-C feeds nothing, so its single-fed list renders as None.
    assert any(row.startswith("| 3 | UPS-C | UNKNOWN |") and row.endswith("| None |") for row in rows)


def test_power_risk_markdown_escapes_cells() -> None:
    site = _power_site()
    site.site_id = "site|77"
    markdown = generate_power_risk_markdown_report(site, _graph(), [])
    assert markdown.splitlines()[0] == "# Power Risk Report: site\\|77"


# ---------------------------------------------------------------------------
# Package exports
# ---------------------------------------------------------------------------


def test_package_exports_phases_15_16() -> None:
    expected = (
        "OuiMatch", "OuiRegistry", "classify_mac", "is_locally_administered", "is_multicast",
        "AuditChainReport", "verify_audit_chain",
        "BlastRadius", "PowerCycleError", "PowerDependencyGraph", "PowerFeed", "PowerMapLoadResult",
        "PowerMapLoader", "PowerMapProblem", "PowerRiskEntry", "device_criticality",
        "find_false_redundancy", "find_single_fed_critical", "generate_power_json_report",
        "generate_power_markdown_report", "generate_power_risk_json_report",
        "generate_power_risk_markdown_report", "rank_power_risk",
    )
    for name in expected:
        assert hasattr(sot_validator, name)
        assert name in sot_validator.__all__
    assert sot_validator.__all__ == sorted(sot_validator.__all__)
    assert len(sot_validator.__all__) == len(set(sot_validator.__all__))

    from sot_validator.enrichment import OuiRegistry

    assert sot_validator.OuiRegistry is OuiRegistry
    assert sot_validator.verify_audit_chain is verify_audit_chain
