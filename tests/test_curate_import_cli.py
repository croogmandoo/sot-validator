"""CLI tests for `sot-validator curate-import`."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3

import pytest

from sot_validator.cli import main
from sot_validator.curation import CurationStore, ItemEditPatch, verify_audit_chain
from sot_validator.models import NetworkDevice, Port, Site

HEADER = "record_type,record_id,field,new_value,reason\n"
TWO_CHANGES = (
    "NetworkDevice,dev-1,hostname,sw-01-new,rename",
    "Port,p-1,vlan_id,20,move",
)

LEGACY_AUDIT_DDL = """
CREATE TABLE audit_log (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    changes_json TEXT NOT NULL,
    reason TEXT NOT NULL,
    site_id TEXT
);
"""

FLEET_TOML = """
[[sites]]
site_id = "site-1"
name = "Lab"
block = "10.1.0.0/16"
active_subnets = ["10.1.1.0/24"]
"""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _site() -> Site:
    return Site(
        site_id="site-1",
        name="Lab",
        devices=[
            NetworkDevice(
                device_id="dev-1",
                site_id="site-1",
                hostname="sw-01",
                management_ip="10.1.1.2",
                ports=[Port(port_id="p-1", device_id="dev-1", name="1:1", vlan_id="10")],
            )
        ],
    )


@pytest.fixture()
def env(tmp_path: Path) -> dict[str, Path]:
    db = tmp_path / "curation.db"
    with CurationStore(db) as store:
        store.upsert_patch(
            ItemEditPatch(target_type="NetworkDevice", target_id="dev-1", notes="seed"),
            actor="seed",
        )
    snapshot = tmp_path / "site.json"
    snapshot.write_text(json.dumps(_site().to_dict()), encoding="utf-8")
    csv_path = _write_csv(tmp_path / "edits.csv", *TWO_CHANGES)
    return {"tmp": tmp_path, "db": db, "snapshot": snapshot, "csv": csv_path}


def _write_csv(path: Path, *rows: str) -> Path:
    path.write_text(HEADER + "".join(f"{row}\n" for row in rows), encoding="utf-8")
    return path


def _run(capsys, *args: str) -> tuple[int, str, str]:
    rc = main(list(args))
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


def _base(env: dict[str, Path], csv_path: Path | None = None) -> list[str]:
    return [
        "curate-import",
        "--curation-db", str(env["db"]),
        "--snapshot", str(env["snapshot"]),
        "--csv", str(csv_path or env["csv"]),
    ]


def _token(out: str) -> str:
    lines = [line for line in out.splitlines() if line.startswith("confirm_token: ")]
    assert len(lines) == 1
    return lines[0].split(": ", 1)[1]


def _assert_single_error_line(err: str) -> None:
    lines = err.strip().splitlines()
    assert len(lines) == 1
    assert lines[0].startswith("error: ")
    assert "Traceback" not in err


def _files(tmp_path: Path) -> set[Path]:
    return set(tmp_path.rglob("*"))


def test_preview_then_apply_round_trip(env, capsys):
    rc, out, err = _run(capsys, *_base(env), "--preview")
    assert rc == 0, err
    assert "change: 2 no_op: 0 conflict: 0 invalid: 0" in out
    assert "can_apply: true" in out
    assert 'row 2: change NetworkDevice "dev-1" "hostname": "sw-01" -> "sw-01-new"' in out
    token = _token(out)

    with CurationStore(env["db"]) as store:
        before = len(store.list_audit_log(limit=1000))

    rc, out, err = _run(capsys, *_base(env), "--apply", "--confirm-token", token)
    assert rc == 0, err
    assert out.startswith("applied 2 rows: batch_id batch-")
    batch_id = out.strip().rsplit(" ", 1)[1]

    with CurationStore(env["db"]) as store:
        entries = store.list_audit_log(limit=1000)
        assert len(entries) == before + 2
        batched = [e for e in entries if e.changes.get("batch_id") == batch_id]
        assert len(batched) == 2
        assert verify_audit_chain(store).ok
    assert main(["audit", "verify", "--curation-db", str(env["db"])]) == 0


def test_apply_json_output(env, capsys):
    rc, out, _ = _run(capsys, *_base(env), "--preview", "--json")
    token = json.loads(out)["confirm_token"]
    rc, out, err = _run(capsys, *_base(env), "--apply", "--confirm-token", token, "--json")
    assert rc == 0, err
    payload = json.loads(out)
    assert payload["applied"] == 2
    assert payload["batch_id"].startswith("batch-")


def test_all_no_op_apply_applies_zero_rows(env, capsys):
    csv_path = _write_csv(env["tmp"] / "noop.csv", "NetworkDevice,dev-1,hostname,sw-01,")
    rc, out, _ = _run(capsys, *_base(env, csv_path), "--preview")
    assert rc == 0
    assert "can_apply: false" in out
    rc, out, err = _run(capsys, *_base(env, csv_path), "--apply", "--confirm-token", _token(out))
    assert rc == 0, err
    assert out.startswith("applied 0 rows: batch_id batch-")


@pytest.mark.parametrize("as_json", [False, True])
def test_preview_writes_nothing(env, capsys, as_json):
    before = _sha256(env["db"])
    files = _files(env["tmp"])
    rc, _, err = _run(capsys, *_base(env), "--preview", *(["--json"] if as_json else []))
    assert rc == 0, err
    assert _sha256(env["db"]) == before
    assert _files(env["tmp"]) == files


def test_preview_on_legacy_unchained_db_writes_nothing(env, capsys):
    legacy = env["tmp"] / "legacy.db"
    CurationStore(legacy).close()
    conn = sqlite3.connect(str(legacy))
    conn.execute("DROP TABLE audit_log")
    conn.executescript(LEGACY_AUDIT_DDL)
    conn.commit()
    conn.close()
    before = _sha256(legacy)
    args = _base(env)
    args[2] = str(legacy)
    rc, out, err = _run(capsys, *args, "--preview")
    assert rc == 0, err
    assert "can_apply: true" in out
    assert _sha256(legacy) == before


def test_preview_json_keys_and_invalid_row(env, capsys):
    csv_path = _write_csv(env["tmp"] / "bad.csv", "NetworkDevice,dev-404,hostname,x,")
    rc, out, err = _run(capsys, *_base(env, csv_path), "--preview", "--json")
    assert rc == 0, err
    payload = json.loads(out)
    assert set(payload) == {"site_id", "as_of", "rows", "confirm_token", "counts", "can_apply"}
    assert payload["counts"]["invalid"] == 1
    assert payload["can_apply"] is False

    rc, out, _ = _run(capsys, *_base(env, csv_path), "--preview")
    assert rc == 0
    assert "invalid" in out
    assert "can_apply: false" in out


def test_wrong_token_refused(env, capsys):
    before = _sha256(env["db"])
    rc, _, err = _run(capsys, *_base(env), "--apply", "--confirm-token", "0" * 64)
    assert rc == 2
    _assert_single_error_line(err)
    assert _sha256(env["db"]) == before


def test_stale_store_refused(env, capsys):
    rc, out, _ = _run(capsys, *_base(env), "--preview")
    token = _token(out)
    with CurationStore(env["db"]) as store:
        store.upsert_patch(
            ItemEditPatch(target_type="NetworkDevice", target_id="dev-1", hostname="sw-01-other"),
            actor="someone",
        )
    after_edit = _sha256(env["db"])
    rc, _, err = _run(capsys, *_base(env), "--apply", "--confirm-token", token)
    assert rc == 2
    _assert_single_error_line(err)
    assert _sha256(env["db"]) == after_edit


@pytest.mark.parametrize(
    "rows",
    [
        ("NetworkDevice,dev-1,hostname,a,", "NetworkDevice,dev-1,hostname,b,"),
        ("NetworkDevice,dev-404,hostname,a,",),
    ],
    ids=["conflict", "invalid"],
)
def test_conflict_or_invalid_rows_refused_with_own_token(env, capsys, rows):
    csv_path = _write_csv(env["tmp"] / "rows.csv", *rows)
    rc, out, _ = _run(capsys, *_base(env, csv_path), "--preview")
    assert rc == 0
    before = _sha256(env["db"])
    rc, _, err = _run(capsys, *_base(env, csv_path), "--apply", "--confirm-token", _token(out))
    assert rc == 2
    _assert_single_error_line(err)
    assert _sha256(env["db"]) == before


@pytest.mark.parametrize(
    "extra",
    [
        [],
        ["--preview", "--apply"],
        ["--apply"],
        ["--preview", "--confirm-token", "x"],
        ["--preview", "--csv-missing"],
        ["--preview", "--snapshot-missing"],
        ["--preview", "--as-of", "not-a-date"],
        ["--preview", "--json-db"],
        ["--preview", "--snapshot-bad"],
    ],
    ids=[
        "no-mode", "both-modes", "apply-no-token", "preview-with-token",
        "missing-csv", "missing-snapshot", "bad-as-of", "json-db", "bad-snapshot",
    ],
)
def test_refusals(env, capsys, extra):
    args = _base(env)
    if "--csv-missing" in extra:
        extra.remove("--csv-missing")
        args[6] = str(env["tmp"] / "nope.csv")
    if "--snapshot-missing" in extra:
        extra.remove("--snapshot-missing")
        args[4] = str(env["tmp"] / "nope.json")
    if "--snapshot-bad" in extra:
        extra.remove("--snapshot-bad")
        bad = env["tmp"] / "bad-site.json"
        bad.write_text("{not json", encoding="utf-8")
        args[4] = str(bad)
    if "--json-db" in extra:
        extra.remove("--json-db")
        args[2] = str(env["tmp"] / "curation.json")
    before = _sha256(env["db"])
    files = _files(env["tmp"])
    rc, out, err = _run(capsys, *args, *extra)
    assert rc == 2
    assert out == ""
    _assert_single_error_line(err)
    assert _sha256(env["db"]) == before
    assert _files(env["tmp"]) == files


@pytest.mark.parametrize("mode", [["--preview"], ["--apply", "--confirm-token", "0" * 64]])
def test_missing_db_is_never_created(env, capsys, mode):
    missing = env["tmp"] / "sub" / "missing.db"
    args = _base(env)
    args[2] = str(missing)
    rc, _, err = _run(capsys, *args, *mode)
    assert rc == 2
    _assert_single_error_line(err)
    assert not missing.exists()
    assert not missing.parent.exists()


@pytest.mark.parametrize("mode", [["--preview"], ["--apply", "--confirm-token", "0" * 64]])
def test_non_curation_sqlite_refused(env, capsys, mode):
    other = env["tmp"] / "other.db"
    conn = sqlite3.connect(str(other))
    conn.execute("CREATE TABLE unrelated (x INTEGER)")
    conn.commit()
    conn.close()
    before = _sha256(other)
    args = _base(env)
    args[2] = str(other)
    rc, _, err = _run(capsys, *args, *mode)
    assert rc == 2
    _assert_single_error_line(err)
    assert "not a curation database" in err
    assert _sha256(other) == before


def test_non_sqlite_db_refused(env, capsys):
    text = env["tmp"] / "notes.db"
    text.write_text("this is not sqlite\n" * 20, encoding="utf-8")
    before = _sha256(text)
    args = _base(env)
    args[2] = str(text)
    rc, _, err = _run(capsys, *args, "--apply", "--confirm-token", "0" * 64)
    assert rc == 2
    _assert_single_error_line(err)
    assert _sha256(text) == before


def test_csv_errors_list_every_row(env, capsys):
    bad_header = env["tmp"] / "header.csv"
    bad_header.write_text("record_type,record_id,field,value,reason\nx,y,z,w,\n", encoding="utf-8")
    rc, _, err = _run(capsys, *_base(env, bad_header), "--preview")
    assert rc == 2
    lines = err.strip().splitlines()
    assert lines[0].startswith("error: --csv ")
    assert lines[0].endswith("invalid patch CSV")
    assert lines[1:] == [
        "row 1: unknown header column 'value'",
        "row 1: missing header column 'new_value'",
    ]

    bad_value = _write_csv(
        env["tmp"] / "value.csv",
        "NetworkDevice,dev-1,deleted,maybe,",
        "Port,p-1,hostname,x,",
    )
    rc, _, err = _run(capsys, *_base(env, bad_value), "--preview")
    assert rc == 2
    lines = err.strip().splitlines()
    assert lines[0].startswith("error: --csv ")
    assert len(lines) == 3
    assert lines[1].startswith("row 2: deleted must be one of")
    assert lines[2].startswith("row 3: field 'hostname' is not allowed for Port")


def test_csv_not_utf8_refused(env, capsys):
    latin = env["tmp"] / "latin.csv"
    latin.write_bytes((HEADER + "NetworkDevice,dev-1,hostname,caf\xe9,\n").encode("latin-1"))
    rc, _, err = _run(capsys, *_base(env, latin), "--preview")
    assert rc == 2
    _assert_single_error_line(err)
    assert err.startswith("error: --csv ")


def test_control_characters_never_reach_terminal(env, capsys):
    csv_path = _write_csv(
        env["tmp"] / "ansi.csv",
        "NetworkDevice,dev-1,hostname,\x1b[31mred\x07,\x1b]0;title\x07",
        "NetworkDevice,\x1b[2Jdev-x,hostname,y,",
    )
    rc, out, err = _run(capsys, *_base(env, csv_path), "--preview")
    assert rc == 0, err
    assert "\x1b" not in out and "\x07" not in out
    assert "\x1b" not in err

    bad = _write_csv(env["tmp"] / "ansi-bad.csv", "Port,p-1,\x1b[31mevil,x,")
    rc, out, err = _run(capsys, *_base(env, bad), "--preview")
    assert rc == 2
    assert "\x1b" not in err


def test_as_of_conflict_previews(env, capsys):
    rc, out, err = _run(capsys, *_base(env), "--preview", "--as-of", "2000-01-01T00:00:00Z")
    assert rc == 0, err
    assert "conflict: 1" in out
    assert "can_apply: false" in out


def test_global_config_does_not_change_behaviour(env, capsys):
    config = env["tmp"] / "fleet.toml"
    config.write_text(FLEET_TOML, encoding="utf-8")
    rc_plain, out_plain, _ = _run(capsys, *_base(env), "--preview")
    before = _sha256(env["db"])
    rc, out, err = _run(capsys, "--config", str(config), *_base(env), "--preview")
    assert (rc, out) == (rc_plain, out_plain) == (0, out_plain)
    assert err == ""
    assert _sha256(env["db"]) == before
