"""End-to-end CLI tests for `synth-fleet` (synthetic fleet written as a snapshot folder)."""

from __future__ import annotations

from pathlib import Path

import pytest

from sot_validator.cli import main
from sot_validator.extraction.batch import SnapshotStore
from sot_validator.models import Site
from sot_validator.testing import SyntheticFleetGenerator

SMALL = ["--sites", "3", "--subnets-per-site", "2", "--hosts-per-subnet", "5"]
SITE_FILES = {"synth-site-001.json", "synth-site-002.json", "synth-site-003.json"}


def _run(seed: int, output_dir: Path, *extra: str) -> int:
    return main(["synth-fleet", "--seed", str(seed), *SMALL, *extra, "--output-dir", str(output_dir)])


def _tree(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_writes_one_snapshot_per_site(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "fleet"
    assert _run(7, out) == 0
    captured = capsys.readouterr()
    assert captured.out == f"synth-fleet: 3 site(s) written to {out / 'sites'}\n"
    assert captured.err == ""
    assert {path.name for path in (out / "sites").iterdir()} == SITE_FILES
    assert [path.name for path in out.iterdir()] == ["sites"]


def test_files_load_back_as_generator_sites(tmp_path: Path) -> None:
    out = tmp_path / "fleet"
    assert _run(7, out) == 0
    expected = SyntheticFleetGenerator(7, sites=3, subnets_per_site=2, hosts_per_subnet=5).generate().sites
    loaded = SnapshotStore(out).load_all_sites()
    assert sorted(site.site_id for site in loaded) == [site.site_id for site in expected]
    for site in expected:
        text = (out / "sites" / f"{site.site_id}.json").read_text(encoding="utf-8")
        assert text == site.to_json(indent=2)
        assert Site.from_json(text).site_id == site.site_id


def test_same_seed_is_byte_identical(tmp_path: Path) -> None:
    assert _run(7, tmp_path / "a") == 0
    assert _run(7, tmp_path / "b") == 0
    assert _tree(tmp_path / "a") == _tree(tmp_path / "b")


def test_different_seed_differs(tmp_path: Path) -> None:
    assert _run(7, tmp_path / "a") == 0
    assert _run(8, tmp_path / "c") == 0
    a, c = _tree(tmp_path / "a"), _tree(tmp_path / "c")
    assert a.keys() == c.keys()
    assert a != c


def test_defaults_match_generator() -> None:
    from sot_validator.cli import build_parser

    args = build_parser().parse_args(["synth-fleet", "--seed", "1", "--output-dir", "out"])
    assert (args.sites, args.subnets_per_site, args.hosts_per_subnet) == (100, 10, 60)
    generator = SyntheticFleetGenerator(1)
    assert (generator.sites, generator.subnets_per_site, generator.hosts_per_subnet) == (100, 10, 60)


def test_leaves_unrelated_files_unchanged(tmp_path: Path) -> None:
    out = tmp_path / "fleet"
    (out / "sites").mkdir(parents=True)
    keep = out / "notes.txt"
    keep.write_text("keep me\n", encoding="utf-8")
    other = out / "sites" / "site-999.json"
    other.write_text("{}", encoding="utf-8")
    assert _run(7, out) == 0
    assert keep.read_text(encoding="utf-8") == "keep me\n"
    assert other.read_text(encoding="utf-8") == "{}"
    assert {path.name for path in (out / "sites").iterdir()} == SITE_FILES | {"site-999.json"}
    assert not (out / "checkpoint.json").exists()


def test_overwrites_its_own_site_files(tmp_path: Path) -> None:
    out = tmp_path / "fleet"
    assert _run(8, out) == 0
    assert _run(7, out) == 0
    assert _run(7, tmp_path / "fresh") == 0
    assert _tree(out) == _tree(tmp_path / "fresh")


def _assert_one_error_line(capsys: pytest.CaptureFixture[str], *needles: str) -> str:
    captured = capsys.readouterr()
    assert captured.out == ""
    lines = captured.err.splitlines()
    assert len(lines) == 1, captured.err
    assert lines[0].startswith("error: ")
    assert "Traceback" not in captured.err
    for needle in needles:
        assert needle in lines[0]
    return lines[0]


@pytest.mark.parametrize(
    ("flag", "value", "needle"),
    [
        ("--sites", "0", "sites"),
        ("--sites", "255", "sites"),
        ("--subnets-per-site", "0", "subnets_per_site"),
        ("--subnets-per-site", "257", "subnets_per_site"),
        ("--hosts-per-subnet", "-1", "hosts_per_subnet"),
        ("--hosts-per-subnet", "246", "hosts_per_subnet"),
    ],
)
def test_generator_errors_create_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], flag: str, value: str, needle: str
) -> None:
    out = tmp_path / "fleet"
    code = main(["synth-fleet", "--seed", "1", flag, value, "--output-dir", str(out)])
    assert code == 2
    _assert_one_error_line(capsys, needle)
    assert not out.exists()


def test_output_dir_is_a_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / "sf-file"
    target.write_text("", encoding="utf-8")
    assert main(["synth-fleet", "--seed", "1", "--sites", "1", "--output-dir", str(target)]) == 2
    _assert_one_error_line(capsys, f"error: --output-dir {target}:")
    assert target.read_text(encoding="utf-8") == ""


def test_sites_path_is_a_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "fleet"
    out.mkdir()
    (out / "sites").write_text("x", encoding="utf-8")
    assert _run(1, out) == 2
    _assert_one_error_line(capsys, f"error: --output-dir {out}:")
    assert (out / "sites").read_text(encoding="utf-8") == "x"


def test_site_file_path_is_a_directory(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "fleet"
    (out / "sites" / "synth-site-002.json").mkdir(parents=True)
    assert _run(1, out) == 2
    _assert_one_error_line(capsys, f"error: --output-dir {out}:")


@pytest.mark.parametrize(
    "argv",
    [
        ["synth-fleet", "--seed", "abc", "--output-dir", "out"],
        ["synth-fleet", "--seed", "1", "--sites", "3.5", "--output-dir", "out"],
        ["synth-fleet", "--output-dir", "out"],
        ["synth-fleet", "--seed", "1"],
    ],
)
def test_argparse_errors_exit_2(argv: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as excinfo:
        main(argv)
    assert excinfo.value.code == 2
    assert not (tmp_path / "out").exists()
