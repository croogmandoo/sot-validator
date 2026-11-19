"""Tests for the directory_dns facade: re-exported names and module size limit."""

from __future__ import annotations

from pathlib import Path

import pytest

import sot_validator.signals._directory_ad as directory_ad
import sot_validator.signals._directory_common as directory_common
import sot_validator.signals._directory_dns_collector as directory_dns_collector
import sot_validator.signals._directory_dns_records as directory_dns_records
import sot_validator.signals.directory_dns as directory_dns

SIGNALS_DIR = Path(__file__).resolve().parents[1] / "src" / "sot_validator" / "signals"

REEXPORTED_NAMES = [
    ("ActiveDirectoryCollector", directory_ad),
    ("AdComputerRecord", directory_ad),
    ("DhcpLeaseRecord", directory_dns_records),
    ("DnsDhcpLeaseCollector", directory_dns_collector),
    ("DnsRecord", directory_dns_records),
    ("normalize_hostname", directory_common),
    ("_clean_optional_str", directory_common),
    ("_parse_bool_flag", directory_common),
    ("_normalize_hostname_str", directory_common),
    ("_normalize_fqdn", directory_common),
]


@pytest.mark.parametrize(
    ("name", "module"), REEXPORTED_NAMES, ids=[name for name, _ in REEXPORTED_NAMES]
)
def test_name_importable_from_directory_dns(name: str, module: object) -> None:
    namespace: dict[str, object] = {}
    exec(f"from sot_validator.signals.directory_dns import {name}", namespace)
    assert namespace[name] is getattr(module, name)


def test_normalize_hostname_str_is_shared_cache() -> None:
    assert directory_dns._normalize_hostname_str is directory_common._normalize_hostname_str
    assert hasattr(directory_dns._normalize_hostname_str, "cache_info")


def test_directory_dns_all_unchanged() -> None:
    assert directory_dns.__all__ == [
        "ActiveDirectoryCollector",
        "AdComputerRecord",
        "DhcpLeaseRecord",
        "DnsDhcpLeaseCollector",
        "DnsRecord",
        "normalize_hostname",
    ]


def test_directory_dns_modules_under_800_lines() -> None:
    private = sorted(SIGNALS_DIR.glob("_directory_*.py"))
    assert len(private) == 4
    for path in [SIGNALS_DIR / "directory_dns.py", *private]:
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        assert line_count < 800, f"{path.name} has {line_count} lines"
