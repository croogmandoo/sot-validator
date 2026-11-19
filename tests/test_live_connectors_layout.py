"""Tests for the connectors.live facade: re-exported names, guard lookup and module size limit."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
import time

import pytest

import sot_validator.connectors as connectors
import sot_validator.connectors._live_common as live_common
import sot_validator.connectors._live_scraper as live_scraper
import sot_validator.connectors._live_snmp as live_snmp
import sot_validator.connectors._live_vsphere as live_vsphere
import sot_validator.connectors.live as live
import sot_validator.extraction.guard as guard

CONNECTORS_DIR = Path(__file__).resolve().parents[1] / "src" / "sot_validator" / "connectors"

REEXPORTED_NAMES = [
    ("APC_UPS_MIB_OIDS", live_common),
    ("AuthenticatedScraperSession", live_scraper),
    ("ConnectorReadOnlyError", live_common),
    ("EXTREME_SWITCH_MIB_OIDS", live_common),
    ("LLDP_MIB_OIDS", live_common),
    ("LLDP_REM_PORT_DESC_PREFIX", live_common),
    ("LLDP_REM_PORT_ID_PREFIX", live_common),
    ("LLDP_REM_SYS_NAME_PREFIX", live_common),
    ("PETH_PSE_PORT_ADMIN_ENABLE_PREFIX", live_common),
    ("PETH_PSE_PORT_DETECTION_STATUS_PREFIX", live_common),
    ("POWER_ETHERNET_MIB_OIDS", live_common),
    ("RequestTelemetry", live_common),
    ("SnmpWalkConnector", live_snmp),
    ("VSphereRestConnector", live_vsphere),
    ("_ALLOWED_READONLY_MODES", live_common),
    ("_FORBIDDEN_WRITE_COMMUNITIES", live_common),
    ("_ALLOWED_VCENTER_PATH_PREFIXES", live_common),
    ("_BLOCKED_VCENTER_PATH_SEGMENTS", live_common),
    ("_validate_timeout_and_retries", live_common),
    ("_validate_snmp_readonly_config", live_snmp),
    ("ReadOnlyHttpGuard", guard),
]


@pytest.mark.parametrize(
    ("name", "module"), REEXPORTED_NAMES, ids=[name for name, _ in REEXPORTED_NAMES]
)
def test_name_importable_from_live(name: str, module: object) -> None:
    namespace: dict[str, object] = {}
    exec(f"from sot_validator.connectors.live import {name}", namespace)
    assert namespace[name] is getattr(module, name)


def test_live_reexports_time_module() -> None:
    assert live.time is time


def test_live_all_unchanged() -> None:
    assert live.__all__ == [
        "APC_UPS_MIB_OIDS",
        "AuthenticatedScraperSession",
        "ConnectorReadOnlyError",
        "EXTREME_SWITCH_MIB_OIDS",
        "LLDP_MIB_OIDS",
        "LLDP_REM_PORT_DESC_PREFIX",
        "LLDP_REM_PORT_ID_PREFIX",
        "LLDP_REM_SYS_NAME_PREFIX",
        "PETH_PSE_PORT_ADMIN_ENABLE_PREFIX",
        "PETH_PSE_PORT_DETECTION_STATUS_PREFIX",
        "POWER_ETHERNET_MIB_OIDS",
        "RequestTelemetry",
        "SnmpWalkConnector",
        "VSphereRestConnector",
    ]


def test_connectors_package_names_are_facade_objects() -> None:
    from_live = [name for name in connectors.__all__ if name in live.__all__]
    assert sorted(from_live) == sorted(live.__all__)
    for name in from_live:
        assert getattr(connectors, name) is getattr(live, name), name


@pytest.mark.parametrize("module", [live_scraper, live_vsphere], ids=["scraper", "vsphere"])
def test_private_http_modules_do_not_bind_guard(module: object) -> None:
    assert not hasattr(module, "ReadOnlyHttpGuard")


class _StubGuard:
    calls: list[tuple[str, str, dict[str, str], float]] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        timeout: float,
    ) -> bytes:
        _StubGuard.calls.append((method, url, dict(headers), timeout))
        return b'{"value": []}'


def test_default_urlopen_resolves_guard_through_facade(monkeypatch: pytest.MonkeyPatch) -> None:
    _StubGuard.calls = []
    monkeypatch.setattr(live, "ReadOnlyHttpGuard", _StubGuard)

    session = live.AuthenticatedScraperSession("https://sot.internal")
    assert session._default_urlopen("GET", "https://sot.internal/x", {"A": "b"}, 3.0) == (
        '{"value": []}'
    )
    vsphere = live.VSphereRestConnector(["https://vc01.internal"])
    assert vsphere._default_urlopen(
        "GET", "https://vc01.internal/api/vcenter/vm", {}, 4.0
    ) == {"value": []}

    assert _StubGuard.calls == [
        ("GET", "https://sot.internal/x", {"A": "b"}, 3.0),
        ("GET", "https://vc01.internal/api/vcenter/vm", {}, 4.0),
    ]


def test_live_modules_under_800_lines() -> None:
    private = sorted(CONNECTORS_DIR.glob("_live_*.py"))
    assert len(private) == 4
    for path in [CONNECTORS_DIR / "live.py", *private]:
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        assert line_count < 800, f"{path.name} has {line_count} lines"
