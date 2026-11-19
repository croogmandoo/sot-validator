"""Tests for the management facade: re-exported names and module size limit."""

from __future__ import annotations

from pathlib import Path

import pytest

import sot_validator.signals._management_collector as management_collector
import sot_validator.signals._management_common as management_common
import sot_validator.signals.icmp as icmp
import sot_validator.signals.management as management

SIGNALS_DIR = Path(__file__).resolve().parents[1] / "src" / "sot_validator" / "signals"

EXPECTED_ALL = [
    "ALLOWED_HTTP_METHODS",
    "ALLOWED_SNMP_OPERATIONS",
    "APC_ENTERPRISE_OID_PREFIX",
    "APC_POWERNET_MIB_OIDS",
    "APC_UPS_ADV_BATTERY_CAPACITY_OID",
    "APC_UPS_ADV_OUTPUT_LOAD_OID",
    "APC_UPS_BASIC_IDENT_MODEL_OID",
    "APC_UPS_BASIC_STATE_OUTPUT_STATE_OID",
    "EXTREME_ENTERPRISE_OID_PREFIX",
    "EXTREME_MIB_OIDS",
    "EXTREME_POE_PORT_MEASURED_POWER_PREFIX",
    "EXTREME_POE_PORT_OPERATOR_LIMIT_PREFIX",
    "EXTREME_SYS_SERIAL_NUMBER_OID",
    "EXTREME_SYS_VERSION_OID",
    "FixtureManagementTransport",
    "HttpsProbeResponse",
    "IF_MIB_IF_ADMIN_STATUS_PREFIX",
    "IF_MIB_IF_ALIAS_PREFIX",
    "IF_MIB_IF_LAST_CHANGE_PREFIX",
    "IF_MIB_IF_OPER_STATUS_PREFIX",
    "IF_MIB_OIDS",
    "IP_MIB_NET_TO_MEDIA_PHYS_ADDRESS_PREFIX",
    "IP_MIB_NET_TO_PHYSICAL_PHYS_ADDRESS_PREFIX",
    "IP_MIB_OIDS",
    "ManagementProbeCollector",
    "OID_SYS_DESCR",
    "OID_SYS_NAME",
    "OID_SYS_UPTIME",
    "ReadOnlyViolationError",
    "SNMPV2_MIB_OIDS",
    "SNMPV2_MIB_SYS_DESCR",
    "SNMPV2_MIB_SYS_NAME",
    "SNMPV2_MIB_SYS_UPTIME",
    "ScopeViolationError",
    "SubnetScopeGuard",
    "parse_apc_ups_oids",
    "parse_extreme_switch_oids",
    "validate_readonly_http_method",
    "validate_readonly_snmp_request",
]

DEFINING_MODULES = {
    "ManagementProbeCollector": management_collector,
    "ScopeViolationError": icmp,
    "SubnetScopeGuard": icmp,
}


@pytest.mark.parametrize("name", EXPECTED_ALL)
def test_name_importable_from_management(name: str) -> None:
    namespace: dict[str, object] = {}
    exec(f"from sot_validator.signals.management import {name}", namespace)
    module = DEFINING_MODULES.get(name, management_common)
    assert namespace[name] is getattr(module, name)


def test_management_all_unchanged() -> None:
    assert management.__all__ == EXPECTED_ALL


def test_management_modules_under_800_lines() -> None:
    private = sorted(SIGNALS_DIR.glob("_management_*.py"))
    assert len(private) == 2
    for path in [SIGNALS_DIR / "management.py", *private]:
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        assert line_count < 800, f"{path.name} has {line_count} lines"
