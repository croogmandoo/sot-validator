"""SNMP OID constants, read-only SNMP/HTTP guards, Extreme/APC OID parsers and the fixture management transport."""

from __future__ import annotations

from dataclasses import dataclass
import json
import pathlib
from typing import Any, Mapping, Optional

from sot_validator.signals.icmp import SubnetScopeGuard

# ---------------------------------------------------------------------------
# Canonical SNMP OID Constants (docs/DISCOVERY.md Section 6.2)
# ---------------------------------------------------------------------------

# Standard MIB-II (SNMPv2-MIB)
SNMPV2_MIB_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SNMPV2_MIB_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SNMPV2_MIB_SYS_NAME = "1.3.6.1.2.1.1.5.0"

OID_SYS_DESCR = SNMPV2_MIB_SYS_DESCR
OID_SYS_UPTIME = SNMPV2_MIB_SYS_UPTIME
OID_SYS_NAME = SNMPV2_MIB_SYS_NAME

SNMPV2_MIB_OIDS: tuple[str, ...] = (
    SNMPV2_MIB_SYS_DESCR,
    SNMPV2_MIB_SYS_UPTIME,
    SNMPV2_MIB_SYS_NAME,
)

# IF-MIB Port Status & Alias OID Prefixes
IF_MIB_IF_ADMIN_STATUS_PREFIX = "1.3.6.1.2.1.2.2.1.7"
IF_MIB_IF_OPER_STATUS_PREFIX = "1.3.6.1.2.1.2.2.1.8"
IF_MIB_IF_LAST_CHANGE_PREFIX = "1.3.6.1.2.1.2.2.1.9"
IF_MIB_IF_ALIAS_PREFIX = "1.3.6.1.2.1.31.1.1.1.18"

IF_MIB_OIDS: tuple[str, ...] = (
    IF_MIB_IF_ADMIN_STATUS_PREFIX,
    IF_MIB_IF_OPER_STATUS_PREFIX,
    IF_MIB_IF_LAST_CHANGE_PREFIX,
    IF_MIB_IF_ALIAS_PREFIX,
)

# IP-MIB ARP / Neighbor Table OID Prefixes
IP_MIB_NET_TO_MEDIA_PHYS_ADDRESS_PREFIX = "1.3.6.1.2.1.4.22.1.2"
IP_MIB_NET_TO_PHYSICAL_PHYS_ADDRESS_PREFIX = "1.3.6.1.2.1.4.35.1.4"

IP_MIB_OIDS: tuple[str, ...] = (
    IP_MIB_NET_TO_MEDIA_PHYS_ADDRESS_PREFIX,
    IP_MIB_NET_TO_PHYSICAL_PHYS_ADDRESS_PREFIX,
)

# Extreme Networks Enterprise MIBs (1.3.6.1.4.1.1916)
EXTREME_ENTERPRISE_OID_PREFIX = "1.3.6.1.4.1.1916"
EXTREME_SYS_VERSION_OID = "1.3.6.1.4.1.1916.1.1.1.13.0"
EXTREME_SYS_SERIAL_NUMBER_OID = "1.3.6.1.4.1.1916.1.1.1.16.0"
EXTREME_POE_PORT_OPERATOR_LIMIT_PREFIX = "1.3.6.1.4.1.1916.1.27.2.1.1.4"
EXTREME_POE_PORT_MEASURED_POWER_PREFIX = "1.3.6.1.4.1.1916.1.27.2.1.1.5"

EXTREME_MIB_OIDS: tuple[str, ...] = (
    EXTREME_SYS_VERSION_OID,
    EXTREME_SYS_SERIAL_NUMBER_OID,
    EXTREME_POE_PORT_OPERATOR_LIMIT_PREFIX,
    EXTREME_POE_PORT_MEASURED_POWER_PREFIX,
)

# APC UPS PowerNet-MIB (1.3.6.1.4.1.318)
APC_ENTERPRISE_OID_PREFIX = "1.3.6.1.4.1.318"
APC_UPS_BASIC_IDENT_MODEL_OID = "1.3.6.1.4.1.318.1.1.1.1.1.1.0"
APC_UPS_BASIC_STATE_OUTPUT_STATE_OID = "1.3.6.1.4.1.318.1.1.1.11.1.1.0"
APC_UPS_ADV_BATTERY_CAPACITY_OID = "1.3.6.1.4.1.318.1.1.1.2.2.1.0"
APC_UPS_ADV_OUTPUT_LOAD_OID = "1.3.6.1.4.1.318.1.1.1.4.2.3.0"

APC_POWERNET_MIB_OIDS: tuple[str, ...] = (
    APC_UPS_BASIC_IDENT_MODEL_OID,
    APC_UPS_BASIC_STATE_OUTPUT_STATE_OID,
    APC_UPS_ADV_BATTERY_CAPACITY_OID,
    APC_UPS_ADV_OUTPUT_LOAD_OID,
)

ALLOWED_SNMP_OPERATIONS: frozenset[str] = frozenset({"GET", "GETNEXT", "GETBULK", "WALK"})
ALLOWED_HTTP_METHODS: frozenset[str] = frozenset({"GET", "HEAD"})


class ReadOnlyViolationError(PermissionError, ValueError):
    """Raised when a mutating SNMP SET operation, write profile, or non-GET HTTP method is requested."""


def validate_readonly_snmp_request(
    *,
    operation: str = "GET",
    mode: str = "readonly",
) -> None:
    """Enforce Phase 1 read-only SNMP access (GET/WALK only, mode='readonly')."""
    op_upper = (operation or "").strip().upper()
    if op_upper not in ALLOWED_SNMP_OPERATIONS:
        raise ReadOnlyViolationError(
            f"SNMP operation {operation!r} is prohibited in Phase 1; "
            f"only read-only {sorted(ALLOWED_SNMP_OPERATIONS)} queries are allowed"
        )
    mode_lower = (mode or "").strip().lower()
    if mode_lower != "readonly":
        raise ReadOnlyViolationError(
            f"SNMP mode {mode!r} is prohibited in Phase 1; mode must be 'readonly'"
        )


def validate_readonly_http_method(method: str = "GET") -> None:
    """Enforce Phase 1 read-only HTTP/HTTPS method (GET or HEAD only)."""
    method_upper = (method or "").strip().upper()
    if method_upper not in ALLOWED_HTTP_METHODS:
        raise ReadOnlyViolationError(
            f"HTTP method {method!r} is prohibited for management probes; "
            "only GET or HEAD requests are allowed"
        )


@dataclass(frozen=True)
class HttpsProbeResponse:
    """Result returned by a read-only HTTPS/TCP management reachability probe."""

    reachable: bool
    status_code: Optional[int] = None
    port: int = 443
    detail: Optional[str] = None


def parse_extreme_switch_oids(oids: Mapping[str, Any]) -> dict[str, Any]:
    """Parse Extreme Networks switch SNMP walk OIDs into normalized hardware and port metrics."""
    sys_descr = str(oids.get(SNMPV2_MIB_SYS_DESCR, ""))
    sys_uptime = str(oids.get(SNMPV2_MIB_SYS_UPTIME, ""))
    sys_name = str(oids.get(SNMPV2_MIB_SYS_NAME, ""))
    os_version = str(oids.get(EXTREME_SYS_VERSION_OID, ""))
    serial_number = str(oids.get(EXTREME_SYS_SERIAL_NUMBER_OID, ""))

    oper_prefix = f"{IF_MIB_IF_OPER_STATUS_PREFIX}."
    admin_prefix = f"{IF_MIB_IF_ADMIN_STATUS_PREFIX}."
    poe_power_prefix = f"{EXTREME_POE_PORT_MEASURED_POWER_PREFIX}."
    media_arp_prefix = f"{IP_MIB_NET_TO_MEDIA_PHYS_ADDRESS_PREFIX}."
    phys_arp_prefix = f"{IP_MIB_NET_TO_PHYSICAL_PHYS_ADDRESS_PREFIX}."

    ports_up = 0
    ports_down = 0
    ports_admin_up = 0
    for oid, val in oids.items():
        if oid.startswith(oper_prefix):
            try:
                status_int = int(val)
            except (TypeError, ValueError):
                status_int = 0
            if status_int == 1:
                ports_up += 1
            else:
                ports_down += 1
        elif oid.startswith(admin_prefix):
            try:
                if int(val) == 1:
                    ports_admin_up += 1
            except (TypeError, ValueError):
                pass

    poe_active_ports = 0
    poe_total_mw = 0
    for oid, val in oids.items():
        if oid.startswith(poe_power_prefix):
            try:
                mw = int(val)
            except (TypeError, ValueError):
                mw = 0
            if mw > 0:
                poe_active_ports += 1
                poe_total_mw += mw

    media_arp_macs = [
        str(val) for oid, val in oids.items() if oid.startswith(media_arp_prefix)
    ]
    phys_arp_macs = [
        str(val) for oid, val in oids.items() if oid.startswith(phys_arp_prefix)
    ]
    arp_entry_count = len(media_arp_macs) if media_arp_macs else len(phys_arp_macs)

    return {
        "vendor": "Extreme Networks",
        "sys_name": sys_name,
        "sys_descr": sys_descr,
        "sys_uptime": sys_uptime,
        "os_version": os_version,
        "serial_number": serial_number,
        "ports_total": ports_up + ports_down,
        "ports_up": ports_up,
        "ports_down": ports_down,
        "ports_admin_up": ports_admin_up,
        "poe_active_ports": poe_active_ports,
        "poe_total_mw": poe_total_mw,
        "poe_total_watts": round(poe_total_mw / 1000.0, 2),
        "arp_entries": arp_entry_count,
    }


def parse_apc_ups_oids(oids: Mapping[str, Any]) -> dict[str, Any]:
    """Parse APC UPS PowerNet-MIB SNMP walk OIDs into normalized status and battery/load metrics."""
    sys_descr = str(oids.get(SNMPV2_MIB_SYS_DESCR, ""))
    sys_uptime = str(oids.get(SNMPV2_MIB_SYS_UPTIME, ""))
    sys_name = str(oids.get(SNMPV2_MIB_SYS_NAME, ""))
    model = str(oids.get(APC_UPS_BASIC_IDENT_MODEL_OID, ""))
    output_state_flags = str(oids.get(APC_UPS_BASIC_STATE_OUTPUT_STATE_OID, ""))

    # In APC PowerNet-MIB::upsBasicStateOutputState, bit 4 (index 3, 0-based) == '1' means On Line
    on_line = len(output_state_flags) >= 4 and output_state_flags[3] == "1"

    raw_battery = oids.get(APC_UPS_ADV_BATTERY_CAPACITY_OID)
    battery_capacity_pct: Optional[int] = (
        int(raw_battery) if raw_battery is not None else None
    )

    raw_load = oids.get(APC_UPS_ADV_OUTPUT_LOAD_OID)
    output_load_pct: Optional[int] = int(raw_load) if raw_load is not None else None

    return {
        "vendor": "APC",
        "sys_name": sys_name,
        "sys_descr": sys_descr,
        "sys_uptime": sys_uptime,
        "model": model,
        "output_state_flags": output_state_flags,
        "on_line": on_line,
        "output_status": "onLine" if on_line else "offLine",
        "battery_capacity_pct": battery_capacity_pct,
        "output_load_pct": output_load_pct,
    }


class FixtureManagementTransport:
    """Read-only SNMP and management fixture transport loaded from discovery JSON."""

    def __init__(self, fixture_data: Mapping[str, Any]) -> None:
        snmp_profile = fixture_data.get("snmp_profile", {})
        mode = str(snmp_profile.get("mode", "readonly"))
        validate_readonly_snmp_request(operation="GET", mode=mode)

        self.site_id: Optional[str] = fixture_data.get("site_id")
        self.site_prefix: Optional[str] = fixture_data.get("site_prefix")
        self.scoped_subnets: list[str] = list(fixture_data.get("scoped_subnets", []))
        self.snmp_profile: dict[str, Any] = dict(snmp_profile)

        self._targets_by_id: dict[str, dict[str, Any]] = {}
        self._targets_by_ip: dict[str, dict[str, Any]] = {}
        for target_id, entry in fixture_data.get("targets", {}).items():
            target_copy = dict(entry)
            self._targets_by_id[str(target_id)] = target_copy
            ip_addr = target_copy.get("ip_address")
            if ip_addr:
                self._targets_by_ip[str(ip_addr).strip()] = target_copy

    @classmethod
    def from_file(cls, path: str | pathlib.Path) -> FixtureManagementTransport:
        raw = pathlib.Path(path).read_text(encoding="utf-8")
        return cls(json.loads(raw))

    def build_scope_guard(self) -> SubnetScopeGuard:
        return SubnetScopeGuard(
            subnets=self.scoped_subnets,
            recorded_ips=list(self._targets_by_ip.keys()),
            site_prefix=self.site_prefix,
        )

    def query_snmp(
        self,
        target: str,
        timeout_seconds: float = 2.0,
        *,
        operation: str = "GET",
    ) -> Optional[dict[str, Any]]:
        """Perform a read-only SNMP GET/walk lookup by IP address or target_id."""
        _ = timeout_seconds
        validate_readonly_snmp_request(
            operation=operation,
            mode=str(self.snmp_profile.get("mode", "readonly")),
        )
        record = self._targets_by_ip.get(target) or self._targets_by_id.get(target)
        if record is None or not record.get("snmp_reachable", False):
            return None
        oids = record.get("oids")
        if not isinstance(oids, Mapping) or not oids:
            return None
        return dict(oids)
