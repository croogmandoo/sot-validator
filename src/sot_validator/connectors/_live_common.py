"""Shared OID constants, read-only constants, errors and telemetry for the live connectors."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from sot_validator.extraction.client import (
    ReadOnlyViolationError as ExtractionReadOnlyViolationError,
)
from sot_validator.signals.management import (
    APC_POWERNET_MIB_OIDS,
    EXTREME_MIB_OIDS,
    IF_MIB_OIDS,
    IP_MIB_OIDS,
    ReadOnlyViolationError as ManagementReadOnlyViolationError,
    SNMPV2_MIB_OIDS,
)

# ---------------------------------------------------------------------------
# Phase 4 Canonical MIB OID Constants (LLDP-MIB, POWER-ETHERNET-MIB, Composites)
# ---------------------------------------------------------------------------

LLDP_REM_PORT_ID_PREFIX = "1.0.8802.1.1.2.1.4.1.1.7"
LLDP_REM_PORT_DESC_PREFIX = "1.0.8802.1.1.2.1.4.1.1.8"
LLDP_REM_SYS_NAME_PREFIX = "1.0.8802.1.1.2.1.4.1.1.9"

LLDP_MIB_OIDS: tuple[str, ...] = (
    LLDP_REM_PORT_ID_PREFIX,
    LLDP_REM_PORT_DESC_PREFIX,
    LLDP_REM_SYS_NAME_PREFIX,
)

PETH_PSE_PORT_ADMIN_ENABLE_PREFIX = "1.3.6.1.2.1.105.1.1.1.3"
PETH_PSE_PORT_DETECTION_STATUS_PREFIX = "1.3.6.1.2.1.105.1.1.1.6"

POWER_ETHERNET_MIB_OIDS: tuple[str, ...] = (
    PETH_PSE_PORT_ADMIN_ENABLE_PREFIX,
    PETH_PSE_PORT_DETECTION_STATUS_PREFIX,
)

EXTREME_SWITCH_MIB_OIDS: tuple[str, ...] = (
    SNMPV2_MIB_OIDS
    + IF_MIB_OIDS
    + IP_MIB_OIDS
    + LLDP_MIB_OIDS
    + POWER_ETHERNET_MIB_OIDS
    + EXTREME_MIB_OIDS
)

APC_UPS_MIB_OIDS: tuple[str, ...] = SNMPV2_MIB_OIDS + APC_POWERNET_MIB_OIDS

_ALLOWED_READONLY_MODES: frozenset[str] = frozenset(
    {"readonly", "read_only", "read-only", "ro"}
)

_FORBIDDEN_WRITE_COMMUNITIES: frozenset[str] = frozenset(
    {"private", "write", "rw", "read-write", "readwrite", "admin-rw", "private-rw"}
)

_ALLOWED_VCENTER_PATH_PREFIXES: tuple[str, ...] = (
    "/api/vcenter/vm",
    "/api/vcenter/host",
    "/api/cis/session",
)

_BLOCKED_VCENTER_PATH_SEGMENTS: frozenset[str] = frozenset(
    {
        "power",
        "reset",
        "reboot",
        "shutdown",
        "suspend",
        "delete",
        "create",
        "action",
        "reconfigure",
        "relocate",
        "migrate",
        "clone",
        "mount",
        "unmount",
        "disconnect",
        "maintenance",
    }
)


class ConnectorReadOnlyError(
    ManagementReadOnlyViolationError, ExtractionReadOnlyViolationError
):
    """Raised when a live connector blocks a mutating HTTP, vCenter REST, or SNMP operation."""


@dataclass
class RequestTelemetry:
    """Operational request counters and latency metrics for a live connector."""

    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    retried_requests: int = 0
    blocked_mutations: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    last_target: Optional[str] = None
    latencies_ms: list[float] = field(default_factory=list)

    @property
    def average_latency_ms(self) -> float:
        if not self.latencies_ms:
            return 0.0
        return round(sum(self.latencies_ms) / len(self.latencies_ms), 3)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "retried_requests": self.retried_requests,
            "blocked_mutations": self.blocked_mutations,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "last_target": self.last_target,
            "latencies_ms": list(self.latencies_ms),
            "average_latency_ms": self.average_latency_ms,
        }


def _validate_timeout_and_retries(
    timeout_seconds: float,
    max_retries: int,
    backoff_seconds: float,
) -> tuple[float, int, float]:
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or timeout_seconds <= 0
    ):
        raise ValueError("timeout_seconds must be a number > 0")
    if (
        isinstance(max_retries, bool)
        or not isinstance(max_retries, int)
        or max_retries < 0
    ):
        raise ValueError("max_retries must be an integer >= 0")
    if (
        isinstance(backoff_seconds, bool)
        or not isinstance(backoff_seconds, (int, float))
        or backoff_seconds < 0
    ):
        raise ValueError("backoff_seconds must be a number >= 0")
    return float(timeout_seconds), int(max_retries), float(backoff_seconds)
