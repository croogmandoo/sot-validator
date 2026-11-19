"""Read-only live pilot connector transports for SoT HTML scraping, vSphere REST, and SNMP."""

from __future__ import annotations

import time

from sot_validator.connectors._live_common import (
    _ALLOWED_READONLY_MODES,
    _ALLOWED_VCENTER_PATH_PREFIXES,
    _BLOCKED_VCENTER_PATH_SEGMENTS,
    _FORBIDDEN_WRITE_COMMUNITIES,
    APC_UPS_MIB_OIDS,
    EXTREME_SWITCH_MIB_OIDS,
    LLDP_MIB_OIDS,
    LLDP_REM_PORT_DESC_PREFIX,
    LLDP_REM_PORT_ID_PREFIX,
    LLDP_REM_SYS_NAME_PREFIX,
    PETH_PSE_PORT_ADMIN_ENABLE_PREFIX,
    PETH_PSE_PORT_DETECTION_STATUS_PREFIX,
    POWER_ETHERNET_MIB_OIDS,
    ConnectorReadOnlyError,
    RequestTelemetry,
    _validate_timeout_and_retries,
)
from sot_validator.connectors._live_scraper import AuthenticatedScraperSession
from sot_validator.connectors._live_snmp import (
    SnmpWalkConnector,
    _validate_snmp_readonly_config,
)
from sot_validator.connectors._live_vsphere import VSphereRestConnector
from sot_validator.extraction.guard import ReadOnlyHttpGuard


__all__ = [
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
