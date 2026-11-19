"""Read-only cross-VLAN router ARP/neighbor and DHCP lease table collector."""

from __future__ import annotations

from sot_validator.discovery._router_collector import (
    RouterArpDhcpCollector,
    _is_synthetic_device_hostname,
    _is_synthetic_equipment_name,
)
from sot_validator.discovery._router_common import (
    IF_MIB_IF_DESCR_PREFIX,
    IF_MIB_IF_NAME_PREFIX,
    IP_MIB_NET_TO_MEDIA_NET_ADDRESS_PREFIX,
    IP_MIB_NET_TO_MEDIA_TYPE_PREFIX,
    _coerce_datetime,
    _vlan_from_interface,
    _vlan_from_ip,
)
from sot_validator.discovery._router_parsers import RouterTableParsers
from sot_validator.discovery._router_records import DhcpLeaseRecord, RouterArpRecord

__all__ = [
    "DhcpLeaseRecord",
    "RouterArpDhcpCollector",
    "RouterArpRecord",
    "RouterTableParsers",
]
