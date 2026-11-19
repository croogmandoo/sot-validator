"""Native two-stage /16-to-/24 subnet discovery scanner and live Site bootstrapper."""

from __future__ import annotations

from sot_validator.discovery._scanner_common import (
    DEFAULT_GATEWAY_OCTETS,
    DEFAULT_TCP_PORTS,
    _HEX_RE,
    _NEIGH_STATES,
    _PING_RTT_PATTERN,
    _SERVER_TCP_PORTS,
    _infer_host_role,
    _infer_vlan_id_from_subnet,
    _normalize_mac,
    _role_to_equipment_category,
    parse_ip_neigh_output,
)
from sot_validator.discovery._scanner_engine import SubnetDiscoveryScanner
from sot_validator.discovery._scanner_models import DiscoveredHost, DiscoveryConfig
from sot_validator.discovery._scanner_probes import (
    _DEFAULT_CHILD_PATH,
    _default_arp_table_reader,
    _default_async_ping,
    _default_async_rdns,
    _default_async_tcp_probe,
    _minimal_child_env,
    _run_coro_sync,
)

__all__ = [
    "DEFAULT_GATEWAY_OCTETS",
    "DEFAULT_TCP_PORTS",
    "DiscoveredHost",
    "DiscoveryConfig",
    "SubnetDiscoveryScanner",
    "parse_ip_neigh_output",
]
