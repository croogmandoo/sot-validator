"""Discovery scanner constants, MAC/VLAN/role helpers and the ``ip neigh`` parser."""

from __future__ import annotations

from collections.abc import Sequence
import ipaddress
import re
from typing import Optional

from sot_validator.models import EquipmentCategory

DEFAULT_GATEWAY_OCTETS: tuple[int, ...] = (1,)
DEFAULT_TCP_PORTS: tuple[int, ...] = (
    22,
    53,
    80,
    443,
    445,
    5000,
    8000,
    8006,
    8080,
    8123,
    8443,
    9000,
)
_SERVER_TCP_PORTS: frozenset[int] = frozenset({22, 80, 443, 8000, 8080, 8443, 9000})
_NEIGH_STATES: frozenset[str] = frozenset(
    {
        "REACHABLE",
        "STALE",
        "DELAY",
        "PROBE",
        "FAILED",
        "NOARP",
        "PERMANENT",
        "INCOMPLETE",
        "NONE",
    }
)
_PING_RTT_PATTERN = re.compile(r"time[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*ms", re.IGNORECASE)
_HEX_RE = re.compile(r"^[0-9a-f]{1,2}$")


def _normalize_mac(mac: Optional[str]) -> Optional[str]:
    """Normalize a MAC address string to lowercase colon-separated format."""
    if mac is None:
        return None
    if not isinstance(mac, str):
        raise ValueError("mac_address must be a string or None")
    cleaned = mac.strip().lower()
    if not cleaned:
        return None

    if ":" in cleaned or "-" in cleaned:
        sep = ":" if ":" in cleaned else "-"
        parts = cleaned.split(sep)
        if len(parts) == 6 and all(_HEX_RE.match(p) for p in parts):
            return ":".join(p.zfill(2) for p in parts)

    hex_only = "".join(ch for ch in cleaned if ch not in (":", "-", "."))
    if len(hex_only) == 12 and all(ch in "0123456789abcdef" for ch in hex_only):
        return ":".join(hex_only[i : i + 2] for i in range(0, 12, 2))

    return cleaned


def _infer_vlan_id_from_subnet(subnet_cidr: str) -> str:
    """Infer a canonical VLAN ID string from a /24 subnet's third octet."""
    net = ipaddress.ip_network(subnet_cidr.strip(), strict=False)
    octets = str(net.network_address).split(".")
    third_octet = int(octets[2]) if len(octets) >= 3 else 1
    return str(third_octet) if third_octet > 0 else "1"


def parse_ip_neigh_output(
    raw_output: str,
) -> dict[str, tuple[Optional[str], Optional[str]]]:
    """Parse ``ip -4 neigh show`` output into ``{ip: (mac_or_none, state_or_none)}``."""
    if not isinstance(raw_output, str) or not raw_output.strip():
        return {}

    neighbors: dict[str, tuple[Optional[str], Optional[str]]] = {}
    for raw_line in raw_output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        tokens = line.split()
        if not tokens:
            continue

        ip_candidate = tokens[0]
        try:
            addr = ipaddress.ip_address(ip_candidate)
        except ValueError:
            continue
        if not isinstance(addr, ipaddress.IPv4Address):
            continue

        mac: Optional[str] = None
        for idx, tok in enumerate(tokens[:-1]):
            if tok.lower() == "lladdr":
                mac = _normalize_mac(tokens[idx + 1])
                break

        state: Optional[str] = None
        last_upper = tokens[-1].upper()
        if last_upper in _NEIGH_STATES or (
            last_upper.isalpha() and last_upper == tokens[-1]
        ):
            state = last_upper

        neighbors[str(addr)] = (mac, state)

    return neighbors


def _infer_host_role(
    *,
    ip: str,
    gateway_octets: Sequence[int] = DEFAULT_GATEWAY_OCTETS,
    mac_address: Optional[str] = None,
    open_tcp_ports: Sequence[int] = (),
    hostname: Optional[str] = None,
) -> str:
    """Deterministically infer a host's network/equipment role from discovery signals."""
    norm_mac = (_normalize_mac(mac_address) or "").lower()
    host_lower = (hostname or "").strip().lower()
    port_set = set(open_tcp_ports)

    last_octet: Optional[int] = None
    try:
        addr = ipaddress.IPv4Address(ip.strip())
        last_octet = int(str(addr).split(".")[3])
    except ValueError:
        last_octet = None

    # Extreme Networks switch OUI or switch hostname pattern
    if (
        norm_mac.startswith("00:04:96")
        or "switch" in host_lower
        or "sw-" in host_lower
    ):
        return "switch"

    # Gateway octet router
    if last_octet is not None and last_octet in gateway_octets:
        return "router"

    # APC UPS OUI or UPS hostname
    if norm_mac.startswith("00:c0:b7") or "ups" in host_lower:
        return "ups"

    # Proxmox / ESXi / Hypervisor
    if (
        8006 in port_set
        or norm_mac.startswith("bc:24:11")
        or any(tok in host_lower for tok in ("pve", "proxmox", "esxi", "hypervisor"))
    ):
        return "hypervisor"

    # NAS / SAN / SMB storage
    if (
        5000 in port_set
        or 445 in port_set
        or any(tok in host_lower for tok in ("nas", "san", "synology"))
    ):
        return "nas_storage"

    # DNS server (non-gateway)
    if 53 in port_set:
        return "dns_server"

    # Home Assistant / automation hub
    if 8123 in port_set:
        return "automation_hub"

    # IoT device (e.g. Ecobee OUI 44:61:32)
    if (
        norm_mac.startswith("44:61:32")
        or "iot" in host_lower
        or "ecobee" in host_lower
    ):
        return "iot_device"

    # General server ports
    if port_set & _SERVER_TCP_PORTS:
        return "server"

    return "host"


def _role_to_equipment_category(role: str) -> EquipmentCategory:
    """Map an inferred host role to a canonical EquipmentCategory."""
    norm = (role or "").strip().lower()
    if norm == "ups":
        return EquipmentCategory.UPS
    if norm in ("nas_storage", "san"):
        return EquipmentCategory.SAN
    if norm in ("hypervisor", "dns_server", "server", "automation_hub"):
        return EquipmentCategory.SERVER
    if norm == "vm":
        return EquipmentCategory.VM
    return EquipmentCategory.OTHER
