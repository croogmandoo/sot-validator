"""Data-quality rule constants, the QualityFinding record and shared helpers."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import hashlib
import ipaddress
import re
from typing import Any, Iterable, Mapping, Optional

from sot_validator.models import IPAddress, Site
from sot_validator.topology.fdb_mapper import VALID_PORT_MODES

RULE_DUPLICATE_IP = "duplicate_ip"
RULE_DUPLICATE_MAC = "duplicate_mac"
RULE_IP_OUTSIDE_SITE_BLOCK = "ip_outside_site_block"
RULE_IP_OUTSIDE_ACTIVE_SUBNET = "ip_outside_active_subnet"
RULE_ORPHAN_REFERENCE = "orphan_reference"
RULE_HOSTNAME_MISMATCH = "hostname_mismatch"
RULE_CROSS_SITE_DUPLICATE_IP = "cross_site_duplicate_ip"
RULE_CROSS_SITE_DUPLICATE_MAC = "cross_site_duplicate_mac"

SINGLE_SITE_RULES: tuple[str, ...] = (
    RULE_DUPLICATE_IP,
    RULE_DUPLICATE_MAC,
    RULE_IP_OUTSIDE_SITE_BLOCK,
    RULE_IP_OUTSIDE_ACTIVE_SUBNET,
    RULE_ORPHAN_REFERENCE,
    RULE_HOSTNAME_MISMATCH,
)

CROSS_SITE_RULES: tuple[str, ...] = (
    RULE_CROSS_SITE_DUPLICATE_IP,
    RULE_CROSS_SITE_DUPLICATE_MAC,
)

ALL_RULE_NAMES: tuple[str, ...] = SINGLE_SITE_RULES + CROSS_SITE_RULES

VALID_SEVERITIES: tuple[str, ...] = ("error", "warning", "info")

_TRUNK_PORT_MODES: frozenset[str] = frozenset({"trunk", "uplink"})

# Six colon/dash-separated octets, three dot-separated quads, or 12 bare hex digits.
_MAC_PATTERN = re.compile(
    r"(?:[0-9a-f]{2}([:-])[0-9a-f]{2}(?:\1[0-9a-f]{2}){4}"
    r"|[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}"
    r"|[0-9a-f]{12})"
)


def _compute_finding_id(rule: str, record_ids: Iterable[str]) -> str:
    """Return the stable SHA-256 identity of a rule plus its sorted record ids."""
    canonical = f"{rule}|{', '.join(sorted(record_ids))}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class QualityFinding:
    """Single internal SoT data-quality conflict."""

    finding_id: str
    site_id: str
    rule: str
    severity: str
    record_type: str
    record_ids: list[str]
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(
                f"severity must be one of {VALID_SEVERITIES}, got {self.severity!r}"
            )
        self.record_ids = list(self.record_ids)
        self.evidence = dict(self.evidence)


def _canonical_ip_key(value: str) -> str:
    """Return a canonical lookup key, normalizing strings that parse as IP addresses."""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except (AttributeError, ValueError):
        return value


def _normalized_ip(value: Optional[str]) -> Optional[ipaddress.IPv4Address]:
    """Return the IPv4 address for a value, or None when it is not one."""
    if not isinstance(value, str):
        return None
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    return address if isinstance(address, ipaddress.IPv4Address) else None


def _normalized_network(cidr: Optional[str]) -> Optional[ipaddress.IPv4Network]:
    """Return the IPv4 network for a CIDR string, or None when it is not one."""
    if not isinstance(cidr, str):
        return None
    try:
        network = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        return None
    return network if isinstance(network, ipaddress.IPv4Network) else None


def _normalized_mac(value: Optional[str]) -> Optional[str]:
    """Return a canonical MAC address, or None for blanks, IPs and malformed values."""
    if not isinstance(value, str):
        return None
    cleaned = value.strip().lower()
    if not _MAC_PATTERN.fullmatch(cleaned):
        return None
    hex_only = re.sub(r"[:.-]", "", cleaned)
    return ":".join(hex_only[i : i + 2] for i in range(0, 12, 2))


def _ip_assignment_ref(record: IPAddress) -> str:
    """Return the stable identity of an IP assignment record."""
    if record.assigned_object_type and record.assigned_object_id:
        return f"{record.assigned_object_type}:{record.assigned_object_id}"
    return f"ip:{_canonical_ip_key(record.ip)}"


def _parse_site_block(
    value: Optional[str | ipaddress.IPv4Network],
) -> Optional[ipaddress.IPv4Network]:
    if value is None:
        return None
    if isinstance(value, ipaddress.IPv4Network):
        network = value
    else:
        try:
            network = ipaddress.ip_network(str(value).strip(), strict=False)
        except ValueError as exc:
            raise ValueError(
                f"site_block must be a valid IPv4 /16 network: {value!r}"
            ) from exc
    if not isinstance(network, ipaddress.IPv4Network) or network.prefixlen != 16:
        raise ValueError(f"site_block must be an IPv4 /16 network: {value!r}")
    return network


def _parse_port_modes(
    port_modes: Optional[Mapping[str, str]],
) -> dict[str, str]:
    if port_modes is None:
        return {}
    modes: dict[str, str] = {}
    for port_id, mode in port_modes.items():
        if not isinstance(port_id, str) or not port_id.strip():
            raise ValueError(
                f"port_modes keys must be non-empty strings, got {port_id!r}"
            )
        if mode not in VALID_PORT_MODES:
            raise ValueError(
                f"Invalid port mode for {port_id!r}: {mode!r} "
                f"(expected one of {VALID_PORT_MODES})"
            )
        modes[port_id] = mode
    return modes


def _parse_name_map(
    names: Optional[Mapping[str, str]],
) -> dict[str, str]:
    if names is None:
        return {}
    parsed: dict[str, str] = {}
    for key, value in names.items():
        if not isinstance(key, str) or not key.strip():
            raise ValueError(
                f"hostname signal keys must be non-empty strings, got {key!r}"
            )
        if not isinstance(value, str):
            raise ValueError(f"hostname signal values must be strings, got {value!r}")
        parsed[_canonical_ip_key(key)] = value
    return parsed


def _lookup_name(names: Mapping[str, str], key: Optional[str]) -> Optional[str]:
    if not isinstance(key, str) or not key.strip():
        return None
    return names.get(_canonical_ip_key(key))


def _derive_site_block(site: Site) -> Optional[ipaddress.IPv4Network]:
    """Derive the site /16: most common subnet supernet, ties lexicographic."""
    counts: Counter[str] = Counter()
    for subnet in site.subnets:
        network = _normalized_network(subnet.cidr)
        if network is None:
            continue
        if network.prefixlen >= 16:
            block = network.supernet(new_prefix=16)
        else:
            block = ipaddress.ip_network(
                f"{network.network_address}/16", strict=False
            )
        counts[str(block)] += 1
    if not counts:
        return None
    best = min(counts.items(), key=lambda item: (-item[1], item[0]))
    return ipaddress.ip_network(best[0])
