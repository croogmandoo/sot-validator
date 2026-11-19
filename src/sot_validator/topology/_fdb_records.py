"""FDB entry records, port classification results, constants and helpers for the FDB mapper."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
import json
import re
from typing import Any, Optional

from sot_validator.models import (
    NetworkDevice,
    Port,
    Site,
    _require_non_empty_str,
)
from sot_validator.topology.device_types import normalize_mac_address

VALID_PORT_MODES: tuple[str, ...] = ("access", "trunk", "uplink", "empty")

_ROUTER_ROLES: frozenset[str] = frozenset(
    {"router", "l3_switch", "firewall", "gateway"}
)
_ROUTER_HOSTNAME_TOKENS: frozenset[str] = frozenset(
    {"router", "gw", "gateway", "rtr", "udm", "edge"}
)
_SWITCH_HOSTNAME_TOKENS: frozenset[str] = frozenset(
    {"sw", "switch", "idf", "mdf", "exos", "voss", "core"}
)
_IGNORED_PORT_TOKENS: frozenset[str] = frozenset(
    {
        "cpu",
        "router",
        "switch",
        "sup-eth1(r)",
        "sup-eth1",
        "vl1",
        "drop",
        "blackhole",
        "self",
        "none",
        "-",
        "m",
        "d",
        "s",
        "p",
        "b",
        "i",
        "l",
        "dynamic",
        "static",
        "permanent",
        "learned",
        "mgmt",
        "self-ip",
    }
)
_MAC_CANDIDATE_PATTERN = re.compile(
    r"^(?:[0-9a-fA-F]{2}(?:[:\-][0-9a-fA-F]{2}){5}|[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}|[0-9a-fA-F]{12})$"
)
_PAREN_VLAN_PATTERN = re.compile(r"\((\d{1,4})\)")
_VLAN_SUFFIX_PATTERN = re.compile(r"(?:vlan|vl)[_\-]?(\d{1,4})$", re.IGNORECASE)
_VOSS_PORT_PREFIX_PATTERN = re.compile(r"^port[\-_]?(\d+/\d+(?:/\d+)?)$", re.IGNORECASE)
_QBRIDGE_FDB_OID_PATTERN = re.compile(
    r"^\.?(?:1\.3\.6\.1\.2\.1\.17\.7\.1\.2\.2\.1\.2|dot1qTpFdbPort)\.(\d+)\.(\d+)\.(\d+)\.(\d+)\.(\d+)\.(\d+)\.(\d+)$"
)
_BRIDGE_FDB_OID_PATTERN = re.compile(
    r"^\.?(?:1\.3\.6\.1\.2\.1\.17\.4\.3\.1\.2|dot1dTpFdbPort)\.(\d+)\.(\d+)\.(\d+)\.(\d+)\.(\d+)\.(\d+)$"
)
_HOSTNAME_TRAILING_DIGITS_PATTERN = re.compile(r"\d+$")


def _parse_mac_token(raw: Any) -> Optional[str]:
    """Normalize a token only when it is shaped like a full MAC address (CLI-safe)."""
    if not isinstance(raw, str) or not raw.strip():
        return None
    cleaned = raw.strip()
    if not _MAC_CANDIDATE_PATTERN.match(cleaned):
        return None
    try:
        return normalize_mac_address(cleaned)
    except ValueError:
        return None


def _parse_static_flag(value: Any) -> bool:
    """Parse FDB static/status values (bool, Q-BRIDGE status int, or string)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        # Q-BRIDGE-MIB dot1qTpFdbStatus: 1=other, 2=invalid, 3=learned, 4=self, 5=mgmt
        return value in (4, 5)
    if isinstance(value, str):
        return value.strip().lower() in ("static", "permanent", "mgmt", "4", "5", "true")
    return False


def _normalize_vlan_id(raw: Any) -> Optional[str]:
    if raw is None or isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return str(raw) if raw > 0 else None
    text = str(raw).strip()
    if not text:
        return None
    m_paren = _PAREN_VLAN_PATTERN.search(text)
    if m_paren:
        val = int(m_paren.group(1))
        return str(val) if val > 0 else None
    m_suffix = _VLAN_SUFFIX_PATTERN.search(text)
    if m_suffix:
        val = int(m_suffix.group(1))
        return str(val) if val > 0 else None
    if text.isdigit():
        val = int(text)
        return str(val) if val > 0 else None
    return text


def _normalize_voss_port_name(raw_port: str) -> str:
    cleaned = raw_port.strip()
    m = _VOSS_PORT_PREFIX_PATTERN.match(cleaned)
    if m:
        return m.group(1)
    return cleaned


def _is_ignored_port_token(token: str) -> bool:
    cleaned = token.strip().lower()
    if not cleaned or cleaned in _IGNORED_PORT_TOKENS:
        return True
    if cleaned.startswith("sup-eth") or cleaned.startswith("cpu"):
        return True
    if re.match(r"^vl(?:an)?\d+$", cleaned):
        return True
    return False


def _looks_like_port_name(token: str) -> bool:
    cleaned = token.strip()
    if not cleaned or _is_ignored_port_token(cleaned):
        return False
    if _parse_mac_token(cleaned) is not None:
        return False
    # Common switch port formats: 1:1, 1/1, Gi1/0/1, Port-1/1, eth1, Po1, lag1, etc.
    if re.match(r"^\d+[:/]\d+(?:[:/]\d+)*$", cleaned):
        return True
    if _VOSS_PORT_PREFIX_PATTERN.match(cleaned):
        return True
    if re.match(
        r"^(?:gi|fa|te|tw|fo|hu|et|eth|ge|xe|po|port-channel|lag|mlt|trk|bridge|br|eno|ens|enp)[a-z0-9\-_/:.]*$",
        cleaned,
        re.IGNORECASE,
    ):
        return True
    return False


def _site_gateway_ips(site: Site) -> set[str]:
    gateway_ips: set[str] = set()
    for v in site.vlans:
        if v.gateway and v.gateway.strip():
            gateway_ips.add(v.gateway.strip())
    for s in site.subnets:
        if s.gateway and s.gateway.strip():
            gateway_ips.add(s.gateway.strip())
    return gateway_ips


def _unlink_port_from_equipment(site: Site, dev: NetworkDevice, port: Port) -> None:
    """Remove references to `port` from every `Equipment.connected_ports` in `site`."""
    refs = {port.port_id, f"{dev.device_id}:{port.name}", f"{dev.hostname}:{port.name}"}
    # A bare port name is only cleared when it identifies this port uniquely in the site
    name_is_unique = not any(
        p.name == port.name
        for d in site.devices
        for p in d.ports
        if p is not port
    )
    if name_is_unique:
        refs.add(port.name)
    for eq in site.equipment:
        if any(ref in refs for ref in eq.connected_ports):
            eq.connected_ports = [ref for ref in eq.connected_ports if ref not in refs]


def _deduplicate_entries(entries: Sequence[FdbEntry]) -> list[FdbEntry]:
    seen: dict[tuple[str, str, str, Optional[str]], FdbEntry] = {}
    ordered_keys: list[tuple[str, str, str, Optional[str]]] = []
    for entry in entries:
        key = (
            entry.device_id,
            entry.port_name,
            entry.mac_address,
            entry.vlan_id,
        )
        if key not in seen:
            seen[key] = entry
            ordered_keys.append(key)
        elif entry.is_static and not seen[key].is_static:
            seen[key] = entry
    return [seen[k] for k in ordered_keys]


@dataclass
class FdbEntry:
    """Normalized switch Forwarding Database (FDB) / Bridge-MIB MAC table entry."""

    device_id: str
    port_name: str
    mac_address: str
    vlan_id: Optional[str] = None
    is_static: bool = False

    def __post_init__(self) -> None:
        _require_non_empty_str(self.device_id, "device_id")
        _require_non_empty_str(self.port_name, "port_name")
        self.device_id = self.device_id.strip()
        self.port_name = self.port_name.strip()
        self.mac_address = normalize_mac_address(self.mac_address)
        if self.vlan_id is not None:
            if isinstance(self.vlan_id, bool):
                raise ValueError("vlan_id must be a string, int, or None")
            cleaned_vlan = str(self.vlan_id).strip()
            self.vlan_id = cleaned_vlan if cleaned_vlan else None
        self.is_static = bool(self.is_static)

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "port_name": self.port_name,
            "mac_address": self.mac_address,
            "vlan_id": self.vlan_id,
            "is_static": self.is_static,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> FdbEntry:
        return cls(
            device_id=data["device_id"],
            port_name=data["port_name"],
            mac_address=data["mac_address"],
            vlan_id=data.get("vlan_id"),
            is_static=_parse_static_flag(data.get("is_static", False)),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> FdbEntry:
        return cls.from_dict(json.loads(raw))


@dataclass
class PortClassificationResult:
    """Inferred port mode (`access`, `trunk`, `uplink`, `empty`) and downstream binding metadata."""

    device_id: str
    port_name: str
    port_mode: str
    learned_mac_count: int = 0
    vlan_ids: list[str] = field(default_factory=list)
    bound_mac: Optional[str] = None
    bound_device_id: Optional[str] = None
    rationale: str = ""

    def __post_init__(self) -> None:
        _require_non_empty_str(self.device_id, "device_id")
        _require_non_empty_str(self.port_name, "port_name")
        _require_non_empty_str(self.port_mode, "port_mode")
        self.device_id = self.device_id.strip()
        self.port_name = self.port_name.strip()

        normalized_mode = self.port_mode.strip().lower()
        if normalized_mode not in VALID_PORT_MODES:
            raise ValueError(
                f"Invalid port_mode {self.port_mode!r}; must be one of {VALID_PORT_MODES}"
            )
        self.port_mode = normalized_mode

        if (
            isinstance(self.learned_mac_count, bool)
            or not isinstance(self.learned_mac_count, int)
            or self.learned_mac_count < 0
        ):
            raise ValueError("learned_mac_count must be a non-negative integer")

        dedup_vlans: list[str] = []
        for v in self.vlan_ids or []:
            if v is None or isinstance(v, bool):
                continue
            v_str = str(v).strip()
            if v_str and v_str not in dedup_vlans:
                dedup_vlans.append(v_str)
        self.vlan_ids = dedup_vlans

        if self.bound_mac is not None:
            self.bound_mac = normalize_mac_address(self.bound_mac)

        if self.bound_device_id is not None:
            cleaned_dev = str(self.bound_device_id).strip()
            self.bound_device_id = cleaned_dev if cleaned_dev else None

        self.rationale = str(self.rationale) if self.rationale is not None else ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "port_name": self.port_name,
            "port_mode": self.port_mode,
            "learned_mac_count": self.learned_mac_count,
            "vlan_ids": list(self.vlan_ids),
            "bound_mac": self.bound_mac,
            "bound_device_id": self.bound_device_id,
            "rationale": self.rationale,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PortClassificationResult:
        return cls(
            device_id=data["device_id"],
            port_name=data["port_name"],
            port_mode=data["port_mode"],
            learned_mac_count=data.get("learned_mac_count", 0),
            vlan_ids=list(data.get("vlan_ids", [])),
            bound_mac=data.get("bound_mac"),
            bound_device_id=data.get("bound_device_id"),
            rationale=data.get("rationale", ""),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> PortClassificationResult:
        return cls.from_dict(json.loads(raw))
