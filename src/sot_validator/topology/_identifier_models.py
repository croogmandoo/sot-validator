"""Role identifier records: HostIdentification and ConsolidatedRouter."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Optional

from sot_validator.models import (
    NetworkDevice,
    Port,
    _require_non_empty_str,
)
from sot_validator.topology._identifier_helpers import (
    VALID_HOST_ROLES,
    _normalize_optional_mac,
)
from sot_validator.topology.device_types import DeviceTypeCatalog

@dataclass
class HostIdentification:
    """Evaluated network role and VLAN/subnet metadata for a discovered host."""

    ip: str
    role: str
    confidence: float
    mac: Optional[str] = None
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    open_ports: list[int] = field(default_factory=list)
    subnet_cidr: Optional[str] = None
    inferred_vlan_id: Optional[str] = None
    is_gateway_ip: bool = False
    suggested_template_id: Optional[str] = None
    reasons: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        _require_non_empty_str(self.ip, "ip")
        _require_non_empty_str(self.role, "role")
        normalized_role = self.role.strip().lower()
        if normalized_role not in VALID_HOST_ROLES:
            raise ValueError(
                f"Invalid host role {self.role!r}; must be one of {VALID_HOST_ROLES}"
            )
        self.role = normalized_role

        if isinstance(self.confidence, bool) or not isinstance(
            self.confidence, (int, float)
        ):
            raise ValueError("confidence must be a float between 0.0 and 1.0")
        self.confidence = float(self.confidence)
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("confidence must be between 0.0 and 1.0")

        self.mac = _normalize_optional_mac(self.mac)
        self.open_ports = [int(p) for p in self.open_ports]
        self.reasons = [str(r) for r in self.reasons]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "role": self.role,
            "confidence": self.confidence,
            "mac": self.mac,
            "vendor": self.vendor,
            "hostname": self.hostname,
            "open_ports": list(self.open_ports),
            "subnet_cidr": self.subnet_cidr,
            "inferred_vlan_id": self.inferred_vlan_id,
            "is_gateway_ip": self.is_gateway_ip,
            "suggested_template_id": self.suggested_template_id,
            "reasons": list(self.reasons),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> HostIdentification:
        return cls(
            ip=data["ip"],
            role=data["role"],
            confidence=data.get("confidence", 0.5),
            mac=data.get("mac"),
            vendor=data.get("vendor"),
            hostname=data.get("hostname"),
            open_ports=list(data.get("open_ports", [])),
            subnet_cidr=data.get("subnet_cidr"),
            inferred_vlan_id=data.get("inferred_vlan_id"),
            is_gateway_ip=bool(data.get("is_gateway_ip", False)),
            suggested_template_id=data.get("suggested_template_id"),
            reasons=list(data.get("reasons", [])),
        )


@dataclass
class ConsolidatedRouter:
    """Multi-VLAN router consolidated from multiple gateway interfaces across subnets."""

    router_id: str
    hostname: Optional[str]
    primary_ip: str
    gateway_ips: list[str]
    mac_addresses: list[str]
    subnet_cidrs: list[str]
    vlan_ids: list[str]
    vendor: Optional[str] = None
    suggested_template_id: str = "unifi-multi-vlan-router"

    def __post_init__(self) -> None:
        _require_non_empty_str(self.router_id, "router_id")
        _require_non_empty_str(self.primary_ip, "primary_ip")
        self.gateway_ips = list(self.gateway_ips)
        self.mac_addresses = [
            norm
            for m in self.mac_addresses
            if (norm := _normalize_optional_mac(m)) is not None
        ]
        self.subnet_cidrs = list(self.subnet_cidrs)
        self.vlan_ids = [str(v) for v in self.vlan_ids]

    def to_dict(self) -> dict[str, Any]:
        return {
            "router_id": self.router_id,
            "hostname": self.hostname,
            "primary_ip": self.primary_ip,
            "gateway_ips": list(self.gateway_ips),
            "mac_addresses": list(self.mac_addresses),
            "subnet_cidrs": list(self.subnet_cidrs),
            "vlan_ids": list(self.vlan_ids),
            "vendor": self.vendor,
            "suggested_template_id": self.suggested_template_id,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ConsolidatedRouter:
        return cls(
            router_id=data["router_id"],
            hostname=data.get("hostname"),
            primary_ip=data["primary_ip"],
            gateway_ips=list(data.get("gateway_ips", [])),
            mac_addresses=list(data.get("mac_addresses", [])),
            subnet_cidrs=list(data.get("subnet_cidrs", [])),
            vlan_ids=list(data.get("vlan_ids", [])),
            vendor=data.get("vendor"),
            suggested_template_id=data.get(
                "suggested_template_id", "unifi-multi-vlan-router"
            ),
        )

    def to_network_device(
        self,
        site_id: str,
        catalog: Optional[DeviceTypeCatalog] = None,
    ) -> NetworkDevice:
        """Create a canonical router NetworkDevice with one Port per VLAN/gateway interface."""
        _require_non_empty_str(site_id, "site_id")
        resolved_catalog = catalog if catalog is not None else DeviceTypeCatalog()
        try:
            template = resolved_catalog.get(self.suggested_template_id)
            vendor = self.vendor or template.vendor
            model = template.model
            role = template.role
            naming_pattern = template.port_naming_pattern
        except KeyError:
            vendor = self.vendor or "Ubiquiti"
            model = "UniFi Gateway Enterprise"
            role = "router"
            naming_pattern = "eth{n}"

        interface_count = max(len(self.gateway_ips), len(self.vlan_ids), 1)
        ports: list[Port] = []
        for idx in range(interface_count):
            port_num = idx + 1
            port_name = (
                naming_pattern.format(n=port_num)
                if "{n}" in naming_pattern
                else f"eth{port_num}"
            )
            vlan_id = (
                self.vlan_ids[idx]
                if idx < len(self.vlan_ids)
                else (self.vlan_ids[0] if self.vlan_ids else None)
            )
            mac = (
                self.mac_addresses[idx]
                if idx < len(self.mac_addresses)
                else (self.mac_addresses[0] if self.mac_addresses else None)
            )
            ports.append(
                Port(
                    port_id=f"{self.router_id}:{port_name}",
                    device_id=self.router_id,
                    name=port_name,
                    admin_status="up",
                    oper_status="up",
                    poe_status=None,
                    connected_device_id=None,
                    connected_mac=mac,
                    vlan_id=vlan_id,
                )
            )

        return NetworkDevice(
            device_id=self.router_id,
            site_id=site_id,
            hostname=self.hostname or self.router_id,
            management_ip=self.primary_ip,
            vendor=vendor,
            model=model,
            role=role,
            ports=ports,
        )
