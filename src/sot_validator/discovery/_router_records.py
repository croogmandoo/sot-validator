"""Normalized router ARP/neighbor and DHCP lease record dataclasses."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from sot_validator.discovery._router_common import (
    _canonical_ipv4,
    _coerce_datetime,
    _format_dt,
    _normalize_router_mac,
    _optional_name,
    _optional_token,
    _parse_lease_expiry,
)


@dataclass
class RouterArpRecord:
    """Normalized ARP/neighbor entry read from a gateway router or L3 switch."""

    ip: str
    mac_address: Optional[str] = None
    interface: Optional[str] = None
    vlan_id: Optional[str] = None
    state: Optional[str] = "REACHABLE"
    router_id: Optional[str] = None
    observed_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        self.ip = _canonical_ipv4(self.ip)
        self.mac_address = _normalize_router_mac(self.mac_address)
        self.interface = _optional_token(self.interface, "interface")
        self.vlan_id = _optional_token(self.vlan_id, "vlan_id")
        if self.state is not None:
            if not isinstance(self.state, str):
                raise ValueError("state must be a string or None")
            cleaned_state = self.state.strip().upper()
            self.state = cleaned_state if cleaned_state else None
        self.router_id = _optional_token(self.router_id, "router_id")
        self.observed_at = _coerce_datetime(self.observed_at, "observed_at")

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "mac_address": self.mac_address,
            "interface": self.interface,
            "vlan_id": self.vlan_id,
            "state": self.state,
            "router_id": self.router_id,
            "observed_at": _format_dt(self.observed_at),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RouterArpRecord:
        return cls(
            ip=data["ip"],
            mac_address=data.get("mac_address"),
            interface=data.get("interface"),
            vlan_id=data.get("vlan_id"),
            state=data.get("state", "REACHABLE"),
            router_id=data.get("router_id"),
            observed_at=data.get("observed_at"),
        )


@dataclass
class DhcpLeaseRecord:
    """Normalized DHCPv4 lease read from a DHCP server lease table or export."""

    ip: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    lease_expires_at: Optional[datetime] = None
    subnet_id: Optional[str] = None
    client_id: Optional[str] = None

    def __post_init__(self) -> None:
        self.ip = _canonical_ipv4(self.ip)
        self.mac_address = _normalize_router_mac(self.mac_address)
        self.hostname = _optional_name(self.hostname, "hostname")
        self.lease_expires_at = _parse_lease_expiry(self.lease_expires_at)
        self.subnet_id = _optional_token(self.subnet_id, "subnet_id")
        self.client_id = _optional_name(self.client_id, "client_id")

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "mac_address": self.mac_address,
            "hostname": self.hostname,
            "lease_expires_at": _format_dt(self.lease_expires_at),
            "subnet_id": self.subnet_id,
            "client_id": self.client_id,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DhcpLeaseRecord:
        return cls(
            ip=data["ip"],
            mac_address=data.get("mac_address"),
            hostname=data.get("hostname"),
            lease_expires_at=data.get("lease_expires_at"),
            subnet_id=data.get("subnet_id"),
            client_id=data.get("client_id"),
        )
