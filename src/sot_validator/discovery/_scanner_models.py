"""Discovery scanner host and configuration models."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
import ipaddress
from typing import Any, Optional

from sot_validator.discovery._scanner_common import (
    DEFAULT_GATEWAY_OCTETS,
    DEFAULT_TCP_PORTS,
    _normalize_mac,
)


@dataclass
class DiscoveredHost:
    """Host record discovered during a scoped /24 subnet sweep."""

    ip: str
    subnet_cidr: str
    vlan_id: str
    icmp_reachable: bool = False
    rtt_ms: Optional[float] = None
    open_tcp_ports: list[int] = field(default_factory=list)
    mac_address: Optional[str] = None
    arp_state: Optional[str] = None
    hostname: Optional[str] = None
    inferred_role: str = "host"

    def __post_init__(self) -> None:
        if not isinstance(self.ip, str) or not self.ip.strip():
            raise ValueError("ip must be a non-empty string")
        self.ip = str(ipaddress.IPv4Address(self.ip.strip()))

        if not isinstance(self.subnet_cidr, str) or not self.subnet_cidr.strip():
            raise ValueError("subnet_cidr must be a non-empty string")
        net = ipaddress.ip_network(self.subnet_cidr.strip(), strict=False)
        if not isinstance(net, ipaddress.IPv4Network):
            raise ValueError("subnet_cidr must be an IPv4 network")
        self.subnet_cidr = str(net)

        if isinstance(self.vlan_id, int) and not isinstance(self.vlan_id, bool):
            self.vlan_id = str(self.vlan_id)
        if not isinstance(self.vlan_id, str) or not self.vlan_id.strip():
            raise ValueError("vlan_id must be a non-empty string")
        self.vlan_id = self.vlan_id.strip()

        self.icmp_reachable = bool(self.icmp_reachable)
        if self.rtt_ms is not None:
            if isinstance(self.rtt_ms, bool) or not isinstance(
                self.rtt_ms, (int, float)
            ):
                raise ValueError("rtt_ms must be a number or None")
            self.rtt_ms = float(self.rtt_ms)

        if self.open_tcp_ports is None:
            self.open_tcp_ports = []
        else:
            normalized_ports: set[int] = set()
            for p in self.open_tcp_ports:
                if isinstance(p, bool) or not isinstance(p, int) or not (1 <= p <= 65535):
                    raise ValueError(f"Invalid TCP port: {p!r}")
                normalized_ports.add(p)
            self.open_tcp_ports = sorted(normalized_ports)

        self.mac_address = _normalize_mac(self.mac_address)
        if isinstance(self.arp_state, str):
            cleaned_state = self.arp_state.strip().upper()
            self.arp_state = cleaned_state if cleaned_state else None
        elif self.arp_state is not None:
            raise ValueError("arp_state must be a string or None")

        if isinstance(self.hostname, str):
            cleaned_host = self.hostname.strip()
            self.hostname = cleaned_host if cleaned_host else None
        elif self.hostname is not None:
            raise ValueError("hostname must be a string or None")

        if not isinstance(self.inferred_role, str) or not self.inferred_role.strip():
            self.inferred_role = "host"
        else:
            self.inferred_role = self.inferred_role.strip()

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "subnet_cidr": self.subnet_cidr,
            "vlan_id": self.vlan_id,
            "icmp_reachable": self.icmp_reachable,
            "rtt_ms": self.rtt_ms,
            "open_tcp_ports": list(self.open_tcp_ports),
            "mac_address": self.mac_address,
            "arp_state": self.arp_state,
            "hostname": self.hostname,
            "inferred_role": self.inferred_role,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DiscoveredHost:
        return cls(
            ip=data["ip"],
            subnet_cidr=data["subnet_cidr"],
            vlan_id=data["vlan_id"],
            icmp_reachable=bool(data.get("icmp_reachable", False)),
            rtt_ms=data.get("rtt_ms"),
            open_tcp_ports=list(data.get("open_tcp_ports", [])),
            mac_address=data.get("mac_address"),
            arp_state=data.get("arp_state"),
            hostname=data.get("hostname"),
            inferred_role=data.get("inferred_role", "host"),
        )


@dataclass
class DiscoveryConfig:
    """Configuration for two-stage /16-to-/24 subnet and host discovery."""

    cidr: str = "10.42.0.0/16"
    gateway_octets: tuple[int, ...] = DEFAULT_GATEWAY_OCTETS
    tcp_ports: tuple[int, ...] = DEFAULT_TCP_PORTS
    max_concurrency: int = 128
    ping_timeout_sec: float = 1.0
    tcp_timeout_sec: float = 0.35
    max_active_subnets: int = 32

    def __post_init__(self) -> None:
        if not isinstance(self.cidr, str) or not self.cidr.strip():
            raise ValueError("cidr must be a non-empty IPv4 /16 or /24 CIDR string")
        try:
            network = ipaddress.ip_network(self.cidr.strip(), strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR {self.cidr!r}: {exc}") from exc
        if not isinstance(network, ipaddress.IPv4Network) or network.prefixlen not in (
            16,
            24,
        ):
            raise ValueError(
                f"DiscoveryConfig.cidr must be an IPv4 /16 or /24 prefix, got {self.cidr!r}"
            )
        self.cidr = str(network)

        if isinstance(self.gateway_octets, (str, bytes)) or not isinstance(
            self.gateway_octets, Iterable
        ):
            raise ValueError("gateway_octets must be a non-empty sequence of integers")
        gw_list: list[int] = []
        for octet in self.gateway_octets:
            if (
                isinstance(octet, bool)
                or not isinstance(octet, int)
                or not (1 <= octet <= 254)
            ):
                raise ValueError(
                    f"gateway_octets entries must be integers in 1..254, got {octet!r}"
                )
            if octet not in gw_list:
                gw_list.append(octet)
        if not gw_list:
            raise ValueError("gateway_octets must not be empty")
        self.gateway_octets = tuple(gw_list)

        if isinstance(self.tcp_ports, (str, bytes)) or not isinstance(
            self.tcp_ports, Iterable
        ):
            raise ValueError("tcp_ports must be a sequence of integers in 1..65535")
        ports_list: list[int] = []
        for port in self.tcp_ports:
            if (
                isinstance(port, bool)
                or not isinstance(port, int)
                or not (1 <= port <= 65535)
            ):
                raise ValueError(
                    f"tcp_ports entries must be integers in 1..65535, got {port!r}"
                )
            if port not in ports_list:
                ports_list.append(port)
        self.tcp_ports = tuple(ports_list)

        if (
            isinstance(self.max_concurrency, bool)
            or not isinstance(self.max_concurrency, int)
            or self.max_concurrency < 1
        ):
            raise ValueError("max_concurrency must be an integer >= 1")

        if (
            isinstance(self.max_active_subnets, bool)
            or not isinstance(self.max_active_subnets, int)
            or self.max_active_subnets < 1
        ):
            raise ValueError("max_active_subnets must be an integer >= 1")

        if (
            isinstance(self.ping_timeout_sec, bool)
            or not isinstance(self.ping_timeout_sec, (int, float))
            or self.ping_timeout_sec <= 0
        ):
            raise ValueError("ping_timeout_sec must be a number > 0")
        self.ping_timeout_sec = float(self.ping_timeout_sec)

        if (
            isinstance(self.tcp_timeout_sec, bool)
            or not isinstance(self.tcp_timeout_sec, (int, float))
            or self.tcp_timeout_sec <= 0
        ):
            raise ValueError("tcp_timeout_sec must be a number > 0")
        self.tcp_timeout_sec = float(self.tcp_timeout_sec)

