"""Forward/reverse DNS record and DHCP lease record types."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from sot_validator.signals._directory_common import (
    _clean_optional_str,
    _parse_bool_flag,
    normalize_hostname,
)
from sot_validator.signals.base import normalize_utc_datetime, resolve_evaluation_time
from sot_validator.signals.icmp import _parse_ipv4_host


@dataclass(init=False)
class DnsRecord:
    """Forward ('A') or reverse ('PTR') DNS record."""

    record_type: str
    hostname: str
    ip: str
    ttl: Optional[int] = None
    observed_at: Optional[datetime] = None

    def __init__(
        self,
        record_type: str = "A",
        hostname: Optional[str] = None,
        ip: Optional[str] = None,
        ttl: Optional[int] = None,
        observed_at: Optional[datetime | str] = None,
        *,
        type: Optional[str] = None,
        name: Optional[str] = None,
        fqdn: Optional[str] = None,
        ptrdname: Optional[str] = None,
        target: Optional[str] = None,
        ip_address: Optional[str] = None,
        address: Optional[str] = None,
    ) -> None:
        raw_type = _clean_optional_str(type if type is not None else record_type)
        if not raw_type:
            raise ValueError("record_type must be 'A' or 'PTR'")
        norm_type = raw_type.upper()
        if norm_type not in ("A", "PTR"):
            raise ValueError(f"Unsupported DNS record_type {raw_type!r}; expected 'A' or 'PTR'")

        raw_host = _clean_optional_str(
            hostname
            if hostname is not None
            else (name or fqdn or ptrdname or target)
        )
        if not raw_host:
            raise ValueError("DNS record hostname must be a non-empty string")

        raw_ip = _clean_optional_str(
            ip if ip is not None else (ip_address or address)
        )
        if not raw_ip:
            raise ValueError("DNS record ip must be a non-empty string")
        parsed_ip = _parse_ipv4_host(raw_ip)

        self.record_type = norm_type
        self.hostname = raw_host
        self.ip = str(parsed_ip)
        self.ttl = int(ttl) if ttl is not None else None
        if observed_at is not None and (
            not isinstance(observed_at, str) or observed_at.strip()
        ):
            self.observed_at = normalize_utc_datetime(
                observed_at, field_name="observed_at"
            )
        else:
            self.observed_at = None

    @property
    def normalized_hostname(self) -> Optional[str]:
        return normalize_hostname(self.hostname)

    @property
    def ip_address(self) -> str:
        return self.ip

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": self.record_type,
            "hostname": self.hostname,
            "ip": self.ip,
            "ttl": self.ttl,
            "observed_at": (
                self.observed_at.isoformat() if self.observed_at is not None else None
            ),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DnsRecord:
        return cls(
            record_type=data.get("record_type") or data.get("type") or "A",
            hostname=(
                data.get("hostname")
                or data.get("name")
                or data.get("fqdn")
                or data.get("ptrdname")
                or data.get("target")
            ),
            ip=data.get("ip") or data.get("ip_address") or data.get("address"),
            ttl=data.get("ttl"),
            observed_at=data.get("observed_at"),
        )


@dataclass(init=False)
class DhcpLeaseRecord:
    """DHCP lease record scoped to a site's /24 IPv4 subnet."""

    ip: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    subnet_cidr: Optional[str] = None
    status: str = "active"
    lease_expiration: Optional[datetime] = None
    observed_at: Optional[datetime] = None

    def __init__(
        self,
        ip: Optional[str] = None,
        hostname: Optional[str] = None,
        mac_address: Optional[str] = None,
        subnet_cidr: Optional[str] = None,
        status: Optional[str] = None,
        lease_expiration: Optional[datetime | str] = None,
        observed_at: Optional[datetime | str] = None,
        *,
        ip_address: Optional[str] = None,
        client_hostname: Optional[str] = None,
        name: Optional[str] = None,
        fqdn: Optional[str] = None,
        mac: Optional[str] = None,
        client_mac: Optional[str] = None,
        subnet: Optional[str] = None,
        cidr: Optional[str] = None,
        scope: Optional[str] = None,
        active: Optional[bool] = None,
        expires_at: Optional[datetime | str] = None,
        lease_end: Optional[datetime | str] = None,
        expiration: Optional[datetime | str] = None,
        last_seen: Optional[datetime | str] = None,
        timestamp: Optional[datetime | str] = None,
    ) -> None:
        raw_ip = _clean_optional_str(ip if ip is not None else ip_address)
        if not raw_ip:
            raise ValueError("DHCP lease ip must be a non-empty string")
        parsed_ip = _parse_ipv4_host(raw_ip)
        self.ip = str(parsed_ip)

        self.hostname = _clean_optional_str(
            hostname
            if hostname is not None
            else (client_hostname or name or fqdn)
        )
        self.mac_address = _clean_optional_str(
            mac_address if mac_address is not None else (mac or client_mac)
        )
        self.subnet_cidr = _clean_optional_str(
            subnet_cidr
            if subnet_cidr is not None
            else (subnet or cidr or scope)
        )

        if status is not None and str(status).strip():
            self.status = str(status).strip().lower()
        elif active is not None:
            self.status = "active" if _parse_bool_flag(active) else "expired"
        else:
            self.status = "active"

        raw_exp = (
            lease_expiration
            if lease_expiration is not None
            else (expires_at or lease_end or expiration)
        )
        if raw_exp is not None and (not isinstance(raw_exp, str) or raw_exp.strip()):
            self.lease_expiration = normalize_utc_datetime(
                raw_exp, field_name="lease_expiration"
            )
        else:
            self.lease_expiration = None

        raw_obs = (
            observed_at
            if observed_at is not None
            else (last_seen or timestamp)
        )
        if raw_obs is not None and (not isinstance(raw_obs, str) or raw_obs.strip()):
            self.observed_at = normalize_utc_datetime(
                raw_obs, field_name="observed_at"
            )
        else:
            self.observed_at = None

    @property
    def ip_address(self) -> str:
        return self.ip

    @property
    def client_hostname(self) -> Optional[str]:
        return self.hostname

    @property
    def normalized_hostname(self) -> Optional[str]:
        return normalize_hostname(self.hostname)

    def is_active(
        self, evaluation_time: Optional[datetime | str] = None
    ) -> bool:
        """Return True if the DHCP lease status is active and not expired."""
        norm_status = self.status.strip().lower()
        if norm_status in (
            "expired",
            "inactive",
            "free",
            "released",
            "abandoned",
            "disabled",
            "false",
            "0",
        ):
            return False
        if norm_status not in (
            "active",
            "bound",
            "leased",
            "reserved",
            "true",
            "1",
        ):
            return False

        if self.lease_expiration is not None:
            if evaluation_time is not None:
                eval_dt = resolve_evaluation_time(evaluation_time)
                if self.lease_expiration <= eval_dt:
                    return False
            elif (
                self.observed_at is not None
                and self.lease_expiration <= self.observed_at
            ):
                return False
        return True

    @property
    def active(self) -> bool:
        return self.is_active()

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "mac_address": self.mac_address,
            "subnet_cidr": self.subnet_cidr,
            "status": self.status,
            "lease_expiration": (
                self.lease_expiration.isoformat()
                if self.lease_expiration is not None
                else None
            ),
            "observed_at": (
                self.observed_at.isoformat() if self.observed_at is not None else None
            ),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DhcpLeaseRecord:
        return cls(
            ip=data.get("ip") or data.get("ip_address"),
            hostname=(
                data.get("hostname")
                or data.get("client_hostname")
                or data.get("name")
                or data.get("fqdn")
            ),
            mac_address=(
                data.get("mac_address")
                or data.get("mac")
                or data.get("client_mac")
            ),
            subnet_cidr=(
                data.get("subnet_cidr")
                or data.get("subnet")
                or data.get("cidr")
                or data.get("scope")
            ),
            status=data.get("status"),
            active=data.get("active"),
            lease_expiration=(
                data.get("lease_expiration")
                if data.get("lease_expiration") is not None
                else (
                    data.get("expires_at")
                    or data.get("lease_end")
                    or data.get("expiration")
                )
            ),
            observed_at=(
                data.get("observed_at")
                if data.get("observed_at") is not None
                else (data.get("last_seen") or data.get("timestamp"))
            ),
        )
