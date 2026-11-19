"""LLDP neighbor, guard decision and blocked port records for port reclamation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import json
from typing import Any, Optional

from sot_validator.models import _require_non_empty_str
from sot_validator.remediation._port_reclamation_common import (
    _clean_optional_str,
    _decode_lldp_capabilities,
    _normalize_str_tuple,
)


@dataclass(frozen=True)
class LldpNeighborRecord:
    """Normalized LLDP or CDP neighbor discovery record associated with a switch port."""

    port_id: Optional[str] = None
    port_name: Optional[str] = None
    lldp_rem_sys_name: Optional[str] = None
    lldp_rem_sys_cap_enabled: tuple[str, ...] = ()
    neighbor_device_role: Optional[str] = None
    lldp_rem_sys_desc: Optional[str] = None
    neighbor_port_id: Optional[str] = None
    protocol: str = "lldp"

    def __init__(
        self,
        port_id: Optional[str] = None,
        port_name: Optional[str] = None,
        lldp_rem_sys_name: Optional[str] = None,
        lldp_rem_sys_cap_enabled: Any = (),
        neighbor_device_role: Optional[str] = None,
        lldp_rem_sys_desc: Optional[str] = None,
        neighbor_port_id: Optional[str] = None,
        protocol: str = "lldp",
        *,
        lldpRemSysName: Optional[str] = None,
        lldpRemSysCapEnabled: Any = None,
        lldpRemSysDesc: Optional[str] = None,
        sys_name: Optional[str] = None,
        neighbor_name: Optional[str] = None,
        device_id: Optional[str] = None,
        chassis_id: Optional[str] = None,
        capabilities: Any = None,
        sys_capabilities: Any = None,
        neighbor_role: Optional[str] = None,
        device_role: Optional[str] = None,
        role: Optional[str] = None,
        sys_descr: Optional[str] = None,
        platform: Optional[str] = None,
        local_port: Optional[str] = None,
        remote_port: Optional[str] = None,
    ) -> None:
        resolved_port_id = _clean_optional_str(port_id)
        resolved_port_name = _clean_optional_str(port_name or local_port)
        resolved_sys_name = _clean_optional_str(
            lldp_rem_sys_name
            or lldpRemSysName
            or sys_name
            or neighbor_name
            or device_id
            or chassis_id
        )
        raw_caps = (
            lldp_rem_sys_cap_enabled
            if lldp_rem_sys_cap_enabled not in ((), None)
            else (
                lldpRemSysCapEnabled
                if lldpRemSysCapEnabled is not None
                else (
                    capabilities
                    if capabilities is not None
                    else sys_capabilities
                )
            )
        )
        resolved_caps = _decode_lldp_capabilities(raw_caps)
        resolved_role = _clean_optional_str(
            neighbor_device_role or neighbor_role or device_role or role
        )
        resolved_desc = _clean_optional_str(
            lldp_rem_sys_desc or lldpRemSysDesc or sys_descr or platform
        )
        resolved_neighbor_port = _clean_optional_str(
            neighbor_port_id or remote_port
        )
        resolved_protocol = (_clean_optional_str(protocol) or "lldp").lower()

        object.__setattr__(self, "port_id", resolved_port_id)
        object.__setattr__(self, "port_name", resolved_port_name)
        object.__setattr__(self, "lldp_rem_sys_name", resolved_sys_name)
        object.__setattr__(self, "lldp_rem_sys_cap_enabled", resolved_caps)
        object.__setattr__(self, "neighbor_device_role", resolved_role)
        object.__setattr__(self, "lldp_rem_sys_desc", resolved_desc)
        object.__setattr__(self, "neighbor_port_id", resolved_neighbor_port)
        object.__setattr__(self, "protocol", resolved_protocol)

    @property
    def lldpRemSysName(self) -> Optional[str]:
        """MIB-style alias for lldp_rem_sys_name."""
        return self.lldp_rem_sys_name

    @property
    def lldpRemSysCapEnabled(self) -> tuple[str, ...]:
        """MIB-style alias for lldp_rem_sys_cap_enabled."""
        return self.lldp_rem_sys_cap_enabled

    @property
    def lldpRemSysDesc(self) -> Optional[str]:
        """MIB-style alias for lldp_rem_sys_desc."""
        return self.lldp_rem_sys_desc

    @property
    def sys_name(self) -> Optional[str]:
        """Alias for lldp_rem_sys_name."""
        return self.lldp_rem_sys_name

    @property
    def capabilities(self) -> tuple[str, ...]:
        """Alias for lldp_rem_sys_cap_enabled."""
        return self.lldp_rem_sys_cap_enabled

    @property
    def role(self) -> Optional[str]:
        """Alias for neighbor_device_role."""
        return self.neighbor_device_role

    def to_dict(self) -> dict[str, Any]:
        return {
            "port_id": self.port_id,
            "port_name": self.port_name,
            "lldp_rem_sys_name": self.lldp_rem_sys_name,
            "lldp_rem_sys_cap_enabled": list(self.lldp_rem_sys_cap_enabled),
            "neighbor_device_role": self.neighbor_device_role,
            "lldp_rem_sys_desc": self.lldp_rem_sys_desc,
            "neighbor_port_id": self.neighbor_port_id,
            "protocol": self.protocol,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> LldpNeighborRecord:
        if isinstance(data, cls):
            return data
        return cls(
            port_id=data.get("port_id"),
            port_name=data.get("port_name") or data.get("local_port") or data.get("port"),
            lldp_rem_sys_name=(
                data.get("lldp_rem_sys_name")
                or data.get("lldpRemSysName")
                or data.get("sys_name")
                or data.get("neighbor_name")
                or data.get("device_id")
                or data.get("chassis_id")
            ),
            lldp_rem_sys_cap_enabled=(
                data.get("lldp_rem_sys_cap_enabled")
                if "lldp_rem_sys_cap_enabled" in data
                else (
                    data.get("lldpRemSysCapEnabled")
                    if "lldpRemSysCapEnabled" in data
                    else (
                        data.get("capabilities")
                        if "capabilities" in data
                        else data.get("sys_capabilities")
                    )
                )
            ),
            neighbor_device_role=(
                data.get("neighbor_device_role")
                or data.get("neighbor_role")
                or data.get("device_role")
                or data.get("role")
            ),
            lldp_rem_sys_desc=(
                data.get("lldp_rem_sys_desc")
                or data.get("lldpRemSysDesc")
                or data.get("sys_descr")
                or data.get("platform")
            ),
            neighbor_port_id=(
                data.get("neighbor_port_id")
                or data.get("lldp_rem_port_id")
                or data.get("lldpRemPortId")
                or data.get("remote_port")
            ),
            protocol=data.get("protocol", "lldp"),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> LldpNeighborRecord:
        return cls.from_dict(json.loads(raw))


@dataclass(frozen=True)
class LldpGuardDecision:
    """Safety evaluation result from LldpUplinkGuard for a candidate switch port."""

    port_id: str
    device_id: str
    port_name: str
    blocked: bool
    block_reason: Optional[str] = None
    block_reasons: tuple[str, ...] = ()
    matched_rules: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_non_empty_str(self.port_id, "port_id")
        _require_non_empty_str(self.device_id, "device_id")
        _require_non_empty_str(self.port_name, "port_name")
        object.__setattr__(self, "blocked", bool(self.blocked))

        reasons = _normalize_str_tuple(self.block_reasons)
        rules = _normalize_str_tuple(self.matched_rules)
        primary_reason = _clean_optional_str(self.block_reason)

        if self.blocked:
            if primary_reason is None and reasons:
                primary_reason = "; ".join(reasons)
            if primary_reason is None:
                raise ValueError(
                    "block_reason must be a non-empty string when blocked=True"
                )
            if not reasons:
                reasons = (primary_reason,)
        else:
            primary_reason = None
            reasons = ()
            rules = ()

        object.__setattr__(self, "block_reason", primary_reason)
        object.__setattr__(self, "block_reasons", reasons)
        object.__setattr__(self, "matched_rules", rules)

    @property
    def reason(self) -> Optional[str]:
        """Alias for block_reason."""
        return self.block_reason

    @property
    def allowed(self) -> bool:
        """Return True when the port passed all uplink guard checks."""
        return not self.blocked

    def to_dict(self) -> dict[str, Any]:
        return {
            "port_id": self.port_id,
            "device_id": self.device_id,
            "port_name": self.port_name,
            "blocked": self.blocked,
            "block_reason": self.block_reason,
            "block_reasons": list(self.block_reasons),
            "matched_rules": list(self.matched_rules),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> LldpGuardDecision:
        if isinstance(data, cls):
            return data
        return cls(
            port_id=data["port_id"],
            device_id=data["device_id"],
            port_name=data.get("port_name") or data.get("name", ""),
            blocked=bool(data["blocked"]),
            block_reason=data.get("block_reason"),
            block_reasons=tuple(data.get("block_reasons", ())),
            matched_rules=tuple(data.get("matched_rules", ())),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> LldpGuardDecision:
        return cls.from_dict(json.loads(raw))


@dataclass(frozen=True)
class BlockedPortRecord:
    """Audit record for a switch port blocked from reclamation by LldpUplinkGuard or streak policy."""

    port_id: str
    device_id: str
    port_name: str
    site_id: Optional[str] = None
    device_hostname: Optional[str] = None
    blocked: bool = True
    block_reason: str = ""
    block_reasons: tuple[str, ...] = ()
    matched_rules: tuple[str, ...] = ()
    admin_status: Optional[str] = None
    oper_status: Optional[str] = None
    poe_status: Optional[str] = None
    vlan_id: Optional[str] = None
    description: Optional[str] = None
    connected_device_id: Optional[str] = None
    inactive_runs: int = 0
    inactive_days: float = 0.0

    def __post_init__(self) -> None:
        _require_non_empty_str(self.port_id, "port_id")
        _require_non_empty_str(self.device_id, "device_id")
        _require_non_empty_str(self.port_name, "port_name")
        object.__setattr__(self, "blocked", bool(self.blocked))

        reasons = _normalize_str_tuple(self.block_reasons)
        rules = _normalize_str_tuple(self.matched_rules)
        primary_reason = _clean_optional_str(self.block_reason) or ""

        if not primary_reason and reasons:
            primary_reason = "; ".join(reasons)
        if self.blocked and not primary_reason:
            raise ValueError(
                "block_reason must be a non-empty string when blocked=True"
            )
        if primary_reason and not reasons:
            reasons = (primary_reason,)

        if isinstance(self.inactive_runs, bool) or not isinstance(
            self.inactive_runs, int
        ) or self.inactive_runs < 0:
            raise ValueError("inactive_runs must be a non-negative integer")
        if isinstance(self.inactive_days, bool) or not isinstance(
            self.inactive_days, (int, float)
        ) or float(self.inactive_days) < 0.0:
            raise ValueError("inactive_days must be a non-negative number")

        object.__setattr__(self, "block_reason", primary_reason)
        object.__setattr__(self, "block_reasons", reasons)
        object.__setattr__(self, "matched_rules", rules)
        object.__setattr__(self, "inactive_days", float(self.inactive_days))

    @property
    def name(self) -> str:
        """Alias for port_name."""
        return self.port_name

    @property
    def reason(self) -> str:
        """Alias for block_reason."""
        return self.block_reason

    @property
    def consecutive_stale_runs(self) -> int:
        """Alias for inactive_runs."""
        return self.inactive_runs

    @property
    def stale_duration_days(self) -> float:
        """Alias for inactive_days."""
        return self.inactive_days

    def to_dict(self) -> dict[str, Any]:
        return {
            "port_id": self.port_id,
            "device_id": self.device_id,
            "port_name": self.port_name,
            "site_id": self.site_id,
            "device_hostname": self.device_hostname,
            "blocked": self.blocked,
            "block_reason": self.block_reason,
            "block_reasons": list(self.block_reasons),
            "matched_rules": list(self.matched_rules),
            "admin_status": self.admin_status,
            "oper_status": self.oper_status,
            "poe_status": self.poe_status,
            "vlan_id": self.vlan_id,
            "description": self.description,
            "connected_device_id": self.connected_device_id,
            "inactive_runs": self.inactive_runs,
            "inactive_days": self.inactive_days,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> BlockedPortRecord:
        if isinstance(data, cls):
            return data
        return cls(
            port_id=data["port_id"],
            device_id=data["device_id"],
            port_name=data.get("port_name") or data.get("name", ""),
            site_id=data.get("site_id"),
            device_hostname=data.get("device_hostname"),
            blocked=bool(data.get("blocked", True)),
            block_reason=data.get("block_reason") or data.get("reason") or "",
            block_reasons=tuple(data.get("block_reasons", ())),
            matched_rules=tuple(data.get("matched_rules", ())),
            admin_status=data.get("admin_status"),
            oper_status=data.get("oper_status"),
            poe_status=data.get("poe_status"),
            vlan_id=data.get("vlan_id"),
            description=data.get("description"),
            connected_device_id=data.get("connected_device_id"),
            inactive_runs=int(
                data.get(
                    "inactive_runs", data.get("consecutive_stale_runs", 0)
                )
            ),
            inactive_days=float(
                data.get("inactive_days", data.get("stale_duration_days", 0.0))
            ),
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> BlockedPortRecord:
        return cls.from_dict(json.loads(raw))
