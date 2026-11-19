"""LLDP uplink guard blocking reclamation of infrastructure and active ports."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
import re
from typing import Any, Optional

from sot_validator.models import (
    ArpEntry,
    Equipment,
    EquipmentCategory,
    IPAddress,
    NetworkDevice,
    Port,
    Site,
)
from sot_validator.remediation._port_reclamation_common import (
    DEFAULT_BLOCKED_LLDP_CAPABILITIES,
    DEFAULT_CRITICAL_INFRASTRUCTURE_KEYWORDS,
    _LLDP_INFRASTRUCTURE_ROLES_AND_KEYWORDS,
    _clean_optional_str,
    _coerce_port_and_extras,
)
from sot_validator.remediation._port_reclamation_lldp import _LldpNeighborResolverMixin
from sot_validator.remediation._port_reclamation_records import (
    LldpGuardDecision,
    LldpNeighborRecord,
)
from sot_validator.signals.arp import _normalize_mac
from sot_validator.signals.base import (
    SECONDS_PER_DAY,
    normalize_utc_datetime,
    resolve_evaluation_time,
)
from sot_validator.signals.port_state import _OPER_ACTIVE_VALUES


class LldpUplinkGuard(_LldpNeighborResolverMixin):
    """Safety guard blocking reclamation of uplinks, trunks, WAPs, UPSs, and active ports."""

    def __init__(
        self,
        *,
        critical_keywords: Iterable[str] = DEFAULT_CRITICAL_INFRASTRUCTURE_KEYWORDS,
        blocked_capabilities: Iterable[str] = DEFAULT_BLOCKED_LLDP_CAPABILITIES,
        arp_active_within_days: float = 30.0,
    ) -> None:
        if isinstance(arp_active_within_days, bool) or not isinstance(
            arp_active_within_days, (int, float)
        ) or float(arp_active_within_days) < 0.0:
            raise ValueError(
                "arp_active_within_days must be a non-negative number"
            )
        self.critical_keywords: tuple[str, ...] = tuple(
            kw.strip().lower()
            for kw in critical_keywords
            if isinstance(kw, str) and kw.strip()
        )
        self.blocked_capabilities: tuple[str, ...] = tuple(
            cap.strip().lower()
            for cap in blocked_capabilities
            if isinstance(cap, str) and cap.strip()
        )
        self.arp_active_within_days: float = float(arp_active_within_days)

    def evaluate_port(
        self,
        port: Port | Mapping[str, Any],
        *,
        device: Optional[NetworkDevice | Mapping[str, Any]] = None,
        site: Optional[Site | Mapping[str, Any]] = None,
        description: Optional[str] = None,
        tagged_vlans: Optional[Iterable[str | int]] = None,
        is_trunk: Optional[bool] = None,
        vlan_mode: Optional[str] = None,
        lldp_neighbors: Optional[
            LldpNeighborRecord
            | Mapping[str, Any]
            | Sequence[LldpNeighborRecord | Mapping[str, Any]]
        ] = None,
        mapped_equipment: Optional[
            Equipment
            | NetworkDevice
            | Mapping[str, Any]
            | Sequence[Equipment | NetworkDevice | Mapping[str, Any]]
        ] = None,
        ip_addresses: Optional[Sequence[IPAddress | Mapping[str, Any]]] = None,
        arp_entries: Optional[Sequence[ArpEntry | Mapping[str, Any]]] = None,
        has_recent_arp_activity: Optional[bool] = None,
        has_recent_mac_activity: Optional[bool] = None,
        active_macs: Optional[Iterable[str]] = None,
        evaluation_time: Optional[datetime | str] = None,
    ) -> LldpGuardDecision:
        """Evaluate whether `port` must be blocked from switch port/PoE reclamation."""
        resolved_site: Optional[Site] = None
        if site is not None:
            resolved_site = (
                site if isinstance(site, Site) else Site.from_dict(site)
            )

        resolved_device: Optional[NetworkDevice] = None
        if device is not None:
            resolved_device = (
                device
                if isinstance(device, NetworkDevice)
                else NetworkDevice.from_dict(device)
            )

        port_obj, extras = _coerce_port_and_extras(
            port,
            default_device_id=(
                resolved_device.device_id
                if resolved_device is not None
                else None
            ),
        )

        reasons: list[str] = []
        rules: list[str] = []

        def _add_block(rule_name: str, reason_text: str) -> None:
            if rule_name not in rules:
                rules.append(rule_name)
            if reason_text not in reasons:
                reasons.append(reason_text)

        # Resolve connected peer NetworkDevices and Equipment
        connected_devices, connected_equipment = self._resolve_connected_peers(
            port=port_obj,
            device=resolved_device,
            site=resolved_site,
            mapped_equipment=mapped_equipment,
        )

        # 1. Active LLDP / CDP neighbor check ("lldp_neighbor")
        matched_neighbors = self._resolve_port_lldp_neighbors(
            port=port_obj,
            extras=extras,
            lldp_neighbors=lldp_neighbors,
        )
        for neighbor in matched_neighbors:
            cap_hits = self._match_blocked_capabilities(
                neighbor.lldp_rem_sys_cap_enabled
            )
            role_or_name_hits = self._match_neighbor_infrastructure_indicators(
                neighbor
            )
            if cap_hits or role_or_name_hits:
                neighbor_label = (
                    neighbor.lldp_rem_sys_name
                    or neighbor.neighbor_device_role
                    or "unknown-neighbor"
                )
                detail_parts: list[str] = []
                if cap_hits:
                    detail_parts.append(
                        f"capabilities={','.join(cap_hits)}"
                    )
                if role_or_name_hits:
                    detail_parts.append(
                        f"indicators={','.join(role_or_name_hits)}"
                    )
                detail_str = ", ".join(detail_parts)
                _add_block(
                    "lldp_neighbor",
                    f"LLDP/CDP neighbor {neighbor_label!r} on port {port_obj.name} ({detail_str})",
                )

        for peer_dev in connected_devices:
            _add_block(
                "lldp_neighbor",
                f"Port {port_obj.name} is connected to network device {peer_dev.hostname!r} ({peer_dev.device_id})",
            )

        # 2. Critical infrastructure keywords or UPS category ("critical_keyword")
        resolved_description = _clean_optional_str(
            description
            if description is not None
            else extras.get("description")
        )
        text_sources: list[tuple[str, str]] = []
        if resolved_description:
            text_sources.append(("port description", resolved_description))
        if port_obj.name:
            text_sources.append(("port name", port_obj.name))
        if port_obj.connected_device_id:
            text_sources.append(
                ("connected_device_id", port_obj.connected_device_id)
            )
        for neighbor in matched_neighbors:
            if neighbor.lldp_rem_sys_name:
                text_sources.append(
                    ("LLDP neighbor sys_name", neighbor.lldp_rem_sys_name)
                )
            if neighbor.neighbor_device_role:
                text_sources.append(
                    ("LLDP neighbor role", neighbor.neighbor_device_role)
                )
            if neighbor.lldp_rem_sys_desc:
                text_sources.append(
                    ("LLDP neighbor description", neighbor.lldp_rem_sys_desc)
                )

        for eq in connected_equipment:
            if eq.category is EquipmentCategory.UPS:
                _add_block(
                    "critical_keyword",
                    f"Mapped equipment {eq.name!r} ({eq.equipment_id}) is critical category UPS",
                )
            for label, val in (
                ("equipment name", eq.name),
                ("equipment_id", eq.equipment_id),
                ("equipment category", eq.category.value),
            ):
                if val:
                    text_sources.append((label, val))

        for peer_dev in connected_devices:
            for label, val in (
                ("peer device hostname", peer_dev.hostname),
                ("peer device_id", peer_dev.device_id),
                ("peer device vendor", peer_dev.vendor),
                ("peer device model", peer_dev.model),
                ("peer device role", peer_dev.role),
            ):
                if val:
                    text_sources.append((label, val))

        # Also inspect raw mapping fields if mapped_equipment had custom dicts
        for raw_peer in self._iter_raw_mappings(mapped_equipment):
            for key in (
                "name",
                "hostname",
                "equipment_id",
                "device_id",
                "vendor",
                "model",
                "role",
                "category",
                "description",
            ):
                val = _clean_optional_str(raw_peer.get(key))
                if val:
                    text_sources.append((f"mapped {key}", val))

        matched_keywords: list[tuple[str, str, str]] = []
        for source_label, text in text_sources:
            lowered = text.lower()
            for kw in self.critical_keywords:
                if self._keyword_matches_text(kw, lowered):
                    matched_keywords.append((kw, source_label, text))

        if matched_keywords:
            kw, source_label, text = matched_keywords[0]
            unique_kws = list(dict.fromkeys(m[0] for m in matched_keywords))
            _add_block(
                "critical_keyword",
                f"Critical infrastructure keyword {kw!r} (matched {unique_kws}) in {source_label} {text!r}",
            )

        # 3. Multi-VLAN tagged trunk check ("tagged_trunk")
        trunk_reason = self._check_tagged_trunk(
            port=port_obj,
            extras=extras,
            tagged_vlans=tagged_vlans,
            is_trunk=is_trunk,
            vlan_mode=vlan_mode,
        )
        if trunk_reason is not None:
            _add_block("tagged_trunk", trunk_reason)

        # 4. Operational link UP or recent ARP/MAC activity ("oper_up_or_active_arp")
        oper_norm = (
            port_obj.oper_status.strip().lower()
            if isinstance(port_obj.oper_status, str)
            and port_obj.oper_status.strip()
            else None
        )
        if oper_norm is not None and oper_norm in _OPER_ACTIVE_VALUES:
            _add_block(
                "oper_up_or_active_arp",
                f"Port {port_obj.name} operational status is active (oper_status={port_obj.oper_status!r})",
            )

        arp_reason = self._check_recent_arp_or_mac_activity(
            port=port_obj,
            extras=extras,
            site=resolved_site,
            connected_equipment=connected_equipment,
            ip_addresses=ip_addresses,
            arp_entries=arp_entries,
            has_recent_arp_activity=has_recent_arp_activity,
            has_recent_mac_activity=has_recent_mac_activity,
            active_macs=active_macs,
            evaluation_time=evaluation_time,
        )
        if arp_reason is not None:
            _add_block("oper_up_or_active_arp", arp_reason)

        is_blocked = len(reasons) > 0
        return LldpGuardDecision(
            port_id=port_obj.port_id,
            device_id=port_obj.device_id,
            port_name=port_obj.name,
            blocked=is_blocked,
            block_reason="; ".join(reasons) if is_blocked else None,
            block_reasons=tuple(reasons),
            matched_rules=tuple(rules),
        )

    inspect_port = evaluate_port
    __call__ = evaluate_port

    @staticmethod
    def _keyword_matches_text(keyword: str, lowered_text: str) -> bool:
        """Check whether `keyword` matches `lowered_text` without spurious short-word substring hits."""
        if not keyword or not lowered_text:
            return False
        if keyword in ("wan", "wap", "ups", "apc"):
            pattern = rf"(?<![a-z0-9]){re.escape(keyword)}(?![a-z])"
            return re.search(pattern, lowered_text) is not None
        return keyword in lowered_text

    def _match_blocked_capabilities(
        self, capabilities: Sequence[str]
    ) -> list[str]:
        hits: list[str] = []
        for raw_cap in capabilities:
            lowered = raw_cap.strip().lower()
            if not lowered:
                continue
            tokens = [
                t for t in re.split(r"[^a-z0-9]+", lowered) if t
            ]
            for blocked in self.blocked_capabilities:
                if blocked == lowered or blocked in tokens:
                    if blocked not in hits:
                        hits.append(blocked)
                elif len(blocked) >= 4 and blocked in lowered:
                    if blocked not in hits:
                        hits.append(blocked)
        return hits

    def _match_neighbor_infrastructure_indicators(
        self, neighbor: LldpNeighborRecord
    ) -> list[str]:
        hits: list[str] = []
        for field_val in (
            neighbor.neighbor_device_role,
            neighbor.lldp_rem_sys_name,
            neighbor.lldp_rem_sys_desc,
        ):
            if not field_val:
                continue
            lowered = field_val.lower()
            for kw in _LLDP_INFRASTRUCTURE_ROLES_AND_KEYWORDS:
                if self._keyword_matches_text(kw, lowered) and kw not in hits:
                    hits.append(kw)
            for kw in self.critical_keywords:
                if self._keyword_matches_text(kw, lowered) and kw not in hits:
                    hits.append(kw)
            # Also check standalone "ap", "sw", "rtr", "fw" tokens in role or sys_name
            tokens = [t for t in re.split(r"[^a-z0-9]+", lowered) if t]
            for short_tok in ("ap", "sw", "rtr", "fw"):
                if short_tok in tokens and short_tok not in hits:
                    hits.append(short_tok)
        return hits


    def _check_recent_arp_or_mac_activity(
        self,
        *,
        port: Port,
        extras: Mapping[str, Any],
        site: Optional[Site],
        connected_equipment: Sequence[Equipment],
        ip_addresses: Optional[Sequence[IPAddress | Mapping[str, Any]]],
        arp_entries: Optional[Sequence[ArpEntry | Mapping[str, Any]]],
        has_recent_arp_activity: Optional[bool],
        has_recent_mac_activity: Optional[bool],
        active_macs: Optional[Iterable[str]],
        evaluation_time: Optional[datetime | str],
    ) -> Optional[str]:
        explicit_arp = (
            has_recent_arp_activity
            if has_recent_arp_activity is not None
            else extras.get("has_recent_arp_activity")
        )
        explicit_mac = (
            has_recent_mac_activity
            if has_recent_mac_activity is not None
            else extras.get("has_recent_mac_activity")
        )
        if explicit_arp is True or explicit_mac is True:
            return f"Port {port.name} has recent ARP/MAC activity flagged"

        port_mac_norm = _normalize_mac(port.connected_mac)
        if active_macs is not None and port_mac_norm is not None:
            norm_active = {
                m for m in (_normalize_mac(raw) for raw in active_macs) if m
            }
            if port_mac_norm in norm_active:
                return f"Port {port.name} MAC {port.connected_mac!r} is present in active MAC table"

        eval_dt = resolve_evaluation_time(evaluation_time)

        # Collect candidate IPAddresses and ArpEntries from site and explicit arguments
        candidate_ips: list[IPAddress] = []
        if site is not None:
            candidate_ips.extend(site.ip_addresses)
        if ip_addresses is not None:
            for item in ip_addresses:
                candidate_ips.append(
                    item
                    if isinstance(item, IPAddress)
                    else IPAddress.from_dict(item)
                )

        explicit_arp_entries: list[ArpEntry] = []
        if arp_entries is not None:
            for item in arp_entries:
                explicit_arp_entries.append(
                    item
                    if isinstance(item, ArpEntry)
                    else ArpEntry.from_dict(item)
                )

        eq_ids = {eq.equipment_id for eq in connected_equipment}
        if port.connected_device_id:
            eq_ids.add(port.connected_device_id)
        eq_assigned_ips = {
            ip.strip()
            for eq in connected_equipment
            for ip in eq.assigned_ips
            if ip and ip.strip()
        }

        for ip_obj in candidate_ips:
            ip_mac_norm = _normalize_mac(ip_obj.arp_mac)
            matches_port = (
                (port_mac_norm is not None and ip_mac_norm == port_mac_norm)
                or (
                    ip_obj.assigned_object_id is not None
                    and ip_obj.assigned_object_id in eq_ids
                )
                or (ip_obj.ip in eq_assigned_ips)
            )
            if not matches_port or ip_obj.arp_last_seen is None:
                continue
            seen_dt = normalize_utc_datetime(
                ip_obj.arp_last_seen, field_name="arp_last_seen"
            )
            age_days = max(
                0.0, (eval_dt - seen_dt).total_seconds() / SECONDS_PER_DAY
            )
            if age_days <= self.arp_active_within_days:
                return (
                    f"Port {port.name} has recent ARP entry for IP {ip_obj.ip} "
                    f"(age={age_days:.1f}d <= {self.arp_active_within_days:.1f}d)"
                )

        for arp_obj in explicit_arp_entries:
            arp_mac_norm = _normalize_mac(arp_obj.mac)
            if port_mac_norm is not None and arp_mac_norm == port_mac_norm:
                if arp_obj.last_seen is None:
                    return (
                        f"Port {port.name} MAC {port.connected_mac!r} has live ARP entry for IP {arp_obj.ip}"
                    )
                seen_dt = normalize_utc_datetime(
                    arp_obj.last_seen, field_name="last_seen"
                )
                age_days = max(
                    0.0, (eval_dt - seen_dt).total_seconds() / SECONDS_PER_DAY
                )
                if age_days <= self.arp_active_within_days:
                    return (
                        f"Port {port.name} has recent ARP entry for IP {arp_obj.ip} "
                        f"(age={age_days:.1f}d <= {self.arp_active_within_days:.1f}d)"
                    )

        return None
