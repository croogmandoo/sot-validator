"""LLDP neighbor, peer and trunk resolver helpers mixed into ``LldpUplinkGuard``."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
import re
from typing import Any, Optional

from sot_validator.models import Equipment, NetworkDevice, Port, Site
from sot_validator.remediation._port_reclamation_common import (
    _VLAN_RANGE_PATTERN,
    _clean_optional_str,
    _port_matches_identifier,
)
from sot_validator.remediation._port_reclamation_records import LldpNeighborRecord


class _LldpNeighborResolverMixin:
    """Static LLDP neighbor, connected peer and tagged trunk resolvers for ``LldpUplinkGuard``."""

    @staticmethod
    def _resolve_port_lldp_neighbors(
        *,
        port: Port,
        extras: Mapping[str, Any],
        lldp_neighbors: Optional[Any],
    ) -> list[LldpNeighborRecord]:
        raw_sources: list[Any] = []
        if lldp_neighbors is not None:
            raw_sources.append(lldp_neighbors)
        for key in ("lldp_neighbors", "lldp_neighbor"):
            if key in extras and extras[key] is not None:
                raw_sources.append(extras[key])
        if any(
            k in extras and extras[k] is not None
            for k in (
                "lldp_rem_sys_name",
                "lldpRemSysName",
                "lldp_rem_sys_cap_enabled",
                "lldpRemSysCapEnabled",
                "neighbor_device_role",
            )
        ):
            raw_sources.append(extras)

        matched: list[LldpNeighborRecord] = []
        for source in raw_sources:
            if isinstance(source, LldpNeighborRecord):
                if (
                    source.port_id is None
                    and source.port_name is None
                ) or (
                    (
                        source.port_id is not None
                        and _port_matches_identifier(port, source.port_id)
                    )
                    or (
                        source.port_name is not None
                        and _port_matches_identifier(port, source.port_name)
                    )
                ):
                    matched.append(source)
            elif isinstance(source, Mapping):
                # Check if it's a single neighbor dict vs a port->neighbor lookup mapping
                if any(
                    k in source
                    for k in (
                        "lldp_rem_sys_name",
                        "lldpRemSysName",
                        "sys_name",
                        "neighbor_name",
                        "lldp_rem_sys_cap_enabled",
                        "lldpRemSysCapEnabled",
                        "capabilities",
                        "sys_capabilities",
                        "neighbor_device_role",
                        "neighbor_role",
                        "lldp_rem_sys_desc",
                        "lldpRemSysDesc",
                    )
                ):
                    rec = LldpNeighborRecord.from_dict(source)
                    if (
                        rec.port_id is None
                        and rec.port_name is None
                    ) or (
                        (
                            rec.port_id is not None
                            and _port_matches_identifier(port, rec.port_id)
                        )
                        or (
                            rec.port_name is not None
                            and _port_matches_identifier(port, rec.port_name)
                        )
                    ):
                        matched.append(rec)
                else:
                    for key, val in source.items():
                        if _port_matches_identifier(port, str(key)):
                            matched.extend(
                                _LldpNeighborResolverMixin._coerce_neighbor_list(val)
                            )
            elif isinstance(source, Sequence) and not isinstance(
                source, (str, bytes)
            ):
                for item in source:
                    rec = (
                        item
                        if isinstance(item, LldpNeighborRecord)
                        else LldpNeighborRecord.from_dict(item)
                    )
                    if (
                        rec.port_id is None
                        and rec.port_name is None
                    ) or (
                        (
                            rec.port_id is not None
                            and _port_matches_identifier(port, rec.port_id)
                        )
                        or (
                            rec.port_name is not None
                            and _port_matches_identifier(port, rec.port_name)
                        )
                    ):
                        matched.append(rec)

        return matched

    @staticmethod
    def _coerce_neighbor_list(val: Any) -> list[LldpNeighborRecord]:
        if val is None:
            return []
        if isinstance(val, LldpNeighborRecord):
            return [val]
        if isinstance(val, Mapping):
            return [LldpNeighborRecord.from_dict(val)]
        if isinstance(val, Sequence) and not isinstance(val, (str, bytes)):
            return [
                item
                if isinstance(item, LldpNeighborRecord)
                else LldpNeighborRecord.from_dict(item)
                for item in val
            ]
        return []

    @staticmethod
    def _iter_raw_mappings(
        mapped_equipment: Optional[Any],
    ) -> list[Mapping[str, Any]]:
        if mapped_equipment is None:
            return []
        if isinstance(mapped_equipment, Mapping):
            return [mapped_equipment]
        if isinstance(mapped_equipment, Sequence) and not isinstance(
            mapped_equipment, (str, bytes)
        ):
            return [
                item for item in mapped_equipment if isinstance(item, Mapping)
            ]
        return []

    @staticmethod
    def _resolve_connected_peers(
        *,
        port: Port,
        device: Optional[NetworkDevice],
        site: Optional[Site],
        mapped_equipment: Optional[Any],
    ) -> tuple[list[NetworkDevice], list[Equipment]]:
        connected_devices: list[NetworkDevice] = []
        connected_equipment: list[Equipment] = []
        seen_dev_ids: set[str] = set()
        seen_eq_ids: set[str] = set()

        def _add_dev(dev: NetworkDevice) -> None:
            if dev.device_id not in seen_dev_ids:
                seen_dev_ids.add(dev.device_id)
                connected_devices.append(dev)

        def _add_eq(eq: Equipment) -> None:
            if eq.equipment_id not in seen_eq_ids:
                seen_eq_ids.add(eq.equipment_id)
                connected_equipment.append(eq)

        # If `device` was passed and is a peer device (not the local switch owning `port`)
        if device is not None and device.device_id != port.device_id:
            _add_dev(device)

        if site is not None:
            if port.connected_device_id:
                for dev in site.devices:
                    if dev.device_id != port.device_id and (
                        dev.device_id == port.connected_device_id
                        or dev.hostname == port.connected_device_id
                    ):
                        _add_dev(dev)
            for eq in site.equipment:
                connected_refs = {
                    ref.strip()
                    for ref in eq.connected_ports
                    if ref and ref.strip()
                }
                if (
                    (
                        port.connected_device_id is not None
                        and (
                            eq.equipment_id == port.connected_device_id
                            or eq.name == port.connected_device_id
                        )
                    )
                    or port.port_id in connected_refs
                    or port.name in connected_refs
                    or f"{port.device_id}:{port.name}" in connected_refs
                    or f"{port.device_id}:{port.port_id}" in connected_refs
                ):
                    _add_eq(eq)

        items: list[Any] = []
        if mapped_equipment is not None:
            if isinstance(
                mapped_equipment, (Equipment, NetworkDevice, Mapping)
            ):
                items.append(mapped_equipment)
            elif isinstance(mapped_equipment, Sequence) and not isinstance(
                mapped_equipment, (str, bytes)
            ):
                items.extend(mapped_equipment)

        for item in items:
            if isinstance(item, Equipment):
                _add_eq(item)
            elif isinstance(item, NetworkDevice):
                if item.device_id != port.device_id:
                    _add_dev(item)
            elif isinstance(item, Mapping):
                if "equipment_id" in item:
                    try:
                        _add_eq(Equipment.from_dict(item))
                    except (KeyError, ValueError):
                        pass
                elif "device_id" in item and "hostname" in item:
                    try:
                        dev_obj = NetworkDevice.from_dict(item)
                        if dev_obj.device_id != port.device_id:
                            _add_dev(dev_obj)
                    except (KeyError, ValueError):
                        pass

        return connected_devices, connected_equipment

    @staticmethod
    def _check_tagged_trunk(
        *,
        port: Port,
        extras: Mapping[str, Any],
        tagged_vlans: Optional[Iterable[str | int]],
        is_trunk: Optional[bool],
        vlan_mode: Optional[str],
    ) -> Optional[str]:
        resolved_is_trunk = (
            is_trunk if is_trunk is not None else extras.get("is_trunk")
        )
        if resolved_is_trunk is True:
            return f"Port {port.name} is explicitly marked as a trunk port (is_trunk=True)"

        resolved_vlan_mode = _clean_optional_str(
            vlan_mode if vlan_mode is not None else extras.get("vlan_mode")
        )
        if resolved_vlan_mode and resolved_vlan_mode.lower() in (
            "trunk",
            "tagged",
            "802.1q",
            "dot1q",
        ):
            return f"Port {port.name} has trunk/tagged VLAN mode (vlan_mode={resolved_vlan_mode!r})"

        raw_tagged = (
            tagged_vlans
            if tagged_vlans is not None
            else extras.get("tagged_vlans")
        )
        if raw_tagged is not None:
            if isinstance(raw_tagged, (str, int)):
                tagged_list = [
                    p.strip()
                    for p in re.split(r"[,;|/\s]+", str(raw_tagged))
                    if p.strip()
                ]
            else:
                tagged_list = [
                    str(v).strip() for v in raw_tagged if str(v).strip()
                ]
            if tagged_list:
                return (
                    f"Port {port.name} carries tagged VLANs ({','.join(tagged_list)})"
                )

        if port.vlan_id:
            vlan_raw = port.vlan_id.strip()
            vlan_lower = vlan_raw.lower()
            if any(
                tok in vlan_lower for tok in ("trunk", "tagged", "all", "tag")
            ):
                return f"Port {port.name} vlan_id indicates trunk/tagged state ({vlan_raw!r})"
            if any(sep in vlan_raw for sep in (",", ";", "|", "/")):
                parts = [
                    p.strip()
                    for p in re.split(r"[,;|/]+", vlan_raw)
                    if p.strip()
                ]
                if len(parts) >= 2:
                    return f"Port {port.name} vlan_id contains multiple VLANs ({vlan_raw!r})"
            if _VLAN_RANGE_PATTERN.match(vlan_raw):
                return f"Port {port.name} vlan_id specifies a VLAN range ({vlan_raw!r})"

        return None
