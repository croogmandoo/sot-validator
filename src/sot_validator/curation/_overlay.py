"""Non-destructive merge of curation edits onto a site snapshot and its results."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from typing import TYPE_CHECKING, Optional

from sot_validator.curation._records import (
    ItemEditPatch,
    _coerce_equipment_category,
    _normalize_target_type,
)
from sot_validator.models import (
    Equipment,
    EquipmentCategory,
    NetworkDevice,
    Port,
    Site,
    Subnet,
    VLAN,
    ValidationClassification,
    ValidationResult,
)

if TYPE_CHECKING:
    from sot_validator.curation.store import CurationStore


def _format_pin_rationale(
    existing_rationale: Optional[str],
    pinned_cls: ValidationClassification,
    notes: Optional[str],
) -> str:
    pin_clause = f"Pinned to {pinned_cls.value} by operator"
    if notes:
        pin_clause = f"{pin_clause} ({notes})"

    if not existing_rationale or not existing_rationale.strip():
        return pin_clause

    base = existing_rationale.strip()
    if pin_clause in base:
        return base

    marker = "Pinned to "
    if "; Pinned to " in base:
        base = base.split("; Pinned to ", 1)[0].strip()
    elif base.startswith(marker):
        return pin_clause

    return f"{base}; {pin_clause}" if base else pin_clause


def apply_curation_overlay(
    site: Site,
    store: CurationStore,
    results: Optional[Sequence[ValidationResult]] = None,
) -> tuple[Site, list[ValidationResult]]:
    """Non-destructively merge custom inventory records, field patches, deletions, and pinned classifications."""
    from sot_validator.curation.store import CurationStore

    if not isinstance(site, Site):
        raise ValueError("site must be a Site instance")
    if not isinstance(store, CurationStore):
        raise ValueError("store must be a CurationStore instance")

    curated_site = Site.from_dict(site.to_dict())
    curated_results: list[ValidationResult] = (
        [
            ValidationResult.from_dict(r.to_dict())
            if isinstance(r, ValidationResult)
            else ValidationResult.from_dict(r)
            for r in results
        ]
        if results is not None
        else []
    )

    all_patches = [
        p
        for p in store.list_patches()
        if p.site_id is None or p.site_id == curated_site.site_id
    ]
    patches_by_key: dict[tuple[str, str], ItemEditPatch] = {
        (p.target_type, p.target_id): p for p in all_patches
    }
    deleted_keys: set[tuple[str, str]] = {
        key for key, p in patches_by_key.items() if p.deleted
    }

    # 1. Merge custom VLANs
    for custom_vlan in store._list_custom_vlans(site_id=curated_site.site_id):
        if ("VLAN", custom_vlan.vlan_id) in deleted_keys:
            continue
        vlan_copy = VLAN.from_dict(custom_vlan.to_dict())
        replaced = False
        for idx, existing_vlan in enumerate(curated_site.vlans):
            if existing_vlan.vlan_id == vlan_copy.vlan_id:
                curated_site.vlans[idx] = vlan_copy
                replaced = True
                break
        if not replaced:
            curated_site.vlans.append(vlan_copy)

    # 2. Merge custom Subnets
    for custom_subnet in store._list_custom_subnets(site_id=curated_site.site_id):
        if ("Subnet", custom_subnet.subnet_id) in deleted_keys:
            continue
        subnet_copy = Subnet.from_dict(custom_subnet.to_dict())
        replaced = False
        for idx, existing_subnet in enumerate(curated_site.subnets):
            if existing_subnet.subnet_id == subnet_copy.subnet_id:
                curated_site.subnets[idx] = subnet_copy
                replaced = True
                break
        if not replaced:
            curated_site.subnets.append(subnet_copy)

    # 3. Merge custom NetworkDevices
    for custom_dev in store._list_custom_devices(site_id=curated_site.site_id):
        if ("NetworkDevice", custom_dev.device_id) in deleted_keys:
            continue
        dev_copy = NetworkDevice.from_dict(custom_dev.to_dict())
        replaced = False
        for idx, existing_dev in enumerate(curated_site.devices):
            if existing_dev.device_id == dev_copy.device_id:
                curated_site.devices[idx] = dev_copy
                replaced = True
                break
        if not replaced:
            curated_site.devices.append(dev_copy)

    # 4. Merge custom/updated Ports into devices in site
    devices_by_id: dict[str, NetworkDevice] = {
        d.device_id: d for d in curated_site.devices
    }
    for dev_id, port_site_id, custom_port in store._list_custom_ports(
        site_id=curated_site.site_id
    ):
        if ("Port", custom_port.port_id) in deleted_keys:
            continue
        target_dev = devices_by_id.get(dev_id)
        if target_dev is None:
            continue
        port_copy = Port.from_dict(custom_port.to_dict())
        if port_copy.device_id != dev_id:
            port_copy = replace(port_copy, device_id=dev_id)
        replaced = False
        for idx, existing_port in enumerate(target_dev.ports):
            if existing_port.port_id == port_copy.port_id:
                target_dev.ports[idx] = port_copy
                replaced = True
                break
        if not replaced:
            target_dev.ports.append(port_copy)

    # 5. Merge custom Equipment
    for custom_eq in store._list_custom_equipment(site_id=curated_site.site_id):
        if ("Equipment", custom_eq.equipment_id) in deleted_keys:
            continue
        eq_copy = Equipment.from_dict(custom_eq.to_dict())
        replaced = False
        for idx, existing_eq in enumerate(curated_site.equipment):
            if existing_eq.equipment_id == eq_copy.equipment_id:
                curated_site.equipment[idx] = eq_copy
                replaced = True
                break
        if not replaced:
            curated_site.equipment.append(eq_copy)

    # 6. Apply deletions to Site collections
    if deleted_keys:
        curated_site.devices = [
            d
            for d in curated_site.devices
            if ("NetworkDevice", d.device_id) not in deleted_keys
        ]
        for dev in curated_site.devices:
            dev.ports = [
                p for p in dev.ports if ("Port", p.port_id) not in deleted_keys
            ]
        curated_site.vlans = [
            v
            for v in curated_site.vlans
            if ("VLAN", v.vlan_id) not in deleted_keys
        ]
        curated_site.subnets = [
            s
            for s in curated_site.subnets
            if ("Subnet", s.subnet_id) not in deleted_keys
        ]
        curated_site.ip_addresses = [
            ip_rec
            for ip_rec in curated_site.ip_addresses
            if ("IPAddress", ip_rec.ip) not in deleted_keys
        ]
        curated_site.equipment = [
            e
            for e in curated_site.equipment
            if ("Equipment", e.equipment_id) not in deleted_keys
        ]

    # 7. Apply field patches to Site items
    for dev in curated_site.devices:
        dev_patch = patches_by_key.get(("NetworkDevice", dev.device_id))
        if dev_patch is not None and not dev_patch.deleted:
            new_hostname = (
                dev_patch.hostname
                if dev_patch.hostname is not None
                else dev_patch.name
            )
            if new_hostname is not None:
                dev.hostname = new_hostname
            new_role = (
                dev_patch.role
                if dev_patch.role is not None
                else (
                    dev_patch.category.value
                    if isinstance(dev_patch.category, EquipmentCategory)
                    else dev_patch.category
                )
            )
            if new_role is not None:
                dev.role = new_role
            if dev_patch.vendor is not None:
                dev.vendor = dev_patch.vendor
            if dev_patch.model is not None:
                dev.model = dev_patch.model
            if dev_patch.room is not None and dev_patch.room not in curated_site.rooms:
                curated_site.rooms.append(dev_patch.room)

        for port in dev.ports:
            port_patch = patches_by_key.get(("Port", port.port_id))
            if port_patch is not None and not port_patch.deleted:
                new_port_name = (
                    port_patch.name
                    if port_patch.name is not None
                    else port_patch.hostname
                )
                if new_port_name is not None:
                    port.name = new_port_name
                if port_patch.vlan_id is not None:
                    port.vlan_id = port_patch.vlan_id

    for vlan in curated_site.vlans:
        vlan_patch = patches_by_key.get(("VLAN", vlan.vlan_id))
        if vlan_patch is not None and not vlan_patch.deleted:
            new_vlan_name = (
                vlan_patch.name
                if vlan_patch.name is not None
                else vlan_patch.hostname
            )
            if new_vlan_name is not None:
                vlan.name = new_vlan_name
            if vlan_patch.subnet_id is not None:
                vlan.subnet_id = vlan_patch.subnet_id

    for subnet in curated_site.subnets:
        subnet_patch = patches_by_key.get(("Subnet", subnet.subnet_id))
        if subnet_patch is not None and not subnet_patch.deleted:
            new_subnet_name = (
                subnet_patch.name
                if subnet_patch.name is not None
                else subnet_patch.hostname
            )
            if new_subnet_name is not None:
                subnet.name = new_subnet_name
            if subnet_patch.vlan_id is not None:
                subnet.vlan_id = subnet_patch.vlan_id

    for ip_rec in curated_site.ip_addresses:
        ip_patch = patches_by_key.get(("IPAddress", ip_rec.ip))
        if ip_patch is not None and not ip_patch.deleted:
            if ip_patch.subnet_id is not None:
                ip_rec.subnet_id = ip_patch.subnet_id

    for eq in curated_site.equipment:
        eq_patch = patches_by_key.get(("Equipment", eq.equipment_id))
        if eq_patch is not None and not eq_patch.deleted:
            new_eq_name = (
                eq_patch.name
                if eq_patch.name is not None
                else eq_patch.hostname
            )
            if new_eq_name is not None:
                eq.name = new_eq_name
            raw_cat = (
                eq_patch.category
                if eq_patch.category is not None
                else eq_patch.role
            )
            if raw_cat is not None:
                eq.category = _coerce_equipment_category(raw_cat, "category")
            if eq_patch.room is not None and eq_patch.room not in curated_site.rooms:
                curated_site.rooms.append(eq_patch.room)

    # 8. Build item name index for ValidationResult updates and synthesis
    site_item_names: dict[tuple[str, str], str] = {}
    for dev in curated_site.devices:
        site_item_names[("NetworkDevice", dev.device_id)] = dev.hostname
        for port in dev.ports:
            site_item_names[("Port", port.port_id)] = port.name
    for vlan in curated_site.vlans:
        site_item_names[("VLAN", vlan.vlan_id)] = vlan.name or vlan.vlan_id
    for subnet in curated_site.subnets:
        site_item_names[("Subnet", subnet.subnet_id)] = (
            subnet.name or subnet.cidr
        )
    for ip_rec in curated_site.ip_addresses:
        site_item_names[("IPAddress", ip_rec.ip)] = ip_rec.ip
    for eq in curated_site.equipment:
        site_item_names[("Equipment", eq.equipment_id)] = eq.name

    # 9. Filter deleted items from results and apply patches / pinned_classification
    updated_results: list[ValidationResult] = []
    seen_result_keys: set[tuple[str, str]] = set()

    for res in curated_results:
        try:
            norm_type = _normalize_target_type(res.item_type, "item_type")
        except ValueError:
            norm_type = res.item_type

        key = (norm_type, res.item_id)
        if key in deleted_keys:
            continue

        seen_result_keys.add(key)
        patch = patches_by_key.get(key)
        if key in site_item_names:
            res.name = site_item_names[key]
        elif patch is not None:
            patched_name = patch.name or patch.hostname
            if patched_name is not None:
                res.name = patched_name

        if patch is not None and not patch.deleted:
            if isinstance(
                patch.pinned_classification, ValidationClassification
            ):
                res.classification = patch.pinned_classification
                res.confidence = 1.0
                res.rationale = _format_pin_rationale(
                    res.rationale, patch.pinned_classification, patch.notes
                )
            elif patch.notes:
                note_clause = f"Operator note: {patch.notes}"
                if not res.rationale:
                    res.rationale = note_clause
                elif note_clause not in res.rationale and patch.notes not in res.rationale:
                    res.rationale = f"{res.rationale}; {note_clause}"

        updated_results.append(res)

    # 10. Synthesize ValidationResult for pinned items in site not yet in results
    for (target_type, target_id), item_name in site_item_names.items():
        if (target_type, target_id) in seen_result_keys:
            continue
        patch = patches_by_key.get((target_type, target_id))
        if (
            patch is not None
            and not patch.deleted
            and isinstance(patch.pinned_classification, ValidationClassification)
        ):
            updated_results.append(
                ValidationResult(
                    item_type=target_type,
                    item_id=target_id,
                    site_id=curated_site.site_id,
                    name=item_name,
                    classification=patch.pinned_classification,
                    confidence=1.0,
                    signals=[],
                    rationale=_format_pin_rationale(
                        None, patch.pinned_classification, patch.notes
                    ),
                    evaluated_at=patch.updated_at,
                )
            )
            seen_result_keys.add((target_type, target_id))

    return curated_site, updated_results
