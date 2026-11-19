"""Thread-safe workbench state: curation overlay, classification and CSV import."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import datetime
import io
import ipaddress
import threading
from typing import Any, Optional

from sot_validator.classifier.engine import ClassificationEngine
from sot_validator.curation.bulk import (
    BulkApplyResult,
    PatchPreview,
    apply_patches,
    parse_patch_csv,
    preview_patches,
)
from sot_validator.curation.store import (
    AuditLogEntry,
    CurationStore,
    ItemEditPatch,
    apply_curation_overlay,
)
from sot_validator.models import (
    Site,
    Subnet,
    VLAN,
    ValidationClassification,
    ValidationResult,
)
from sot_validator.topology.device_types import DeviceTypeCatalog
from sot_validator.workbench._server_common import _optional_str
from sot_validator.workbench._server_state_edits import _DeviceEditMixin


class WorkbenchState(_DeviceEditMixin):
    """Thread-safe state container for the interactive inventory and topology workbench."""

    def __init__(
        self,
        site: Site,
        store: Optional[CurationStore] = None,
        catalog: Optional[DeviceTypeCatalog] = None,
        classifier: Optional[ClassificationEngine] = None,
        initial_results: Optional[Sequence[ValidationResult]] = None,
    ) -> None:
        if not isinstance(site, Site):
            raise ValueError("site must be a Site instance")
        self._lock = threading.RLock()
        self.base_site: Site = Site.from_dict(site.to_dict())
        self.store: CurationStore = (
            store if store is not None else CurationStore(":memory:")
        )
        # Ensure underlying SQLite connection can be used across HTTP worker threads
        try:
            import sqlite3

            if getattr(self.store, "db_path", None) not in (None, ":memory:"):
                old_conn = self.store._conn
                self.store._conn = sqlite3.connect(
                    str(self.store.db_path), check_same_thread=False
                )
                self.store._conn.row_factory = sqlite3.Row
                old_conn.close()
            else:
                snapshot = self.store.to_dict()
                old_conn = self.store._conn
                self.store._conn = sqlite3.connect(
                    ":memory:", check_same_thread=False
                )
                self.store._conn.row_factory = sqlite3.Row
                self.store._init_schema()
                self.store._load_state_from_mapping(snapshot)
                old_conn.close()
        except Exception:
            pass

        self.catalog: DeviceTypeCatalog = (
            catalog if catalog is not None else DeviceTypeCatalog()
        )
        self.classifier: ClassificationEngine = (
            classifier if classifier is not None else ClassificationEngine()
        )
        self._base_results: list[ValidationResult] = (
            [
                ValidationResult.from_dict(r.to_dict())
                if isinstance(r, ValidationResult)
                else ValidationResult.from_dict(r)
                for r in initial_results
            ]
            if initial_results is not None
            else []
        )
        self.site: Site = Site.from_dict(self.base_site.to_dict())
        self.results: list[ValidationResult] = []
        self.refresh()

    def refresh(self) -> tuple[Site, list[ValidationResult]]:
        """Re-apply curation overlay and re-run classification on the curated site."""
        with self._lock:
            curated_site, _ = apply_curation_overlay(
                self.base_site, self.store, self._base_results
            )
            fresh_results = self.classifier.classify_site(curated_site)

            if self._base_results:
                base_by_key: dict[tuple[str, str], ValidationResult] = {
                    (r.item_type, r.item_id): r for r in self._base_results
                }
                merged_results: list[ValidationResult] = []
                for fresh in fresh_results:
                    key = (fresh.item_type, fresh.item_id)
                    initial = base_by_key.get(key)
                    if (
                        initial is not None
                        and initial.signals
                        and fresh.classification
                        == ValidationClassification.INSUFFICIENT_DATA
                        and initial.classification
                        != ValidationClassification.INSUFFICIENT_DATA
                    ):
                        preserved = ValidationResult.from_dict(initial.to_dict())
                        preserved.name = fresh.name
                        merged_results.append(preserved)
                    else:
                        merged_results.append(fresh)
                classified_results = merged_results
            else:
                classified_results = fresh_results

            final_site, final_results = apply_curation_overlay(
                curated_site, self.store, classified_results
            )
            self.site = final_site
            self.results = final_results
            return self.site, self.results

    def _build_vlan_subnet_summary(
        self, patches: Sequence[ItemEditPatch]
    ) -> list[dict[str, Any]]:
        patch_by_key: dict[tuple[str, str], ItemEditPatch] = {
            (p.target_type, p.target_id): p for p in patches if not p.deleted
        }
        vlans_by_id: dict[str, VLAN] = {v.vlan_id: v for v in self.site.vlans}
        subnets_by_id: dict[str, Subnet] = {s.subnet_id: s for s in self.site.subnets}
        subnets_by_vlan: dict[str, list[Subnet]] = {}
        for sub in self.site.subnets:
            if sub.vlan_id:
                subnets_by_vlan.setdefault(sub.vlan_id, []).append(sub)

        parsed_subnets: dict[str, ipaddress._BaseNetwork] = {}
        for sub in self.site.subnets:
            try:
                parsed_subnets[sub.subnet_id] = ipaddress.ip_network(
                    sub.cidr, strict=False
                )
            except ValueError:
                continue

        def _count_for(
            vlan_id: Optional[str], subnet_id: Optional[str], cidr: Optional[str]
        ) -> tuple[int, int, int]:
            target_subnet_ids: set[str] = set()
            if subnet_id:
                target_subnet_ids.add(subnet_id)
            if vlan_id:
                for s in subnets_by_vlan.get(vlan_id, ()):
                    target_subnet_ids.add(s.subnet_id)

            net_objs: list[ipaddress._BaseNetwork] = [
                parsed_subnets[sid]
                for sid in target_subnet_ids
                if sid in parsed_subnets
            ]
            if cidr and not net_objs:
                try:
                    net_objs.append(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    pass

            ip_count = 0
            matched_ips: set[str] = set()
            for ip_rec in self.site.ip_addresses:
                if ip_rec.subnet_id in target_subnet_ids:
                    ip_count += 1
                    matched_ips.add(ip_rec.ip)
                elif net_objs:
                    try:
                        ip_val = ipaddress.ip_address(ip_rec.ip)
                        if any(ip_val in net for net in net_objs):
                            ip_count += 1
                            matched_ips.add(ip_rec.ip)
                    except ValueError:
                        pass

            port_count = 0
            port_ids_in_vlan: set[str] = set()
            if vlan_id:
                for dev in self.site.devices:
                    for port in dev.ports:
                        if port.vlan_id == vlan_id:
                            port_count += 1
                            port_ids_in_vlan.add(port.port_id)
                            port_ids_in_vlan.add(port.name)

            eq_count = 0
            for eq in self.site.equipment:
                eq_patch = patch_by_key.get(("Equipment", eq.equipment_id))
                eq_vlan = (
                    (eq_patch.vlan_id or eq_patch.custom_attributes.get("vlan_id"))
                    if eq_patch is not None
                    else None
                )
                eq_subnet = (
                    (eq_patch.subnet_id or eq_patch.custom_attributes.get("subnet_id"))
                    if eq_patch is not None
                    else None
                )
                in_vlan = bool(vlan_id and eq_vlan == vlan_id)
                in_subnet = bool(
                    target_subnet_ids and eq_subnet in target_subnet_ids
                )
                has_port = bool(
                    port_ids_in_vlan
                    and any(cp in port_ids_in_vlan for cp in eq.connected_ports)
                )
                has_ip = False
                for raw_ip in eq.assigned_ips:
                    if raw_ip in matched_ips:
                        has_ip = True
                        break
                    if net_objs:
                        try:
                            ip_val = ipaddress.ip_address(raw_ip)
                            if any(ip_val in net for net in net_objs):
                                has_ip = True
                                break
                        except ValueError:
                            pass
                if in_vlan or in_subnet or has_port or has_ip:
                    eq_count += 1

            return ip_count, port_count, eq_count

        summaries: list[dict[str, Any]] = []
        handled_subnet_ids: set[str] = set()

        for vlan in self.site.vlans:
            linked_subnets = list(subnets_by_vlan.get(vlan.vlan_id, ()))
            if vlan.subnet_id and vlan.subnet_id in subnets_by_id:
                primary_sub = subnets_by_id[vlan.subnet_id]
                if primary_sub not in linked_subnets:
                    linked_subnets.insert(0, primary_sub)

            if linked_subnets:
                for sub in linked_subnets:
                    handled_subnet_ids.add(sub.subnet_id)
                    ip_cnt, port_cnt, eq_cnt = _count_for(
                        vlan.vlan_id, sub.subnet_id, sub.cidr or vlan.cidr
                    )
                    summaries.append(
                        {
                            "vlan_id": vlan.vlan_id,
                            "vlan_name": vlan.name or sub.name or f"VLAN {vlan.vlan_id}",
                            "subnet_id": sub.subnet_id,
                            "cidr": sub.cidr or vlan.cidr,
                            "gateway": sub.gateway or vlan.gateway,
                            "ip_count": ip_cnt,
                            "device_port_count": port_cnt,
                            "equipment_count": eq_cnt,
                        }
                    )
            else:
                ip_cnt, port_cnt, eq_cnt = _count_for(
                    vlan.vlan_id, vlan.subnet_id, vlan.cidr
                )
                summaries.append(
                    {
                        "vlan_id": vlan.vlan_id,
                        "vlan_name": vlan.name or f"VLAN {vlan.vlan_id}",
                        "subnet_id": vlan.subnet_id,
                        "cidr": vlan.cidr,
                        "gateway": vlan.gateway,
                        "ip_count": ip_cnt,
                        "device_port_count": port_cnt,
                        "equipment_count": eq_cnt,
                    }
                )

        for sub in self.site.subnets:
            if sub.subnet_id in handled_subnet_ids:
                continue
            vlan_obj = vlans_by_id.get(sub.vlan_id) if sub.vlan_id else None
            ip_cnt, port_cnt, eq_cnt = _count_for(
                sub.vlan_id, sub.subnet_id, sub.cidr
            )
            summaries.append(
                {
                    "vlan_id": sub.vlan_id,
                    "vlan_name": (
                        vlan_obj.name
                        if vlan_obj and vlan_obj.name
                        else (sub.name or (f"VLAN {sub.vlan_id}" if sub.vlan_id else sub.subnet_id))
                    ),
                    "subnet_id": sub.subnet_id,
                    "cidr": sub.cidr,
                    "gateway": sub.gateway,
                    "ip_count": ip_cnt,
                    "device_port_count": port_cnt,
                    "equipment_count": eq_cnt,
                }
            )

        return summaries

    def get_state_payload(self, audit_limit: int = 50) -> dict[str, Any]:
        """Return a JSON-serializable state payload for the UI and REST API."""
        with self._lock:
            patches = self.store.list_patches(site_id=self.site.site_id)
            all_ports = [p for d in self.site.devices for p in d.ports]
            active_ports = sum(
                1
                for p in all_ports
                if (p.oper_status or "").strip().lower() == "up"
            )
            poe_ports = sum(
                1
                for p in all_ports
                if p.poe_status is not None
                and (p.poe_status or "").strip().lower()
                not in ("", "off", "disabled", "none")
            )
            classification_counts: dict[str, int] = {
                cls.value: 0 for cls in ValidationClassification
            }
            for res in self.results:
                classification_counts[res.classification.value] = (
                    classification_counts.get(res.classification.value, 0) + 1
                )

            summary = {
                "total_devices": len(self.site.devices),
                "total_ports": len(all_ports),
                "active_ports": active_ports,
                "poe_ports": poe_ports,
                "total_vlans": len(self.site.vlans),
                "total_subnets": len(self.site.subnets),
                "total_ips": len(self.site.ip_addresses),
                "total_equipment": len(self.site.equipment),
                "classification_counts": classification_counts,
            }

            audit_entries = self.store.list_audit_log(
                site_id=self.site.site_id, limit=audit_limit
            )

            return {
                "site": self.site.to_dict(),
                "results": [r.to_dict() for r in self.results],
                "templates": [t.to_dict() for t in self.catalog.list_templates()],
                "patches": [p.to_dict() for p in patches],
                "vlan_subnet_summary": self._build_vlan_subnet_summary(patches),
                "summary": summary,
                "audit_log": [a.to_dict() for a in audit_entries],
            }

    def apply_item_patch(
        self,
        payload: Mapping[str, Any] | ItemEditPatch,
        *,
        actor: str = "operator",
        reason: str = "",
    ) -> AuditLogEntry:
        """Apply an ItemEditPatch (or item deletion) to the CurationStore and refresh state."""
        with self._lock:
            if isinstance(payload, ItemEditPatch):
                patch = (
                    payload
                    if payload.site_id is not None
                    else replace(payload, site_id=self.site.site_id)
                )
            elif isinstance(payload, Mapping):
                data = dict(payload)
                if not data.get("site_id"):
                    data["site_id"] = self.site.site_id
                custom_attrs = dict(data.get("custom_attributes") or {})
                patch = ItemEditPatch(
                    target_type=data["target_type"],
                    target_id=data["target_id"],
                    site_id=data.get("site_id"),
                    name=_optional_str(data.get("name")),
                    hostname=_optional_str(data.get("hostname")),
                    category=_optional_str(data.get("category")),
                    role=_optional_str(data.get("role")),
                    vendor=_optional_str(data.get("vendor")),
                    model=_optional_str(data.get("model")),
                    vlan_id=_optional_str(data.get("vlan_id")),
                    subnet_id=_optional_str(data.get("subnet_id")),
                    room=_optional_str(data.get("room")),
                    notes=_optional_str(data.get("notes")),
                    pinned_classification=_optional_str(
                        data.get("pinned_classification")
                    ),
                    custom_attributes=custom_attrs,
                    deleted=bool(data.get("deleted", False)),
                )
            else:
                raise ValueError("payload must be a Mapping or ItemEditPatch")

            if patch.target_type == "Equipment":
                merged_attrs = dict(patch.custom_attributes)
                if patch.vlan_id is not None:
                    merged_attrs["vlan_id"] = patch.vlan_id
                if patch.subnet_id is not None:
                    merged_attrs["subnet_id"] = patch.subnet_id
                if patch.room is not None:
                    merged_attrs["room"] = patch.room
                if merged_attrs != patch.custom_attributes:
                    patch = replace(patch, custom_attributes=merged_attrs)

            if patch.deleted:
                entry = self.store.delete_item(
                    patch.target_type,
                    patch.target_id,
                    actor=actor,
                    reason=reason,
                    site_id=patch.site_id or self.site.site_id,
                )
            else:
                entry = self.store.upsert_patch(patch, actor=actor, reason=reason)

            self.refresh()
            return entry

    def preview_csv(
        self, csv_text: str, as_of: Optional[datetime | str] = None
    ) -> PatchPreview:
        """Parse a bulk patch CSV and preview it against the base site without writing."""
        with self._lock:
            patches = parse_patch_csv(io.StringIO(csv_text))
            return preview_patches(self.store, self.base_site, patches, as_of)

    def apply_csv(
        self,
        csv_text: str,
        as_of: Optional[datetime | str],
        confirm_token: str,
        actor: str,
    ) -> BulkApplyResult:
        """Rebuild the preview of a bulk patch CSV, apply it if the token matches, then refresh."""
        with self._lock:
            patches = parse_patch_csv(io.StringIO(csv_text))
            preview = preview_patches(self.store, self.base_site, patches, as_of)
            result = apply_patches(self.store, preview, actor, confirm_token)
            self.refresh()
            return result
