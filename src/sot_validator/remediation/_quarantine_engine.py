"""Quarantine graduation engine building approval manifests from validation results."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
import ipaddress
from typing import Any, ClassVar, Optional
import uuid

from sot_validator.history.ledger import (
    HistoryStore,
    ItemStreakSummary,
)
from sot_validator.models import (
    Equipment,
    EquipmentCategory,
    IPAddress,
    NetworkDevice,
    Port,
    SignalType,
    Site,
    Subnet,
    ValidationClassification,
    ValidationResult,
)
from sot_validator.remediation._quarantine_common import (
    ApprovalStatus,
    QuarantineGraduationStatus,
    RemediationOperation,
    _canonical_token,
    _word_tokens,
)
from sot_validator.remediation._quarantine_manifest import RemediationApprovalManifest
from sot_validator.remediation._quarantine_policy import (
    QuarantineManifestEntry,
    QuarantinePolicy,
)
from sot_validator.remediation.sink import (
    ProposedRemediationAction,
    RemediationActionType,
    _resolve_plan_timestamp,
)


@dataclass
class _SiteInventoryIndex:
    """Internal lookup index over Site objects for category, role, vendor, and IP/subnet checks."""

    equipment_by_site_id: dict[tuple[str, str], Equipment] = field(
        default_factory=dict
    )
    equipment_by_id: dict[str, Equipment] = field(default_factory=dict)
    devices_by_site_id: dict[tuple[str, str], NetworkDevice] = field(
        default_factory=dict
    )
    devices_by_id: dict[str, NetworkDevice] = field(default_factory=dict)
    ports_by_site_id: dict[tuple[str, str], Port] = field(default_factory=dict)
    ports_by_id: dict[str, Port] = field(default_factory=dict)
    ips_by_site_ip: dict[tuple[str, str], IPAddress] = field(
        default_factory=dict
    )
    ips_by_ip: dict[str, IPAddress] = field(default_factory=dict)
    ips_by_assigned_obj: dict[str, list[str]] = field(default_factory=dict)
    subnets_by_site_id: dict[tuple[str, str], Subnet] = field(
        default_factory=dict
    )
    subnets_by_id: dict[str, Subnet] = field(default_factory=dict)

    @classmethod
    def from_sites(
        cls,
        sites: Optional[Site | Sequence[Site | Mapping[str, Any]] | Mapping[str, Any]],
    ) -> _SiteInventoryIndex:
        idx = cls()
        if sites is None:
            return idx

        if isinstance(sites, Site):
            site_list = [sites]
        elif isinstance(sites, Mapping):
            if "site_id" in sites and "name" in sites:
                site_list = [Site.from_dict(sites)]
            else:
                site_list = [
                    v if isinstance(v, Site) else Site.from_dict(v)
                    for v in sites.values()
                ]
        else:
            site_list = [
                s if isinstance(s, Site) else Site.from_dict(s) for s in sites
            ]

        for site in site_list:
            for eq in site.equipment:
                idx.equipment_by_site_id[(site.site_id, eq.equipment_id)] = eq
                idx.equipment_by_id[eq.equipment_id] = eq
            for dev in site.devices:
                idx.devices_by_site_id[(site.site_id, dev.device_id)] = dev
                idx.devices_by_id[dev.device_id] = dev
                for port in dev.ports:
                    idx.ports_by_site_id[(site.site_id, port.port_id)] = port
                    idx.ports_by_id[port.port_id] = port
            for sub in site.subnets:
                idx.subnets_by_site_id[(site.site_id, sub.subnet_id)] = sub
                idx.subnets_by_id[sub.subnet_id] = sub
            for ip_rec in site.ip_addresses:
                idx.ips_by_site_ip[(site.site_id, ip_rec.ip)] = ip_rec
                idx.ips_by_ip[ip_rec.ip] = ip_rec
                if ip_rec.assigned_object_id:
                    bucket = idx.ips_by_assigned_obj.setdefault(
                        ip_rec.assigned_object_id, []
                    )
                    if ip_rec.ip not in bucket:
                        bucket.append(ip_rec.ip)

        return idx


def _try_parse_ip_addr(
    value: Optional[str],
) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    if not value or not isinstance(value, str):
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    if "/" in cleaned:
        cleaned = cleaned.split("/", 1)[0].strip()
    try:
        return ipaddress.ip_address(cleaned)
    except ValueError:
        return None


class QuarantineEngine:
    """Evaluates ValidationResult items alongside HistoryStore streaks against QuarantinePolicy."""

    FLAG_STALE_IN_SOT: ClassVar[RemediationOperation] = (
        RemediationOperation.FLAG_STALE_IN_SOT
    )
    RECLAIM_STALE_IP: ClassVar[RemediationOperation] = (
        RemediationOperation.RECLAIM_STALE_IP
    )
    DECOMMISSION_VM_RECORD: ClassVar[RemediationOperation] = (
        RemediationOperation.DECOMMISSION_VM_RECORD
    )
    PROPOSE_PORT_SHUTDOWN: ClassVar[RemediationOperation] = (
        RemediationOperation.PROPOSE_PORT_SHUTDOWN
    )
    EXEMPT_PROTECTED: ClassVar[RemediationOperation] = (
        RemediationOperation.EXEMPT_PROTECTED
    )

    def __init__(self, policy: Optional[QuarantinePolicy] = None) -> None:
        if policy is None:
            self.policy = QuarantinePolicy()
        elif isinstance(policy, QuarantinePolicy):
            self.policy = policy
        elif isinstance(policy, Mapping):
            self.policy = QuarantinePolicy.from_dict(policy)
        else:
            raise ValueError("policy must be a QuarantinePolicy instance or None")

    def map_target_operation(
        self,
        res: ValidationResult,
        site_index: Optional[_SiteInventoryIndex] = None,
    ) -> RemediationOperation:
        """Map an inventory item to its default Phase 2 RemediationOperation."""
        norm_type = _canonical_token(res.item_type)
        if norm_type in ("ipaddress", "ip"):
            return RemediationOperation.RECLAIM_STALE_IP
        if norm_type == "port":
            return RemediationOperation.PROPOSE_PORT_SHUTDOWN
        if norm_type in ("vm", "virtualmachine"):
            return RemediationOperation.DECOMMISSION_VM_RECORD

        if site_index is not None:
            eq = site_index.equipment_by_site_id.get(
                (res.site_id, res.item_id)
            ) or site_index.equipment_by_id.get(res.item_id)
            if eq is not None and eq.category is EquipmentCategory.VM:
                return RemediationOperation.DECOMMISSION_VM_RECORD

        has_vm_signal = any(
            s.signal_type is SignalType.VM_POWER_STATE for s in res.signals
        )
        if has_vm_signal:
            return RemediationOperation.DECOMMISSION_VM_RECORD

        if norm_type == "equipment":
            tokens = _word_tokens(res.item_id) | _word_tokens(res.name)
            if "vm" in tokens:
                return RemediationOperation.DECOMMISSION_VM_RECORD

        return RemediationOperation.FLAG_STALE_IN_SOT

    def check_protection(
        self,
        res: ValidationResult,
        site_index: Optional[_SiteInventoryIndex] = None,
    ) -> Optional[str]:
        """Return an exemption reason string if `res` matches a policy protection allowlist, else None."""
        # 1. Protected item IDs
        if self.policy.protected_item_ids:
            protected_ids_exact = set(self.policy.protected_item_ids)
            protected_ids_lower = {pid.lower() for pid in self.policy.protected_item_ids}
            composite_key = f"{res.item_type}:{res.item_id}"
            if (
                res.item_id in protected_ids_exact
                or res.item_id.lower() in protected_ids_lower
                or composite_key in protected_ids_exact
                or composite_key.lower() in protected_ids_lower
            ):
                return f"Protected item_id {res.item_id!r} in policy allowlist"

        # 2. Protected categories / roles / vendors
        if self.policy.protected_categories or self.policy.protected_vendors:
            item_categories: set[str] = set()
            item_vendors: set[str] = set()

            item_categories.add(res.item_type.lower())
            item_categories.add(_canonical_token(res.item_type))
            if _canonical_token(res.item_type) == "networkdevice":
                item_categories.update({"network_device", "networkdevice", "switch"})

            eq_found = False
            dev_found = False
            if site_index is not None:
                eq = site_index.equipment_by_site_id.get(
                    (res.site_id, res.item_id)
                ) or site_index.equipment_by_id.get(res.item_id)
                if eq is not None:
                    eq_found = True
                    item_categories.add(eq.category.value.lower())
                    item_categories.add(_canonical_token(eq.category.value))

                dev = site_index.devices_by_site_id.get(
                    (res.site_id, res.item_id)
                ) or site_index.devices_by_id.get(res.item_id)
                if dev is not None:
                    dev_found = True
                    if dev.role:
                        role_clean = dev.role.strip().lower()
                        role_canon = _canonical_token(role_clean)
                        item_categories.add(role_clean)
                        item_categories.add(role_canon)
                        if role_canon in ("core", "coreswitch"):
                            item_categories.update(
                                {"core", "core_switch", "coreswitch"}
                            )
                    if dev.vendor:
                        vendor_clean = dev.vendor.strip().lower()
                        vendor_canon = _canonical_token(vendor_clean)
                        item_vendors.add(vendor_clean)
                        item_vendors.add(vendor_canon)
                        item_categories.add(vendor_clean)
                        item_categories.add(vendor_canon)
                        for tok in _word_tokens(vendor_clean):
                            item_vendors.add(tok)
                            item_categories.add(tok)

            if not eq_found and not dev_found:
                name_id_tokens = _word_tokens(res.item_id) | _word_tokens(res.name)
                if "ups" in name_id_tokens or "apc" in name_id_tokens:
                    item_categories.add("ups")
                if "apc" in name_id_tokens:
                    item_vendors.add("apc")
                if "extreme" in name_id_tokens:
                    item_vendors.add("extreme")
                    item_categories.add("extreme")
                if "core" in name_id_tokens:
                    item_categories.update({"core", "core_switch", "coreswitch"})

            for prot_cat in self.policy.protected_categories:
                prot_canon = _canonical_token(prot_cat)
                if prot_cat.lower() in item_categories or prot_canon in item_categories:
                    return f"Protected category {prot_cat!r} in policy allowlist"

            for prot_vendor in self.policy.protected_vendors:
                prot_canon = _canonical_token(prot_vendor)
                if prot_vendor.lower() in item_vendors or prot_canon in item_vendors:
                    return f"Protected vendor {prot_vendor!r} in policy allowlist"

        # 3. Protected subnets
        if self.policy.protected_subnets:
            networks = [
                ipaddress.ip_network(cidr, strict=False)
                for cidr in self.policy.protected_subnets
            ]
            candidate_ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []

            for raw_candidate in (res.item_id, res.name):
                parsed = _try_parse_ip_addr(raw_candidate)
                if parsed is not None and parsed not in candidate_ips:
                    candidate_ips.append(parsed)

            if site_index is not None:
                eq = site_index.equipment_by_site_id.get(
                    (res.site_id, res.item_id)
                ) or site_index.equipment_by_id.get(res.item_id)
                if eq is not None:
                    for raw_ip in eq.assigned_ips:
                        parsed = _try_parse_ip_addr(raw_ip)
                        if parsed is not None and parsed not in candidate_ips:
                            candidate_ips.append(parsed)

                dev = site_index.devices_by_site_id.get(
                    (res.site_id, res.item_id)
                ) or site_index.devices_by_id.get(res.item_id)
                if dev is not None and dev.management_ip:
                    parsed = _try_parse_ip_addr(dev.management_ip)
                    if parsed is not None and parsed not in candidate_ips:
                        candidate_ips.append(parsed)

                for linked_ip in site_index.ips_by_assigned_obj.get(
                    res.item_id, ()
                ):
                    parsed = _try_parse_ip_addr(linked_ip)
                    if parsed is not None and parsed not in candidate_ips:
                        candidate_ips.append(parsed)

                ip_rec = site_index.ips_by_site_ip.get(
                    (res.site_id, res.item_id)
                ) or site_index.ips_by_ip.get(res.item_id)
                if ip_rec is not None:
                    parsed = _try_parse_ip_addr(ip_rec.ip)
                    if parsed is not None and parsed not in candidate_ips:
                        candidate_ips.append(parsed)

            for ip_addr in candidate_ips:
                for net in networks:
                    if ip_addr.version == net.version and ip_addr in net:
                        return (
                            f"Item IP {str(ip_addr)!r} falls within protected subnet {str(net)!r}"
                        )

        return None

    @staticmethod
    def _resolve_streak_lookup(
        history: Optional[
            HistoryStore
            | Sequence[ItemStreakSummary | Mapping[str, Any]]
            | Mapping[Any, ItemStreakSummary | Mapping[str, Any]]
        ],
    ) -> tuple[
        Optional[HistoryStore],
        dict[tuple[str, str, str], ItemStreakSummary],
        dict[tuple[str, str], ItemStreakSummary],
        dict[str, ItemStreakSummary],
        list[ItemStreakSummary],
    ]:
        by_site_type_id: dict[tuple[str, str, str], ItemStreakSummary] = {}
        by_type_id: dict[tuple[str, str], ItemStreakSummary] = {}
        by_id: dict[str, ItemStreakSummary] = {}
        all_streaks: list[ItemStreakSummary] = []

        if history is None:
            return None, by_site_type_id, by_type_id, by_id, all_streaks

        if isinstance(history, HistoryStore):
            for st in history.list_streaks():
                by_site_type_id[(st.site_id, st.item_type, st.item_id)] = st
                by_type_id[(st.item_type, st.item_id)] = st
                by_id[st.item_id] = st
                all_streaks.append(st)
            return history, by_site_type_id, by_type_id, by_id, all_streaks

        if isinstance(history, Mapping):
            raw_items = list(history.values())
        else:
            raw_items = list(history)

        for raw in raw_items:
            st = (
                raw
                if isinstance(raw, ItemStreakSummary)
                else ItemStreakSummary.from_dict(raw)
            )
            by_site_type_id[(st.site_id, st.item_type, st.item_id)] = st
            by_type_id[(st.item_type, st.item_id)] = st
            by_id[st.item_id] = st
            all_streaks.append(st)

        return None, by_site_type_id, by_type_id, by_id, all_streaks

    def evaluate(
        self,
        results: Optional[
            Sequence[ValidationResult | ItemStreakSummary | Mapping[str, Any]]
            | HistoryStore
        ] = None,
        history: Optional[
            HistoryStore
            | Sequence[ItemStreakSummary | Mapping[str, Any]]
            | Mapping[Any, ItemStreakSummary | Mapping[str, Any]]
        ] = None,
        *,
        streaks: Optional[
            HistoryStore
            | Sequence[ItemStreakSummary | Mapping[str, Any]]
            | Mapping[Any, ItemStreakSummary | Mapping[str, Any]]
        ] = None,
        sites: Optional[
            Site | Sequence[Site | Mapping[str, Any]] | Mapping[str, Any]
        ] = None,
        override_protected: bool = False,
        generated_at: Optional[datetime | str] = None,
        manifest_id: Optional[str] = None,
        include_below_threshold: bool = False,
    ) -> RemediationApprovalManifest:
        """Evaluate ValidationResult items and streak history against QuarantinePolicy."""
        effective_history = history if history is not None else streaks
        if isinstance(results, HistoryStore) and effective_history is None:
            effective_history = results
            results = None

        _, by_site_type_id, by_type_id, by_id, all_streaks = (
            self._resolve_streak_lookup(effective_history)
        )
        site_index = _SiteInventoryIndex.from_sites(sites)
        manifest_dt = _resolve_plan_timestamp(generated_at)

        candidates: list[tuple[ValidationResult, Optional[ItemStreakSummary]]] = []

        if results is not None:
            for raw_item in results:
                if isinstance(raw_item, ItemStreakSummary):
                    st = raw_item
                    res = ValidationResult(
                        item_type=st.item_type,
                        item_id=st.item_id,
                        site_id=st.site_id,
                        name=st.name,
                        classification=st.current_classification,
                        confidence=st.current_confidence,
                        evaluated_at=st.first_seen_at,
                    )
                    candidates.append((res, st))
                elif isinstance(raw_item, ValidationResult):
                    res = raw_item
                    st = (
                        by_site_type_id.get(
                            (res.site_id, res.item_type, res.item_id)
                        )
                        or by_type_id.get((res.item_type, res.item_id))
                        or by_id.get(res.item_id)
                    )
                    candidates.append((res, st))
                elif isinstance(raw_item, Mapping):
                    if "consecutive_stale_runs" in raw_item and "current_classification" in raw_item:
                        st = ItemStreakSummary.from_dict(raw_item)
                        res = ValidationResult(
                            item_type=st.item_type,
                            item_id=st.item_id,
                            site_id=st.site_id,
                            name=st.name,
                            classification=st.current_classification,
                            confidence=st.current_confidence,
                            evaluated_at=st.first_seen_at,
                        )
                        candidates.append((res, st))
                    else:
                        res = ValidationResult.from_dict(raw_item)
                        st = (
                            by_site_type_id.get(
                                (res.site_id, res.item_type, res.item_id)
                            )
                            or by_type_id.get((res.item_type, res.item_id))
                            or by_id.get(res.item_id)
                        )
                        candidates.append((res, st))
                else:
                    raise ValueError(f"Unsupported result item: {raw_item!r}")
        else:
            for st in all_streaks:
                res = ValidationResult(
                    item_type=st.item_type,
                    item_id=st.item_id,
                    site_id=st.site_id,
                    name=st.name,
                    classification=st.current_classification,
                    confidence=st.current_confidence,
                    evaluated_at=st.first_seen_at,
                )
                candidates.append((res, st))

        effective_override = bool(
            override_protected or self.policy.allow_protected_override
        )
        entries: list[QuarantineManifestEntry] = []

        for res, streak in candidates:
            if res.classification is not ValidationClassification.STALE_LIKELY_UNUSED:
                continue

            consecutive_runs = (
                streak.consecutive_stale_runs if streak is not None else 1
            )
            stale_days = (
                streak.stale_duration_days if streak is not None else 0.0
            )
            confidence = res.confidence

            target_op = self.map_target_operation(res, site_index=site_index)
            protection_reason = self.check_protection(res, site_index=site_index)

            proposed_dt = (
                res.evaluated_at if res.evaluated_at is not None else manifest_dt
            )
            action = ProposedRemediationAction(
                action_type=RemediationActionType.MARK_STALE_CANDIDATE,
                site_id=res.site_id,
                item_type=res.item_type,
                item_id=res.item_id,
                name=res.name,
                classification=res.classification,
                confidence=confidence,
                rationale=res.rationale,
                proposed_at=proposed_dt,
                dry_run=True,
            )

            if protection_reason is not None and not effective_override:
                entries.append(
                    QuarantineManifestEntry(
                        action=action,
                        streak=streak,
                        site_id=res.site_id,
                        item_type=res.item_type,
                        item_id=res.item_id,
                        name=res.name,
                        classification=res.classification,
                        confidence=confidence,
                        consecutive_stale_runs=consecutive_runs,
                        stale_duration_days=stale_days,
                        target_operation=target_op,
                        graduation_status=QuarantineGraduationStatus.EXEMPT_PROTECTED,
                        approval_status=ApprovalStatus.EXEMPT,
                        exemption_reason=protection_reason,
                        rationale=res.rationale,
                        proposed_at=proposed_dt,
                        dry_run=True,
                    )
                )
                continue

            meets_thresholds = (
                consecutive_runs >= self.policy.min_consecutive_stale_runs
                and stale_days >= self.policy.min_stale_days
                and confidence >= self.policy.min_confidence
            )
            if meets_thresholds:
                entries.append(
                    QuarantineManifestEntry(
                        action=action,
                        streak=streak,
                        site_id=res.site_id,
                        item_type=res.item_type,
                        item_id=res.item_id,
                        name=res.name,
                        classification=res.classification,
                        confidence=confidence,
                        consecutive_stale_runs=consecutive_runs,
                        stale_duration_days=stale_days,
                        target_operation=target_op,
                        graduation_status=QuarantineGraduationStatus.ELIGIBLE,
                        approval_status=ApprovalStatus.PENDING,
                        exemption_reason=None,
                        rationale=res.rationale,
                        proposed_at=proposed_dt,
                        dry_run=True,
                    )
                )
            elif include_below_threshold:
                entries.append(
                    QuarantineManifestEntry(
                        action=action,
                        streak=streak,
                        site_id=res.site_id,
                        item_type=res.item_type,
                        item_id=res.item_id,
                        name=res.name,
                        classification=res.classification,
                        confidence=confidence,
                        consecutive_stale_runs=consecutive_runs,
                        stale_duration_days=stale_days,
                        target_operation=target_op,
                        graduation_status=QuarantineGraduationStatus.BELOW_THRESHOLD,
                        approval_status=ApprovalStatus.REJECTED,
                        exemption_reason=None,
                        rationale=res.rationale,
                        proposed_at=proposed_dt,
                        dry_run=True,
                    )
                )

        entries.sort(key=lambda e: (e.site_id, e.item_type, e.item_id))
        resolved_manifest_id = (
            manifest_id
            if manifest_id is not None
            else f"manifest-{uuid.uuid4().hex[:12]}"
        )
        return RemediationApprovalManifest(
            entries=entries,
            policy=self.policy,
            generated_at=manifest_dt,
            manifest_id=resolved_manifest_id,
            dry_run=True,
        )

    def build_manifest(
        self,
        results: Optional[
            Sequence[ValidationResult | ItemStreakSummary | Mapping[str, Any]]
            | HistoryStore
        ] = None,
        history: Optional[
            HistoryStore
            | Sequence[ItemStreakSummary | Mapping[str, Any]]
            | Mapping[Any, ItemStreakSummary | Mapping[str, Any]]
        ] = None,
        **kwargs: Any,
    ) -> RemediationApprovalManifest:
        """Alias for evaluate()."""
        return self.evaluate(results, history, **kwargs)
