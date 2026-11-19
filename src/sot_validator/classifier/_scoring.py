"""Scoring mixin for ClassificationEngine: classify_signals, the _score_* methods and the _build_*_rationale methods."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any, Optional

from sot_validator.classifier._helpers import (
    _EvaluatedSignalView,
    _has_actionable_identifiers,
    _has_healthy_tools_detail,
    _is_windows_context,
    _sot_power_state_is_active,
)
from sot_validator.classifier._policy import (
    _ACTIVE_PROBE_SIGNAL_TYPES,
    _SUBSTANTIVE_STALE_SIGNAL_TYPES,
)
from sot_validator.models import (
    Equipment,
    EquipmentCategory,
    SignalStatus,
    SignalType,
    Site,
    ValidationClassification,
    ValidationResult,
    ValidationSignal,
)

class _ScoringMixin:
    """Classification scoring and rationale methods for ClassificationEngine."""

    def classify_signals(
        self,
        signals: Sequence[ValidationSignal],
        *,
        item_type: str = "Equipment",
        item_id: str = "unknown",
        site_id: str = "unknown",
        name: Optional[str] = None,
        target: Optional[Any] = None,
        site: Optional[Site] = None,
        evaluation_time: Optional[datetime | str] = None,
    ) -> ValidationResult:
        """Classify a sequence of ValidationSignal objects into a ValidationResult."""
        eval_dt = self._resolve_eval_time(evaluation_time)
        resolved_name = name.strip() if isinstance(name, str) and name.strip() else item_id
        views = self._normalize_signals(signals, eval_dt)
        normalized_signals = [v.signal for v in views]

        # 1. Check Insufficient Data
        applicable_views = [
            v
            for v in views
            if v.effective_status is not SignalStatus.NOT_APPLICABLE
        ]
        has_directory_or_dns_match = any(
            v.signal.signal_type
            in (SignalType.AD_COMPUTER_ACCOUNT, SignalType.DNS_DHCP_LEASE)
            for v in applicable_views
        )
        if (
            not views
            or not applicable_views
            or (
                not _has_actionable_identifiers(target, site=site)
                and not has_directory_or_dns_match
            )
        ):
            rationale = (
                f"Insufficient Data for {item_type} {resolved_name} ({item_id}): "
                "no actionable identifiers or applicable validation signals available "
                "(all signals absent or NOT_APPLICABLE)."
            )
            return ValidationResult(
                item_type=item_type,
                item_id=item_id,
                site_id=site_id,
                name=resolved_name,
                classification=ValidationClassification.INSUFFICIENT_DATA,
                confidence=0.0,
                signals=normalized_signals,
                rationale=rationale,
                evaluated_at=eval_dt,
            )

        effective_views = [v for v in applicable_views if not v.discounted]
        by_type: dict[SignalType, list[_EvaluatedSignalView]] = {}
        for v in effective_views:
            by_type.setdefault(v.signal.signal_type, []).append(v)

        def _has_status(sig_type: SignalType, status: SignalStatus) -> bool:
            return any(
                v.effective_status is status for v in by_type.get(sig_type, ())
            )

        icmp_active = _has_status(SignalType.ICMP_REACHABILITY, SignalStatus.ACTIVE)
        snmp_active = _has_status(
            SignalType.SNMP_API_REACHABILITY, SignalStatus.ACTIVE
        )
        arp_active = _has_status(SignalType.ARP_RECENCY, SignalStatus.ACTIVE)
        vm_active = _has_status(SignalType.VM_POWER_STATE, SignalStatus.ACTIVE)
        ad_active = _has_status(SignalType.AD_COMPUTER_ACCOUNT, SignalStatus.ACTIVE)
        dns_dhcp_active = _has_status(
            SignalType.DNS_DHCP_LEASE, SignalStatus.ACTIVE
        )
        port_active = _has_status(SignalType.PORT_STATE, SignalStatus.ACTIVE)
        last_seen_active = _has_status(
            SignalType.LAST_SEEN_TIMESTAMP, SignalStatus.ACTIVE
        )

        icmp_unreachable = _has_status(
            SignalType.ICMP_REACHABILITY, SignalStatus.UNREACHABLE
        )
        snmp_unreachable = _has_status(
            SignalType.SNMP_API_REACHABILITY, SignalStatus.UNREACHABLE
        )
        vm_unreachable = _has_status(
            SignalType.VM_POWER_STATE, SignalStatus.UNREACHABLE
        )
        vm_inactive = _has_status(SignalType.VM_POWER_STATE, SignalStatus.INACTIVE)
        arp_inactive = _has_status(SignalType.ARP_RECENCY, SignalStatus.INACTIVE)
        ad_disabled = any(
            v.effective_status is SignalStatus.INACTIVE
            and (
                v.signal.metadata.get("enabled") is False
                or "disabled" in (v.signal.details or "").lower()
                or "enabled=false" in (v.signal.details or "").lower()
            )
            for v in by_type.get(SignalType.AD_COMPUTER_ACCOUNT, ())
        )

        any_error = any(
            v.effective_status is SignalStatus.ERROR for v in effective_views
        )
        any_non_active = any(
            v.effective_status
            in (
                SignalStatus.INACTIVE,
                SignalStatus.UNREACHABLE,
                SignalStatus.ERROR,
            )
            for v in effective_views
        )

        # 2. Check Confirmed Active
        has_high_confidence_active = False
        windows_firewall_override = False

        if snmp_active or icmp_active:
            has_high_confidence_active = True
        elif vm_active or arp_active or ad_active or (dns_dhcp_active and not ad_disabled and not vm_inactive):
            if icmp_unreachable and not self.policy.windows_vm_ignore_icmp_unreachable:
                has_high_confidence_active = False
            else:
                has_high_confidence_active = True
                if icmp_unreachable:
                    windows_firewall_override = True

        port_or_last_seen_confirmed = False
        if not has_high_confidence_active:
            if port_active and not any_error and not vm_unreachable and not vm_inactive:
                other_active = any(
                    v.effective_status is SignalStatus.ACTIVE
                    and v.signal.signal_type is not SignalType.PORT_STATE
                    for v in effective_views
                )
                probe_failed = (
                    icmp_unreachable
                    or snmp_unreachable
                    or _has_status(SignalType.ICMP_REACHABILITY, SignalStatus.ERROR)
                    or _has_status(
                        SignalType.SNMP_API_REACHABILITY, SignalStatus.ERROR
                    )
                )
                last_seen_inactive = _has_status(
                    SignalType.LAST_SEEN_TIMESTAMP, SignalStatus.INACTIVE
                )
                if not probe_failed and not arp_inactive and (
                    other_active or not last_seen_inactive
                ):
                    port_or_last_seen_confirmed = True
            elif last_seen_active and not any_non_active:
                port_or_last_seen_confirmed = True

        if has_high_confidence_active or port_or_last_seen_confirmed:
            confidence = self._score_confirmed_active(
                effective_views,
                windows_firewall_override=windows_firewall_override,
                target=target,
            )
            rationale = self._build_confirmed_active_rationale(
                item_type=item_type,
                item_id=item_id,
                name=resolved_name,
                views=effective_views,
                windows_firewall_override=windows_firewall_override,
                target=target,
            )
            return ValidationResult(
                item_type=item_type,
                item_id=item_id,
                site_id=site_id,
                name=resolved_name,
                classification=ValidationClassification.CONFIRMED_ACTIVE,
                confidence=confidence,
                signals=normalized_signals,
                rationale=rationale,
                evaluated_at=eval_dt,
            )

        # 3. Check Unreachable / Needs Manual Review vs Stale / Likely Unused
        has_intermediate = any(v.is_intermediate for v in effective_views)
        has_substantive_stale = any(
            v.signal.signal_type in _SUBSTANTIVE_STALE_SIGNAL_TYPES
            and v.effective_status is SignalStatus.INACTIVE
            and v.is_stale
            for v in effective_views
        )

        sot_claimed_on_conflict = False
        if isinstance(target, Equipment) and not vm_inactive:
            if _sot_power_state_is_active(target) or (
                target.category is EquipmentCategory.VM
                and not _has_status(
                    SignalType.VM_POWER_STATE, SignalStatus.INACTIVE
                )
                and (icmp_unreachable or snmp_unreachable)
            ):
                sot_claimed_on_conflict = True

        has_conflict = (
            port_active
            or last_seen_active
            or vm_active
            or arp_active
            or ad_active
            or dns_dhcp_active
            or sot_claimed_on_conflict
        )
        all_unreachable = all(
            v.effective_status is SignalStatus.UNREACHABLE for v in effective_views
        )

        if (
            has_conflict
            or any_error
            or vm_unreachable
            or has_intermediate
            or all_unreachable
            or not has_substantive_stale
        ):
            confidence = self._score_unreachable_needs_review(
                effective_views,
                has_conflict=has_conflict,
                any_error=any_error,
                vm_unreachable=vm_unreachable,
                has_intermediate=has_intermediate,
            )
            rationale = self._build_unreachable_rationale(
                item_type=item_type,
                item_id=item_id,
                name=resolved_name,
                views=effective_views,
                has_conflict=has_conflict,
                sot_claimed_on_conflict=sot_claimed_on_conflict,
                any_error=any_error,
                vm_unreachable=vm_unreachable,
                has_intermediate=has_intermediate,
            )
            return ValidationResult(
                item_type=item_type,
                item_id=item_id,
                site_id=site_id,
                name=resolved_name,
                classification=ValidationClassification.UNREACHABLE_NEEDS_REVIEW,
                confidence=confidence,
                signals=normalized_signals,
                rationale=rationale,
                evaluated_at=eval_dt,
            )

        # 4. Stale / Likely Unused
        confidence = self._score_stale_likely_unused(views)
        rationale = self._build_stale_rationale(
            item_type=item_type,
            item_id=item_id,
            name=resolved_name,
            views=views,
        )
        return ValidationResult(
            item_type=item_type,
            item_id=item_id,
            site_id=site_id,
            name=resolved_name,
            classification=ValidationClassification.STALE_LIKELY_UNUSED,
            confidence=confidence,
            signals=normalized_signals,
            rationale=rationale,
            evaluated_at=eval_dt,
        )

    def _score_confirmed_active(
        self,
        views: Sequence[_EvaluatedSignalView],
        *,
        windows_firewall_override: bool,
        target: Optional[Any],
    ) -> float:
        active_views = [
            v for v in views if v.effective_status is SignalStatus.ACTIVE
        ]
        active_types = {v.signal.signal_type for v in active_views}

        base = 0.65
        if SignalType.VM_POWER_STATE in active_types:
            base = max(base, 0.86)
            if any(
                _has_healthy_tools_detail(v.signal.details)
                for v in active_views
                if v.signal.signal_type is SignalType.VM_POWER_STATE
            ):
                base += 0.04
        if SignalType.SNMP_API_REACHABILITY in active_types:
            base = max(base, 0.86)
        if SignalType.AD_COMPUTER_ACCOUNT in active_types:
            base = max(base, 0.85)
        if SignalType.ARP_RECENCY in active_types:
            if windows_firewall_override or _is_windows_context(target, views):
                base = max(base, 0.85)
            else:
                base = max(base, 0.82)
        if SignalType.DNS_DHCP_LEASE in active_types:
            base = max(base, 0.82)
        if SignalType.ICMP_REACHABILITY in active_types:
            base = max(base, 0.82)
        if SignalType.PORT_STATE in active_types:
            base = max(base, 0.72)
        if SignalType.LAST_SEEN_TIMESTAMP in active_types:
            base = max(base, 0.65)

        corroboration_bonus = 0.0
        if len(active_types) > 1:
            sorted_weights = sorted(
                (self.policy.weight_for(st) for st in active_types),
                reverse=True,
            )
            for extra_weight in sorted_weights[1:]:
                corroboration_bonus += min(0.06, extra_weight * 0.15)

        penalty = 0.0
        for v in views:
            if v.effective_status in (SignalStatus.INACTIVE, SignalStatus.ERROR):
                penalty += 0.04
            elif (
                v.effective_status is SignalStatus.ACTIVE
                and v.signal.metadata.get("dns_mismatch") is True
            ):
                penalty += 0.04
            elif v.effective_status is SignalStatus.UNREACHABLE:
                if (
                    windows_firewall_override
                    and v.signal.signal_type in _ACTIVE_PROBE_SIGNAL_TYPES
                ):
                    continue
                if (
                    v.signal.signal_type in _ACTIVE_PROBE_SIGNAL_TYPES
                    and SignalType.ARP_RECENCY in active_types
                    and SignalType.PORT_STATE in active_types
                ):
                    continue
                penalty += 0.03

        score = base + corroboration_bonus - penalty
        if windows_firewall_override and (
            SignalType.VM_POWER_STATE in active_types
            or SignalType.ARP_RECENCY in active_types
            or SignalType.AD_COMPUTER_ACCOUNT in active_types
            or (
                SignalType.DNS_DHCP_LEASE in active_types
                and not any(
                    v.signal.metadata.get("dns_mismatch") is True
                    for v in active_views
                )
            )
        ):
            score = max(0.85, score)

        return round(min(1.0, max(0.60, score)), 4)

    def _score_stale_likely_unused(
        self, views: Sequence[_EvaluatedSignalView]
    ) -> float:
        effective = [v for v in views if not v.discounted]
        stale_types = {
            v.signal.signal_type
            for v in effective
            if v.signal.signal_type in _SUBSTANTIVE_STALE_SIGNAL_TYPES
            and v.effective_status is SignalStatus.INACTIVE
            and v.is_stale
        }
        unreachable_probe_types = {
            v.signal.signal_type
            for v in effective
            if v.signal.signal_type in _ACTIVE_PROBE_SIGNAL_TYPES
            and v.effective_status is SignalStatus.UNREACHABLE
        }

        base = 0.72 if SignalType.VM_POWER_STATE in stale_types else 0.66
        bonus = 0.0
        sorted_stale_weights = sorted(
            (self.policy.weight_for(st) for st in stale_types),
            reverse=True,
        )
        for idx, weight in enumerate(sorted_stale_weights):
            if idx == 0:
                bonus += min(0.06, weight * 0.12)
            else:
                bonus += min(0.09, 0.05 + weight * 0.12)

        for probe_type in unreachable_probe_types:
            bonus += min(0.06, 0.03 + self.policy.weight_for(probe_type) * 0.08)

        score = base + bonus
        return round(min(1.0, max(0.60, score)), 4)

    def _score_unreachable_needs_review(
        self,
        views: Sequence[_EvaluatedSignalView],
        *,
        has_conflict: bool,
        any_error: bool,
        vm_unreachable: bool,
        has_intermediate: bool,
    ) -> float:
        if any_error:
            base = 0.30
        elif vm_unreachable:
            base = 0.40
        elif has_conflict:
            base = 0.55
        elif has_intermediate:
            base = 0.50
        else:
            base = 0.45

        non_na_count = sum(
            1
            for v in views
            if v.effective_status is not SignalStatus.NOT_APPLICABLE
        )
        adjustment = min(0.10, max(0, non_na_count - 1) * 0.03)
        score = base + adjustment
        return round(min(0.75, max(0.20, score)), 4)

    def _build_confirmed_active_rationale(
        self,
        *,
        item_type: str,
        item_id: str,
        name: str,
        views: Sequence[_EvaluatedSignalView],
        windows_firewall_override: bool,
        target: Optional[Any],
    ) -> str:
        active_summaries = [
            f"{v.signal.signal_type.value}=ACTIVE"
            for v in views
            if v.effective_status is SignalStatus.ACTIVE
        ]
        notes: list[str] = []
        if windows_firewall_override:
            if _is_windows_context(target, views):
                notes.append(
                    "Windows VM rule applied: active vCenter power state / Guest Tools heartbeat "
                    "or recent ARP overrides ICMP_REACHABILITY=UNREACHABLE (host firewall blocks ICMP)"
                )
            else:
                notes.append(
                    "active vCenter/ARP signal overrides ICMP_REACHABILITY=UNREACHABLE"
                )
        for v in views:
            if (
                v.signal.signal_type is SignalType.VM_POWER_STATE
                and v.effective_status is SignalStatus.ACTIVE
                and _has_healthy_tools_detail(v.signal.details)
            ):
                notes.append("VMware Guest Tools heartbeat healthy")
                break

        note_str = f" ({'; '.join(notes)})" if notes else ""
        return (
            f"Confirmed Active for {item_type} {name} ({item_id}): "
            f"corroborated by {', '.join(active_summaries)}"
            f" within {self.policy.active_within_days:g}d active window{note_str}."
        )

    def _build_unreachable_rationale(
        self,
        *,
        item_type: str,
        item_id: str,
        name: str,
        views: Sequence[_EvaluatedSignalView],
        has_conflict: bool,
        sot_claimed_on_conflict: bool,
        any_error: bool,
        vm_unreachable: bool,
        has_intermediate: bool,
    ) -> str:
        sig_summaries = [
            f"{v.signal.signal_type.value}={v.effective_status.value}"
            for v in views
        ]
        reasons: list[str] = []
        if has_conflict:
            if any(
                v.signal.signal_type is SignalType.PORT_STATE
                and v.effective_status is SignalStatus.ACTIVE
                for v in views
            ):
                reasons.append(
                    "conflicting signals: switch port is ACTIVE (link UP or PoE power draw) "
                    "while network probes/ARP are unreachable or stale"
                )
            elif sot_claimed_on_conflict:
                reasons.append(
                    "conflicting signals: record is marked active/VM in SoT while probes fail "
                    "and no recent ARP or vCenter power-off confirmation is available"
                )
            else:
                reasons.append(
                    "conflicting active and inactive/unreachable validation signals"
                )
        if vm_unreachable:
            reasons.append(
                "vCenter hypervisor inventory is UNREACHABLE for VM verification"
            )
        if any_error:
            reasons.append("signal evaluation or probe returned ERROR")
        if has_intermediate:
            reasons.append(
                f"activity timestamp is in intermediate aging window "
                f"(> {self.policy.active_within_days:g}d and <= {self.policy.stale_after_days:g}d)"
            )
        if not reasons:
            reasons.append(
                "active probes timed out (UNREACHABLE) without corroborating historical inactivity"
            )

        return (
            f"Unreachable / Needs Manual Review for {item_type} {name} ({item_id}): "
            f"{'; '.join(reasons)} [{', '.join(sig_summaries)}]."
        )

    def _build_stale_rationale(
        self,
        *,
        item_type: str,
        item_id: str,
        name: str,
        views: Sequence[_EvaluatedSignalView],
    ) -> str:
        effective = [v for v in views if not v.discounted]
        discounted = [v for v in views if v.discounted]
        sig_summaries = [
            f"{v.signal.signal_type.value}={v.effective_status.value}"
            for v in effective
        ]
        discount_note = (
            " (shared hypervisor trunk PORT_STATE=ACTIVE discounted for powered-off VM)"
            if discounted
            else ""
        )
        return (
            f"Stale / Likely Unused for {item_type} {name} ({item_id}): "
            f"all applicable signals indicate inactivity beyond {self.policy.stale_after_days:g}d "
            f"stale threshold [{', '.join(sig_summaries)}]{discount_note}."
        )

    score_signals = classify_signals
