"""Per-site parity evaluation mixin for DualRunParityChecker."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from typing import Any, Optional

from sot_validator.migration._parity_models import (
    ParityDiscrepancy,
    SiteMigrationReadinessScorecard,
)
from sot_validator.migration._parity_records import (
    _STALE_MODERN_STATUSES,
    _UNTRACKED_DISCREPANCY_TYPES,
    PARITY_ENTITY_COLLECTIONS,
    CutoverRecommendation,
    ParityDiscrepancyType,
    _clamp_percentage,
    _clean_optional_str,
    _extract_legacy_id,
    _extract_record_identifier,
    _record_candidate_tokens,
)
from sot_validator.migration.exporter import (
    ModernSoTExporter,
    _normalize_discrepancies,
    _normalize_sites_input,
    _normalize_validation_results,
    _resolve_timestamp,
    _strip_ip_mask,
    slugify,
)
from sot_validator.models import Site, ValidationClassification, ValidationResult
from sot_validator.reconciliation.reconciler import (
    DiscrepancyRecord,
    ReconciliationReport,
)


class _ParityEvaluateMixin:
    """Per-site parity evaluation (evaluate_site) for DualRunParityChecker."""

    def evaluate_site(
        self,
        site_or_golden: Optional[Any] = None,
        modern_bundle: Optional[Any] = None,
        *,
        site_id: Optional[str] = None,
        site: Optional[Site | Mapping[str, Any]] = None,
        golden_bundle: Optional[Mapping[str, Any] | ModernSoTExporter] = None,
        target_bundle: Optional[Any] = None,
        sites: Optional[
            Sequence[Site | Mapping[str, Any]] | Mapping[str, Any] | Site
        ] = None,
        validation_results: Optional[
            Sequence[ValidationResult | Mapping[str, Any]] | Mapping[str, Any]
        ] = None,
        reconciliation_report: Optional[
            ReconciliationReport
            | Sequence[DiscrepancyRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        stale_item_ids: Optional[Iterable[str]] = None,
        approved_discrepancy_ids: Optional[Iterable[str]] = None,
        unresolved_untracked_discrepancies: Optional[
            ReconciliationReport
            | Sequence[DiscrepancyRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        waived_discrepancy_ids: Optional[Iterable[str]] = None,
        waive_all_parity_discrepancies: Optional[bool] = None,
        merge_untracked: Optional[bool] = None,
        evaluated_at: Optional[datetime | str] = None,
    ) -> SiteMigrationReadinessScorecard:
        """Evaluate dual-run parity and readiness scorecard for a single site."""
        if site_or_golden is not None:
            if isinstance(site_or_golden, str):
                site_id = site_id or site_or_golden
            elif isinstance(site_or_golden, Site) or (
                isinstance(site_or_golden, Mapping)
                and not self._is_bundle_mapping(site_or_golden)
            ):
                site = site if site is not None else site_or_golden
            elif self._is_bundle_mapping(site_or_golden):
                golden_bundle = (
                    golden_bundle if golden_bundle is not None else site_or_golden
                )

        eff_modern_input = (
            modern_bundle
            if modern_bundle is not None
            else (
                target_bundle
                if target_bundle is not None
                else self._modern_bundle
            )
        )
        eff_golden_input = (
            golden_bundle if golden_bundle is not None else self._golden_bundle
        )
        eff_sites_input = (
            site
            if site is not None
            else (sites if sites is not None else self._sites)
        )
        if eff_sites_input is None and isinstance(eff_golden_input, ModernSoTExporter):
            eff_sites_input = eff_golden_input._raw_sites

        eff_val_input = (
            validation_results
            if validation_results is not None
            else self._validation_results
        )
        if eff_val_input is None and isinstance(eff_golden_input, ModernSoTExporter):
            eff_val_input = eff_golden_input._validation_results

        eff_recon_input = (
            reconciliation_report
            if reconciliation_report is not None
            else self._reconciliation_report
        )
        if eff_recon_input is None and isinstance(eff_golden_input, ModernSoTExporter):
            eff_recon_input = eff_golden_input._discrepancies

        norm_sites = _normalize_sites_input(eff_sites_input)
        norm_results = _normalize_validation_results(eff_val_input)
        norm_recon = _normalize_discrepancies(eff_recon_input)
        norm_unresolved_untracked = _normalize_discrepancies(
            unresolved_untracked_discrepancies
            if unresolved_untracked_discrepancies is not None
            else self._unresolved_untracked_discrepancies
        )

        eff_approved: Optional[set[str]] = (
            {str(x).strip() for x in approved_discrepancy_ids if str(x).strip()}
            if approved_discrepancy_ids is not None
            else self._approved_discrepancy_ids
        )
        eff_merge_untracked = (
            bool(merge_untracked)
            if merge_untracked is not None
            else self.merge_untracked
        )

        if eff_golden_input is not None:
            full_golden_bundle = self._coerce_to_bundle(eff_golden_input)
        else:
            full_golden_bundle = self._coerce_to_bundle(
                norm_sites,
                validation_results=norm_results,
                reconciliation_report=norm_recon,
                approved_discrepancy_ids=eff_approved,
                merge_untracked=eff_merge_untracked,
                filter_for_golden=True,
            )

        full_modern_bundle = self._coerce_to_bundle(eff_modern_input)

        # Resolve target site_id and site_name
        resolved_site_id = site_id
        resolved_site_name = ""
        raw_site_obj: Optional[Site] = None

        if resolved_site_id is None:
            if norm_sites:
                resolved_site_id = norm_sites[0].site_id
                resolved_site_name = norm_sites[0].name
                raw_site_obj = norm_sites[0]
            elif full_golden_bundle.get("sites"):
                first_s = full_golden_bundle["sites"][0]
                resolved_site_id = (
                    _extract_legacy_id(first_s)
                    or _clean_optional_str(first_s.get("slug"))
                    or _clean_optional_str(first_s.get("name"))
                    or "site-001"
                )
                resolved_site_name = (
                    _clean_optional_str(first_s.get("name")) or resolved_site_id
                )
            elif full_modern_bundle.get("sites"):
                first_s = full_modern_bundle["sites"][0]
                resolved_site_id = (
                    _extract_legacy_id(first_s)
                    or _clean_optional_str(first_s.get("slug"))
                    or _clean_optional_str(first_s.get("name"))
                    or "site-001"
                )
                resolved_site_name = (
                    _clean_optional_str(first_s.get("name")) or resolved_site_id
                )
            else:
                resolved_site_id = "site-001"

        target_slug = slugify(resolved_site_id)
        for s_obj in norm_sites:
            if s_obj.site_id == resolved_site_id or slugify(s_obj.site_id) == target_slug:
                raw_site_obj = s_obj
                resolved_site_id = s_obj.site_id
                resolved_site_name = s_obj.name
                break

        if not resolved_site_name:
            for s_rec in full_golden_bundle.get("sites", []) + full_modern_bundle.get(
                "sites", []
            ):
                s_leg = _extract_legacy_id(s_rec)
                s_slg = _clean_optional_str(s_rec.get("slug"))
                if s_leg == resolved_site_id or (s_slg and slugify(s_slg) == target_slug):
                    resolved_site_name = (
                        _clean_optional_str(s_rec.get("name")) or resolved_site_id
                    )
                    if s_leg:
                        resolved_site_id = s_leg
                    break
        if not resolved_site_name:
            resolved_site_name = resolved_site_id

        total_known_sites = max(
            len(norm_sites),
            len(full_golden_bundle.get("sites", [])),
            len(full_modern_bundle.get("sites", [])),
        )
        single_site_context = total_known_sites <= 1

        golden_site_bundle = self._filter_bundle_for_site(
            full_golden_bundle,
            resolved_site_id,
            single_site_context=single_site_context,
            raw_site=raw_site_obj,
        )
        modern_site_bundle = self._filter_bundle_for_site(
            full_modern_bundle,
            resolved_site_id,
            single_site_context=single_site_context,
            raw_site=raw_site_obj,
        )

        combined_stale_ids = set(self._stale_item_ids)
        if stale_item_ids is not None:
            combined_stale_ids.update(
                str(x).strip() for x in stale_item_ids if str(x).strip()
            )

        stale_tokens = self._collect_stale_tokens(
            resolved_site_id,
            norm_sites,
            norm_results,
            combined_stale_ids,
            golden_site_bundle,
        )

        # Separate active golden items from any stale items in golden_site_bundle
        active_golden_by_entity: dict[str, list[dict[str, Any]]] = {}
        active_golden_tokens_by_entity: dict[str, set[str]] = {}
        for entity_type in PARITY_ENTITY_COLLECTIONS:
            active_list: list[dict[str, Any]] = []
            entity_tokens: set[str] = set()
            for rec in golden_site_bundle.get(entity_type, ()):
                status_lower = str(rec.get("status") or "").strip().lower()
                rec_tokens = _record_candidate_tokens(entity_type, rec)
                if status_lower in _STALE_MODERN_STATUSES or (rec_tokens & stale_tokens):
                    stale_tokens.update(rec_tokens)
                    continue
                active_list.append(rec)
                entity_tokens.update(rec_tokens)
            active_golden_by_entity[entity_type] = active_list
            active_golden_tokens_by_entity[entity_type] = entity_tokens

        # Build host -> golden IP lookup for device/VM IP comparison
        golden_ip_by_host: dict[str, str] = {}
        for ip_rec in active_golden_by_entity.get("ip_addresses", ()):
            addr = _clean_optional_str(ip_rec.get("address") or ip_rec.get("ip"))
            if not addr:
                continue
            for host_key in ("assigned_object", "dns_name"):
                host_val = _clean_optional_str(ip_rec.get(host_key))
                if host_val:
                    golden_ip_by_host.setdefault(host_val.lower(), addr)

        discrepancies: list[ParityDiscrepancy] = []
        leaked_modern_indices: dict[str, set[int]] = {
            et: set() for et in PARITY_ENTITY_COLLECTIONS
        }

        # 1. Detect STALE_LEAKED_TO_MODERN_SOT
        for entity_type in PARITY_ENTITY_COLLECTIONS:
            for m_idx, m_rec in enumerate(modern_site_bundle.get(entity_type, ())):
                status_lower = str(m_rec.get("status") or "").strip().lower()
                m_tokens = _record_candidate_tokens(entity_type, m_rec)

                if entity_type == "interfaces":
                    # Only flag interfaces as leaked stale if explicitly in stale_item_ids or carrying stale status
                    is_leaked = status_lower in _STALE_MODERN_STATUSES or bool(
                        m_tokens
                        & {t.lower() for t in combined_stale_ids}
                    )
                else:
                    is_active_golden = any(
                        self._records_match_exact(entity_type, g_rec, m_rec)
                        for g_rec in active_golden_by_entity[entity_type]
                    )
                    is_leaked = status_lower in _STALE_MODERN_STATUSES or (
                        bool(m_tokens & stale_tokens) and not is_active_golden
                    )

                if is_leaked:
                    leaked_modern_indices[entity_type].add(m_idx)
                    item_id = _extract_record_identifier(entity_type, m_rec)
                    legacy_id = _extract_legacy_id(m_rec)
                    disc_id = (
                        f"parity-{slugify(resolved_site_id)}-stale-leaked-"
                        f"{slugify(entity_type)}-{slugify(item_id)}"
                    )
                    discrepancies.append(
                        ParityDiscrepancy(
                            discrepancy_id=disc_id,
                            discrepancy_type=ParityDiscrepancyType.STALE_LEAKED_TO_MODERN_SOT,
                            site_id=resolved_site_id,
                            entity_type=entity_type,
                            item_identifier=item_id,
                            expected_value="absent",
                            actual_value=status_lower or "present",
                            details=(
                                f"Stale/quarantined {entity_type} record '{item_id}'"
                                + (f" (legacy_sot_id={legacy_id})" if legacy_id else "")
                                + " leaked into target Modern SoT bundle"
                            ),
                        )
                    )

        # 2. Match active golden items against modern items & detect MISSING_IN_MODERN_SOT and ATTRIBUTE_MISMATCH
        golden_item_discrepancies: dict[tuple[str, int], list[ParityDiscrepancy]] = {}
        for entity_type in PARITY_ENTITY_COLLECTIONS:
            g_list = active_golden_by_entity[entity_type]
            m_list = modern_site_bundle.get(entity_type, [])
            matched_g_to_m: dict[int, int] = {}
            used_m_indices: set[int] = set(leaked_modern_indices[entity_type])

            # Pass 1: exact identity match
            for g_idx, g_rec in enumerate(g_list):
                for m_idx, m_rec in enumerate(m_list):
                    if m_idx in used_m_indices:
                        continue
                    if self._records_match_exact(entity_type, g_rec, m_rec):
                        matched_g_to_m[g_idx] = m_idx
                        used_m_indices.add(m_idx)
                        break

            # Pass 2: fallback natural-attribute match for unmatched items
            for g_idx, g_rec in enumerate(g_list):
                if g_idx in matched_g_to_m:
                    continue
                for m_idx, m_rec in enumerate(m_list):
                    if m_idx in used_m_indices:
                        continue
                    if self._records_match_fallback(entity_type, g_rec, m_rec):
                        matched_g_to_m[g_idx] = m_idx
                        used_m_indices.add(m_idx)
                        break

            for g_idx, g_rec in enumerate(g_list):
                item_discs: list[ParityDiscrepancy] = []
                if g_idx not in matched_g_to_m:
                    item_id = _extract_record_identifier(entity_type, g_rec)
                    legacy_id = _extract_legacy_id(g_rec)
                    disc_id = (
                        f"parity-{slugify(resolved_site_id)}-missing-"
                        f"{slugify(entity_type)}-{slugify(item_id)}"
                    )
                    missing_disc = ParityDiscrepancy(
                        discrepancy_id=disc_id,
                        discrepancy_type=ParityDiscrepancyType.MISSING_IN_MODERN_SOT,
                        site_id=resolved_site_id,
                        entity_type=entity_type,
                        item_identifier=item_id,
                        expected_value=item_id,
                        actual_value=None,
                        details=(
                            f"Active golden {entity_type} record '{item_id}'"
                            + (f" (legacy_sot_id={legacy_id})" if legacy_id else "")
                            + " is missing from target Modern SoT bundle"
                        ),
                    )
                    item_discs.append(missing_disc)
                    discrepancies.append(missing_disc)
                else:
                    m_rec = m_list[matched_g_to_m[g_idx]]
                    attr_mismatches = self._compare_matched_records(
                        resolved_site_id,
                        entity_type,
                        g_rec,
                        m_rec,
                        golden_ip_by_host=golden_ip_by_host,
                    )
                    item_discs.extend(attr_mismatches)
                    discrepancies.extend(attr_mismatches)

                golden_item_discrepancies[(entity_type, g_idx)] = item_discs

        # 3. Apply waivers to discrepancies
        eff_waive_all = (
            bool(waive_all_parity_discrepancies)
            if waive_all_parity_discrepancies is not None
            else self.waive_all_parity_discrepancies
        )
        combined_waived_raw = set(self._waived_discrepancy_ids)
        if waived_discrepancy_ids is not None:
            combined_waived_raw.update(
                str(x).strip() for x in waived_discrepancy_ids if str(x).strip()
            )
        waived_tokens = self._expand_waived_tokens(combined_waived_raw)

        # Build lookup from item_identifier to record tokens for waiver matching
        record_tokens_by_item: dict[tuple[str, str], set[str]] = {}
        for entity_type in PARITY_ENTITY_COLLECTIONS:
            for rec in active_golden_by_entity[entity_type] + modern_site_bundle.get(
                entity_type, []
            ):
                iid = _extract_record_identifier(entity_type, rec)
                record_tokens_by_item.setdefault((entity_type, iid), set()).update(
                    _record_candidate_tokens(entity_type, rec)
                )

        for disc in discrepancies:
            if eff_waive_all:
                disc.waived = True
                continue
            candidate_waiver_keys = {
                disc.discrepancy_id,
                disc.discrepancy_id.lower(),
                disc.item_identifier,
                disc.item_identifier.lower(),
                slugify(disc.item_identifier),
                _strip_ip_mask(disc.item_identifier),
                f"{disc.entity_type}:{disc.item_identifier}",
                f"{disc.entity_type}:{disc.item_identifier}".lower(),
            }
            candidate_waiver_keys.update(
                record_tokens_by_item.get((disc.entity_type, disc.item_identifier), set())
            )
            if candidate_waiver_keys & waived_tokens:
                disc.waived = True

        # 4. Compute validation classification counts for this site
        site_val_results = [
            r
            for r in norm_results
            if r.site_id in (resolved_site_id, target_slug, "unknown", "*")
        ]
        confirmed_active_count = sum(
            1
            for r in site_val_results
            if r.classification is ValidationClassification.CONFIRMED_ACTIVE
        )
        stale_count = sum(
            1
            for r in site_val_results
            if r.classification is ValidationClassification.STALE_LIKELY_UNUSED
        )
        unreachable_count = sum(
            1
            for r in site_val_results
            if r.classification is ValidationClassification.UNREACHABLE_NEEDS_REVIEW
        )
        insufficient_data_count = sum(
            1
            for r in site_val_results
            if r.classification is ValidationClassification.INSUFFICIENT_DATA
        )

        if not site_val_results:
            confirmed_active_count = (
                len(active_golden_by_entity["devices"])
                + len(active_golden_by_entity["virtual_machines"])
                + len(active_golden_by_entity["ip_addresses"])
            )

        # 5. Compute unresolved untracked Shadow IT count for this site
        unresolved_untracked_ids: set[str] = set()
        for u_disc in norm_unresolved_untracked:
            if (
                u_disc.site_id not in (resolved_site_id, target_slug)
                and not single_site_context
            ):
                continue
            if u_disc.discrepancy_type not in _UNTRACKED_DISCREPANCY_TYPES:
                continue
            u_tokens = {
                u_disc.discrepancy_id,
                u_disc.discrepancy_id.lower(),
                u_disc.observed_identifier,
                u_disc.observed_identifier.lower(),
            }
            if u_disc.observed_ip:
                u_tokens.add(_strip_ip_mask(u_disc.observed_ip))
            if u_disc.observed_hostname:
                u_tokens.add(u_disc.observed_hostname.lower())
            if eff_waive_all or (u_tokens & waived_tokens):
                continue
            unresolved_untracked_ids.add(u_disc.discrepancy_id)

        for r_disc in norm_recon:
            if (
                r_disc.site_id not in (resolved_site_id, target_slug)
                and not single_site_context
            ):
                continue
            if r_disc.discrepancy_type not in _UNTRACKED_DISCREPANCY_TYPES:
                continue
            r_tokens = {
                r_disc.discrepancy_id,
                r_disc.discrepancy_id.lower(),
                r_disc.observed_identifier,
                r_disc.observed_identifier.lower(),
            }
            if r_disc.observed_ip:
                r_tokens.add(_strip_ip_mask(r_disc.observed_ip))
            if r_disc.observed_hostname:
                r_tokens.add(r_disc.observed_hostname.lower())

            if eff_waive_all or (r_tokens & waived_tokens):
                continue
            if eff_approved is not None and (r_tokens & eff_approved):
                if self._is_untracked_resolved_in_bundle(r_disc, modern_site_bundle):
                    continue
            if not self._is_untracked_resolved_in_bundle(r_disc, modern_site_bundle):
                unresolved_untracked_ids.add(r_disc.discrepancy_id)

        unresolved_untracked_count = len(unresolved_untracked_ids)

        # 6. Compute parity_match_percentage, readiness_score, and CutoverRecommendation
        expected_golden_items = sum(
            len(active_golden_by_entity[et]) for et in PARITY_ENTITY_COLLECTIONS
        )
        unwaived_missing_or_mismatched = sum(
            1
            for item_discs in golden_item_discrepancies.values()
            if any(not d.waived for d in item_discs)
        )
        unwaived_leaked = sum(
            1
            for d in discrepancies
            if not d.waived
            and d.discrepancy_type
            is ParityDiscrepancyType.STALE_LEAKED_TO_MODERN_SOT
        )
        unwaived_missing = sum(
            1
            for d in discrepancies
            if not d.waived
            and d.discrepancy_type is ParityDiscrepancyType.MISSING_IN_MODERN_SOT
        )
        unwaived_mismatched = sum(
            1
            for d in discrepancies
            if not d.waived
            and d.discrepancy_type is ParityDiscrepancyType.ATTRIBUTE_MISMATCH
        )
        waived_discrepancy_count = sum(1 for d in discrepancies if d.waived)

        matched_modern_items = max(
            0, expected_golden_items - unwaived_missing_or_mismatched
        )

        if expected_golden_items > 0:
            parity_match_percentage = _clamp_percentage(
                ((matched_modern_items - unwaived_leaked) / expected_golden_items)
                * 100.0
            )
        else:
            parity_match_percentage = 100.0 if unwaived_leaked == 0 else 0.0

        non_stale_validated = (
            confirmed_active_count + unreachable_count + insufficient_data_count
        )
        validation_ratio = (
            confirmed_active_count / non_stale_validated
            if non_stale_validated > 0
            else 1.0
        )
        validation_penalty = max(
            (1.0 - validation_ratio) * 40.0,
            5.0 * (unreachable_count + insufficient_data_count),
        )
        untracked_penalty = 5.0 * unresolved_untracked_count
        leaked_penalty = 15.0 * unwaived_leaked

        if expected_golden_items > 0 and matched_modern_items == 0:
            raw_readiness = 0.0
        else:
            raw_readiness = (
                parity_match_percentage
                - validation_penalty
                - untracked_penalty
                - leaked_penalty
            )
        readiness_score = _clamp_percentage(raw_readiness)

        blocking_reasons: list[str] = []
        if unwaived_leaked > 0:
            blocking_reasons.append(
                f"{unwaived_leaked} stale/quarantined item(s) leaked into Modern SoT"
            )
        if unwaived_missing > 0:
            blocking_reasons.append(
                f"{unwaived_missing} active golden item(s) missing in Modern SoT"
            )
        if unwaived_mismatched > 0:
            blocking_reasons.append(
                f"{unwaived_mismatched} attribute mismatch discrepancy(ies) detected"
            )
        if unreachable_count > 0:
            blocking_reasons.append(
                f"{unreachable_count} item(s) classified as Unreachable / Needs Manual Review"
            )
        if insufficient_data_count > 0:
            blocking_reasons.append(
                f"{insufficient_data_count} item(s) classified as Insufficient Data"
            )
        if unresolved_untracked_count > 0:
            blocking_reasons.append(
                f"{unresolved_untracked_count} unresolved untracked Shadow IT asset(s)"
            )
        if expected_golden_items > 0 and matched_modern_items == 0:
            blocking_reasons.append(
                "Zero golden inventory items matched in Modern SoT"
            )

        if (
            unwaived_leaked > 0
            or parity_match_percentage < self.blocked_parity_threshold
            or readiness_score < self.blocked_score_threshold
            or (expected_golden_items > 0 and matched_modern_items == 0)
        ):
            recommendation = CutoverRecommendation.BLOCKED
        elif (
            parity_match_percentage == 100.0
            and len([d for d in discrepancies if not d.waived]) == 0
            and unreachable_count == 0
            and insufficient_data_count == 0
            and unresolved_untracked_count == 0
            and readiness_score >= self.ready_score_threshold
        ):
            recommendation = CutoverRecommendation.READY_FOR_CUTOVER
            blocking_reasons = []
        else:
            recommendation = CutoverRecommendation.NEEDS_REMEDIATION

        resolved_ts = _resolve_timestamp(
            evaluated_at if evaluated_at is not None else self._evaluated_at
        )

        return SiteMigrationReadinessScorecard(
            site_id=resolved_site_id,
            site_name=resolved_site_name,
            readiness_score=readiness_score,
            recommendation=recommendation,
            parity_match_percentage=parity_match_percentage,
            confirmed_active_count=confirmed_active_count,
            stale_count=stale_count,
            unreachable_count=unreachable_count,
            insufficient_data_count=insufficient_data_count,
            unresolved_untracked_count=unresolved_untracked_count,
            expected_golden_items=expected_golden_items,
            matched_modern_items=matched_modern_items,
            discrepancies=discrepancies,
            waived_discrepancy_count=waived_discrepancy_count,
            blocking_reasons=blocking_reasons,
            evaluated_at=resolved_ts,
        )
