"""Bundle coercion and record matching mixin for DualRunParityChecker."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Optional

from sot_validator.migration._parity_models import ParityDiscrepancy
from sot_validator.migration._parity_records import (
    _STALE_MODERN_STATUSES,
    PARITY_ENTITY_COLLECTIONS,
    ParityDiscrepancyType,
    _clean_optional_str,
    _extract_explicit_ip,
    _extract_legacy_id,
    _extract_record_identifier,
    _record_candidate_tokens,
)
from sot_validator.migration.exporter import (
    ENTITY_COLLECTION_KEYS,
    GoldenInventoryFilter,
    ModernSoTExporter,
    _normalize_sites_input,
    _parse_vlan_vid,
    _strip_ip_mask,
    slugify,
)
from sot_validator.models import Site, ValidationClassification, ValidationResult
from sot_validator.reconciliation.reconciler import DiscrepancyRecord


class _ParityMatchingMixin:
    """Bundle coercion, waiver/stale tokens, site filtering and record matching for DualRunParityChecker."""

    @staticmethod
    def _is_bundle_mapping(obj: Any) -> bool:
        if isinstance(obj, ModernSoTExporter):
            return True
        if not isinstance(obj, Mapping):
            return False
        if "site_id" in obj and "name" in obj and "devices" in obj:
            # This is a serialized Site dict, not a ModernSoTExporter bundle
            devices_val = obj.get("devices")
            if isinstance(devices_val, Sequence) and devices_val:
                first_dev = devices_val[0]
                if isinstance(first_dev, Mapping) and "device_id" in first_dev:
                    return False
            if "subnets" in obj or "equipment" in obj:
                return False
        return any(k in obj for k in ENTITY_COLLECTION_KEYS) or "target_platform" in obj

    def _coerce_to_bundle(
        self,
        source: Any,
        *,
        validation_results: Optional[list[ValidationResult]] = None,
        reconciliation_report: Optional[list[DiscrepancyRecord]] = None,
        approved_discrepancy_ids: Optional[set[str]] = None,
        merge_untracked: bool = True,
        filter_for_golden: bool = False,
    ) -> dict[str, list[dict[str, Any]]]:
        if source is None:
            return {k: [] for k in ENTITY_COLLECTION_KEYS}
        if isinstance(source, ModernSoTExporter):
            raw_bundle = source.to_dict()
            return {
                k: [dict(item) for item in raw_bundle.get(k, [])]
                for k in ENTITY_COLLECTION_KEYS
            }
        if isinstance(source, Mapping) and self._is_bundle_mapping(source):
            return {
                k: [dict(item) for item in source.get(k, [])]
                for k in ENTITY_COLLECTION_KEYS
            }

        sites_list = _normalize_sites_input(source)
        if filter_for_golden:
            exporter = ModernSoTExporter(
                sites=sites_list,
                validation_results=validation_results,
                reconciliation_report=reconciliation_report,
                merge_untracked=merge_untracked,
                approved_discrepancy_ids=approved_discrepancy_ids,
                target_platform=self.target_platform,
            )
        else:
            inv_filter = GoldenInventoryFilter(
                include_stale=True,
                include_unreachable=True,
                include_insufficient_data=True,
                merge_untracked=False,
            )
            exporter = ModernSoTExporter(
                sites=sites_list,
                inventory_filter=inv_filter,
                target_platform=self.target_platform,
            )
        raw_bundle = exporter.to_dict()
        return {
            k: [dict(item) for item in raw_bundle.get(k, [])]
            for k in ENTITY_COLLECTION_KEYS
        }

    @staticmethod
    def _expand_waived_tokens(raw_ids: Iterable[str]) -> set[str]:
        tokens: set[str] = set()
        for item in raw_ids:
            text = str(item).strip()
            if not text:
                continue
            tokens.add(text)
            tokens.add(text.lower())
            tokens.add(slugify(text))
            clean_ip = _strip_ip_mask(text)
            if clean_ip:
                tokens.add(clean_ip)
        return tokens

    @staticmethod
    def _collect_stale_tokens(
        site_id: str,
        raw_sites: Sequence[Site],
        validation_results: Sequence[ValidationResult],
        explicit_stale_ids: Iterable[str],
        golden_bundle_records: Mapping[str, Sequence[Mapping[str, Any]]],
    ) -> set[str]:
        site_slug = slugify(site_id)
        tokens: set[str] = set()

        def _add_token(val: Optional[str]) -> None:
            if not val:
                return
            cleaned = str(val).strip()
            if not cleaned:
                return
            tokens.add(cleaned)
            tokens.add(cleaned.lower())
            tokens.add(slugify(cleaned))
            clean_ip = _strip_ip_mask(cleaned)
            if clean_ip and clean_ip[0].isdigit():
                tokens.add(clean_ip)
                tokens.add(f"{site_id}:ip:{clean_ip}")
                tokens.add(f"{site_slug}:ip:{clean_ip}")

        for s_id in explicit_stale_ids:
            _add_token(s_id)

        for res in validation_results:
            if res.site_id not in (site_id, site_slug, "unknown", "*"):
                continue
            if res.classification is ValidationClassification.STALE_LIKELY_UNUSED:
                _add_token(res.item_id)
                _add_token(res.name)

        for site in raw_sites:
            if site.site_id != site_id and slugify(site.site_id) != site_slug:
                continue
            for dev in site.devices:
                if (
                    dev.device_id in tokens
                    or dev.hostname.lower() in tokens
                    or slugify(dev.hostname) in tokens
                ):
                    _add_token(dev.device_id)
                    _add_token(dev.hostname)
                    _add_token(dev.management_ip)
            for eq in site.equipment:
                if (
                    eq.equipment_id in tokens
                    or eq.name.lower() in tokens
                    or slugify(eq.name) in tokens
                ):
                    _add_token(eq.equipment_id)
                    _add_token(eq.name)
                    for raw_ip in eq.assigned_ips:
                        _add_token(raw_ip)
            for ip_rec in site.ip_addresses:
                clean_ip = _strip_ip_mask(ip_rec.ip)
                if (
                    ip_rec.ip in tokens
                    or clean_ip in tokens
                    or (
                        ip_rec.assigned_object_id
                        and ip_rec.assigned_object_id in tokens
                    )
                ):
                    _add_token(ip_rec.ip)

        for entity_type in PARITY_ENTITY_COLLECTIONS:
            for rec in golden_bundle_records.get(entity_type, ()):
                status_lower = str(rec.get("status") or "").strip().lower()
                if status_lower in _STALE_MODERN_STATUSES:
                    for tok in _record_candidate_tokens(entity_type, rec):
                        _add_token(tok)

        return tokens

    @staticmethod
    def _filter_bundle_for_site(
        bundle: Mapping[str, Sequence[Mapping[str, Any]]],
        site_id: str,
        *,
        single_site_context: bool = False,
        raw_site: Optional[Site] = None,
    ) -> dict[str, list[dict[str, Any]]]:
        site_slug = slugify(site_id)
        site_device_names: set[str] = set()
        if raw_site is not None:
            for dev in raw_site.devices:
                site_device_names.add(dev.hostname.lower())
                site_device_names.add(slugify(dev.hostname))
            for eq in raw_site.equipment:
                site_device_names.add(eq.name.lower())
                site_device_names.add(slugify(eq.name))

        scoped: dict[str, list[dict[str, Any]]] = {
            k: [] for k in ENTITY_COLLECTION_KEYS
        }

        for s_rec in bundle.get("sites", ()):
            rec_slug = slugify(
                _clean_optional_str(s_rec.get("slug"))
                or _extract_legacy_id(s_rec)
                or _clean_optional_str(s_rec.get("name"))
                or ""
            )
            legacy_id = _extract_legacy_id(s_rec)
            if (
                rec_slug == site_slug
                or legacy_id == site_id
                or single_site_context
            ):
                scoped["sites"].append(dict(s_rec))

        for entity_type in (
            "devices",
            "virtual_machines",
            "ip_addresses",
            "vlans",
            "prefixes",
        ):
            for rec in bundle.get(entity_type, ()):
                rec_site = _clean_optional_str(rec.get("site"))
                legacy_id = _extract_legacy_id(rec)
                if rec_site:
                    if rec_site == site_id or slugify(rec_site) == site_slug:
                        scoped[entity_type].append(dict(rec))
                        if entity_type == "devices":
                            d_name = _clean_optional_str(
                                rec.get("name") or rec.get("hostname")
                            )
                            if d_name:
                                site_device_names.add(d_name.lower())
                                site_device_names.add(slugify(d_name))
                elif legacy_id.startswith(f"{site_id}:") or legacy_id.startswith(
                    f"{site_slug}:"
                ):
                    scoped[entity_type].append(dict(rec))
                elif single_site_context:
                    scoped[entity_type].append(dict(rec))
                    if entity_type == "devices":
                        d_name = _clean_optional_str(
                            rec.get("name") or rec.get("hostname")
                        )
                        if d_name:
                            site_device_names.add(d_name.lower())
                            site_device_names.add(slugify(d_name))

        for rec in bundle.get("interfaces", ()):
            rec_site = _clean_optional_str(rec.get("site"))
            dev_name = _clean_optional_str(rec.get("device"))
            if rec_site:
                if rec_site == site_id or slugify(rec_site) == site_slug:
                    scoped["interfaces"].append(dict(rec))
            elif dev_name and (
                dev_name.lower() in site_device_names
                or slugify(dev_name) in site_device_names
            ):
                scoped["interfaces"].append(dict(rec))
            elif single_site_context:
                scoped["interfaces"].append(dict(rec))

        return scoped

    @staticmethod
    def _records_match_exact(
        entity_type: str,
        g_rec: Mapping[str, Any],
        m_rec: Mapping[str, Any],
    ) -> bool:
        g_legacy = _extract_legacy_id(g_rec)
        m_legacy = _extract_legacy_id(m_rec)
        if g_legacy and m_legacy and g_legacy == m_legacy:
            return True

        g_slug = _clean_optional_str(g_rec.get("slug"))
        m_slug = _clean_optional_str(m_rec.get("slug"))
        if g_slug and m_slug and slugify(g_slug) == slugify(m_slug):
            return True

        if entity_type in ("devices", "virtual_machines"):
            g_name = _clean_optional_str(g_rec.get("name") or g_rec.get("hostname"))
            m_name = _clean_optional_str(m_rec.get("name") or m_rec.get("hostname"))
            if g_name and m_name and g_name.lower() == m_name.lower():
                return True

        elif entity_type == "ip_addresses":
            g_addr = _strip_ip_mask(
                _clean_optional_str(g_rec.get("address") or g_rec.get("ip"))
            )
            m_addr = _strip_ip_mask(
                _clean_optional_str(m_rec.get("address") or m_rec.get("ip"))
            )
            if g_addr and m_addr and g_addr == m_addr:
                return True

        elif entity_type == "vlans":
            g_vid = _parse_vlan_vid(
                g_rec.get("vid")
                if g_rec.get("vid") is not None
                else g_rec.get("vlan_id"),
                fallback=None,
            )
            m_vid = _parse_vlan_vid(
                m_rec.get("vid")
                if m_rec.get("vid") is not None
                else m_rec.get("vlan_id"),
                fallback=None,
            )
            if g_vid is not None and m_vid is not None and g_vid == m_vid:
                return True

        elif entity_type == "prefixes":
            g_pfx = _clean_optional_str(g_rec.get("prefix") or g_rec.get("cidr"))
            m_pfx = _clean_optional_str(m_rec.get("prefix") or m_rec.get("cidr"))
            if g_pfx and m_pfx and g_pfx == m_pfx:
                return True

        elif entity_type == "interfaces":
            g_dev = (_clean_optional_str(g_rec.get("device")) or "").lower()
            m_dev = (_clean_optional_str(m_rec.get("device")) or "").lower()
            g_name = (_clean_optional_str(g_rec.get("name")) or "").lower()
            m_name = (_clean_optional_str(m_rec.get("name")) or "").lower()
            if g_name and m_name and g_name == m_name:
                if not g_dev or not m_dev or g_dev == m_dev:
                    return True

        return False

    @staticmethod
    def _records_match_fallback(
        entity_type: str,
        g_rec: Mapping[str, Any],
        m_rec: Mapping[str, Any],
    ) -> bool:
        if entity_type == "ip_addresses":
            g_obj = _clean_optional_str(
                g_rec.get("assigned_object") or g_rec.get("dns_name")
            )
            m_obj = _clean_optional_str(
                m_rec.get("assigned_object") or m_rec.get("dns_name")
            )
            if g_obj and m_obj and g_obj.lower() == m_obj.lower():
                return True

        elif entity_type == "vlans":
            g_name = _clean_optional_str(g_rec.get("name"))
            m_name = _clean_optional_str(m_rec.get("name"))
            if g_name and m_name and g_name.lower() == m_name.lower():
                return True

        elif entity_type == "prefixes":
            g_desc = _clean_optional_str(g_rec.get("description"))
            m_desc = _clean_optional_str(m_rec.get("description"))
            if g_desc and m_desc and g_desc.lower() == m_desc.lower():
                return True

        return False

    @staticmethod
    def _compare_matched_records(
        site_id: str,
        entity_type: str,
        g_rec: Mapping[str, Any],
        m_rec: Mapping[str, Any],
        *,
        golden_ip_by_host: Mapping[str, str],
    ) -> list[ParityDiscrepancy]:
        mismatches: list[ParityDiscrepancy] = []
        item_id = _extract_record_identifier(entity_type, g_rec)

        def _add_mismatch(
            attr: str,
            expected: Any,
            actual: Any,
            details: str,
        ) -> None:
            disc_id = (
                f"parity-{slugify(site_id)}-mismatch-"
                f"{slugify(entity_type)}-{slugify(item_id)}-{slugify(attr)}"
            )
            mismatches.append(
                ParityDiscrepancy(
                    discrepancy_id=disc_id,
                    discrepancy_type=ParityDiscrepancyType.ATTRIBUTE_MISMATCH,
                    site_id=site_id,
                    entity_type=entity_type,
                    item_identifier=item_id,
                    attribute_name=attr,
                    expected_value=expected,
                    actual_value=actual,
                    details=details,
                )
            )

        if entity_type in ("devices", "virtual_machines"):
            g_name = _clean_optional_str(g_rec.get("name") or g_rec.get("hostname"))
            m_name = _clean_optional_str(m_rec.get("name") or m_rec.get("hostname"))
            if g_name and m_name and g_name != m_name:
                _add_mismatch(
                    "hostname",
                    g_name,
                    m_name,
                    f"{entity_type} hostname mismatch for '{item_id}': expected '{g_name}', got '{m_name}'",
                )

            g_role = _clean_optional_str(g_rec.get("role"))
            m_role = _clean_optional_str(m_rec.get("role"))
            if g_role and m_role and slugify(g_role) != slugify(m_role):
                _add_mismatch(
                    "role",
                    g_role,
                    m_role,
                    f"{entity_type} role mismatch for '{item_id}': expected '{g_role}', got '{m_role}'",
                )

            g_ip = _extract_explicit_ip(g_rec) or (
                golden_ip_by_host.get(g_name.lower()) if g_name else None
            )
            m_ip = _extract_explicit_ip(m_rec)
            if g_ip and m_ip and _strip_ip_mask(g_ip) != _strip_ip_mask(m_ip):
                _add_mismatch(
                    "ip_address",
                    g_ip,
                    m_ip,
                    f"{entity_type} IP assignment mismatch for '{item_id}': expected '{g_ip}', got '{m_ip}'",
                )

            if (
                "vlan" in g_rec
                or "vid" in g_rec
                or "vlan" in m_rec
                or "vid" in m_rec
            ):
                g_vlan = _parse_vlan_vid(
                    g_rec.get("vlan")
                    if g_rec.get("vlan") is not None
                    else g_rec.get("vid"),
                    fallback=None,
                )
                m_vlan = _parse_vlan_vid(
                    m_rec.get("vlan")
                    if m_rec.get("vlan") is not None
                    else m_rec.get("vid"),
                    fallback=None,
                )
                if g_vlan is not None and m_vlan is not None and g_vlan != m_vlan:
                    _add_mismatch(
                        "vlan",
                        g_vlan,
                        m_vlan,
                        f"{entity_type} VLAN mismatch for '{item_id}': expected {g_vlan}, got {m_vlan}",
                    )

        elif entity_type == "ip_addresses":
            g_addr = _clean_optional_str(g_rec.get("address") or g_rec.get("ip"))
            m_addr = _clean_optional_str(m_rec.get("address") or m_rec.get("ip"))
            if g_addr and m_addr:
                if _strip_ip_mask(g_addr) != _strip_ip_mask(m_addr) or (
                    "/" in g_addr and "/" in m_addr and g_addr != m_addr
                ):
                    _add_mismatch(
                        "ip_address",
                        g_addr,
                        m_addr,
                        f"IP address mismatch for '{item_id}': expected '{g_addr}', got '{m_addr}'",
                    )

            g_dns = _clean_optional_str(g_rec.get("dns_name"))
            m_dns = _clean_optional_str(m_rec.get("dns_name"))
            g_obj = _clean_optional_str(g_rec.get("assigned_object"))
            m_obj = _clean_optional_str(m_rec.get("assigned_object"))

            dns_diff = bool(g_dns and m_dns and g_dns != m_dns)
            obj_diff = bool(g_obj and m_obj and g_obj != m_obj)

            if dns_diff and not obj_diff:
                _add_mismatch(
                    "hostname",
                    g_dns,
                    m_dns,
                    f"IP DNS hostname mismatch for '{item_id}': expected '{g_dns}', got '{m_dns}'",
                )
            elif obj_diff and not dns_diff:
                _add_mismatch(
                    "ip_address",
                    g_obj,
                    m_obj,
                    f"IP assigned_object mismatch for '{item_id}': expected '{g_obj}', got '{m_obj}'",
                )
            elif dns_diff and obj_diff:
                _add_mismatch(
                    "hostname",
                    g_dns,
                    m_dns,
                    f"IP hostname/assignment mismatch for '{item_id}': expected '{g_dns}', got '{m_dns}'",
                )

            if (
                "vlan" in g_rec
                or "vid" in g_rec
                or "vlan" in m_rec
                or "vid" in m_rec
            ):
                g_vlan = _parse_vlan_vid(
                    g_rec.get("vlan")
                    if g_rec.get("vlan") is not None
                    else g_rec.get("vid"),
                    fallback=None,
                )
                m_vlan = _parse_vlan_vid(
                    m_rec.get("vlan")
                    if m_rec.get("vlan") is not None
                    else m_rec.get("vid"),
                    fallback=None,
                )
                if g_vlan is not None and m_vlan is not None and g_vlan != m_vlan:
                    _add_mismatch(
                        "vlan",
                        g_vlan,
                        m_vlan,
                        f"IP VLAN mismatch for '{item_id}': expected {g_vlan}, got {m_vlan}",
                    )

        elif entity_type == "vlans":
            g_vid = _parse_vlan_vid(
                g_rec.get("vid")
                if g_rec.get("vid") is not None
                else g_rec.get("vlan_id"),
                fallback=None,
            )
            m_vid = _parse_vlan_vid(
                m_rec.get("vid")
                if m_rec.get("vid") is not None
                else m_rec.get("vlan_id"),
                fallback=None,
            )
            if g_vid is not None and m_vid is not None and g_vid != m_vid:
                _add_mismatch(
                    "vlan",
                    g_vid,
                    m_vid,
                    f"VLAN ID mismatch for '{item_id}': expected {g_vid}, got {m_vid}",
                )

            g_name = _clean_optional_str(g_rec.get("name"))
            m_name = _clean_optional_str(m_rec.get("name"))
            if g_name and m_name and g_name != m_name:
                _add_mismatch(
                    "hostname",
                    g_name,
                    m_name,
                    f"VLAN name mismatch for '{item_id}': expected '{g_name}', got '{m_name}'",
                )

        elif entity_type == "prefixes":
            g_vlan = _parse_vlan_vid(g_rec.get("vlan"), fallback=None)
            m_vlan = _parse_vlan_vid(m_rec.get("vlan"), fallback=None)
            if g_vlan != m_vlan and (g_vlan is not None or m_vlan is not None):
                _add_mismatch(
                    "vlan",
                    g_vlan,
                    m_vlan,
                    f"Prefix VLAN mismatch for '{item_id}': expected {g_vlan}, got {m_vlan}",
                )

        elif entity_type == "interfaces":
            g_vlan = _parse_vlan_vid(
                g_rec.get("untagged_vlan")
                if "untagged_vlan" in g_rec
                else g_rec.get("vlan"),
                fallback=None,
            )
            m_vlan = _parse_vlan_vid(
                m_rec.get("untagged_vlan")
                if "untagged_vlan" in m_rec
                else m_rec.get("vlan"),
                fallback=None,
            )
            if g_vlan != m_vlan and (g_vlan is not None or m_vlan is not None):
                _add_mismatch(
                    "vlan",
                    g_vlan,
                    m_vlan,
                    f"Interface untagged VLAN mismatch for '{item_id}': expected {g_vlan}, got {m_vlan}",
                )

        return mismatches

    @staticmethod
    def _is_untracked_resolved_in_bundle(
        disc: DiscrepancyRecord,
        modern_site_bundle: Mapping[str, Sequence[Mapping[str, Any]]],
    ) -> bool:
        all_modern_tokens: set[str] = set()
        for entity_type in ("devices", "virtual_machines", "ip_addresses"):
            for rec in modern_site_bundle.get(entity_type, ()):
                status_lower = str(rec.get("status") or "").strip().lower()
                if status_lower in _STALE_MODERN_STATUSES:
                    continue
                all_modern_tokens.update(_record_candidate_tokens(entity_type, rec))

        candidates: set[str] = set()
        if disc.observed_hostname:
            candidates.add(disc.observed_hostname)
            candidates.add(disc.observed_hostname.lower())
            candidates.add(slugify(disc.observed_hostname))
        if disc.observed_ip:
            clean_ip = _strip_ip_mask(disc.observed_ip)
            if clean_ip:
                candidates.add(clean_ip)
        if disc.observed_identifier:
            candidates.add(disc.observed_identifier)
            candidates.add(disc.observed_identifier.lower())
            candidates.add(slugify(disc.observed_identifier))
            clean_obs_ip = _strip_ip_mask(disc.observed_identifier)
            if clean_obs_ip and clean_obs_ip[0].isdigit():
                candidates.add(clean_obs_ip)

        return bool(candidates & all_modern_tokens)
