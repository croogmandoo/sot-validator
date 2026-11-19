"""InventoryReconciler: compares Site snapshots against live discovery feeds."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
import ipaddress
from typing import Any, Optional

from sot_validator.enrichment import OuiRegistry
from sot_validator.models import ArpEntry, Equipment, NetworkDevice, Site, Subnet
from sot_validator.reconciliation._normalizers import _ReconcilerNormalizers
from sot_validator.reconciliation._records import (
    DiscrepancyRecord,
    DiscrepancyType,
    _hostnames_match,
    _resolve_timestamp,
    _short_hostname,
    _slugify_id,
)
from sot_validator.reconciliation._report import ReconciliationReport
from sot_validator.reconciliation.oui_annotation import partition_randomized
from sot_validator.signals.hypervisor import (
    HypervisorInventoryProvider,
    HypervisorVmRecord,
    VmPowerState,
    _format_mac_canonical,
    _normalize_ip,
    _normalize_mac,
)
from sot_validator.signals.management import FixtureManagementTransport


class InventoryReconciler(_ReconcilerNormalizers):
    """Compares Site snapshots against live discovery feeds to surface untracked assets and drift."""

    def __init__(
        self,
        *,
        vcenter_provider: Optional[
            HypervisorInventoryProvider
            | Sequence[HypervisorVmRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        vms: Optional[Sequence[HypervisorVmRecord | Mapping[str, Any]]] = None,
        arp_entries: Optional[
            Sequence[ArpEntry | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        snmp_targets: Optional[
            Mapping[str, Any]
            | Sequence[Mapping[str, Any]]
            | FixtureManagementTransport
        ] = None,
        icmp_responses: Optional[
            Mapping[str, Any] | Sequence[Any]
        ] = None,
        oui_registry: Optional[OuiRegistry] = None,
        exclude_randomized_macs: bool = False,
    ) -> None:
        self.vcenter_provider = vcenter_provider
        self.vms = vms
        self.arp_entries = arp_entries
        self.snmp_targets = snmp_targets
        self.icmp_responses = icmp_responses
        self.oui_registry = oui_registry
        self.exclude_randomized_macs = exclude_randomized_macs


    def reconcile(
        self,
        sites: Sequence[Site | Mapping[str, Any]]
        | Mapping[str, Site | Mapping[str, Any]]
        | Site,
        *,
        vcenter_provider: Optional[
            HypervisorInventoryProvider
            | Sequence[HypervisorVmRecord | Mapping[str, Any]]
            | Mapping[str, Any]
        ] = None,
        vms: Optional[Sequence[HypervisorVmRecord | Mapping[str, Any]]] = None,
        arp_entries: Optional[
            Sequence[ArpEntry | Mapping[str, Any]] | Mapping[str, Any]
        ] = None,
        snmp_targets: Optional[
            Mapping[str, Any]
            | Sequence[Mapping[str, Any]]
            | FixtureManagementTransport
        ] = None,
        icmp_responses: Optional[Mapping[str, Any] | Sequence[Any]] = None,
        generated_at: Optional[datetime | str] = None,
    ) -> ReconciliationReport:
        """Compare Site snapshots against live discovery feeds and return a ReconciliationReport."""
        sites_by_id = self._normalize_sites(sites)
        subnet_index = self._build_subnet_index(sites_by_id)
        report_dt = _resolve_timestamp(generated_at)

        resolved_vc = (
            vcenter_provider
            if vcenter_provider is not None
            else self.vcenter_provider
        )
        resolved_vms = vms if vms is not None else self.vms
        resolved_arp = (
            arp_entries if arp_entries is not None else self.arp_entries
        )
        resolved_snmp = (
            snmp_targets if snmp_targets is not None else self.snmp_targets
        )
        resolved_icmp = (
            icmp_responses
            if icmp_responses is not None
            else self.icmp_responses
        )

        vm_records = self._normalize_vm_records(resolved_vc, resolved_vms)
        arp_observations = self._normalize_arp_observations(resolved_arp)
        snmp_observations = self._normalize_snmp_observations(resolved_snmp)
        icmp_ips = self._normalize_icmp_reachable_ips(resolved_icmp)

        discrepancies: list[DiscrepancyRecord] = []
        seq = 0

        def _next_id(site_id: str, dtype: DiscrepancyType) -> str:
            nonlocal seq
            seq += 1
            return f"disc-{_slugify_id(site_id)}-{dtype.value.lower().replace('_', '-')}-{seq:04d}"

        # Track active IPs discovered across feeds per (site_id, ip)
        # Value: dict with subnet, primary_source, mac, hostname, target_type, target_id, arp_source_device_id
        active_ip_observations: dict[tuple[str, str], dict[str, Any]] = {}

        def _record_active_ip(
            site_id: str,
            subnet: Subnet,
            ip_str: str,
            source: str,
            *,
            mac: Optional[str] = None,
            hostname: Optional[str] = None,
            target_type: Optional[str] = None,
            target_id: Optional[str] = None,
            arp_source_device_id: Optional[str] = None,
        ) -> None:
            key = (site_id, ip_str)
            existing = active_ip_observations.get(key)
            if existing is None:
                active_ip_observations[key] = {
                    "site_id": site_id,
                    "subnet": subnet,
                    "ip": ip_str,
                    "source": source,
                    "mac": _format_mac_canonical(mac),
                    "hostname": hostname,
                    "target_type": target_type,
                    "target_id": target_id,
                    "arp_source_device_id": arp_source_device_id,
                }
            else:
                if not existing.get("mac") and mac:
                    existing["mac"] = _format_mac_canonical(mac)
                if not existing.get("hostname") and hostname:
                    existing["hostname"] = hostname
                if not existing.get("target_type") and target_type:
                    existing["target_type"] = target_type
                if not existing.get("target_id") and target_id:
                    existing["target_id"] = target_id
                if not existing.get("arp_source_device_id") and arp_source_device_id:
                    existing["arp_source_device_id"] = arp_source_device_id

        # -------------------------------------------------------------------
        # 1. Multi-vCenter VM Reconciliation (UNTRACKED_VM & ATTRIBUTE_MISMATCH)
        # -------------------------------------------------------------------
        site_id_lookup = {sid.lower(): sid for sid in sites_by_id}

        for vm in vm_records:
            resolved_site_id: Optional[str] = None
            resolved_subnet: Optional[Subnet] = None
            primary_scoped_ip: Optional[str] = None

            if vm.site_id and vm.site_id.lower() in site_id_lookup:
                resolved_site_id = site_id_lookup[vm.site_id.lower()]

            for vm_ip in vm.ip_addresses:
                match = self._match_ip_to_allocated_subnet(
                    vm_ip,
                    subnet_index,
                    site_id_filter=resolved_site_id,
                )
                if match is not None:
                    resolved_site_id, resolved_subnet, primary_scoped_ip = match
                    break

            if resolved_site_id is None:
                if vm.site_id and vm.site_id.lower().startswith("site-"):
                    # Explicitly tagged for another site not in the current batch
                    continue
                if len(sites_by_id) == 1:
                    resolved_site_id = next(iter(sites_by_id.keys()))
                else:
                    continue

            site = sites_by_id[resolved_site_id]
            matched_eq, _ = self._match_vm_to_equipment(vm, site)

            # Record active VM NIC IPs inside allocated /24 subnets when VM is powered on
            if vm.power_state is VmPowerState.POWERED_ON:
                vm_short_slug = _slugify_id(
                    _short_hostname(vm.guest_hostname or vm.vm_name) or vm.vm_moref
                )
                inferred_eq_id = (
                    matched_eq.equipment_id
                    if matched_eq is not None
                    else f"eq-{_slugify_id(site.site_id)}-vm-{vm_short_slug}"
                )
                for vm_ip in vm.ip_addresses:
                    ip_match = self._match_ip_to_allocated_subnet(
                        vm_ip, subnet_index, site_id_filter=site.site_id
                    )
                    if ip_match is not None:
                        _, sub_obj, norm_vm_ip = ip_match
                        _record_active_ip(
                            site.site_id,
                            sub_obj,
                            norm_vm_ip,
                            "vcenter",
                            mac=vm.mac_addresses[0] if vm.mac_addresses else None,
                            hostname=vm.guest_hostname or vm.vm_name,
                            target_type="equipment",
                            target_id=inferred_eq_id,
                        )

            if matched_eq is None:
                if vm.power_state is not VmPowerState.POWERED_ON:
                    continue
                obs_ip = primary_scoped_ip or (
                    vm.ip_addresses[0] if vm.ip_addresses else None
                )
                obs_mac = vm.mac_addresses[0] if vm.mac_addresses else None
                obs_host = vm.guest_hostname or vm.vm_name
                obs_id = vm.bios_uuid or vm.vm_moref or vm.vm_name
                sub_token = resolved_subnet.subnet_id if resolved_subnet else ""
                short_slug = _slugify_id(_short_hostname(obs_host) or vm.vm_moref)
                suggested_eq_id = f"eq-{_slugify_id(site.site_id)}-vm-{short_slug}"
                discrepancies.append(
                    DiscrepancyRecord(
                        discrepancy_id=_next_id(
                            site.site_id, DiscrepancyType.UNTRACKED_VM
                        ),
                        discrepancy_type=DiscrepancyType.UNTRACKED_VM,
                        site_id=site.site_id,
                        observed_identifier=obs_id,
                        observed_ip=obs_ip,
                        observed_mac=obs_mac,
                        observed_hostname=obs_host,
                        source="vcenter",
                        sot_item_id=None,
                        details=(
                            f"Powered-on VM '{vm.vm_name}' on {vm.vcenter_instance} "
                            f"has no matching Equipment in SoT "
                            f"(item_id={suggested_eq_id}, vcenter_instance={vm.vcenter_instance}, "
                            f"vm_moref={vm.vm_moref}, bios_uuid={vm.bios_uuid or 'none'}, "
                            f"subnet_id={sub_token or 'none'}, "
                            f"guest_os={vm.guest_os_family or 'unknown'})"
                        ),
                        recommended_onboarding_action=(
                            f"Insert VM '{obs_host}' ({obs_ip or 'no-ip'}) as equipment "
                            f"'{suggested_eq_id}' in site {site.site_id}"
                        ),
                    )
                )
            else:
                # Check for ATTRIBUTE_MISMATCH between matched_eq and vm
                mismatch_reasons: list[str] = []

                name_matches_vm = _hostnames_match(matched_eq.name, vm.vm_name)
                name_matches_guest = (
                    _hostnames_match(matched_eq.name, vm.guest_hostname)
                    if vm.guest_hostname is not None
                    else True
                )
                if not name_matches_vm or not name_matches_guest:
                    live_host = vm.guest_hostname or vm.vm_name
                    mismatch_reasons.append(
                        f"hostname mismatch (SoT={matched_eq.name!r} vs vCenter={live_host!r})"
                    )

                sot_ips, sot_macs = self._collect_equipment_ips_and_macs(
                    matched_eq, site
                )
                vm_ips = {
                    norm
                    for ip in vm.ip_addresses
                    if (norm := _normalize_ip(ip)) is not None
                }
                if sot_ips and vm_ips and sot_ips.isdisjoint(vm_ips):
                    mismatch_reasons.append(
                        f"IP mismatch (SoT={sorted(sot_ips)} vs vCenter={sorted(vm_ips)})"
                    )

                vm_macs = {
                    norm
                    for m in vm.mac_addresses
                    if (norm := _normalize_mac(m)) is not None
                }
                if sot_macs and vm_macs and sot_macs.isdisjoint(vm_macs):
                    sot_canon = sorted(
                        _format_mac_canonical(m) or m for m in sot_macs
                    )
                    vm_canon = sorted(
                        _format_mac_canonical(m) or m for m in vm.mac_addresses
                    )
                    mismatch_reasons.append(
                        f"MAC mismatch (SoT={sot_canon} vs vCenter={vm_canon})"
                    )

                if mismatch_reasons:
                    discrepancies.append(
                        DiscrepancyRecord(
                            discrepancy_id=_next_id(
                                site.site_id, DiscrepancyType.ATTRIBUTE_MISMATCH
                            ),
                            discrepancy_type=DiscrepancyType.ATTRIBUTE_MISMATCH,
                            site_id=site.site_id,
                            observed_identifier=vm.bios_uuid or vm.vm_moref or vm.vm_name,
                            observed_ip=vm.ip_addresses[0] if vm.ip_addresses else None,
                            observed_mac=vm.mac_addresses[0] if vm.mac_addresses else None,
                            observed_hostname=vm.guest_hostname or vm.vm_name,
                            source="vcenter",
                            sot_item_id=matched_eq.equipment_id,
                            details=(
                                f"vCenter attribute drift on {matched_eq.equipment_id}: "
                                + "; ".join(mismatch_reasons)
                            ),
                            recommended_onboarding_action=(
                                f"Update SoT equipment '{matched_eq.equipment_id}' attributes "
                                "to match live vCenter inventory"
                            ),
                        )
                    )

        # -------------------------------------------------------------------
        # 2. SNMP / Management Discovery (UNTRACKED_DEVICE & ATTRIBUTE_MISMATCH)
        # -------------------------------------------------------------------
        for snmp_obs in snmp_observations:
            match = self._match_ip_to_allocated_subnet(
                snmp_obs.ip,
                subnet_index,
                site_id_filter=snmp_obs.site_id,
            )
            if match is None:
                continue
            site_id, subnet, norm_ip = match
            site = sites_by_id[site_id]

            # Match against site.devices or site.equipment
            matched_dev: Optional[NetworkDevice] = None
            matched_eq_snmp: Optional[Equipment] = None

            for dev in site.devices:
                if _normalize_ip(dev.management_ip) == norm_ip or (
                    snmp_obs.sys_name
                    and _hostnames_match(dev.hostname, snmp_obs.sys_name)
                ):
                    matched_dev = dev
                    break

            if matched_dev is None:
                for eq in site.equipment:
                    eq_ips = {_normalize_ip(ip) for ip in eq.assigned_ips if _normalize_ip(ip)}
                    if norm_ip in eq_ips or (
                        snmp_obs.sys_name
                        and _hostnames_match(eq.name, snmp_obs.sys_name)
                    ):
                        matched_eq_snmp = eq
                        break

            short_slug = _slugify_id(
                _short_hostname(snmp_obs.sys_name) or norm_ip
            )
            inferred_dev_id = (
                matched_dev.device_id
                if matched_dev is not None
                else (
                    matched_eq_snmp.equipment_id
                    if matched_eq_snmp is not None
                    else f"dev-{_slugify_id(site.site_id)}-{short_slug}"
                )
            )
            _record_active_ip(
                site.site_id,
                subnet,
                norm_ip,
                "snmp",
                mac=snmp_obs.mac_address,
                hostname=snmp_obs.sys_name,
                target_type=(
                    "equipment"
                    if matched_eq_snmp is not None
                    else "network_device"
                ),
                target_id=inferred_dev_id,
            )

            if matched_dev is None and matched_eq_snmp is None:
                vendor_tok = (snmp_obs.vendor or "Unknown").replace(" ", "_")
                model_tok = (snmp_obs.model or "Unknown").replace(" ", "_")
                role_tok = snmp_obs.role or "access-switch"
                discrepancies.append(
                    DiscrepancyRecord(
                        discrepancy_id=_next_id(
                            site.site_id, DiscrepancyType.UNTRACKED_DEVICE
                        ),
                        discrepancy_type=DiscrepancyType.UNTRACKED_DEVICE,
                        site_id=site.site_id,
                        observed_identifier=snmp_obs.sys_name or norm_ip,
                        observed_ip=norm_ip,
                        observed_mac=snmp_obs.mac_address,
                        observed_hostname=snmp_obs.sys_name,
                        source="snmp",
                        sot_item_id=None,
                        details=(
                            f"Untracked SNMP responder at {norm_ip} in subnet {subnet.subnet_id} "
                            f"(item_id={inferred_dev_id}, vendor={vendor_tok}, model={model_tok}, "
                            f"role={role_tok}, subnet_id={subnet.subnet_id}, "
                            f"os_version={snmp_obs.os_version or 'none'}, "
                            f"serial_number={snmp_obs.serial_number or 'none'})"
                        ),
                        recommended_onboarding_action=(
                            f"Onboard SNMP device '{snmp_obs.sys_name or norm_ip}' "
                            f"({snmp_obs.vendor or 'Unknown'}) into SoT for site {site.site_id}"
                        ),
                    )
                )
            else:
                # Check SNMP vs SoT ATTRIBUTE_MISMATCH
                mismatch_reasons = []
                if matched_dev is not None:
                    sot_id = matched_dev.device_id
                    sot_host = matched_dev.hostname
                    sot_ips = (
                        {_normalize_ip(matched_dev.management_ip)}
                        if _normalize_ip(matched_dev.management_ip)
                        else set()
                    )
                    sot_macs = {
                        norm
                        for ip_rec in site.ip_addresses
                        if (
                            ip_rec.assigned_object_id == matched_dev.device_id
                            or _normalize_ip(ip_rec.ip) in sot_ips
                        )
                        for raw_m in (
                            ip_rec.arp_mac,
                            ip_rec.arp_entry.arp_mac if ip_rec.arp_entry else None,
                        )
                        if (norm := _normalize_mac(raw_m)) is not None
                    }
                else:
                    assert matched_eq_snmp is not None
                    sot_id = matched_eq_snmp.equipment_id
                    sot_host = matched_eq_snmp.name
                    sot_ips, sot_macs = self._collect_equipment_ips_and_macs(
                        matched_eq_snmp, site
                    )

                if snmp_obs.sys_name and not _hostnames_match(
                    sot_host, snmp_obs.sys_name
                ):
                    mismatch_reasons.append(
                        f"sysName/hostname mismatch (SoT={sot_host!r} vs SNMP={snmp_obs.sys_name!r})"
                    )
                if sot_ips and norm_ip not in sot_ips:
                    mismatch_reasons.append(
                        f"management IP mismatch (SoT={sorted(sot_ips)} vs SNMP={norm_ip!r})"
                    )
                obs_norm_mac = _normalize_mac(snmp_obs.mac_address)
                if obs_norm_mac and sot_macs and obs_norm_mac not in sot_macs:
                    sot_canon = sorted(
                        _format_mac_canonical(m) or m for m in sot_macs
                    )
                    mismatch_reasons.append(
                        f"MAC mismatch (SoT={sot_canon} vs SNMP={snmp_obs.mac_address!r})"
                    )

                if mismatch_reasons:
                    discrepancies.append(
                        DiscrepancyRecord(
                            discrepancy_id=_next_id(
                                site.site_id, DiscrepancyType.ATTRIBUTE_MISMATCH
                            ),
                            discrepancy_type=DiscrepancyType.ATTRIBUTE_MISMATCH,
                            site_id=site.site_id,
                            observed_identifier=snmp_obs.sys_name or norm_ip,
                            observed_ip=norm_ip,
                            observed_mac=snmp_obs.mac_address,
                            observed_hostname=snmp_obs.sys_name,
                            source="snmp",
                            sot_item_id=sot_id,
                            details=(
                                f"SNMP attribute drift on {sot_id}: "
                                + "; ".join(mismatch_reasons)
                            ),
                            recommended_onboarding_action=(
                                f"Update SoT record '{sot_id}' to match SNMP discovery on {norm_ip}"
                            ),
                        )
                    )

        # -------------------------------------------------------------------
        # 3. ARP Discovery (Record active IPs & ARP vs SoT ATTRIBUTE_MISMATCH)
        # -------------------------------------------------------------------
        for arp_obs in arp_observations:
            match = self._match_ip_to_allocated_subnet(
                arp_obs.ip,
                subnet_index,
                site_id_filter=arp_obs.site_id,
            )
            if match is None:
                continue
            site_id, subnet, norm_ip = match
            site = sites_by_id[site_id]

            # Record for UNTRACKED_IP evaluation (ARP has priority over ICMP/vCenter/SNMP for IP source)
            existing_ip_obs = active_ip_observations.get((site_id, norm_ip))
            if existing_ip_obs is not None:
                existing_ip_obs["source"] = "arp"
                existing_ip_obs["mac"] = arp_obs.mac
                if arp_obs.arp_source_device_id:
                    existing_ip_obs["arp_source_device_id"] = arp_obs.arp_source_device_id
                if arp_obs.hostname and not existing_ip_obs.get("hostname"):
                    existing_ip_obs["hostname"] = arp_obs.hostname
            else:
                _record_active_ip(
                    site.site_id,
                    subnet,
                    norm_ip,
                    "arp",
                    mac=arp_obs.mac,
                    hostname=arp_obs.hostname,
                    arp_source_device_id=arp_obs.arp_source_device_id,
                )

            # Check if IP exists in site.ip_addresses or equipment/devices for ATTRIBUTE_MISMATCH
            matched_ip_rec = next(
                (
                    ip_rec
                    for ip_rec in site.ip_addresses
                    if _normalize_ip(ip_rec.ip) == norm_ip
                ),
                None,
            )
            matched_eq_arp = next(
                (
                    eq
                    for eq in site.equipment
                    if norm_ip
                    in {_normalize_ip(ip) for ip in eq.assigned_ips if _normalize_ip(ip)}
                    or (
                        matched_ip_rec is not None
                        and matched_ip_rec.assigned_object_id == eq.equipment_id
                    )
                ),
                None,
            )

            if matched_ip_rec is not None or matched_eq_arp is not None:
                mismatch_reasons = []
                obs_norm_mac = _normalize_mac(arp_obs.mac)

                recorded_macs: set[str] = set()
                if matched_ip_rec is not None:
                    for raw_m in (
                        matched_ip_rec.arp_mac,
                        matched_ip_rec.arp_entry.arp_mac
                        if matched_ip_rec.arp_entry
                        else None,
                    ):
                        if (norm_m := _normalize_mac(raw_m)) is not None:
                            recorded_macs.add(norm_m)

                if matched_eq_arp is not None:
                    _, eq_macs = self._collect_equipment_ips_and_macs(
                        matched_eq_arp, site
                    )
                    recorded_macs.update(eq_macs)

                if obs_norm_mac and recorded_macs and obs_norm_mac not in recorded_macs:
                    sot_canon = sorted(
                        _format_mac_canonical(m) or m for m in recorded_macs
                    )
                    mismatch_reasons.append(
                        f"ARP MAC mismatch for {norm_ip} (SoT={sot_canon} vs ARP={arp_obs.mac!r})"
                    )

                if (
                    arp_obs.arp_source_device_id
                    and matched_ip_rec is not None
                    and matched_ip_rec.arp_source_device_id
                    and arp_obs.arp_source_device_id.lower()
                    != matched_ip_rec.arp_source_device_id.lower()
                ):
                    mismatch_reasons.append(
                        f"ARP source switch mismatch for {norm_ip} "
                        f"(SoT={matched_ip_rec.arp_source_device_id!r} vs ARP={arp_obs.arp_source_device_id!r})"
                    )

                if arp_obs.connected_port and matched_eq_arp is not None:
                    allowed_port_refs: set[str] = {
                        p.strip().lower()
                        for p in matched_eq_arp.connected_ports
                        if p and p.strip()
                    }
                    for dev in site.devices:
                        for port in dev.ports:
                            if (
                                port.connected_device_id == matched_eq_arp.equipment_id
                                or port.port_id.lower() in allowed_port_refs
                            ):
                                allowed_port_refs.add(port.port_id.lower())
                                allowed_port_refs.add(port.name.lower())
                                allowed_port_refs.add(
                                    f"{dev.device_id}:{port.name}".lower()
                                )
                    if (
                        allowed_port_refs
                        and arp_obs.connected_port.lower() not in allowed_port_refs
                    ):
                        mismatch_reasons.append(
                            f"switch port mapping mismatch for {norm_ip} "
                            f"(SoT={matched_eq_arp.connected_ports} vs ARP={arp_obs.connected_port!r})"
                        )

                if mismatch_reasons:
                    sot_item_id = (
                        (
                            matched_ip_rec.assigned_object_id
                            if matched_ip_rec and matched_ip_rec.assigned_object_id
                            else None
                        )
                        or (
                            matched_eq_arp.equipment_id
                            if matched_eq_arp is not None
                            else None
                        )
                        or (matched_ip_rec.ip if matched_ip_rec is not None else norm_ip)
                    )
                    discrepancies.append(
                        DiscrepancyRecord(
                            discrepancy_id=_next_id(
                                site.site_id, DiscrepancyType.ATTRIBUTE_MISMATCH
                            ),
                            discrepancy_type=DiscrepancyType.ATTRIBUTE_MISMATCH,
                            site_id=site.site_id,
                            observed_identifier=norm_ip,
                            observed_ip=norm_ip,
                            observed_mac=arp_obs.mac,
                            observed_hostname=arp_obs.hostname,
                            source="arp",
                            sot_item_id=sot_item_id,
                            details=(
                                f"ARP attribute drift on {sot_item_id} ({norm_ip}): "
                                + "; ".join(mismatch_reasons)
                            ),
                            recommended_onboarding_action=(
                                f"Update SoT MAC/port assignment for '{sot_item_id}' ({norm_ip})"
                            ),
                        )
                    )

        # -------------------------------------------------------------------
        # 4. Scoped Active ICMP Discovery (Record active IPs)
        # -------------------------------------------------------------------
        for icmp_ip in icmp_ips:
            match = self._match_ip_to_allocated_subnet(icmp_ip, subnet_index)
            if match is None:
                continue
            site_id, subnet, norm_ip = match
            existing_obs = active_ip_observations.get((site_id, norm_ip))
            if existing_obs is None:
                _record_active_ip(site_id, subnet, norm_ip, "icmp")
            elif existing_obs["source"] in ("vcenter", "snmp"):
                # Keep richer MAC/hostname from vCenter/SNMP if present, or preserve source
                pass

        # -------------------------------------------------------------------
        # 5. Evaluate UNTRACKED_IP across all sites' allocated /24 subnets
        # -------------------------------------------------------------------
        for (site_id, norm_ip), obs in sorted(
            active_ip_observations.items(),
            key=lambda kv: (kv[0][0], ipaddress.ip_address(kv[0][1])),
        ):
            site = sites_by_id[site_id]
            recorded_site_ips = {
                norm
                for ip_rec in site.ip_addresses
                if (norm := _normalize_ip(ip_rec.ip)) is not None
            }
            if norm_ip in recorded_site_ips:
                continue

            subnet_obj: Subnet = obs["subnet"]
            src: str = obs["source"]
            mac_val: Optional[str] = obs.get("mac")
            host_val: Optional[str] = obs.get("hostname")
            t_type: str = obs.get("target_type") or (
                "network_device" if src == "snmp" else "equipment"
            )
            ip_slug = _slugify_id(norm_ip)
            t_id: str = obs.get("target_id") or (
                f"dev-{_slugify_id(site_id)}-{ip_slug}"
                if t_type == "network_device"
                else f"eq-{_slugify_id(site_id)}-{ip_slug}"
            )
            arp_dev: Optional[str] = obs.get("arp_source_device_id")
            item_id = f"ip-{_slugify_id(site_id)}-{ip_slug}"

            discrepancies.append(
                DiscrepancyRecord(
                    discrepancy_id=_next_id(site_id, DiscrepancyType.UNTRACKED_IP),
                    discrepancy_type=DiscrepancyType.UNTRACKED_IP,
                    site_id=site_id,
                    observed_identifier=norm_ip,
                    observed_ip=norm_ip,
                    observed_mac=mac_val,
                    observed_hostname=host_val,
                    source=src,
                    sot_item_id=None,
                    details=(
                        f"Active IP {norm_ip} in allocated /24 subnet {subnet_obj.subnet_id} "
                        f"({subnet_obj.cidr}) has no IPAddress record in SoT "
                        f"(item_id={item_id}, subnet_id={subnet_obj.subnet_id}, "
                        f"target_type={t_type}, target_id={t_id}, "
                        f"arp_source_device_id={arp_dev or 'none'})"
                    ),
                    recommended_onboarding_action=(
                        f"Register IP {norm_ip} in subnet {subnet_obj.subnet_id} "
                        f"(ip_arp_entries) for site {site_id}"
                    ),
                )
            )

        excluded: Optional[list[DiscrepancyRecord]] = None
        if self.exclude_randomized_macs:
            discrepancies, excluded = partition_randomized(discrepancies, self.oui_registry)
        return ReconciliationReport(
            discrepancies=discrepancies,
            generated_at=report_dt,
            excluded_discrepancies=excluded,
            oui_registry=self.oui_registry,
        )
