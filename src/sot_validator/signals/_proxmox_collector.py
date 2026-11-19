"""Proxmox VE and Docker/Portainer VM_POWER_STATE signal collector."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any, Optional

from sot_validator.models import (
    ArpEntry,
    Equipment,
    IPAddress,
    NetworkDevice,
    Port,
    SignalStatus,
    SignalType,
    Site,
    ValidationSignal,
)
from sot_validator.signals._proxmox_correlation import (
    _evaluate_equipment_target,
    enrich_site_with_guests,
)
from sot_validator.signals._proxmox_parsing import (
    PROXMOX_MAC_OUI,
    _require_non_empty_str,
    is_proxmox_mac,
    normalize_ip_address,
    normalize_mac_address,
)
from sot_validator.signals._proxmox_records import (
    ContainerEndpointRecord,
    ProxmoxGuestRecord,
)
from sot_validator.signals._proxmox_snapshot import ProxmoxClusterSnapshot
from sot_validator.signals.base import (
    SignalCollector,
    resolve_evaluation_time,
)


class ProxmoxContainerCollector(SignalCollector):
    """Evaluate VM_POWER_STATE validation signals for Proxmox VE guests and Docker/Portainer containers."""

    signal_type = SignalType.VM_POWER_STATE

    def __init__(
        self,
        snapshot: Optional[ProxmoxClusterSnapshot] = None,
        *,
        evaluation_time: Optional[datetime | str] = None,
        source: str = "proxmox_container.vm_power_state",
    ) -> None:
        self.snapshot = snapshot
        self.evaluation_time = (
            resolve_evaluation_time(evaluation_time)
            if evaluation_time is not None
            else None
        )
        self.source = _require_non_empty_str(source, "source")

    def evaluate(
        self,
        target: Any,
        *,
        snapshot: Optional[ProxmoxClusterSnapshot] = None,
        site: Optional[Site] = None,
        ip_addresses: Optional[Sequence[IPAddress]] = None,
        arp_entries: Optional[Sequence[ArpEntry]] = None,
        ports: Optional[Sequence[Port]] = None,
        evaluation_time: Optional[datetime | str] = None,
        **kwargs: Any,
    ) -> ValidationSignal:
        """Evaluate VM_POWER_STATE for a guest, container, Equipment, IPAddress, device or port target.

        Pass ``site`` for Equipment enriched by ``enrich_site_with_guests``: its ``hypervisor_id`` is the
        host's equipment ID (e.g. ``eq-pve-01``), and without ``site`` it cannot be resolved to a Proxmox
        host, so name/VMID correlation is skipped (IP and MAC correlation still apply).
        """
        eval_dt = (
            resolve_evaluation_time(evaluation_time)
            if evaluation_time is not None
            else (self.evaluation_time or resolve_evaluation_time(None))
        )
        active_snapshot = snapshot if snapshot is not None else self.snapshot

        if isinstance(target, ProxmoxGuestRecord):
            return self._evaluate_guest_record(target, eval_dt)

        if isinstance(target, ContainerEndpointRecord):
            return self._evaluate_container_record(target, eval_dt)

        if isinstance(target, (NetworkDevice, Port)):
            return ValidationSignal(
                signal_type=SignalType.VM_POWER_STATE,
                status=SignalStatus.NOT_APPLICABLE,
                observed_at=eval_dt,
                age_seconds=0.0,
                details=f"Target {type(target).__name__} is physical network infrastructure; Proxmox/container check not applicable",
                source=self.source,
                metadata={"target_type": type(target).__name__},
            )

        if isinstance(target, IPAddress):
            return self._evaluate_ip_target(
                target,
                snapshot=active_snapshot,
                site=site,
                arp_entries=arp_entries,
                ports=ports,
                eval_dt=eval_dt,
            )

        if isinstance(target, Equipment):
            return self._evaluate_equipment_target(
                target,
                snapshot=active_snapshot,
                site=site,
                ip_addresses=ip_addresses,
                arp_entries=arp_entries,
                ports=ports,
                eval_dt=eval_dt,
            )

        return ValidationSignal(
            signal_type=SignalType.VM_POWER_STATE,
            status=SignalStatus.NOT_APPLICABLE,
            observed_at=eval_dt,
            age_seconds=0.0,
            details=f"Unsupported target type for Proxmox/container correlation: {type(target).__name__}",
            source=self.source,
            metadata={"target_type": type(target).__name__},
        )

    def _evaluate_guest_record(
        self, guest: ProxmoxGuestRecord, eval_dt: datetime
    ) -> ValidationSignal:
        status = SignalStatus.ACTIVE if guest.is_running else SignalStatus.INACTIVE
        return ValidationSignal(
            signal_type=SignalType.VM_POWER_STATE,
            status=status,
            observed_at=eval_dt,
            age_seconds=0.0,
            details=(
                f"Proxmox {guest.guest_type.upper()} {guest.name} (vmid={guest.vmid} on {guest.node}) "
                f"is {guest.status}"
            ),
            source=self.source,
            metadata={
                "correlation_key": "direct_guest",
                "vmid": guest.vmid,
                "guest_type": guest.guest_type,
                "node": guest.node,
                "host_ip": guest.host_ip,
                "status": guest.status,
                "proxmox_mac_detected": guest.has_proxmox_mac,
                "matched_guests": [guest.to_dict()],
                "matched_containers": [],
            },
        )

    def _evaluate_container_record(
        self, container: ContainerEndpointRecord, eval_dt: datetime
    ) -> ValidationSignal:
        status = SignalStatus.ACTIVE if container.is_running else SignalStatus.INACTIVE
        return ValidationSignal(
            signal_type=SignalType.VM_POWER_STATE,
            status=status,
            observed_at=eval_dt,
            age_seconds=0.0,
            details=(
                f"Container {container.name} ({container.container_id[:12]}, image={container.image}) "
                f"is {container.state}"
            ),
            source=self.source,
            metadata={
                "correlation_key": "direct_container",
                "container_id": container.container_id,
                "name": container.name,
                "image": container.image,
                "host_ip": container.host_ip,
                "state": container.state,
                "proxmox_mac_detected": False,
                "matched_guests": [],
                "matched_containers": [container.to_dict()],
            },
        )

    def _evaluate_ip_target(
        self,
        ip_rec: IPAddress,
        *,
        snapshot: Optional[ProxmoxClusterSnapshot],
        site: Optional[Site],
        arp_entries: Optional[Sequence[ArpEntry]],
        ports: Optional[Sequence[Port]],
        eval_dt: datetime,
    ) -> ValidationSignal:
        norm_ip = normalize_ip_address(ip_rec.ip)
        candidate_macs: list[str] = []
        for raw_m in (
            ip_rec.arp_mac,
            ip_rec.arp_entry.arp_mac if isinstance(ip_rec.arp_entry, ArpEntry) else None,
        ):
            nm = normalize_mac_address(raw_m)
            if nm and nm not in candidate_macs:
                candidate_macs.append(nm)

        if arp_entries and norm_ip:
            for entry in arp_entries:
                if normalize_ip_address(entry.ip) == norm_ip:
                    nm = normalize_mac_address(entry.arp_mac)
                    if nm and nm not in candidate_macs:
                        candidate_macs.append(nm)

        pve_mac_detected = any(is_proxmox_mac(m) for m in candidate_macs)

        if snapshot is None:
            if pve_mac_detected:
                return ValidationSignal(
                    signal_type=SignalType.VM_POWER_STATE,
                    status=SignalStatus.UNREACHABLE,
                    observed_at=eval_dt,
                    age_seconds=0.0,
                    details=f"IP {ip_rec.ip} has Proxmox MAC OUI ({PROXMOX_MAC_OUI}), but no Proxmox snapshot is available",
                    source=self.source,
                    metadata={
                        "ip": ip_rec.ip,
                        "mac_addresses": candidate_macs,
                        "proxmox_mac_detected": True,
                    },
                )
            return ValidationSignal(
                signal_type=SignalType.VM_POWER_STATE,
                status=SignalStatus.NOT_APPLICABLE,
                observed_at=eval_dt,
                age_seconds=0.0,
                details=f"No Proxmox/container snapshot configured for IP {ip_rec.ip}",
                source=self.source,
                metadata={"ip": ip_rec.ip, "proxmox_mac_detected": False},
            )

        matched_guests: list[ProxmoxGuestRecord] = []
        matched_containers: list[ContainerEndpointRecord] = []
        correlation_key: Optional[str] = None

        for mac in candidate_macs:
            for g in snapshot.find_guests(mac=mac):
                if g not in matched_guests:
                    matched_guests.append(g)
                    correlation_key = correlation_key or "mac"

        if norm_ip:
            for g in snapshot.find_guests(ip=norm_ip):
                if g not in matched_guests:
                    matched_guests.append(g)
                    correlation_key = correlation_key or "ip"
            for c in snapshot.find_containers(ip=norm_ip):
                if c not in matched_containers:
                    matched_containers.append(c)
                    correlation_key = correlation_key or "ip"

        if matched_guests or matched_containers:
            return self._build_correlated_signal(
                target_label=f"IP {ip_rec.ip}",
                matched_guests=matched_guests,
                matched_containers=matched_containers,
                correlation_key=correlation_key or "ip",
                pve_mac_detected=pve_mac_detected or any(g.has_proxmox_mac for g in matched_guests),
                eval_dt=eval_dt,
            )

        if pve_mac_detected:
            if snapshot.unreachable_hosts or (not snapshot.guests and not snapshot.containers):
                return ValidationSignal(
                    signal_type=SignalType.VM_POWER_STATE,
                    status=SignalStatus.UNREACHABLE,
                    observed_at=eval_dt,
                    age_seconds=0.0,
                    details=(
                        f"IP {ip_rec.ip} has Proxmox OUI MAC ({candidate_macs[0]}), "
                        "but Proxmox host snapshot is unreachable or empty"
                    ),
                    source=self.source,
                    metadata={
                        "ip": ip_rec.ip,
                        "mac_addresses": candidate_macs,
                        "proxmox_mac_detected": True,
                        "unreachable_hosts": sorted(snapshot.unreachable_hosts),
                    },
                )
            return ValidationSignal(
                signal_type=SignalType.VM_POWER_STATE,
                status=SignalStatus.INACTIVE,
                observed_at=eval_dt,
                age_seconds=0.0,
                details=(
                    f"IP {ip_rec.ip} has Proxmox OUI MAC ({candidate_macs[0]}), "
                    "but no matching guest exists in Proxmox cluster snapshot"
                ),
                source=self.source,
                metadata={
                    "ip": ip_rec.ip,
                    "mac_addresses": candidate_macs,
                    "proxmox_mac_detected": True,
                },
            )

        return ValidationSignal(
            signal_type=SignalType.VM_POWER_STATE,
            status=SignalStatus.NOT_APPLICABLE,
            observed_at=eval_dt,
            age_seconds=0.0,
            details=f"IP {ip_rec.ip} did not match any Proxmox guest or container",
            source=self.source,
            metadata={"ip": ip_rec.ip, "proxmox_mac_detected": False},
        )

    def _evaluate_equipment_target(
        self,
        equipment: Equipment,
        *,
        snapshot: Optional[ProxmoxClusterSnapshot],
        site: Optional[Site],
        ip_addresses: Optional[Sequence[IPAddress]],
        arp_entries: Optional[Sequence[ArpEntry]],
        ports: Optional[Sequence[Port]],
        eval_dt: datetime,
    ) -> ValidationSignal:
        return _evaluate_equipment_target(
            self,
            equipment,
            snapshot=snapshot,
            site=site,
            ip_addresses=ip_addresses,
            arp_entries=arp_entries,
            ports=ports,
            eval_dt=eval_dt,
        )

    def _build_correlated_signal(
        self,
        *,
        target_label: str,
        matched_guests: list[ProxmoxGuestRecord],
        matched_containers: list[ContainerEndpointRecord],
        correlation_key: str,
        pve_mac_detected: bool,
        eval_dt: datetime,
    ) -> ValidationSignal:
        any_running = any(g.is_running for g in matched_guests) or any(
            c.is_running for c in matched_containers
        )
        status = SignalStatus.ACTIVE if any_running else SignalStatus.INACTIVE

        summary_parts: list[str] = []
        for g in matched_guests:
            summary_parts.append(
                f"Proxmox {g.guest_type.upper()} {g.name} (vmid={g.vmid}, node={g.node}, status={g.status})"
            )
        for c in matched_containers:
            summary_parts.append(
                f"Container {c.name} (id={c.container_id[:12]}, state={c.state})"
            )

        return ValidationSignal(
            signal_type=SignalType.VM_POWER_STATE,
            status=status,
            observed_at=eval_dt,
            age_seconds=0.0,
            details=f"{target_label} correlated via {correlation_key}: {'; '.join(summary_parts)}",
            source=self.source,
            metadata={
                "correlation_key": correlation_key,
                "proxmox_mac_detected": pve_mac_detected,
                "matched_guests": [g.to_dict() for g in matched_guests],
                "matched_containers": [c.to_dict() for c in matched_containers],
            },
        )

    def enrich_site_with_guests(
        self,
        site: Site,
        *,
        snapshot: Optional[ProxmoxClusterSnapshot] = None,
    ) -> Site:
        """Return an enriched Site copy with Proxmox guests and containers linked via hypervisor_id."""
        return enrich_site_with_guests(
            self,
            site,
            snapshot=snapshot,
        )


ProxmoxContainerCorrelator = ProxmoxContainerCollector
