"""Device, port and VLAN edit methods mixed into ``WorkbenchState``."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import ipaddress
from typing import Any, Optional

from sot_validator.curation.store import AuditLogEntry
from sot_validator.models import (
    NetworkDevice,
    Port,
    Subnet,
    VLAN,
    _parse_optional_datetime,
    _require_non_empty_str,
)
from sot_validator.topology.device_types import (
    DevicePortManager,
    normalize_mac_address,
)
from sot_validator.workbench._server_common import (
    WorkbenchNotFoundError,
    _optional_str,
    _slugify,
)


class _DeviceEditMixin:
    """Device creation, port and VLAN upserts for ``WorkbenchState``."""

    def create_device(
        self,
        payload: Mapping[str, Any],
        *,
        actor: str = "operator",
        reason: str = "",
    ) -> tuple[NetworkDevice, AuditLogEntry]:
        """Create a NetworkDevice (from a template or custom fields), persist it, and refresh state."""
        if not isinstance(payload, Mapping):
            raise ValueError("payload must be a mapping")

        with self._lock:
            hostname = _require_non_empty_str(
                payload.get("hostname"), "hostname"
            ).strip()
            site_id = (
                _optional_str(payload.get("site_id")) or self.site.site_id
            )
            raw_device_id = _optional_str(payload.get("device_id"))
            device_id = raw_device_id if raw_device_id else _slugify(hostname, prefix="dev")

            template_id = _optional_str(payload.get("template_id"))
            management_ip = _optional_str(payload.get("management_ip"))
            vendor = _optional_str(payload.get("vendor"))
            model = _optional_str(payload.get("model"))
            role = _optional_str(payload.get("role"))
            default_vlan_id = _optional_str(payload.get("default_vlan_id"))
            last_seen = _parse_optional_datetime(
                payload.get("last_seen"), "last_seen"
            )

            raw_port_count = payload.get("port_count")
            port_count: Optional[int] = None
            if raw_port_count is not None and raw_port_count != "":
                if isinstance(raw_port_count, bool):
                    raise ValueError("port_count must be a non-negative integer")
                try:
                    port_count = int(raw_port_count)
                except (TypeError, ValueError) as exc:
                    raise ValueError("port_count must be a non-negative integer") from exc
                if port_count < 0:
                    raise ValueError("port_count must be a non-negative integer")

            if template_id:
                device = self.catalog.instantiate_device(
                    template_id,
                    device_id=device_id,
                    site_id=site_id,
                    hostname=hostname,
                    management_ip=management_ip,
                    port_count=port_count,
                    default_vlan_id=default_vlan_id,
                    last_seen=last_seen,
                )
                if vendor is not None:
                    device.vendor = vendor
                if model is not None:
                    device.model = model
                if role is not None:
                    device.role = role
            else:
                device = NetworkDevice(
                    device_id=device_id,
                    site_id=site_id,
                    hostname=hostname,
                    management_ip=management_ip,
                    vendor=vendor,
                    model=model,
                    role=role,
                    last_seen=last_seen,
                    ports=[],
                )
                if port_count is not None and port_count > 0:
                    naming_pattern = (
                        _optional_str(payload.get("port_naming_pattern")) or "1:{n}"
                    )
                    mgr = DevicePortManager(device)
                    mgr.add_port_range(
                        start=1,
                        end=port_count,
                        naming_pattern=naming_pattern,
                        vlan_id=default_vlan_id,
                        overwrite=True,
                    )

            explicit_ports = payload.get("ports")
            if explicit_ports is not None:
                if not isinstance(explicit_ports, Sequence) or isinstance(
                    explicit_ports, (str, bytes)
                ):
                    raise ValueError("ports must be a list of port specifications")
                mgr = DevicePortManager(device)
                for p_spec in explicit_ports:
                    if isinstance(p_spec, Port):
                        mgr.add_port(
                            p_spec.name,
                            port_id=p_spec.port_id,
                            admin_status=p_spec.admin_status,
                            oper_status=p_spec.oper_status,
                            poe_status=p_spec.poe_status,
                            vlan_id=p_spec.vlan_id,
                            connected_device_id=p_spec.connected_device_id,
                            connected_mac=p_spec.connected_mac,
                            overwrite=True,
                        )
                    elif isinstance(p_spec, Mapping):
                        p_name = _require_non_empty_str(
                            p_spec.get("name"), "port.name"
                        ).strip()
                        mgr.add_port(
                            p_name,
                            port_id=_optional_str(p_spec.get("port_id")),
                            admin_status=_optional_str(p_spec.get("admin_status")) or "up",
                            oper_status=_optional_str(p_spec.get("oper_status")) or "down",
                            poe_status=_optional_str(p_spec.get("poe_status")),
                            vlan_id=_optional_str(p_spec.get("vlan_id")) or default_vlan_id,
                            connected_device_id=_optional_str(
                                p_spec.get("connected_device_id")
                            ),
                            connected_mac=_optional_str(p_spec.get("connected_mac")),
                            overwrite=True,
                        )
                    else:
                        raise ValueError("Each entry in ports must be a Port or mapping")

            entry = self.store.add_custom_device(device, actor=actor, reason=reason)
            self.refresh()
            created = next(
                (d for d in self.site.devices if d.device_id == device.device_id),
                device,
            )
            return created, entry

    def upsert_device_ports(
        self,
        payload: Mapping[str, Any],
        *,
        actor: str = "operator",
        reason: str = "",
    ) -> tuple[list[Port], list[AuditLogEntry]]:
        """Provision or update single ports, port ranges, or batch port lists on a NetworkDevice."""
        if not isinstance(payload, Mapping):
            raise ValueError("payload must be a mapping")

        with self._lock:
            device_id = _require_non_empty_str(
                payload.get("device_id"), "device_id"
            ).strip()
            target_dev = next(
                (d for d in self.site.devices if d.device_id == device_id), None
            )
            if target_dev is None:
                raise WorkbenchNotFoundError(
                    f"NetworkDevice {device_id!r} not found in site {self.site.site_id!r}"
                )

            working_dev = NetworkDevice.from_dict(target_dev.to_dict())
            mgr = DevicePortManager(working_dev)
            overwrite = bool(payload.get("overwrite", True))

            default_admin = _optional_str(payload.get("admin_status"))
            default_oper = _optional_str(payload.get("oper_status"))
            default_poe = _optional_str(payload.get("poe_status"))
            default_vlan = _optional_str(payload.get("vlan_id"))
            default_conn_dev = _optional_str(payload.get("connected_device_id"))
            default_conn_mac = _optional_str(payload.get("connected_mac"))

            def _upsert_single(spec: Mapping[str, Any]) -> Port:
                raw_name = _optional_str(spec.get("name"))
                raw_port_id = _optional_str(spec.get("port_id"))
                if not raw_name and not raw_port_id:
                    raise ValueError("Port specification requires 'name' or 'port_id'")

                existing_port: Optional[Port] = None
                for p in working_dev.ports:
                    if (raw_port_id and p.port_id == raw_port_id) or (
                        raw_name and p.name == raw_name
                    ):
                        existing_port = p
                        break

                resolved_name = (
                    raw_name
                    or (existing_port.name if existing_port is not None else None)
                    or (
                        raw_port_id.split(":", 1)[1]
                        if raw_port_id and ":" in raw_port_id
                        else raw_port_id
                    )
                )
                assert resolved_name is not None
                resolved_port_id = (
                    raw_port_id
                    or (existing_port.port_id if existing_port is not None else None)
                    or f"{device_id}:{resolved_name}"
                )

                admin_status = (
                    _optional_str(spec["admin_status"])
                    if "admin_status" in spec
                    else (
                        default_admin
                        if default_admin is not None
                        else (existing_port.admin_status if existing_port else "up")
                    )
                )
                oper_status = (
                    _optional_str(spec["oper_status"])
                    if "oper_status" in spec
                    else (
                        default_oper
                        if default_oper is not None
                        else (existing_port.oper_status if existing_port else "down")
                    )
                )
                poe_status = (
                    _optional_str(spec["poe_status"])
                    if "poe_status" in spec
                    else (
                        default_poe
                        if "poe_status" in payload
                        else (existing_port.poe_status if existing_port else None)
                    )
                )
                vlan_id = (
                    _optional_str(spec["vlan_id"])
                    if "vlan_id" in spec
                    else (
                        default_vlan
                        if "vlan_id" in payload
                        else (existing_port.vlan_id if existing_port else None)
                    )
                )
                connected_device_id = (
                    _optional_str(spec["connected_device_id"])
                    if "connected_device_id" in spec
                    else (
                        default_conn_dev
                        if "connected_device_id" in payload
                        else (
                            existing_port.connected_device_id if existing_port else None
                        )
                    )
                )
                raw_mac = (
                    _optional_str(spec["connected_mac"])
                    if "connected_mac" in spec
                    else (
                        default_conn_mac
                        if "connected_mac" in payload
                        else (existing_port.connected_mac if existing_port else None)
                    )
                )
                item_overwrite = bool(spec.get("overwrite", overwrite))
                return mgr.add_port(
                    resolved_name,
                    port_id=resolved_port_id,
                    admin_status=admin_status,
                    oper_status=oper_status,
                    poe_status=poe_status,
                    vlan_id=vlan_id,
                    connected_device_id=connected_device_id,
                    connected_mac=raw_mac,
                    overwrite=item_overwrite,
                )

            touched_ports: list[Port] = []
            batch_ports = payload.get("ports")
            range_spec = _optional_str(payload.get("range_spec"))
            raw_start = payload.get("start")
            raw_end = payload.get("end")

            if batch_ports is not None:
                if not isinstance(batch_ports, Sequence) or isinstance(
                    batch_ports, (str, bytes)
                ):
                    raise ValueError("ports must be a sequence of port mappings")
                if not batch_ports:
                    raise ValueError("ports list must not be empty")
                for item in batch_ports:
                    if not isinstance(item, Mapping):
                        raise ValueError("Each item in ports must be a mapping")
                    touched_ports.append(_upsert_single(item))
            elif range_spec is not None or (
                raw_start is not None and raw_end is not None
            ):
                start_int: Optional[int] = None
                end_int: Optional[int] = None
                if raw_start is not None or raw_end is not None:
                    if isinstance(raw_start, bool) or isinstance(raw_end, bool):
                        raise ValueError("start and end must be integers")
                    try:
                        start_int = int(raw_start)  # type: ignore[arg-type]
                        end_int = int(raw_end)  # type: ignore[arg-type]
                    except (TypeError, ValueError) as exc:
                        raise ValueError("start and end must be integers") from exc
                naming_pattern = (
                    _optional_str(payload.get("naming_pattern")) or "{n}"
                )
                created_range = mgr.add_port_range(
                    range_spec,
                    start=start_int,
                    end=end_int,
                    naming_pattern=naming_pattern,
                    admin_status=default_admin or "up",
                    oper_status=default_oper or "down",
                    poe_status=default_poe,
                    vlan_id=default_vlan,
                    overwrite=overwrite,
                )
                norm_mac = (
                    normalize_mac_address(default_conn_mac)
                    if default_conn_mac is not None
                    else None
                )
                for p in created_range:
                    if default_conn_dev is not None:
                        p.connected_device_id = default_conn_dev
                    if norm_mac is not None:
                        p.connected_mac = norm_mac
                touched_ports.extend(created_range)
            else:
                touched_ports.append(_upsert_single(payload))

            audit_entries: list[AuditLogEntry] = []
            for p in touched_ports:
                entry = self.store.add_or_update_port(
                    device_id,
                    p,
                    actor=actor,
                    reason=reason,
                    site_id=self.site.site_id,
                )
                audit_entries.append(entry)

            self.refresh()
            return touched_ports, audit_entries

    def upsert_vlan(
        self,
        payload: Mapping[str, Any],
        *,
        actor: str = "operator",
        reason: str = "",
    ) -> tuple[VLAN, Optional[Subnet], AuditLogEntry]:
        """Add or update a VLAN and optional associated Subnet, persist it, and refresh state."""
        if not isinstance(payload, Mapping):
            raise ValueError("payload must be a mapping")

        with self._lock:
            raw_vlan_id = payload.get("vlan_id")
            if raw_vlan_id is None or str(raw_vlan_id).strip() == "":
                raise ValueError("vlan_id must be a non-empty string")
            vlan_id = str(raw_vlan_id).strip()
            site_id = (
                _optional_str(payload.get("site_id")) or self.site.site_id
            )
            name = _optional_str(payload.get("name"))
            subnet_id = _optional_str(payload.get("subnet_id"))
            cidr = _optional_str(payload.get("cidr"))
            gateway = _optional_str(payload.get("gateway"))

            subnet_payload = payload.get("subnet")
            if isinstance(subnet_payload, Mapping):
                subnet_id = _optional_str(subnet_payload.get("subnet_id")) or subnet_id
                cidr = _optional_str(subnet_payload.get("cidr")) or cidr
                gateway = _optional_str(subnet_payload.get("gateway")) or gateway
                if name is None:
                    name = _optional_str(subnet_payload.get("name"))

            if cidr is not None:
                try:
                    ipaddress.ip_network(cidr, strict=False)
                except ValueError as exc:
                    raise ValueError(f"Invalid subnet CIDR: {cidr!r}") from exc

            subnet_obj: Optional[Subnet] = None
            if cidr is not None:
                resolved_subnet_id = (
                    subnet_id or f"{site_id}-subnet-vlan-{vlan_id}"
                )
                subnet_obj = Subnet(
                    subnet_id=resolved_subnet_id,
                    site_id=site_id,
                    cidr=cidr,
                    vlan_id=vlan_id,
                    gateway=gateway,
                    name=name or f"VLAN {vlan_id}",
                )
                subnet_id = resolved_subnet_id

            vlan_obj = VLAN(
                vlan_id=vlan_id,
                site_id=site_id,
                name=name,
                subnet_id=subnet_id,
                cidr=cidr,
                gateway=gateway,
            )

            entry = self.store.add_custom_vlan(
                vlan_obj, subnet=subnet_obj, actor=actor, reason=reason
            )
            self.refresh()
            return vlan_obj, subnet_obj, entry
