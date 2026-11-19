"""Deterministic parsers for gateway ARP/neighbor tables and DHCP lease exports."""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
import csv
from datetime import datetime
import io
import ipaddress
import json
import re
from typing import Any, Optional

from sot_validator.discovery._router_common import (
    _EXOS_NUMERIC_STATIC_TOKENS,
    _EXOS_STATIC_TOKENS,
    _ISC_LEASE_BLOCK_RE,
    _ISC_LEASE_START_RE,
    _ISC_STATEMENT_RE,
    _KEA_INFINITE_LFT,
    _LEASE_CLIENT_ID_KEYS,
    _LEASE_EXPIRY_KEYS,
    _LEASE_HOSTNAME_KEYS,
    _LEASE_IP_KEYS,
    _LEASE_MAC_KEYS,
    _LEASE_SUBNET_KEYS,
    _VOSS_TYPES,
    IF_MIB_IF_DESCR_PREFIX,
    IF_MIB_IF_NAME_PREFIX,
    IP_MIB_NET_TO_MEDIA_NET_ADDRESS_PREFIX,
    IP_MIB_NET_TO_MEDIA_TYPE_PREFIX,
    _canonical_ipv4,
    _first_value,
    _is_ipv4,
    _normalize_router_mac,
    _optional_token,
    _snmp_text,
    _snmp_type_state,
    _vlan_from_interface,
    _vlan_from_ip,
    _vlan_from_number,
)
from sot_validator.discovery._router_records import DhcpLeaseRecord, RouterArpRecord
from sot_validator.discovery.scanner import _NEIGH_STATES
from sot_validator.signals.management import (
    IP_MIB_NET_TO_MEDIA_PHYS_ADDRESS_PREFIX,
    IP_MIB_NET_TO_PHYSICAL_PHYS_ADDRESS_PREFIX,
)


class RouterTableParsers:
    """Deterministic parsers for gateway ARP/neighbor tables and DHCP lease exports."""

    # ------------------------------------------------------------------ ARP / neighbor

    @staticmethod
    def _parse_ip_neigh_tokens(
        tokens: Sequence[str],
        router_id: Optional[str],
        observed_at: Optional[datetime | str],
    ) -> Optional[RouterArpRecord]:
        if not tokens or not _is_ipv4(tokens[0]):
            return None
        interface: Optional[str] = None
        mac_token: Optional[str] = None
        for idx, tok in enumerate(tokens[:-1]):
            lowered = tok.lower()
            if lowered == "dev" and interface is None:
                interface = tokens[idx + 1]
            elif lowered == "lladdr" and mac_token is None:
                mac_token = tokens[idx + 1]
        last_upper = tokens[-1].upper()
        state = last_upper if last_upper in _NEIGH_STATES else None
        ip = str(ipaddress.IPv4Address(tokens[0]))
        return RouterArpRecord(
            ip=ip,
            mac_address=mac_token,
            interface=interface,
            vlan_id=_vlan_from_interface(interface) or _vlan_from_ip(ip),
            state=state,
            router_id=router_id,
            observed_at=observed_at,
        )

    @staticmethod
    def _parse_exos_tokens(
        tokens: Sequence[str],
        router_id: Optional[str],
        observed_at: Optional[datetime | str],
    ) -> Optional[RouterArpRecord]:
        if len(tokens) >= 2 and _is_ipv4(tokens[0]):
            start = 0
        elif len(tokens) >= 3 and _is_ipv4(tokens[1]):
            start = 1
        else:
            return None
        ip = str(ipaddress.IPv4Address(tokens[start]))
        mac_token = tokens[start + 1] if len(tokens) > start + 1 else None
        # Remaining columns: Age, Static, VLAN name, VID, Port
        rest = list(tokens[start + 2 :])
        static_token = rest[1].upper() if len(rest) > 1 else ""
        vlan_name = rest[2] if len(rest) > 2 else None
        vid_token = rest[3] if len(rest) > 3 and rest[3].isdigit() else None
        port_token = rest[4] if len(rest) > 4 and rest[4] != "-" else None

        mac = _normalize_router_mac(mac_token)
        if static_token in ("YES", "STATIC", "1"):
            state = "STATIC"
        elif mac is None:
            state = "INCOMPLETE"
        else:
            state = "DYNAMIC"
        vlan_id = (
            _vlan_from_number(vid_token)
            or _vlan_from_number(vlan_name)
            or _vlan_from_ip(ip)
        )
        return RouterArpRecord(
            ip=ip,
            mac_address=mac,
            interface=port_token,
            vlan_id=vlan_id,
            state=state,
            router_id=router_id,
            observed_at=observed_at,
        )

    @staticmethod
    def _parse_voss_tokens(
        tokens: Sequence[str],
        router_id: Optional[str],
        observed_at: Optional[datetime | str],
    ) -> Optional[RouterArpRecord]:
        if len(tokens) < 2 or not _is_ipv4(tokens[0]):
            return None
        ip = str(ipaddress.IPv4Address(tokens[0]))
        mac = _normalize_router_mac(tokens[1])
        vlan_token = tokens[2] if len(tokens) > 2 else None
        port_token = tokens[3] if len(tokens) > 3 and tokens[3] != "-" else None
        type_token = tokens[4].upper() if len(tokens) > 4 else None
        state = type_token or ("INCOMPLETE" if mac is None else None)
        vlan_id = (
            _vlan_from_number(vlan_token)
            if vlan_token is not None and vlan_token.isdigit()
            else None
        ) or _vlan_from_interface(port_token) or _vlan_from_ip(ip)
        return RouterArpRecord(
            ip=ip,
            mac_address=mac,
            interface=port_token,
            vlan_id=vlan_id,
            state=state,
            router_id=router_id,
            observed_at=observed_at,
        )

    @staticmethod
    def _iter_lines(raw_output: str) -> Iterator[list[str]]:
        if not isinstance(raw_output, str):
            raise ValueError("raw_output must be a string")
        for raw_line in raw_output.splitlines():
            tokens = raw_line.split()
            if tokens and not tokens[0].startswith(("#", "=", "-")):
                yield tokens

    @classmethod
    def _parse_lines(
        cls,
        raw_output: str,
        line_parser: Any,
        router_id: Optional[str],
        observed_at: Optional[datetime | str],
    ) -> list[RouterArpRecord]:
        records: list[RouterArpRecord] = []
        for tokens in cls._iter_lines(raw_output):
            try:
                record = line_parser(tokens, router_id, observed_at)
            except ValueError:
                continue
            if record is not None:
                records.append(record)
        return records

    @classmethod
    def parse_ip_neigh(
        cls,
        raw_output: str,
        *,
        router_id: Optional[str] = None,
        observed_at: Optional[datetime | str] = None,
    ) -> list[RouterArpRecord]:
        """Parse Linux / UniFi / EdgeOS ``ip -4 neigh show`` output."""
        return cls._parse_lines(
            raw_output, cls._parse_ip_neigh_tokens, router_id, observed_at
        )

    @classmethod
    def parse_extremexos_arp(
        cls,
        raw_output: str,
        *,
        router_id: Optional[str] = None,
        observed_at: Optional[datetime | str] = None,
    ) -> list[RouterArpRecord]:
        """Parse ExtremeXOS ``show iparp`` table output (with or without ``VR`` column)."""
        return cls._parse_lines(
            raw_output, cls._parse_exos_tokens, router_id, observed_at
        )

    @classmethod
    def parse_voss_arp(
        cls,
        raw_output: str,
        *,
        router_id: Optional[str] = None,
        observed_at: Optional[datetime | str] = None,
    ) -> list[RouterArpRecord]:
        """Parse Extreme VOSS ``show ip arp`` table output."""
        return cls._parse_lines(
            raw_output, cls._parse_voss_tokens, router_id, observed_at
        )

    @classmethod
    def _classify_cli_line(cls, tokens: Sequence[str]) -> Any:
        if len(tokens) < 2:
            return None
        if _is_ipv4(tokens[0]):
            lowered = {t.lower() for t in tokens}
            if "dev" in lowered or "lladdr" in lowered:
                return cls._parse_ip_neigh_tokens
            exos_shape = len(tokens) >= 4 and tokens[2].isdigit()
            if exos_shape and tokens[3].upper() in _EXOS_STATIC_TOKENS:
                return cls._parse_exos_tokens
            # VOSS before numeric EXOS static flags: a VOSS port can be a bare "1"
            if len(tokens) >= 5 and tokens[4].upper() in _VOSS_TYPES:
                return cls._parse_voss_tokens
            if exos_shape and tokens[3] in _EXOS_NUMERIC_STATIC_TOKENS:
                return cls._parse_exos_tokens
            return None
        if len(tokens) >= 3 and _is_ipv4(tokens[1]):
            return cls._parse_exos_tokens
        return None

    @classmethod
    def parse_cli_arp(
        cls,
        raw_output: str,
        *,
        router_id: Optional[str] = None,
        observed_at: Optional[datetime | str] = None,
    ) -> list[RouterArpRecord]:
        """Auto-detect and parse ``ip neigh``, ExtremeXOS and VOSS ARP text output."""
        records: list[RouterArpRecord] = []
        for tokens in cls._iter_lines(raw_output):
            line_parser = cls._classify_cli_line(tokens)
            if line_parser is None:
                continue
            try:
                record = line_parser(tokens, router_id, observed_at)
            except ValueError:
                continue
            if record is not None:
                records.append(record)
        return records

    @staticmethod
    def _split_arp_index(
        suffix: str, *, physical: bool
    ) -> Optional[tuple[str, str]]:
        parts = suffix.split(".")
        if physical and len(parts) == 7 and parts[1:3] == ["1", "4"]:
            parts = [parts[0], *parts[3:]]
        if len(parts) != 5 or not all(p.isdigit() for p in parts):
            return None
        ip = ".".join(parts[1:])
        if not _is_ipv4(ip):
            return None
        return parts[0], str(ipaddress.IPv4Address(ip))

    @classmethod
    def _parse_snmp_oids(
        cls,
        oids: Mapping[str, Any],
        router_id: Optional[str],
        observed_at: Optional[datetime | str],
    ) -> list[RouterArpRecord]:
        entries: dict[tuple[str, str], dict[str, Any]] = {}
        if_names: dict[str, str] = {}
        if_descrs: dict[str, str] = {}
        arp_prefixes = (
            (IP_MIB_NET_TO_MEDIA_PHYS_ADDRESS_PREFIX, "mac", False),
            (IP_MIB_NET_TO_MEDIA_NET_ADDRESS_PREFIX, "net", False),
            (IP_MIB_NET_TO_MEDIA_TYPE_PREFIX, "type", False),
            (IP_MIB_NET_TO_PHYSICAL_PHYS_ADDRESS_PREFIX, "mac", True),
        )

        for raw_oid, raw_value in oids.items():
            oid = str(raw_oid).strip().lstrip(".")
            if oid.startswith("iso."):
                oid = "1." + oid[4:]
            if oid.startswith(IF_MIB_IF_NAME_PREFIX + "."):
                name = _snmp_text(raw_value)
                if name:
                    if_names[oid[len(IF_MIB_IF_NAME_PREFIX) + 1 :]] = name
                continue
            if oid.startswith(IF_MIB_IF_DESCR_PREFIX + "."):
                descr = _snmp_text(raw_value)
                if descr:
                    if_descrs[oid[len(IF_MIB_IF_DESCR_PREFIX) + 1 :]] = descr
                continue
            for prefix, kind, physical in arp_prefixes:
                if not oid.startswith(prefix + "."):
                    continue
                index = cls._split_arp_index(oid[len(prefix) + 1 :], physical=physical)
                if index is None:
                    break
                # Net-address rows only register the index; MAC/type rows fill it in
                entry = entries.setdefault(index, {})
                if kind == "mac":
                    if entry.get("mac") is None:
                        entry["mac"] = _snmp_text(raw_value)
                elif kind == "type":
                    entry["type"] = _snmp_type_state(raw_value)
                break

        records: list[RouterArpRecord] = []
        for (if_index, ip), entry in sorted(
            entries.items(),
            key=lambda item: (ipaddress.IPv4Address(item[0][1]), int(item[0][0])),
        ):
            interface = if_names.get(if_index) or if_descrs.get(if_index) or if_index
            try:
                mac = _normalize_router_mac(entry.get("mac"))
            except ValueError:
                continue
            state = entry.get("type") or ("REACHABLE" if mac else None)
            records.append(
                RouterArpRecord(
                    ip=ip,
                    mac_address=mac,
                    interface=interface,
                    vlan_id=_vlan_from_interface(interface) or _vlan_from_ip(ip),
                    state=state,
                    router_id=router_id,
                    observed_at=observed_at,
                )
            )
        return records

    @staticmethod
    def _snmp_row_to_record(
        row: Mapping[str, Any],
        router_id: Optional[str],
        observed_at: Optional[datetime | str],
    ) -> RouterArpRecord:
        ip = _snmp_text(_first_value(row, ("ip", "ipNetToMediaNetAddress")))
        if ip is None:
            raise ValueError("SNMP ARP row is missing an IP address")
        ip = _canonical_ipv4(ip)
        mac = _snmp_text(
            _first_value(row, ("mac_address", "mac", "ipNetToMediaPhysAddress"))
        )
        interface = _snmp_text(_first_value(row, ("interface", "if_index", "ifIndex")))
        raw_state = _first_value(row, ("state",))
        if raw_state is not None:
            state: Optional[str] = str(raw_state)
        else:
            state = _snmp_type_state(row.get("ipNetToMediaType"))
        normalized_mac = _normalize_router_mac(mac)
        if state is None and normalized_mac is not None:
            state = "REACHABLE"
        vlan_id = (
            _optional_token(row.get("vlan_id"), "vlan_id")
            or _vlan_from_interface(interface)
            or _vlan_from_ip(ip)
        )
        return RouterArpRecord(
            ip=ip,
            mac_address=normalized_mac,
            interface=interface,
            vlan_id=vlan_id,
            state=state,
            router_id=row.get("router_id") or router_id,
            observed_at=row.get("observed_at") or observed_at,
        )

    @classmethod
    def parse_snmp_arp(
        cls,
        raw_data: str | Mapping[str, Any] | Sequence[Mapping[str, Any]],
        *,
        router_id: Optional[str] = None,
        observed_at: Optional[datetime | str] = None,
    ) -> list[RouterArpRecord]:
        """Parse IP-MIB ARP walk data from a JSON string, OID dict, or row dicts."""
        data: Any = raw_data
        if isinstance(raw_data, str):
            if not raw_data.strip():
                return []
            data = json.loads(raw_data)

        if isinstance(data, Mapping):
            oids = data.get("oids")
            return cls._parse_snmp_oids(
                oids if isinstance(oids, Mapping) else data, router_id, observed_at
            )
        if isinstance(data, Sequence) and not isinstance(data, (str, bytes)):
            records: list[RouterArpRecord] = []
            for row in data:
                if not isinstance(row, Mapping):
                    continue
                try:
                    records.append(cls._snmp_row_to_record(row, router_id, observed_at))
                except ValueError:
                    continue
            return records
        raise ValueError("SNMP ARP data must be a JSON string, mapping, or sequence")

    # ------------------------------------------------------------------ DHCP leases

    @staticmethod
    def parse_dnsmasq_leases(
        raw_text: str, *, subnet_id: Optional[str] = None
    ) -> list[DhcpLeaseRecord]:
        """Parse ``dnsmasq.leases`` lines (``<expiry> <mac> <ip> <hostname> <client_id>``)."""
        if not isinstance(raw_text, str):
            raise ValueError("raw_text must be a string")
        leases: list[DhcpLeaseRecord] = []
        for raw_line in raw_text.splitlines():
            tokens = raw_line.split()
            if len(tokens) < 3 or tokens[0].startswith("#") or tokens[0].lower() == "duid":
                continue
            try:
                leases.append(
                    DhcpLeaseRecord(
                        ip=tokens[2],
                        mac_address=tokens[1],
                        hostname=tokens[3] if len(tokens) > 3 else None,
                        lease_expires_at=tokens[0],
                        subnet_id=subnet_id,
                        client_id=tokens[4] if len(tokens) > 4 else None,
                    )
                )
            except ValueError:
                continue
        return leases

    @staticmethod
    def _lease_from_row(
        row: Mapping[str, Any], ip_hint: Optional[str], subnet_id: Optional[str]
    ) -> DhcpLeaseRecord:
        lowered = {str(k).strip().lower(): v for k, v in row.items() if k is not None}
        ip = _first_value(lowered, _LEASE_IP_KEYS) or ip_hint
        mac = _first_value(lowered, _LEASE_MAC_KEYS)
        if isinstance(mac, str) and mac.strip().lower().startswith("ethernet "):
            mac = mac.strip()[len("ethernet ") :]
        expires: Any = _first_value(lowered, _LEASE_EXPIRY_KEYS)
        if expires is None:
            cltt = _first_value(lowered, ("cltt",))
            valid_lft = _first_value(lowered, ("valid-lft", "valid_lft"))
            if cltt is not None and valid_lft is not None:
                lft = int(float(valid_lft))
                expires = None if lft >= _KEA_INFINITE_LFT else int(float(cltt)) + lft
        return DhcpLeaseRecord(
            ip=ip,
            mac_address=mac,
            hostname=_first_value(lowered, _LEASE_HOSTNAME_KEYS),
            lease_expires_at=expires,
            subnet_id=_first_value(lowered, _LEASE_SUBNET_KEYS) or subnet_id,
            client_id=_first_value(lowered, _LEASE_CLIENT_ID_KEYS),
        )

    @classmethod
    def _iter_lease_rows(cls, data: Any) -> Iterator[tuple[Optional[str], Mapping[str, Any]]]:
        if isinstance(data, Mapping):
            lowered_keys = {str(k).strip().lower() for k in data}
            if isinstance(data.get("arguments"), Mapping):
                yield from cls._iter_lease_rows(data["arguments"])
            elif "leases" in data:
                yield from cls._iter_lease_rows(data["leases"])
            elif lowered_keys & set(_LEASE_IP_KEYS):
                yield None, data
            else:
                for key, value in data.items():
                    if isinstance(value, Mapping) and _is_ipv4(str(key).strip()):
                        yield str(key).strip(), value
        elif isinstance(data, Sequence) and not isinstance(data, (str, bytes)):
            for item in data:
                if isinstance(item, Mapping) and (
                    "arguments" in item or "leases" in item
                ):
                    yield from cls._iter_lease_rows(item)
                elif isinstance(item, Mapping):
                    yield None, item

    @classmethod
    def parse_json_dhcp_leases(
        cls,
        raw_data: str | Mapping[str, Any] | Sequence[Mapping[str, Any]],
        *,
        subnet_id: Optional[str] = None,
    ) -> list[DhcpLeaseRecord]:
        """Parse ISC / Kea DHCPv4 JSON lease exports and generic JSON lease lists."""
        data: Any = raw_data
        if isinstance(raw_data, str):
            if not raw_data.strip():
                return []
            data = json.loads(raw_data)
        if not isinstance(data, (Mapping, Sequence)) or isinstance(data, bytes):
            raise ValueError("DHCP lease data must be a JSON string, mapping, or sequence")
        leases: list[DhcpLeaseRecord] = []
        for ip_hint, row in cls._iter_lease_rows(data):
            try:
                leases.append(cls._lease_from_row(row, ip_hint, subnet_id))
            except (ValueError, TypeError):
                continue
        return leases

    @classmethod
    def parse_csv_dhcp_leases(
        cls, raw_csv: str, *, subnet_id: Optional[str] = None
    ) -> list[DhcpLeaseRecord]:
        """Parse CSV DHCP lease exports with (case-insensitive) header columns."""
        if not isinstance(raw_csv, str):
            raise ValueError("raw_csv must be a string")
        lines = [
            line
            for line in raw_csv.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        leases: list[DhcpLeaseRecord] = []
        for row in csv.DictReader(io.StringIO("\n".join(lines))):
            cleaned = {
                k: (v.strip() if isinstance(v, str) else v)
                for k, v in row.items()
                if k is not None
            }
            try:
                leases.append(cls._lease_from_row(cleaned, None, subnet_id))
            except (ValueError, TypeError):
                continue
        return leases

    @staticmethod
    def parse_isc_dhcpd_leases(
        raw_text: str, *, subnet_id: Optional[str] = None
    ) -> list[DhcpLeaseRecord]:
        """Parse ISC ``dhcpd.leases`` text blocks (``lease <ip> { ... }``)."""
        if not isinstance(raw_text, str):
            raise ValueError("raw_text must be a string")
        leases: list[DhcpLeaseRecord] = []
        for match in _ISC_LEASE_BLOCK_RE.finditer(raw_text):
            fields: dict[str, Optional[str]] = {}
            for stmt_match in _ISC_STATEMENT_RE.finditer(match.group(2)):
                statement = stmt_match.group(1).strip()
                parts = statement.split(None, 1)
                if len(parts) < 2:
                    continue
                keyword, rest = parts[0].lower(), parts[1].strip()
                if keyword == "ends":
                    fields["ends"] = re.sub(r"^(?:\d\s+|epoch\s+)", "", rest)
                elif keyword == "hardware":
                    fields["mac"] = rest.split()[-1]
                elif keyword == "client-hostname":
                    fields["hostname"] = rest.strip('"')
                elif keyword == "uid":
                    fields["client_id"] = rest.strip('"')
            try:
                leases.append(
                    DhcpLeaseRecord(
                        ip=match.group(1),
                        mac_address=fields.get("mac"),
                        hostname=fields.get("hostname"),
                        lease_expires_at=fields.get("ends"),
                        subnet_id=subnet_id,
                        client_id=fields.get("client_id"),
                    )
                )
            except ValueError:
                continue
        return leases

    @classmethod
    def parse_dhcp_leases(
        cls,
        raw_data: str | Mapping[str, Any] | Sequence[Mapping[str, Any]],
        *,
        subnet_id: Optional[str] = None,
    ) -> list[DhcpLeaseRecord]:
        """Detect the lease format (JSON, ISC, CSV or dnsmasq) and parse it."""
        if not isinstance(raw_data, str):
            return cls.parse_json_dhcp_leases(raw_data, subnet_id=subnet_id)
        text = raw_data.strip()
        if not text:
            return []
        if text[0] in "{[":
            return cls.parse_json_dhcp_leases(text, subnet_id=subnet_id)
        if _ISC_LEASE_START_RE.search(text):
            return cls.parse_isc_dhcpd_leases(text, subnet_id=subnet_id)
        first_line = next(
            (
                line
                for line in text.splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ),
            "",
        )
        if "," in first_line:
            return cls.parse_csv_dhcp_leases(text, subnet_id=subnet_id)
        return cls.parse_dnsmasq_leases(text, subnet_id=subnet_id)
