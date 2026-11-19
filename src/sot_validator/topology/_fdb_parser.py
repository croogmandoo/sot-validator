"""Multi-dialect switch CLI / SNMP Q-BRIDGE-MIB / JSON FDB table parser."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import json
from typing import Any, Optional

from sot_validator.models import _require_non_empty_str
from sot_validator.topology._fdb_records import (
    FdbEntry,
    _BRIDGE_FDB_OID_PATTERN,
    _PAREN_VLAN_PATTERN,
    _QBRIDGE_FDB_OID_PATTERN,
    _VLAN_SUFFIX_PATTERN,
    _VOSS_PORT_PREFIX_PATTERN,
    _deduplicate_entries,
    _is_ignored_port_token,
    _looks_like_port_name,
    _normalize_vlan_id,
    _normalize_voss_port_name,
    _parse_mac_token,
    _parse_static_flag,
)
from sot_validator.topology.device_types import normalize_mac_address


class FdbTableParser:
    """Multi-dialect parser for switch CLI FDB outputs and SNMP Q-BRIDGE-MIB / JSON records."""

    def parse_exos(self, text: str, *, device_id: str) -> list[FdbEntry]:
        """Parse ExtremeXOS `show fdb` CLI output into normalized FdbEntry records."""
        _require_non_empty_str(device_id, "device_id")
        if not isinstance(text, str) or not text.strip():
            return []

        entries: list[FdbEntry] = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith(("-", "=", "#", "Mac", "MAC", "Flags", "Total")):
                continue
            tokens = line.split()
            if len(tokens) < 3:
                continue

            norm_mac = _parse_mac_token(tokens[0])
            if norm_mac is None:
                continue

            port_candidate = tokens[-1]
            if _is_ignored_port_token(port_candidate) or not _looks_like_port_name(
                port_candidate
            ):
                continue

            # Extract VLAN ID from second token (or combined VLAN name + `(0010)`)
            vlan_id: Optional[str] = None
            m_paren = _PAREN_VLAN_PATTERN.search(line)
            if m_paren:
                vlan_id = _normalize_vlan_id(m_paren.group(1))
            else:
                vlan_id = _normalize_vlan_id(tokens[1])

            # Inspect middle flag tokens for static ('s', 'sp', 'static', 'permanent')
            middle_tokens = [t.lower() for t in tokens[2:-1]]
            is_static = any(
                t in ("s", "sp", "static", "permanent", "mgmt")
                for t in middle_tokens
            )

            entries.append(
                FdbEntry(
                    device_id=device_id,
                    port_name=port_candidate,
                    mac_address=norm_mac,
                    vlan_id=vlan_id,
                    is_static=is_static,
                )
            )

        return _deduplicate_entries(entries)

    def parse_voss(self, text: str, *, device_id: str) -> list[FdbEntry]:
        """Parse Extreme VOSS `show mac-address-table` / `show vlan mac-address-entry` CLI output."""
        _require_non_empty_str(device_id, "device_id")
        if not isinstance(text, str) or not text.strip():
            return []

        entries: list[FdbEntry] = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith(("-", "=", "#", "Vlan", "VLAN", "Mac", "MAC", "Total")):
                continue
            tokens = line.split()
            if len(tokens) < 3:
                continue

            mac_idx: Optional[int] = None
            norm_mac: Optional[str] = None
            for idx, tok in enumerate(tokens):
                cand = _parse_mac_token(tok)
                if cand is not None:
                    mac_idx = idx
                    norm_mac = cand
                    break

            if norm_mac is None or mac_idx is None:
                continue

            vlan_id: Optional[str] = None
            port_name: Optional[str] = None
            is_static = False

            for idx, tok in enumerate(tokens):
                if idx == mac_idx:
                    continue
                tok_lower = tok.lower()
                if tok_lower in ("static", "permanent", "mgmt"):
                    is_static = True
                    continue
                if tok_lower in ("dynamic", "learned", "age", "aged", "true", "false"):
                    continue

                if (
                    vlan_id is None
                    and (idx < mac_idx or (idx == mac_idx + 1 and tok.isdigit()))
                    and (tok.isdigit() or _VLAN_SUFFIX_PATTERN.match(tok))
                ):
                    vlan_id = _normalize_vlan_id(tok)
                    continue

                if port_name is None and _looks_like_port_name(tok):
                    port_name = _normalize_voss_port_name(tok)

            if port_name is None or _is_ignored_port_token(port_name):
                continue

            entries.append(
                FdbEntry(
                    device_id=device_id,
                    port_name=port_name,
                    mac_address=norm_mac,
                    vlan_id=vlan_id,
                    is_static=is_static,
                )
            )

        return _deduplicate_entries(entries)

    def parse_cisco(self, text: str, *, device_id: str) -> list[FdbEntry]:
        """Parse Cisco IOS / generic `show mac address-table` CLI output."""
        _require_non_empty_str(device_id, "device_id")
        if not isinstance(text, str) or not text.strip():
            return []

        entries: list[FdbEntry] = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith(
                ("-", "=", "#", "Vlan", "VLAN", "Mac", "MAC", "Total", "All")
            ):
                continue
            tokens = [t for t in line.split() if t not in ("*", "+", "G", "R", "O")]
            if len(tokens) < 3:
                continue

            mac_idx: Optional[int] = None
            norm_mac: Optional[str] = None
            for idx, tok in enumerate(tokens):
                cand = _parse_mac_token(tok)
                if cand is not None:
                    mac_idx = idx
                    norm_mac = cand
                    break

            if norm_mac is None or mac_idx is None:
                continue

            port_candidate = tokens[-1]
            if _is_ignored_port_token(port_candidate) or not _looks_like_port_name(
                port_candidate
            ):
                continue

            vlan_id: Optional[str] = None
            if mac_idx > 0:
                vlan_id = _normalize_vlan_id(tokens[0])

            middle_tokens = [t.lower() for t in tokens[mac_idx + 1 : -1]]
            is_static = any(
                t in ("static", "permanent", "s", "mgmt") for t in middle_tokens
            )

            entries.append(
                FdbEntry(
                    device_id=device_id,
                    port_name=port_candidate,
                    mac_address=norm_mac,
                    vlan_id=vlan_id,
                    is_static=is_static,
                )
            )

        return _deduplicate_entries(entries)

    def parse_cli(
        self,
        text: str,
        *,
        device_id: str,
        dialect: str = "auto",
    ) -> list[FdbEntry]:
        """Parse CLI FDB output across `exos`, `voss`, `cisco`, or `auto` dialects."""
        _require_non_empty_str(device_id, "device_id")
        norm_dialect = (dialect or "auto").strip().lower()
        if norm_dialect not in ("auto", "exos", "voss", "cisco"):
            raise ValueError(
                f"Unsupported FDB CLI dialect {dialect!r}; must be one of ('auto', 'exos', 'voss', 'cisco')"
            )

        if norm_dialect == "exos":
            return self.parse_exos(text, device_id=device_id)
        if norm_dialect == "voss":
            return self.parse_voss(text, device_id=device_id)
        if norm_dialect == "cisco":
            return self.parse_cisco(text, device_id=device_id)

        if not isinstance(text, str) or not text.strip():
            return []

        combined: list[FdbEntry] = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            # Check EXOS pattern first (starts with MAC and has paren VLAN or EXOS port N:M)
            tokens = line.split()
            if tokens and _parse_mac_token(tokens[0]) is not None:
                if _PAREN_VLAN_PATTERN.search(line) or (
                    len(tokens) >= 4 and ":" in tokens[-1]
                ):
                    parsed = self.parse_exos(line, device_id=device_id)
                    if parsed:
                        combined.extend(parsed)
                        continue
                parsed_voss = self.parse_voss(line, device_id=device_id)
                if parsed_voss:
                    combined.extend(parsed_voss)
                    continue
                parsed_exos = self.parse_exos(line, device_id=device_id)
                if parsed_exos:
                    combined.extend(parsed_exos)
                    continue

            # Check VOSS vs Cisco
            if any(_VOSS_PORT_PREFIX_PATTERN.match(t) for t in tokens) or any(
                t.lower() in ("learned",) for t in tokens
            ):
                parsed = self.parse_voss(line, device_id=device_id)
                if parsed:
                    combined.extend(parsed)
                    continue

            parsed_cisco = self.parse_cisco(line, device_id=device_id)
            if parsed_cisco:
                combined.extend(parsed_cisco)
                continue

            parsed_voss = self.parse_voss(line, device_id=device_id)
            if parsed_voss:
                combined.extend(parsed_voss)

        return _deduplicate_entries(combined)

    def parse_qbridge_mib(
        self,
        data: str | Sequence[Mapping[str, Any]] | Mapping[str, Any],
        *,
        device_id: Optional[str] = None,
        port_index_map: Optional[Mapping[int | str, str]] = None,
    ) -> list[FdbEntry]:
        """Parse SNMP Q-BRIDGE-MIB / BRIDGE-MIB OID tables or JSON record lists into FdbEntry records."""
        parsed_data: Any = data
        if isinstance(data, str):
            stripped = data.strip()
            if not stripped:
                return []
            parsed_data = json.loads(stripped)

        resolved_port_map: dict[str, str] = {}
        if port_index_map:
            for k, v in port_index_map.items():
                if v is not None and str(v).strip():
                    resolved_port_map[str(k).strip()] = str(v).strip()

        def resolve_port_name(raw_port: Any) -> Optional[str]:
            if raw_port is None or isinstance(raw_port, bool):
                return None
            key = str(raw_port).strip()
            if not key or key == "0":
                return None
            if key in resolved_port_map:
                return resolved_port_map[key]
            return _normalize_voss_port_name(key)

        entries: list[FdbEntry] = []

        if isinstance(parsed_data, Mapping):
            # Wrapper dict with entries/fdb/records list
            record_list: Optional[Sequence[Any]] = None
            for list_key in ("entries", "fdb", "records", "items", "data"):
                if isinstance(parsed_data.get(list_key), Sequence) and not isinstance(
                    parsed_data.get(list_key), (str, bytes)
                ):
                    record_list = parsed_data[list_key]
                    break

            default_dev_id = (
                device_id
                or parsed_data.get("device_id")
                or parsed_data.get("switch_id")
            )

            if record_list is not None:
                return self.parse_qbridge_mib(
                    record_list,
                    device_id=str(default_dev_id) if default_dev_id else None,
                    port_index_map=port_index_map,
                )

            # Single record dict vs OID-keyed mapping
            if any(
                k in parsed_data
                for k in (
                    "mac_address",
                    "mac",
                    "dot1qTpFdbAddress",
                    "dot1dTpFdbAddress",
                )
            ):
                return self.parse_qbridge_mib(
                    [parsed_data],
                    device_id=device_id,
                    port_index_map=port_index_map,
                )

            # OID-keyed mapping: { "<oid>": <bridge_port_or_dict>, ... }
            if not default_dev_id:
                raise ValueError(
                    "device_id is required when parsing OID-keyed Q-BRIDGE-MIB mappings"
                )
            dev_id_str = str(default_dev_id).strip()

            for oid_key, raw_val in parsed_data.items():
                oid_str = str(oid_key).strip()
                vlan_id: Optional[str] = None
                octets: Optional[tuple[int, ...]] = None

                m_q = _QBRIDGE_FDB_OID_PATTERN.match(oid_str)
                if m_q:
                    vlan_id = _normalize_vlan_id(m_q.group(1))
                    octets = tuple(int(m_q.group(i)) for i in range(2, 8))
                else:
                    m_b = _BRIDGE_FDB_OID_PATTERN.match(oid_str)
                    if m_b:
                        octets = tuple(int(m_b.group(i)) for i in range(1, 7))

                if octets is None or any(o < 0 or o > 255 for o in octets):
                    continue

                mac_str = ":".join(f"{o:02x}" for o in octets)
                is_static = False
                if isinstance(raw_val, Mapping):
                    raw_port = (
                        raw_val.get("port_name")
                        or raw_val.get("port")
                        or raw_val.get("bridge_port")
                        or raw_val.get("dot1qTpFdbPort")
                        or raw_val.get("dot1dTpFdbPort")
                    )
                    status_val = raw_val.get("status", raw_val.get("is_static", False))
                    is_static = _parse_static_flag(status_val)
                    if raw_val.get("vlan_id") is not None:
                        vlan_id = _normalize_vlan_id(raw_val.get("vlan_id"))
                else:
                    raw_port = raw_val

                port_name = resolve_port_name(raw_port)
                if not port_name or _is_ignored_port_token(port_name):
                    continue

                entries.append(
                    FdbEntry(
                        device_id=dev_id_str,
                        port_name=port_name,
                        mac_address=mac_str,
                        vlan_id=vlan_id,
                        is_static=is_static,
                    )
                )

            return _deduplicate_entries(entries)

        if isinstance(parsed_data, Sequence) and not isinstance(
            parsed_data, (str, bytes)
        ):
            for item in parsed_data:
                if not isinstance(item, Mapping):
                    continue
                rec_dev_id = (
                    item.get("device_id")
                    or item.get("switch_id")
                    or device_id
                )
                if not rec_dev_id or not str(rec_dev_id).strip():
                    raise ValueError(
                        "Each Q-BRIDGE-MIB record must provide device_id or pass device_id to parse_qbridge_mib"
                    )

                raw_mac = (
                    item.get("mac_address")
                    or item.get("mac")
                    or item.get("dot1qTpFdbAddress")
                    or item.get("dot1dTpFdbAddress")
                )
                if raw_mac is None:
                    continue

                raw_port = (
                    item.get("port_name")
                    or item.get("port")
                    or item.get("interface")
                    or item.get("bridge_port")
                    or item.get("dot1qTpFdbPort")
                    or item.get("dot1dTpFdbPort")
                )
                port_name = resolve_port_name(raw_port)
                if not port_name or _is_ignored_port_token(port_name):
                    continue

                raw_vlan = (
                    item.get("vlan_id")
                    if item.get("vlan_id") is not None
                    else (
                        item.get("vlan")
                        if item.get("vlan") is not None
                        else item.get("fdb_id")
                    )
                )
                vlan_id = _normalize_vlan_id(raw_vlan)

                if "is_static" in item:
                    is_static = _parse_static_flag(item["is_static"])
                else:
                    status_val = item.get(
                        "status",
                        item.get("dot1qTpFdbStatus", item.get("dot1dTpFdbStatus")),
                    )
                    is_static = _parse_static_flag(status_val)

                entries.append(
                    FdbEntry(
                        device_id=str(rec_dev_id).strip(),
                        port_name=port_name,
                        mac_address=normalize_mac_address(str(raw_mac)),
                        vlan_id=vlan_id,
                        is_static=is_static,
                    )
                )

            return _deduplicate_entries(entries)

        raise ValueError("Unsupported Q-BRIDGE-MIB input format")
