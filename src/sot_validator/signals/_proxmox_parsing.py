"""Proxmox VE / Docker MAC, IP, guest-type and state parsing and normalisation helpers."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import ipaddress
import re
from typing import Any, Optional

PROXMOX_MAC_OUI: str = "bc:24:11"

_MAC_COLON_RE = re.compile(
    r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}(?![0-9a-fA-F])"
)
_MAC_DOT_RE = re.compile(
    r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}(?![0-9a-fA-F])"
)
_HWADDR_KV_RE = re.compile(
    r"(?:hwaddr|macaddr|mac|virtio|e1000|vmxnet3|rtl8139)=((?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})",
    re.IGNORECASE,
)
_IP_KV_RE = re.compile(
    r"(?:^|,|\s)(?:ip|ip6|inet|inet6)=([^,\s]+)",
    re.IGNORECASE,
)
_NON_IP_PLACEHOLDERS: frozenset[str] = frozenset(
    {
        "dhcp",
        "dhcp6",
        "manual",
        "auto",
        "none",
        "unknown",
        "n/a",
        "-",
    }
)


def _require_non_empty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


def _clean_optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned if cleaned else None
    text = str(value).strip()
    return text if text else None


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value.split("/", 1)[0])
    except ValueError:
        return False
    return True


def normalize_mac_address(mac: Optional[str]) -> Optional[str]:
    """Normalize a MAC address string (or Proxmox net config string) to lowercase aa:bb:cc:dd:ee:ff."""
    if not isinstance(mac, str):
        return None
    cleaned = mac.strip()
    if not cleaned:
        return None

    kv_match = _HWADDR_KV_RE.search(cleaned)
    if kv_match:
        cleaned = kv_match.group(1)
    else:
        colon_match = _MAC_COLON_RE.search(cleaned)
        if colon_match:
            cleaned = colon_match.group(0)
        else:
            dot_match = _MAC_DOT_RE.search(cleaned)
            if dot_match:
                cleaned = dot_match.group(0)
            elif "." in cleaned or _is_ip_literal(cleaned):
                # Bare-hex fallback must not read IPv4/IPv6 addresses as MACs.
                return None

    hex_only = "".join(ch for ch in cleaned.lower() if ch not in (":", "-", "."))
    if len(hex_only) == 12 and all(c in "0123456789abcdef" for c in hex_only):
        return ":".join(hex_only[i : i + 2] for i in range(0, 12, 2))
    return None


def extract_mac_addresses(value: Any) -> list[str]:
    """Extract and deduplicate normalized MAC addresses from strings, lists, or Proxmox config strings."""
    result: list[str] = []

    def _add(raw: Optional[str]) -> None:
        if not raw:
            return
        for match in _MAC_COLON_RE.findall(raw):
            norm = normalize_mac_address(match)
            if norm and norm not in result:
                result.append(norm)
        for match in _MAC_DOT_RE.findall(raw):
            norm = normalize_mac_address(match)
            if norm and norm not in result:
                result.append(norm)
        norm_direct = normalize_mac_address(raw)
        if norm_direct and norm_direct not in result:
            result.append(norm_direct)

    if value is None:
        return result
    if isinstance(value, str):
        _add(value)
        return result
    if isinstance(value, Mapping):
        for k, v in value.items():
            if isinstance(k, str) and (
                k.lower() in ("hwaddr", "mac", "mac_address", "macaddr", "hardware-address", "hardware_address")
                or k.lower().startswith("net")
            ):
                for m in extract_mac_addresses(v):
                    if m not in result:
                        result.append(m)
        return result
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray)):
        for item in value:
            for m in extract_mac_addresses(item):
                if m not in result:
                    result.append(m)
        return result
    return result


def is_proxmox_mac(mac: Optional[str]) -> bool:
    """Return True when mac normalizes to a valid 12-hex-digit MAC with Proxmox OUI bc:24:11."""
    norm = normalize_mac_address(mac)
    if norm is None:
        return False
    return norm.startswith(PROXMOX_MAC_OUI + ":")


def normalize_ip_address(ip: Optional[str]) -> Optional[str]:
    """Normalize an IPv4/IPv6 address or CIDR string, ignoring loopback and non-IP placeholders."""
    if not isinstance(ip, str):
        return None
    cleaned = ip.strip()
    if not cleaned:
        return None

    kv_match = _IP_KV_RE.search(cleaned)
    if kv_match and "=" in cleaned:
        cleaned = kv_match.group(1).strip()

    if "/" in cleaned:
        cleaned = cleaned.split("/", 1)[0].strip()

    if "%" in cleaned:
        cleaned = cleaned.split("%", 1)[0].strip()

    if not cleaned or cleaned.lower() in _NON_IP_PLACEHOLDERS:
        return None

    try:
        addr = ipaddress.ip_address(cleaned)
    except ValueError:
        return None

    if addr.is_loopback or addr.is_unspecified or addr.is_link_local:
        return None

    return str(addr)


def extract_ip_addresses(value: Any) -> list[str]:
    """Extract and deduplicate normalized IPv4/IPv6 addresses from strings, lists, or config strings."""
    result: list[str] = []

    def _add(raw: Optional[str]) -> None:
        if not raw:
            return
        for match in _IP_KV_RE.findall(raw):
            norm = normalize_ip_address(match)
            if norm and norm not in result:
                result.append(norm)
        for token in re.split(r"[,;\s]+", raw.strip()):
            if not token or "=" in token:
                continue
            norm = normalize_ip_address(token)
            if norm and norm not in result:
                result.append(norm)

    if value is None:
        return result
    if isinstance(value, str):
        _add(value)
        return result
    if isinstance(value, Mapping):
        for k, v in value.items():
            if not isinstance(k, str):
                continue
            kl = k.lower()
            if kl in (
                "ip",
                "ip6",
                "inet",
                "inet6",
                "ip_address",
                "ip-address",
                "ip_addresses",
                "ip-addresses",
                "ipaddress",
                "ips",
                "primary_ip",
            ) or kl.startswith("net"):
                for ip_str in extract_ip_addresses(v):
                    if ip_str not in result:
                        result.append(ip_str)
        return result
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray)):
        for item in value:
            for ip_str in extract_ip_addresses(item):
                if ip_str not in result:
                    result.append(ip_str)
        return result
    return result


def normalize_proxmox_guest_type(value: Any) -> str:
    """Normalize a Proxmox guest type to 'qemu' or 'lxc'."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Unsupported Proxmox guest_type: {value!r}")
    token = value.strip().lower()
    if token in ("qemu", "kvm", "vm"):
        return "qemu"
    if token in ("lxc", "ct", "container"):
        return "lxc"
    raise ValueError(f"Unsupported Proxmox guest_type: {value!r}")


def normalize_proxmox_guest_status(value: Any) -> str:
    """Normalize a Proxmox guest runtime status to 'running', 'stopped', or 'paused'."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Unsupported Proxmox guest status: {value!r}")
    token = value.strip().lower()
    if token in ("running", "online", "active", "up", "started", "on", "powered_on", "poweredon"):
        return "running"
    if token in (
        "stopped",
        "offline",
        "down",
        "halted",
        "shutoff",
        "shut_off",
        "exited",
        "off",
        "powered_off",
        "poweredoff",
    ):
        return "stopped"
    if token in ("paused", "suspended", "suspend", "prelaunch"):
        return "paused"
    raise ValueError(f"Unsupported Proxmox guest status: {value!r}")


def normalize_container_state(value: Any) -> str:
    """Normalize a Docker / Portainer container state to 'running', 'exited', or 'paused'."""
    if isinstance(value, Mapping):
        raw_status = value.get("Status") or value.get("status")
        if raw_status is not None:
            return normalize_container_state(raw_status)
        if value.get("Running") is True or value.get("running") is True:
            return "running"
        if value.get("Paused") is True or value.get("paused") is True:
            return "paused"
        return "exited"

    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Unsupported container state: {value!r}")
    token = value.strip().lower()
    if token in ("running", "up", "healthy", "active", "restarting", "starting", "online"):
        return "running"
    if token in (
        "exited",
        "stopped",
        "dead",
        "created",
        "removing",
        "down",
        "inactive",
        "offline",
        "halted",
    ):
        return "exited"
    if token in ("paused", "suspended", "suspend"):
        return "paused"
    if token.startswith("up "):
        return "running"
    if token.startswith("exited ") or token.startswith("dead"):
        return "exited"
    raise ValueError(f"Unsupported container state: {value!r}")


def _parse_tags(value: Any) -> list[str]:
    if value is None:
        return []
    tags: list[str] = []
    if isinstance(value, str):
        for part in re.split(r"[;,\s]+", value.strip()):
            cleaned = part.strip()
            if cleaned and cleaned not in tags:
                tags.append(cleaned)
        return tags
    if isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray, Mapping)):
        for item in value:
            for sub in _parse_tags(item):
                if sub not in tags:
                    tags.append(sub)
        return tags
    cleaned = _clean_optional_str(value)
    if cleaned:
        tags.append(cleaned)
    return tags


def _coerce_positive_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be a positive integer")
    if isinstance(value, int):
        num = value
    elif isinstance(value, str):
        cleaned = value.strip()
        if "/" in cleaned:
            cleaned = cleaned.rsplit("/", 1)[-1].strip()
        if not cleaned.isdigit():
            raise ValueError(f"{field_name} must be a positive integer, got {value!r}")
        num = int(cleaned)
    else:
        raise ValueError(f"{field_name} must be a positive integer, got {value!r}")
    if num <= 0:
        raise ValueError(f"{field_name} must be a positive integer, got {value!r}")
    return num


def _coerce_optional_non_negative_int(value: Any, field_name: str) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be a non-negative integer")
    if isinstance(value, (int, float)):
        num = int(value)
    elif isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            return None
        try:
            num = int(float(cleaned))
        except ValueError as exc:
            raise ValueError(f"{field_name} must be a non-negative integer, got {value!r}") from exc
    else:
        raise ValueError(f"{field_name} must be a non-negative integer, got {value!r}")
    if num < 0:
        raise ValueError(f"{field_name} must be a non-negative integer, got {value!r}")
    return num


def _parse_interface_payload(payload: Any) -> tuple[list[str], list[str]]:
    """Extract (ip_addresses, mac_addresses) from Proxmox QEMU agent or LXC interface payloads."""
    ips: list[str] = []
    macs: list[str] = []

    def _add_ip(val: Any) -> None:
        for ip_str in extract_ip_addresses(val):
            if ip_str not in ips:
                ips.append(ip_str)

    def _add_mac(val: Any) -> None:
        for mac_str in extract_mac_addresses(val):
            if mac_str not in macs:
                macs.append(mac_str)

    if payload is None:
        return ips, macs

    if isinstance(payload, str):
        _add_ip(payload)
        _add_mac(payload)
        return ips, macs

    if isinstance(payload, Mapping):
        if "data" in payload:
            sub_ips, sub_macs = _parse_interface_payload(payload["data"])
            for i in sub_ips:
                if i not in ips:
                    ips.append(i)
            for m in sub_macs:
                if m not in macs:
                    macs.append(m)
        if "result" in payload:
            sub_ips, sub_macs = _parse_interface_payload(payload["result"])
            for i in sub_ips:
                if i not in ips:
                    ips.append(i)
            for m in sub_macs:
                if m not in macs:
                    macs.append(m)

        iface_name = _clean_optional_str(payload.get("name"))
        if iface_name and iface_name.lower() == "lo":
            return ips, macs

        for mac_key in ("hardware-address", "hardware_address", "hwaddr", "mac", "mac_address", "macaddr"):
            if mac_key in payload:
                _add_mac(payload[mac_key])

        for ip_key in ("ip-addresses", "ip_addresses", "ip-address", "ip_address", "inet", "inet6", "ip", "ip6", "ips"):
            if ip_key in payload:
                val = payload[ip_key]
                if isinstance(val, Iterable) and not isinstance(val, (str, bytes, bytearray, Mapping)):
                    for entry in val:
                        if isinstance(entry, Mapping):
                            _add_ip(entry.get("ip-address") or entry.get("ip_address") or entry.get("ip") or entry.get("inet"))
                        else:
                            _add_ip(entry)
                else:
                    _add_ip(val)

        for k, v in payload.items():
            if isinstance(k, str) and k.lower().startswith("net"):
                _add_ip(v)
                _add_mac(v)
            elif isinstance(v, (Mapping, list, tuple)) and k not in ("data", "result", "ip-addresses", "ip_addresses"):
                sub_ips, sub_macs = _parse_interface_payload(v)
                for i in sub_ips:
                    if i not in ips:
                        ips.append(i)
                for m in sub_macs:
                    if m not in macs:
                        macs.append(m)

        return ips, macs

    if isinstance(payload, Iterable) and not isinstance(payload, (bytes, bytearray)):
        for item in payload:
            sub_ips, sub_macs = _parse_interface_payload(item)
            for i in sub_ips:
                if i not in ips:
                    ips.append(i)
            for m in sub_macs:
                if m not in macs:
                    macs.append(m)

    return ips, macs
