"""NetworkRoleIdentifier: heuristic host role, router consolidation and VLAN/subnet inference."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Optional

from sot_validator.models import (
    Subnet,
    VLAN,
    _require_non_empty_str,
)
from sot_validator.topology._identifier_helpers import (
    KNOWN_OUI_VENDORS,
    _extract_oui_prefix,
    _hostname_tokens,
    _infer_subnet_cidr,
    _infer_vlan_id,
    _matches_hostname,
    _normalize_optional_mac,
    _parse_ipv4_octets,
)
from sot_validator.topology._identifier_models import (
    ConsolidatedRouter,
    HostIdentification,
)

class NetworkRoleIdentifier:
    """Heuristic classifier for routers, switches, VLANs, hypervisors, and network hosts."""

    def __init__(
        self,
        oui_vendors: Optional[Mapping[str, tuple[str, str]]] = None,
    ) -> None:
        self.oui_vendors: dict[str, tuple[str, str]] = dict(KNOWN_OUI_VENDORS)
        if oui_vendors:
            for k, v in oui_vendors.items():
                self.oui_vendors[k.strip().lower()] = v

    def identify_host(
        self,
        ip: str,
        *,
        mac: Optional[str] = None,
        hostname: Optional[str] = None,
        open_ports: Sequence[int] = (),
        subnet_cidr: Optional[str] = None,
        vlan_id: Optional[str] = None,
        peer_gateway_ips: Sequence[str] = (),
    ) -> HostIdentification:
        """Classify a single host observation into one of VALID_HOST_ROLES."""
        _require_non_empty_str(ip, "ip")
        cleaned_ip = ip.strip()
        octets = _parse_ipv4_octets(cleaned_ip)
        is_gateway_ip = octets is not None and octets[3] in (1, 254)

        resolved_cidr = _infer_subnet_cidr(cleaned_ip, subnet_cidr)
        resolved_vlan = _infer_vlan_id(cleaned_ip, vlan_id, resolved_cidr)

        norm_mac = _normalize_optional_mac(mac)
        oui = _extract_oui_prefix(norm_mac)
        vendor: Optional[str] = None
        oui_role_hint: Optional[str] = None
        if oui and oui in self.oui_vendors:
            vendor, oui_role_hint = self.oui_vendors[oui]

        ports_list = sorted({int(p) for p in open_ports})
        ports_set = set(ports_list)
        hostname_lower, host_tokens = _hostname_tokens(hostname)
        peer_gateways = [
            p.strip()
            for p in peer_gateway_ips
            if isinstance(p, str) and p.strip() and p.strip() != cleaned_ip
        ]

        reasons: list[str] = []
        role: str = "workstation_server"
        confidence: float = 0.5
        suggested_template_id: Optional[str] = None

        router_host_match = _matches_hostname(
            hostname_lower,
            host_tokens,
            exact_tokens=("gw", "rtr", "udm", "edge"),
            substrings=("router", "unifi", "gateway"),
        )
        switch_host_match = _matches_hostname(
            hostname_lower,
            host_tokens,
            exact_tokens=("sw", "idf", "mdf"),
            substrings=("switch", "exos", "voss", "core-sw"),
        )
        hypervisor_host_match = _matches_hostname(
            hostname_lower,
            host_tokens,
            exact_tokens=("pve", "hv"),
            substrings=("proxmox", "esxi", "hyperv"),
        )
        automation_host_match = _matches_hostname(
            hostname_lower,
            host_tokens,
            exact_tokens=("hass",),
            substrings=("homeassistant", "hubitat"),
        )
        nas_host_match = _matches_hostname(
            hostname_lower,
            host_tokens,
            exact_tokens=("nas", "san"),
            substrings=("synology", "qnap", "truenas"),
        )
        dns_host_match = _matches_hostname(
            hostname_lower,
            host_tokens,
            exact_tokens=("dns", "ns", "ns1", "ns2"),
            substrings=("pihole", "adguard"),
        )
        iot_host_match = _matches_hostname(
            hostname_lower,
            host_tokens,
            exact_tokens=("ups", "apc", "iot"),
            substrings=("ecobee", "thermostat", "camera"),
        )

        has_non_router_specialist_signature = (
            oui_role_hint in ("switch", "hypervisor", "iot_device")
            or bool(
                switch_host_match
                or hypervisor_host_match
                or automation_host_match
                or nas_host_match
                or iot_host_match
            )
            or bool(ports_set & {8006, 8123, 5000})
        )
        has_strong_router_signature = (
            oui_role_hint == "router"
            or bool(router_host_match)
            or bool(peer_gateways)
        )

        # 1. Gateway / Multi-VLAN Router heuristics
        if has_strong_router_signature or (
            is_gateway_ip and not has_non_router_specialist_signature
        ):
            role = "router"
            suggested_template_id = "unifi-multi-vlan-router"
            score = 0.65
            if is_gateway_ip:
                reasons.append(f"Gateway IP address ({cleaned_ip})")
                score += 0.1
            if peer_gateways:
                reasons.append(
                    f"Multi-VLAN gateway peer interfaces ({len(peer_gateways)} peer subnet(s))"
                )
                score += 0.1
            if oui_role_hint == "router":
                reasons.append(f"Router MAC OUI {oui} ({vendor})")
                score += 0.15
            if router_host_match:
                reasons.append(f"Router hostname pattern ({router_host_match!r})")
                score += 0.1
            if 53 in ports_set or (80 in ports_set and 443 in ports_set):
                reasons.append("Gateway DNS/management ports open")
                score += 0.05
            confidence = min(round(score, 2), 0.99)

        # 2. Switch heuristics
        elif oui_role_hint == "switch" or (
            switch_host_match
            and oui_role_hint is None
            and not (
                iot_host_match
                or hypervisor_host_match
                or automation_host_match
                or nas_host_match
            )
            and not (ports_set & {8006, 8123, 5000})
        ):
            role = "switch"
            if "voss" in hostname_lower or "core" in host_tokens or "core-sw" in hostname_lower:
                suggested_template_id = "extreme-voss-core"
            else:
                suggested_template_id = "extreme-exos-48p"
            score = 0.75
            if oui_role_hint == "switch":
                reasons.append(f"Switch MAC OUI {oui} ({vendor})")
                score += 0.15
            if switch_host_match:
                reasons.append(f"Switch hostname pattern ({switch_host_match!r})")
                score += 0.1
            confidence = min(round(score, 2), 0.99)

        # 3. Hypervisor heuristics
        elif 8006 in ports_set or oui_role_hint == "hypervisor" or hypervisor_host_match:
            role = "hypervisor"
            suggested_template_id = "proxmox-ve-host"
            score = 0.75
            if 8006 in ports_set:
                reasons.append("Proxmox web UI TCP port 8006 open")
                score += 0.15
            if oui_role_hint == "hypervisor":
                reasons.append(f"Hypervisor MAC OUI {oui} ({vendor})")
                score += 0.1
            if hypervisor_host_match:
                reasons.append(f"Hypervisor hostname pattern ({hypervisor_host_match!r})")
                score += 0.1
            confidence = min(round(score, 2), 0.99)

        # 4. Automation Hub heuristics
        elif 8123 in ports_set or automation_host_match:
            role = "automation_hub"
            score = 0.75
            if 8123 in ports_set:
                reasons.append("Home Assistant TCP port 8123 open")
                score += 0.15
            if automation_host_match:
                reasons.append(
                    f"Automation hub hostname pattern ({automation_host_match!r})"
                )
                score += 0.1
            confidence = min(round(score, 2), 0.99)

        # 5. NAS / Storage heuristics
        elif (
            5000 in ports_set
            or nas_host_match
            or (445 in ports_set and (5000 in ports_set or bool(nas_host_match)))
        ):
            role = "nas_storage"
            suggested_template_id = "generic-smb-nas"
            score = 0.75
            if 5000 in ports_set:
                reasons.append("NAS management TCP port 5000 open")
                score += 0.15
            if 445 in ports_set:
                reasons.append("SMB storage TCP port 445 open")
                score += 0.05
            if nas_host_match:
                reasons.append(f"NAS/storage hostname pattern ({nas_host_match!r})")
                score += 0.1
            confidence = min(round(score, 2), 0.99)

        # 6. DNS Server heuristics
        elif 53 in ports_set or dns_host_match:
            role = "dns_server"
            score = 0.75
            if 53 in ports_set:
                reasons.append("DNS service TCP port 53 open")
                score += 0.15
            if dns_host_match:
                reasons.append(f"DNS server hostname pattern ({dns_host_match!r})")
                score += 0.1
            confidence = min(round(score, 2), 0.99)

        # 7. IoT / Embedded / UPS heuristics
        elif oui_role_hint == "iot_device" or iot_host_match:
            role = "iot_device"
            score = 0.75
            if oui_role_hint == "iot_device":
                reasons.append(f"IoT/UPS MAC OUI {oui} ({vendor})")
                score += 0.15
            if iot_host_match:
                reasons.append(f"IoT/UPS hostname pattern ({iot_host_match!r})")
                score += 0.1
            if (
                oui == "00:c0:b7"
                or (vendor and "apc" in vendor.lower())
                or iot_host_match in ("ups", "apc")
                or "ups" in host_tokens
                or "apc" in host_tokens
            ):
                suggested_template_id = "apc-smart-ups"
            confidence = min(round(score, 2), 0.99)

        # 8. Default / Workstation or Server
        else:
            role = "workstation_server"
            if ports_list:
                reasons.append(
                    f"Standard workstation/server ports open ({', '.join(str(p) for p in ports_list)})"
                )
                confidence = 0.65
            else:
                reasons.append("Default host classification (no specialist role signature)")
                confidence = 0.5

        return HostIdentification(
            ip=cleaned_ip,
            role=role,
            confidence=confidence,
            mac=norm_mac,
            vendor=vendor,
            hostname=hostname.strip() if isinstance(hostname, str) and hostname.strip() else None,
            open_ports=ports_list,
            subnet_cidr=resolved_cidr,
            inferred_vlan_id=resolved_vlan,
            is_gateway_ip=is_gateway_ip,
            suggested_template_id=suggested_template_id,
            reasons=reasons,
        )

    def identify_hosts(
        self, observations: Sequence[Mapping[str, Any]]
    ) -> list[HostIdentification]:
        """Batch-classify host scan observations with cross-subnet gateway correlation."""
        gateway_candidates: list[tuple[int, str, Optional[int], Optional[str], Optional[str]]] = []

        for idx, obs in enumerate(observations):
            ip_raw = str(obs.get("ip", "")).strip()
            if not ip_raw:
                continue
            octets = _parse_ipv4_octets(ip_raw)
            host_octet = octets[3] if octets is not None else None
            norm_mac = _normalize_optional_mac(obs.get("mac"))
            oui = _extract_oui_prefix(norm_mac)
            oui_hint = self.oui_vendors.get(oui, (None, None))[1] if oui else None
            hostname_lower, host_tokens = _hostname_tokens(obs.get("hostname"))
            router_host = _matches_hostname(
                hostname_lower,
                host_tokens,
                exact_tokens=("gw", "rtr", "udm", "edge"),
                substrings=("router", "unifi", "gateway"),
            )
            if (
                (host_octet in (1, 254))
                or oui_hint == "router"
                or bool(router_host)
            ):
                gateway_candidates.append((idx, ip_raw, host_octet, norm_mac, oui))

        results: list[HostIdentification] = []
        for idx, obs in enumerate(observations):
            ip_raw = str(obs["ip"]).strip()
            explicit_peers = list(obs.get("peer_gateway_ips") or [])

            octets = _parse_ipv4_octets(ip_raw)
            host_octet = octets[3] if octets is not None else None
            norm_mac = _normalize_optional_mac(obs.get("mac"))
            oui = _extract_oui_prefix(norm_mac)

            inferred_peers: list[str] = list(explicit_peers)
            for cand_idx, cand_ip, cand_octet, cand_mac, cand_oui in gateway_candidates:
                if cand_idx == idx or cand_ip == ip_raw:
                    continue
                same_gateway_octet = (
                    host_octet in (1, 254) and cand_octet == host_octet
                )
                same_mac = bool(norm_mac and cand_mac and norm_mac == cand_mac)
                same_router_oui = bool(
                    oui and cand_oui and oui == cand_oui and oui in self.oui_vendors and self.oui_vendors[oui][1] == "router"
                )
                if same_gateway_octet or same_mac or same_router_oui:
                    if cand_ip not in inferred_peers:
                        inferred_peers.append(cand_ip)

            ident = self.identify_host(
                ip_raw,
                mac=obs.get("mac"),
                hostname=obs.get("hostname"),
                open_ports=obs.get("open_ports") or (),
                subnet_cidr=obs.get("subnet_cidr"),
                vlan_id=obs.get("vlan_id"),
                peer_gateway_ips=inferred_peers,
            )
            results.append(ident)

        return results

    def consolidate_multi_vlan_routers(
        self, identifications: Sequence[HostIdentification]
    ) -> list[ConsolidatedRouter]:
        """Group multi-VLAN router/gateway HostIdentifications into ConsolidatedRouter records."""
        router_items = [
            h for h in identifications if h.role == "router" or h.is_gateway_ip
        ]
        if not router_items:
            return []

        n = len(router_items)
        parent = list(range(n))

        def find(i: int) -> int:
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        def union(i: int, j: int) -> None:
            ri, rj = find(i), find(j)
            if ri != rj:
                if ri < rj:
                    parent[rj] = ri
                else:
                    parent[ri] = rj

        for i in range(n):
            hi = router_items[i]
            oct_i = _parse_ipv4_octets(hi.ip)
            host_oct_i = oct_i[3] if oct_i is not None else None
            oui_i = _extract_oui_prefix(hi.mac)
            host_i = hi.hostname.strip().lower() if hi.hostname else None

            for j in range(i + 1, n):
                hj = router_items[j]
                oct_j = _parse_ipv4_octets(hj.ip)
                host_oct_j = oct_j[3] if oct_j is not None else None
                oui_j = _extract_oui_prefix(hj.mac)
                host_j = hj.hostname.strip().lower() if hj.hostname else None

                same_ip = hi.ip == hj.ip
                same_mac = bool(hi.mac and hj.mac and hi.mac == hj.mac)
                same_hostname = bool(host_i and host_j and host_i == host_j)
                same_router_oui = bool(
                    oui_i
                    and oui_j
                    and oui_i == oui_j
                    and (
                        oui_i == "aa:9c:6c"
                        or (
                            oui_i in self.oui_vendors
                            and self.oui_vendors[oui_i][1] == "router"
                        )
                    )
                    and (hi.is_gateway_ip or hi.role == "router")
                    and (hj.is_gateway_ip or hj.role == "router")
                )
                same_gateway_octet_across_subnets = bool(
                    host_oct_i in (1, 254)
                    and host_oct_i == host_oct_j
                    and hi.subnet_cidr != hj.subnet_cidr
                )

                if (
                    same_ip
                    or same_mac
                    or same_hostname
                    or same_router_oui
                    or same_gateway_octet_across_subnets
                ):
                    union(i, j)

        groups: dict[int, list[HostIdentification]] = {}
        for idx, item in enumerate(router_items):
            root = find(idx)
            groups.setdefault(root, []).append(item)

        consolidated: list[ConsolidatedRouter] = []
        for group_num, members in enumerate(groups.values(), start=1):
            gateway_ips: list[str] = []
            mac_addresses: list[str] = []
            subnet_cidrs: list[str] = []
            vlan_ids: list[str] = []
            hostname: Optional[str] = None
            vendor: Optional[str] = None
            suggested_template_id = "unifi-multi-vlan-router"

            for m in members:
                if m.ip not in gateway_ips:
                    gateway_ips.append(m.ip)
                if m.mac and m.mac not in mac_addresses:
                    mac_addresses.append(m.mac)
                if m.subnet_cidr and m.subnet_cidr not in subnet_cidrs:
                    subnet_cidrs.append(m.subnet_cidr)
                if m.inferred_vlan_id and m.inferred_vlan_id not in vlan_ids:
                    vlan_ids.append(m.inferred_vlan_id)
                if hostname is None and m.hostname:
                    hostname = m.hostname
                if vendor is None and m.vendor:
                    vendor = m.vendor
                if m.suggested_template_id:
                    suggested_template_id = m.suggested_template_id

            consolidated.append(
                ConsolidatedRouter(
                    router_id=f"router-{group_num}",
                    hostname=hostname,
                    primary_ip=gateway_ips[0],
                    gateway_ips=gateway_ips,
                    mac_addresses=mac_addresses,
                    subnet_cidrs=subnet_cidrs,
                    vlan_ids=vlan_ids,
                    vendor=vendor,
                    suggested_template_id=suggested_template_id,
                )
            )

        return consolidated

    def infer_vlans_and_subnets(
        self,
        identifications: Sequence[HostIdentification],
        *,
        site_id: str,
    ) -> tuple[list[VLAN], list[Subnet]]:
        """Infer canonical VLAN and Subnet models from host identifications for a site."""
        _require_non_empty_str(site_id, "site_id")
        if not identifications:
            return [], []

        by_cidr: dict[str, list[HostIdentification]] = {}
        for item in identifications:
            cidr = item.subnet_cidr or _infer_subnet_cidr(item.ip)
            if not cidr:
                continue
            by_cidr.setdefault(cidr, []).append(item)

        vlans: list[VLAN] = []
        subnets: list[Subnet] = []
        used_vlan_ids: set[str] = set()

        for idx, (cidr, members) in enumerate(by_cidr.items(), start=1):
            vlan_id: Optional[str] = None
            for m in members:
                if m.inferred_vlan_id:
                    vlan_id = str(m.inferred_vlan_id)
                    break
            if not vlan_id:
                vlan_id = _infer_vlan_id( members[0].ip, subnet_cidr=cidr) or str(idx)
            if vlan_id in used_vlan_ids:
                vlan_id = f"{vlan_id}-{idx}"
            used_vlan_ids.add(vlan_id)

            gateway_ip: Optional[str] = None
            for m in members:
                if m.is_gateway_ip and m.role == "router":
                    gateway_ip = m.ip
                    break
            if gateway_ip is None:
                for m in members:
                    if m.is_gateway_ip or m.role == "router":
                        gateway_ip = m.ip
                        break

            name = self._infer_subnet_name(members, vlan_id=vlan_id)
            subnet_id = f"{site_id}-subnet-{vlan_id}"

            vlans.append(
                VLAN(
                    vlan_id=vlan_id,
                    site_id=site_id,
                    name=name,
                    subnet_id=subnet_id,
                    cidr=cidr,
                    gateway=gateway_ip,
                )
            )
            subnets.append(
                Subnet(
                    subnet_id=subnet_id,
                    site_id=site_id,
                    cidr=cidr,
                    vlan_id=vlan_id,
                    gateway=gateway_ip,
                    name=name,
                )
            )

        return vlans, subnets

    @staticmethod
    def _infer_subnet_name(
        members: Sequence[HostIdentification], *, vlan_id: str
    ) -> str:
        role_counts: dict[str, int] = {}
        for m in members:
            if m.role == "router" and len(members) > 1:
                continue
            role_counts[m.role] = role_counts.get(m.role, 0) + 1

        category_scores: dict[str, int] = {
            "Hypervisor / Virtualization": role_counts.get("hypervisor", 0),
            "IoT / Automation": role_counts.get("iot_device", 0)
            + role_counts.get("automation_hub", 0),
            "Storage": role_counts.get("nas_storage", 0),
            "Management / Infrastructure": role_counts.get("switch", 0)
            + role_counts.get("dns_server", 0)
            + role_counts.get("router", 0),
            "Workstation / Server": role_counts.get("workstation_server", 0),
        }

        best_category, best_score = max(
            category_scores.items(), key=lambda kv: kv[1]
        )
        if best_score > 0:
            return best_category
        return f"VLAN {vlan_id}"
