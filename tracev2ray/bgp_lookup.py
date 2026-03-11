"""BGP route and upstream analysis.

Uses BGPView API (https://bgpview.io) routed through the working SOCKS5 proxy.
All requests are HTTPS to avoid interception.
"""

import json
from dataclasses import dataclass, field

from . import constants
from .socks_client import https_get_through_socks


@dataclass
class BgpPeerInfo:
    """A BGP peer or upstream provider."""
    asn: int = 0
    name: str = ""
    description: str = ""
    country_code: str = ""

    def display(self) -> str:
        parts = [f"AS{self.asn}"]
        if self.name:
            parts.append(self.name)
        if self.country_code:
            parts.append(f"[{self.country_code}]")
        return " ".join(parts)


@dataclass
class BgpInfo:
    """Full BGP information for an IP address."""
    ip: str = ""
    prefix: str = ""            # e.g. "206.71.158.0/24"
    asn: int = 0
    asn_name: str = ""
    asn_description: str = ""
    country_code: str = ""
    ptr_record: str = ""
    upstreams_v4: list = field(default_factory=list)  # List[BgpPeerInfo]
    rir: str = ""               # ARIN, RIPE, APNIC, LACNIC, AFRINIC
    is_backbone: bool = False
    is_cdn: bool = False
    is_iranian: bool = False
    is_satellite: bool = False
    error: str = ""


def lookup_bgp_for_ip(
    ip: str,
    socks_port: int,
    timeout: float = None,
) -> BgpInfo:
    """Look up BGP information for an IP via BGPView API through proxy.

    Fetches:
      1. IP prefix / owning ASN
      2. Upstream providers for that ASN
    """
    if timeout is None:
        timeout = constants.BGP_TIMEOUT

    result = BgpInfo(ip=ip)

    # --- Step 1: IP prefix lookup ---
    try:
        body = https_get_through_socks(
            "127.0.0.1", socks_port,
            "api.bgpview.io",
            f"/ip/{ip}",
            timeout=timeout,
        )
        data = json.loads(body)

        if data.get("status") == "ok":
            ip_data = data.get("data", {})
            result.ptr_record = ip_data.get("ptr_record", "") or ""
            prefixes = ip_data.get("prefixes", [])
            if prefixes:
                prefix = prefixes[0]
                result.prefix = prefix.get("prefix", "")
                result.rir = prefix.get("rir_allocation", {}).get("rir_name", "") if isinstance(prefix.get("rir_allocation"), dict) else ""
                asn_info = prefix.get("asn") or {}
                result.asn = asn_info.get("asn", 0)
                result.asn_name = asn_info.get("name", "")
                result.asn_description = asn_info.get("description", "")
                result.country_code = asn_info.get("country_code", "")

    except Exception as e:
        result.error = f"BGPView IP lookup failed: {e}"
        return result

    if not result.asn:
        return result

    # Classify the ASN
    result.is_backbone = result.asn in constants.BACKBONE_ASNS
    result.is_cdn = result.asn in constants.CDN_ASN_MAP
    result.is_iranian = result.asn in constants.IRANIAN_ISPS or result.country_code == "IR"
    result.is_satellite = result.asn in constants.SATELLITE_ASNS

    # --- Step 2: Upstream providers ---
    try:
        body = https_get_through_socks(
            "127.0.0.1", socks_port,
            "api.bgpview.io",
            f"/asn/{result.asn}/upstreams",
            timeout=timeout,
        )
        data = json.loads(body)

        if data.get("status") == "ok":
            upstreams = data.get("data", {}).get("ipv4_upstreams", [])
            for u in upstreams[:8]:  # Top 8 upstreams
                peer = BgpPeerInfo(
                    asn=u.get("asn", 0),
                    name=u.get("name", ""),
                    description=u.get("description", ""),
                    country_code=u.get("country_code", ""),
                )
                result.upstreams_v4.append(peer)

    except Exception:
        pass  # Upstreams are enrichment, not critical

    return result


def lookup_bgp_batch(
    ips: list,
    socks_port: int,
    timeout: float = None,
) -> dict:
    """Look up BGP for multiple IPs. Returns dict[ip -> BgpInfo]."""
    if timeout is None:
        timeout = constants.BGP_TIMEOUT

    results = {}
    seen_asns = {}  # asn -> upstreams (avoid duplicate upstream queries)

    for ip in ips:
        info = lookup_bgp_for_ip(ip, socks_port, timeout)
        results[ip] = info

        # Share upstream data if same ASN queried before
        if info.asn and info.asn in seen_asns:
            info.upstreams_v4 = seen_asns[info.asn]
        elif info.asn:
            seen_asns[info.asn] = info.upstreams_v4

    return results
