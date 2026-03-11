"""IP geolocation and ASN lookup.

Primary:  ip-api.com batch API (HTTP, free tier)
Proxy:    ip-api.com via SOCKS5 (for when direct access is blocked)
Offline:  CIDR-based Iranian ISP detection (no API needed)
Fallback: WHOIS over TCP socket
Extra:    PTR (reverse DNS) lookup via socket.gethostbyaddr()
"""

import ipaddress
import json
import socket
import urllib.request
import urllib.error
from dataclasses import dataclass

from . import constants


@dataclass
class GeoInfo:
    """Geolocation and network information for an IP address."""

    ip: str
    country: str = ""
    country_code: str = ""
    city: str = ""
    isp: str = ""
    org: str = ""
    asn: int = 0
    as_name: str = ""
    is_private: bool = False
    ptr: str = ""           # Reverse DNS hostname
    source: str = ""        # "ip-api" | "ip-api-proxy" | "cidr" | "whois" | "local" | "none"

    @property
    def asn_display(self) -> str:
        return f"AS{self.asn}" if self.asn else ""

    @property
    def location_display(self) -> str:
        parts = []
        if self.country_code:
            parts.append(self.country_code)
        if self.city:
            parts.append(self.city)
        return ", ".join(parts) if parts else ""

    @property
    def org_display(self) -> str:
        return self.org or self.isp or self.as_name or ""

    @property
    def is_iranian(self) -> bool:
        return self.country_code == "IR" or self.asn in constants.IRANIAN_ISPS


# Module-level cache
_geo_cache: dict = {}
_ptr_cache: dict = {}

# Pre-compiled CIDR networks (lazy-loaded)
_cidr_networks: list | None = None


def lookup_batch(ips: list, timeout: float = None) -> dict:
    """Batch geolocation lookup via direct API call.

    Falls back to CIDR offline lookup, then WHOIS.
    """
    if timeout is None:
        timeout = constants.GEO_API_TIMEOUT
    return _lookup_batch_impl(ips, timeout, socks_port=None)


def lookup_batch_via_proxy(ips: list, socks_port: int, timeout: float = None) -> dict:
    """Batch geolocation lookup routed through local SOCKS5 proxy.

    Use this when direct internet access to geo APIs is blocked (e.g. from Iran).
    """
    if timeout is None:
        timeout = constants.GEO_API_TIMEOUT
    return _lookup_batch_impl(ips, timeout, socks_port=socks_port)


def lookup_single(ip: str, timeout: float = None) -> GeoInfo:
    """Lookup a single IP directly."""
    return lookup_batch([ip], timeout).get(ip, GeoInfo(ip=ip, source="none"))


def lookup_single_via_proxy(ip: str, socks_port: int, timeout: float = None) -> GeoInfo:
    """Lookup a single IP through proxy."""
    return lookup_batch_via_proxy([ip], socks_port, timeout).get(ip, GeoInfo(ip=ip, source="none"))


def ptr_lookup(ip: str, timeout: float = 3.0) -> str:
    """Reverse DNS lookup (PTR record) for an IP.

    Returns the PTR hostname or empty string on failure.
    """
    if ip in _ptr_cache:
        return _ptr_cache[ip]

    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            result = hostname
        finally:
            socket.setdefaulttimeout(old)
    except Exception:
        result = ""

    _ptr_cache[ip] = result
    return result


def cidr_isp_lookup(ip: str) -> str | None:
    """Offline CIDR-based ISP lookup for Iranian IPs.

    Returns ISP name if the IP falls inside a known Iranian CIDR, else None.
    """
    global _cidr_networks
    if _cidr_networks is None:
        _cidr_networks = []
        for cidr_str, isp_name in constants.IRANIAN_ISP_CIDRS.items():
            try:
                _cidr_networks.append((ipaddress.ip_network(cidr_str, strict=False), isp_name))
            except ValueError:
                pass

    try:
        addr = ipaddress.ip_address(ip)
        for network, isp_name in _cidr_networks:
            if addr in network:
                return isp_name
    except ValueError:
        pass
    return None


# ---------------------------------------------------------------------------
# Internal implementation
# ---------------------------------------------------------------------------

def _lookup_batch_impl(ips: list, timeout: float, socks_port: int | None) -> dict:
    results = {}
    to_query = []

    for ip in ips:
        if ip in _geo_cache:
            results[ip] = _geo_cache[ip]
            continue

        if _is_private_ip(ip):
            info = GeoInfo(ip=ip, is_private=True, source="local",
                           org="Local/Private Network")
            results[ip] = info
            _geo_cache[ip] = info
            continue

        # Try offline CIDR first (instantaneous, no network)
        isp_name = cidr_isp_lookup(ip)
        if isp_name:
            # Found offline, but still query API for full geo
            # Mark and continue to API query
            pass

        to_query.append(ip)

    if not to_query:
        return results

    # --- API query ---
    if socks_port:
        api_results = _query_ip_api_batch_via_proxy(to_query, timeout, socks_port)
    else:
        api_results = _query_ip_api_batch(to_query, timeout)
    results.update(api_results)

    # Fallback for any IPs that still failed
    failed = [ip for ip in to_query if ip not in results]
    for ip in failed:
        # Try CIDR offline lookup
        isp_name = cidr_isp_lookup(ip)
        if isp_name:
            results[ip] = GeoInfo(
                ip=ip, isp=isp_name, org=isp_name,
                country="Iran", country_code="IR",
                source="cidr"
            )
            continue

        # Try WHOIS
        whois_result = _query_whois_fallback(ip)
        if whois_result:
            results[ip] = whois_result
        else:
            results[ip] = GeoInfo(ip=ip, source="none")

    # Enrich with CIDR data where API returned empty country for known Iranian IPs
    for ip in to_query:
        if ip in results:
            geo = results[ip]
            if not geo.country_code or not geo.isp:
                isp_name = cidr_isp_lookup(ip)
                if isp_name:
                    if not geo.country_code:
                        geo.country = "Iran"
                        geo.country_code = "IR"
                    if not geo.isp:
                        geo.isp = isp_name
                        geo.org = isp_name

    _geo_cache.update(results)
    return results


def _query_ip_api_batch(ips: list, timeout: float) -> dict:
    """Query ip-api.com batch endpoint directly."""
    results = {}
    for i in range(0, len(ips), 100):
        chunk = ips[i: i + 100]
        payload = [
            {
                "query": ip,
                "fields": "status,message,query,country,countryCode,city,isp,org,as,asname",
            }
            for ip in chunk
        ]
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                "http://ip-api.com/batch",
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                response_data = json.loads(resp.read().decode("utf-8"))

            for entry in response_data:
                if entry.get("status") != "success":
                    continue
                ip = entry["query"]
                results[ip] = _parse_ip_api_entry(ip, entry, source="ip-api")

        except Exception:
            pass

    return results


def _query_ip_api_batch_via_proxy(ips: list, timeout: float, socks_port: int) -> dict:
    """Query ip-api.com batch endpoint through SOCKS5 proxy.

    Falls back to per-IP ipinfo.io HTTPS queries through proxy.
    """
    results = {}

    # First try ip-api.com individual queries through HTTP proxy
    from .socks_client import http_get_through_socks, https_get_through_socks

    for ip in ips:
        try:
            body = http_get_through_socks(
                "127.0.0.1", socks_port,
                "ip-api.com",
                f"/json/{ip}?fields=status,message,query,country,countryCode,city,isp,org,as,asname",
                timeout=timeout,
            )
            data = json.loads(body)
            if data.get("status") == "success":
                results[ip] = _parse_ip_api_entry(ip, data, source="ip-api-proxy")
        except Exception:
            pass

    # Fallback: try ipinfo.io via HTTPS through proxy for remaining
    failed = [ip for ip in ips if ip not in results]
    for ip in failed:
        try:
            body = https_get_through_socks(
                "127.0.0.1", socks_port,
                "ipinfo.io",
                f"/{ip}/json",
                timeout=timeout,
            )
            data = json.loads(body)
            if "ip" in data:
                asn_str = data.get("org", "")
                asn_num = _parse_asn_number(asn_str.split()[0] if asn_str else "")
                as_name = " ".join(asn_str.split()[1:]) if asn_str else ""
                results[ip] = GeoInfo(
                    ip=ip,
                    country=data.get("country", ""),
                    country_code=data.get("country", ""),
                    city=data.get("city", ""),
                    org=data.get("org", ""),
                    isp=data.get("org", ""),
                    asn=asn_num,
                    as_name=as_name,
                    source="ipinfo-proxy",
                )
        except Exception:
            pass

    return results


def _parse_ip_api_entry(ip: str, entry: dict, source: str) -> "GeoInfo":
    asn = _parse_asn_number(entry.get("as", ""))
    return GeoInfo(
        ip=ip,
        country=entry.get("country", ""),
        country_code=entry.get("countryCode", ""),
        city=entry.get("city", ""),
        isp=entry.get("isp", ""),
        org=entry.get("org", ""),
        asn=asn,
        as_name=entry.get("asname", ""),
        source=source,
    )


def _query_whois_fallback(ip: str, timeout: float = None) -> "GeoInfo | None":
    if timeout is None:
        timeout = constants.WHOIS_TIMEOUT

    for server in ["whois.arin.net", "whois.ripe.net"]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((server, 43))
            sock.sendall(f"{ip}\r\n".encode("utf-8"))

            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            sock.close()

            text = response.decode("utf-8", errors="replace")
            return _parse_whois_response(ip, text)

        except Exception:
            continue

    return None


def _parse_whois_response(ip: str, text: str) -> "GeoInfo | None":
    info = GeoInfo(ip=ip, source="whois")

    for line in text.splitlines():
        line = line.strip()
        lower = line.lower()

        if lower.startswith("orgname:") or lower.startswith("org-name:"):
            info.org = line.split(":", 1)[1].strip()
        elif lower.startswith("country:"):
            val = line.split(":", 1)[1].strip()
            info.country_code = val[:2].upper()
            info.country = val
        elif lower.startswith("netname:"):
            if not info.org:
                info.org = line.split(":", 1)[1].strip()
        elif lower.startswith("descr:"):
            if not info.isp:
                info.isp = line.split(":", 1)[1].strip()

    return info if (info.org or info.country_code) else None


def _parse_asn_number(as_string: str) -> int:
    if not as_string:
        return 0
    s = as_string.strip()
    if s.upper().startswith("AS"):
        s = s[2:]
    num = ""
    for c in s:
        if c.isdigit():
            num += c
        else:
            break
    return int(num) if num else 0


def _is_private_ip(ip: str) -> bool:
    """Check if IP is in private/reserved ranges."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        return False
