"""Deep proxy intelligence gathering.

Everything here runs THROUGH the working SOCKS5 proxy, so:
- We see what the exit server sees
- We can detect X-Forwarded-For chains (intermediate relay IPs)
- We can do geo/BGP lookups from the exit server's perspective
- We can fingerprint the exit environment

Operations:
  1. Exit IP verification (multiple checks for consistency)
  2. X-Forwarded-For / Via chain extraction
  3. IPv6 exit detection
  4. Geo lookup via proxy (for IPs that failed direct lookup)
  5. BGP lookup for all key IPs
  6. Shodan InternetDB (no auth, HTTPS)
  7. PTR reverse DNS for all IPs
  8. Latency triangulation (estimate exit server geography)
"""

import json
import socket
import time
from dataclasses import dataclass, field

from . import constants
from .bgp_lookup import BgpInfo, lookup_bgp_batch
from .geo_lookup import GeoInfo, lookup_batch_via_proxy, ptr_lookup
from .socks_client import (
    https_get_through_socks,
    http_get_through_socks,
    tcp_connect_time_through_socks,
)


@dataclass
class ShodanEntry:
    """Shodan InternetDB data for an IP."""
    ip: str = ""
    hostnames: list = field(default_factory=list)
    ports: list = field(default_factory=list)
    tags: list = field(default_factory=list)
    cpes: list = field(default_factory=list)
    vulns: list = field(default_factory=list)


@dataclass
class LatencyMeasurement:
    """Single latency measurement through proxy."""
    city: str = ""
    country_code: str = ""
    rtt_ms: float = 0.0
    host: str = ""


@dataclass
class ProbeResult:
    """Aggregated results from all through-proxy intelligence probes."""

    # Exit IP verification
    exit_ips: list = field(default_factory=list)     # All exit IPs found
    exit_ip_consistent: bool = True                   # All IPs the same?

    # Relay chain detection via X-Forwarded-For / Via headers
    forwarded_chain: list = field(default_factory=list)   # IP strings from X-Forwarded-For
    via_headers: list = field(default_factory=list)       # Via header values

    # IPv6 exit
    ipv6_exit: str = ""

    # Geo lookups performed through proxy
    proxy_geo: dict = field(default_factory=dict)    # ip -> GeoInfo

    # BGP analysis for all key IPs
    bgp_data: dict = field(default_factory=dict)     # ip -> BgpInfo

    # Shodan InternetDB
    shodan_data: dict = field(default_factory=dict)  # ip -> ShodanEntry

    # PTR records
    ptr_records: dict = field(default_factory=dict)  # ip -> hostname

    # Latency triangulation
    latency_measurements: list = field(default_factory=list)  # List[LatencyMeasurement]
    estimated_city: str = ""
    estimated_country: str = ""

    # Errors per sub-probe
    errors: list = field(default_factory=list)


def run_proxy_probe(
    socks_port: int,
    key_ips: list,
    existing_geo: dict,
    timeout: float = None,
) -> ProbeResult:
    """Run all through-proxy intelligence probes.

    Args:
        socks_port:    Local SOCKS5 proxy port (xray-core)
        key_ips:       IPs to analyze (entry server, exit server, traceroute hops)
        existing_geo:  Already-gathered GeoInfo dict (avoid re-querying)
        timeout:       Per-request timeout (seconds)
    """
    if timeout is None:
        timeout = constants.PROBE_TIMEOUT

    result = ProbeResult()

    # 1. Exit IP + forwarded chain
    _probe_exit_and_chain(socks_port, timeout, result)

    # 2. IPv6 exit
    _probe_ipv6(socks_port, timeout, result)

    # 3. Geo via proxy for IPs that failed direct lookup
    _probe_geo(socks_port, key_ips, existing_geo, timeout, result)

    # 4. BGP for key IPs
    _probe_bgp(socks_port, key_ips, timeout, result)

    # 5. Shodan for key IPs
    _probe_shodan(socks_port, key_ips, timeout, result)

    # 6. PTR records (uses direct DNS, no proxy needed)
    _probe_ptr(key_ips, result)

    # 7. Latency triangulation
    _probe_latency(socks_port, timeout, result)

    return result


# ---------------------------------------------------------------------------
# Sub-probe implementations
# ---------------------------------------------------------------------------

def _probe_exit_and_chain(socks_port: int, timeout: float, result: ProbeResult):
    """Get exit IP and extract X-Forwarded-For / Via relay chain."""

    # Check exit IP using multiple services to verify consistency
    exit_ips_found = []

    for service in constants.IP_ECHO_SERVICES[:3]:
        try:
            body = http_get_through_socks(
                "127.0.0.1", socks_port,
                service["host"], service["path"],
                timeout=timeout,
            )
            ip = _extract_ip(body, service)
            if ip and _looks_like_ip(ip):
                exit_ips_found.append(ip)
        except Exception:
            pass

    if exit_ips_found:
        unique_ips = list(dict.fromkeys(exit_ips_found))
        result.exit_ips = unique_ips
        result.exit_ip_consistent = len(unique_ips) == 1
    else:
        result.errors.append("Could not determine exit IP through proxy")

    # X-Forwarded-For chain via header-echo services
    _probe_forwarded_headers(socks_port, timeout, result)


def _probe_forwarded_headers(socks_port: int, timeout: float, result: ProbeResult):
    """Extract X-Forwarded-For and Via headers to reveal relay chain."""

    for service in constants.HEADER_ECHO_SERVICES:
        try:
            body = http_get_through_socks(
                "127.0.0.1", socks_port,
                service["host"], service["path"],
                timeout=timeout,
            )
            data = json.loads(body)
            headers_dict = _flatten_headers(data)

            # X-Forwarded-For: may contain comma-separated chain of IPs
            xff = headers_dict.get("x-forwarded-for", "")
            if xff:
                chain_ips = [ip.strip() for ip in xff.split(",") if ip.strip()]
                for ip in chain_ips:
                    if _looks_like_ip(ip) and ip not in result.forwarded_chain:
                        result.forwarded_chain.append(ip)

            # Via header
            via = headers_dict.get("via", "")
            if via and via not in result.via_headers:
                result.via_headers.append(via)

            # X-Real-IP
            real_ip = headers_dict.get("x-real-ip", "")
            if real_ip and _looks_like_ip(real_ip) and real_ip not in result.forwarded_chain:
                result.forwarded_chain.append(real_ip)

            break  # One successful call is enough

        except Exception:
            pass


def _probe_ipv6(socks_port: int, timeout: float, result: ProbeResult):
    """Try to get the IPv6 exit address through proxy."""
    try:
        body = https_get_through_socks(
            "127.0.0.1", socks_port,
            "api64.ipify.org", "/",
            timeout=timeout,
        )
        ip = body.strip()
        if ":" in ip:  # IPv6 contains colons
            result.ipv6_exit = ip
    except Exception:
        pass


def _probe_geo(socks_port: int, key_ips: list, existing_geo: dict, timeout: float, result: ProbeResult):
    """Retry geo lookup through proxy for IPs that failed direct lookup."""

    # Find IPs with missing or incomplete geo data
    to_retry = []
    for ip in key_ips:
        geo = existing_geo.get(ip)
        if not geo or (not geo.country_code and not geo.org and geo.source not in ("local", "cidr")):
            to_retry.append(ip)

    if not to_retry:
        return

    try:
        proxy_geo = lookup_batch_via_proxy(to_retry, socks_port, timeout=timeout)
        result.proxy_geo.update(proxy_geo)
    except Exception as e:
        result.errors.append(f"Geo via proxy failed: {e}")


def _probe_bgp(socks_port: int, key_ips: list, timeout: float, result: ProbeResult):
    """BGP lookup for key IPs through proxy."""
    # Filter out private IPs
    public_ips = [ip for ip in key_ips if ip and not _is_private(ip)]

    if not public_ips:
        return

    # Deduplicate and limit to avoid too many API calls
    unique_ips = list(dict.fromkeys(public_ips))[:6]

    try:
        bgp_results = lookup_bgp_batch(unique_ips, socks_port, timeout=timeout)
        result.bgp_data.update(bgp_results)
    except Exception as e:
        result.errors.append(f"BGP lookup failed: {e}")


def _probe_shodan(socks_port: int, key_ips: list, timeout: float, result: ProbeResult):
    """Query Shodan InternetDB (free, no auth) through proxy.

    API: https://internetdb.shodan.io/{ip}
    Returns: {cpes, hostnames, ip, ports, tags, vulns}
    """
    public_ips = [ip for ip in key_ips if ip and not _is_private(ip)]
    unique_ips = list(dict.fromkeys(public_ips))[:4]  # Limit to 4 IPs

    for ip in unique_ips:
        try:
            body = https_get_through_socks(
                "127.0.0.1", socks_port,
                "internetdb.shodan.io", f"/{ip}",
                timeout=timeout,
            )
            data = json.loads(body)
            if "ip" in data or "ports" in data:
                entry = ShodanEntry(
                    ip=ip,
                    hostnames=data.get("hostnames", []),
                    ports=data.get("ports", []),
                    tags=data.get("tags", []),
                    cpes=data.get("cpes", []),
                    vulns=data.get("vulns", []),
                )
                result.shodan_data[ip] = entry
        except Exception:
            pass


def _probe_ptr(key_ips: list, result: ProbeResult):
    """Reverse DNS (PTR) for all key IPs."""
    unique_ips = list(dict.fromkeys(key_ips))

    for ip in unique_ips:
        if ip and not _is_private(ip):
            hostname = ptr_lookup(ip, timeout=3.0)
            if hostname:
                result.ptr_records[ip] = hostname


def _probe_latency(socks_port: int, timeout: float, result: ProbeResult):
    """Measure latency to servers in known locations to triangulate exit geography.

    The location with the LOWEST RTT through the proxy is likely closest to
    the exit server.
    """
    measurements = []

    for host, port, city, country_code in constants.LATENCY_TARGETS:
        rtt = tcp_connect_time_through_socks(
            "127.0.0.1", socks_port,
            host, port,
            timeout=min(timeout, 6.0),
        )
        if rtt is not None:
            measurements.append(LatencyMeasurement(
                city=city,
                country_code=country_code,
                rtt_ms=rtt,
                host=host,
            ))

    if measurements:
        measurements.sort(key=lambda m: m.rtt_ms)
        result.latency_measurements = measurements
        # Best estimate: lowest RTT
        best = measurements[0]
        result.estimated_city = best.city
        result.estimated_country = best.country_code


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _extract_ip(body: str, service: dict) -> str:
    """Extract IP from API response body."""
    fmt = service.get("format", "text")
    if fmt == "json":
        try:
            data = json.loads(body)
            key = service.get("key", "ip")
            return str(data.get(key, "")).strip()
        except Exception:
            pass
    return body.strip().split("\n")[0].strip()


def _flatten_headers(data) -> dict:
    """Flatten nested header structures from echo services."""
    if isinstance(data, dict):
        # httpbin: {"headers": {"X-Forwarded-For": "..."}}
        if "headers" in data and isinstance(data["headers"], dict):
            return {k.lower(): v for k, v in data["headers"].items()}
        # ifconfig.me: {"X_FORWARDED_FOR": "..."}
        return {k.lower().replace("_", "-"): v for k, v in data.items()}
    return {}


def _looks_like_ip(s: str) -> bool:
    """Quick check if string looks like an IPv4 or IPv6 address."""
    s = s.strip()
    # IPv4
    parts = s.split(".")
    if len(parts) == 4:
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            pass
    # IPv6
    if ":" in s:
        return True
    return False


def _is_private(ip: str) -> bool:
    """Check if IP is private/local."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback
    except ValueError:
        return False
