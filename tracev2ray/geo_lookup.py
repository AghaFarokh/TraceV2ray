"""IP geolocation and ASN lookup.

Primary: ip-api.com batch API (HTTP, free tier)
Fallback: WHOIS queries via TCP socket
"""

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
    source: str = ""  # "ip-api" | "whois" | "local"

    @property
    def asn_display(self) -> str:
        if self.asn:
            return f"AS{self.asn}"
        return ""

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


# Module-level cache
_geo_cache: dict = {}


def lookup_batch(ips: list, timeout: float = None) -> dict:
    """Batch geolocation lookup for a list of IPs.

    Args:
        ips: List of IP address strings
        timeout: HTTP request timeout in seconds

    Returns:
        Dict mapping IP -> GeoInfo
    """
    if timeout is None:
        timeout = constants.GEO_API_TIMEOUT

    results = {}
    to_query = []

    for ip in ips:
        # Check cache first
        if ip in _geo_cache:
            results[ip] = _geo_cache[ip]
            continue

        # Tag private IPs
        if _is_private_ip(ip):
            info = GeoInfo(ip=ip, is_private=True, source="local",
                           org="Local/Private Network")
            results[ip] = info
            _geo_cache[ip] = info
            continue

        to_query.append(ip)

    if not to_query:
        return results

    # Try ip-api.com batch endpoint
    api_results = _query_ip_api_batch(to_query, timeout)
    results.update(api_results)

    # Fallback for any IPs that failed
    failed = [ip for ip in to_query if ip not in results]
    for ip in failed:
        whois_result = _query_whois_fallback(ip)
        if whois_result:
            results[ip] = whois_result
        else:
            # Last resort: empty GeoInfo
            results[ip] = GeoInfo(ip=ip, source="none")

    # Cache everything
    _geo_cache.update(results)
    return results


def lookup_single(ip: str, timeout: float = None) -> GeoInfo:
    """Lookup a single IP. Convenience wrapper around lookup_batch."""
    results = lookup_batch([ip], timeout)
    return results.get(ip, GeoInfo(ip=ip, source="none"))


def _query_ip_api_batch(ips: list, timeout: float) -> dict:
    """Query ip-api.com batch endpoint.

    POST http://ip-api.com/batch
    Body: list of {"query": ip, "fields": "..."} objects
    Max 100 IPs per request.

    Note: Free tier requires HTTP, not HTTPS.
    """
    results = {}

    # Process in chunks of 100
    for i in range(0, len(ips), 100):
        chunk = ips[i : i + 100]
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
                asn = _parse_asn_number(entry.get("as", ""))

                results[ip] = GeoInfo(
                    ip=ip,
                    country=entry.get("country", ""),
                    country_code=entry.get("countryCode", ""),
                    city=entry.get("city", ""),
                    isp=entry.get("isp", ""),
                    org=entry.get("org", ""),
                    asn=asn,
                    as_name=entry.get("asname", ""),
                    source="ip-api",
                )

        except Exception:
            pass  # Will fall through to WHOIS fallback

    return results


def _query_whois_fallback(ip: str, timeout: float = None) -> GeoInfo | None:
    """Fallback: query WHOIS server directly via TCP socket."""
    if timeout is None:
        timeout = constants.WHOIS_TIMEOUT

    # Try ARIN first (handles referrals), then RIPE
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


def _parse_whois_response(ip: str, text: str) -> GeoInfo | None:
    """Parse WHOIS response for useful fields."""
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
    """Extract numeric ASN from string like 'AS13335 Cloudflare, Inc.'"""
    if not as_string:
        return 0
    # Remove 'AS' prefix
    s = as_string.strip()
    if s.upper().startswith("AS"):
        s = s[2:]
    # Take first numeric part
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
        parts = [int(p) for p in ip.split(".")]
        if len(parts) != 4:
            return False

        first, second = parts[0], parts[1]

        # 10.0.0.0/8
        if first == 10:
            return True
        # 172.16.0.0/12
        if first == 172 and 16 <= second <= 31:
            return True
        # 192.168.0.0/16
        if first == 192 and second == 168:
            return True
        # 127.0.0.0/8 (loopback)
        if first == 127:
            return True
        # 169.254.0.0/16 (link-local)
        if first == 169 and second == 254:
            return True
        # 100.64.0.0/10 (CGNAT)
        if first == 100 and 64 <= second <= 127:
            return True

        return False
    except (ValueError, IndexError):
        return False
