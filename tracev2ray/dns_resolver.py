"""DNS resolution with CNAME chain detection."""

import socket
import struct
import time
import random
from dataclasses import dataclass, field


@dataclass
class DnsResult:
    """Result of DNS resolution for a hostname."""

    hostname: str
    ips: list = field(default_factory=list)  # Resolved IP addresses
    cname_chain: list = field(default_factory=list)  # CNAME chain if detected
    error: str | None = None
    resolution_time_ms: float = 0.0


def resolve_hostname(hostname: str, timeout: float = 10.0) -> DnsResult:
    """Resolve hostname to IP addresses using system DNS.

    Also attempts CNAME chain detection via raw DNS query.
    """
    result = DnsResult(hostname=hostname)
    start = time.time()

    # Resolve A/AAAA records
    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            seen = set()
            for info in infos:
                ip = info[4][0]
                if ip not in seen:
                    seen.add(ip)
                    result.ips.append(ip)
        finally:
            socket.setdefaulttimeout(old_timeout)
    except socket.gaierror as e:
        result.error = f"DNS resolution failed: {e}"
    except socket.timeout:
        result.error = "DNS resolution timed out"
    except Exception as e:
        result.error = f"DNS error: {e}"

    # Attempt CNAME chain detection (best-effort)
    try:
        result.cname_chain = _detect_cname_chain(hostname)
    except Exception:
        pass  # CNAME detection is optional enrichment

    result.resolution_time_ms = (time.time() - start) * 1000
    return result


def _detect_cname_chain(hostname: str, dns_server: str = "8.8.8.8") -> list:
    """Detect CNAME chain by sending raw DNS query.

    Returns list of CNAME entries, e.g. ["example.com", "cdn.example.com.cdn.cloudflare.net"]
    Returns empty list if no CNAME or if query fails.
    """
    chain = []
    current = hostname
    seen = set()

    for _ in range(10):  # Max 10 CNAME hops to prevent loops
        if current in seen:
            break
        seen.add(current)

        cname = _query_cname(current, dns_server)
        if cname and cname != current:
            chain.append(cname)
            current = cname
        else:
            break

    return chain


def _query_cname(hostname: str, dns_server: str) -> str | None:
    """Send a raw DNS query for CNAME record."""
    query = _build_dns_query(hostname, qtype=5)  # 5 = CNAME

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)
    try:
        sock.sendto(query, (dns_server, 53))
        response, _ = sock.recvfrom(1024)
        return _parse_cname_response(response)
    except Exception:
        return None
    finally:
        sock.close()


def _build_dns_query(hostname: str, qtype: int = 1) -> bytes:
    """Build a raw DNS query packet.

    Args:
        hostname: Domain name to query
        qtype: 1=A, 5=CNAME, 28=AAAA
    """
    # Header: ID(2) + Flags(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)
    tx_id = random.randint(0, 65535)
    flags = 0x0100  # Standard query, recursion desired
    header = struct.pack("!HHHHHH", tx_id, flags, 1, 0, 0, 0)

    # Question section: encode domain name
    question = b""
    for label in hostname.rstrip(".").split("."):
        encoded = label.encode("ascii")
        question += struct.pack("!B", len(encoded)) + encoded
    question += b"\x00"  # Root label

    # QTYPE and QCLASS
    question += struct.pack("!HH", qtype, 1)  # 1 = IN class

    return header + question


def _parse_cname_response(data: bytes) -> str | None:
    """Parse DNS response and extract CNAME record if present."""
    if len(data) < 12:
        return None

    # Parse header
    _, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])

    # Check for valid response
    if not (flags & 0x8000):  # QR bit must be 1 (response)
        return None

    offset = 12

    # Skip question section
    for _ in range(qdcount):
        offset = _skip_name(data, offset)
        if offset is None:
            return None
        offset += 4  # QTYPE + QCLASS

    # Parse answer section
    for _ in range(ancount):
        # Name
        offset = _skip_name(data, offset)
        if offset is None or offset + 10 > len(data):
            return None

        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10

        if rtype == 5:  # CNAME
            name = _read_name(data, offset)
            if name:
                return name

        offset += rdlength

    return None


def _skip_name(data: bytes, offset: int) -> int | None:
    """Skip over a DNS name in the packet, returning new offset."""
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return offset + 1
        if (length & 0xC0) == 0xC0:  # Pointer
            return offset + 2
        offset += 1 + length
    return None


def _read_name(data: bytes, offset: int) -> str | None:
    """Read a DNS name from the packet, following pointers."""
    labels = []
    seen_offsets = set()
    jumps = 0

    while offset < len(data) and jumps < 10:
        if offset in seen_offsets:
            break
        seen_offsets.add(offset)

        length = data[offset]
        if length == 0:
            break
        if (length & 0xC0) == 0xC0:  # Pointer
            if offset + 1 >= len(data):
                break
            pointer = struct.unpack("!H", data[offset : offset + 2])[0] & 0x3FFF
            offset = pointer
            jumps += 1
            continue

        offset += 1
        if offset + length > len(data):
            break
        labels.append(data[offset : offset + length].decode("ascii", errors="replace"))
        offset += length

    return ".".join(labels) if labels else None
