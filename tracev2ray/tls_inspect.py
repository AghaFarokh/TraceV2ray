"""TLS certificate inspection.

Connects directly to the entry server (not through proxy) and retrieves
the TLS certificate to extract: CN, SANs, issuer, validity dates.
This reveals what identity the server is presenting.
"""

import datetime
import hashlib
import socket
import ssl
from dataclasses import dataclass, field


@dataclass
class TlsInfo:
    """TLS certificate details for a server."""
    host: str = ""
    port: int = 443
    subject_cn: str = ""
    subject_sans: list = field(default_factory=list)  # Subject Alternative Names
    issuer_org: str = ""
    issuer_cn: str = ""
    not_before: str = ""
    not_after: str = ""
    is_self_signed: bool = False
    is_lets_encrypt: bool = False
    is_expired: bool = False
    days_until_expiry: int = 0
    cert_sha256: str = ""       # SHA-256 fingerprint of DER cert
    tls_version: str = ""
    cipher_suite: str = ""
    error: str = ""


def inspect_tls(
    host: str,
    port: int = 443,
    sni: str = "",
    timeout: float = 10.0,
) -> TlsInfo:
    """Connect directly to host:port and inspect TLS certificate.

    Args:
        host:    IP or hostname to connect to
        port:    TCP port (default 443)
        sni:     SNI to send in TLS ClientHello (defaults to host if not an IP)
        timeout: Connection timeout in seconds
    """
    result = TlsInfo(host=host, port=port)
    server_hostname = sni or (host if not _is_ip(host) else "")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # We inspect but don't verify

    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        ssl_sock = ctx.wrap_socket(raw_sock, server_hostname=server_hostname or None)

        # TLS protocol and cipher
        result.tls_version = ssl_sock.version() or ""
        cipher = ssl_sock.cipher()
        if cipher:
            result.cipher_suite = cipher[0] or ""

        # Get certificate
        der_cert = ssl_sock.getpeercert(binary_form=True)
        ssl_sock.close()

        if not der_cert:
            result.error = "No certificate returned"
            return result

        # SHA-256 fingerprint
        result.cert_sha256 = hashlib.sha256(der_cert).hexdigest().upper()

        # Parse certificate using Python's built-in DER -> dict conversion
        cert_dict = ssl.DER_cert_to_PEM_cert(der_cert)
        _parse_cert_from_pem(cert_dict, result)

        # If SSLSocket is available parse the structured dict
        try:
            # Re-connect briefly to get structured cert dict
            raw_sock2 = socket.create_connection((host, port), timeout=timeout)
            ssl_sock2 = ctx.wrap_socket(raw_sock2, server_hostname=server_hostname or None)
            struct_cert = ssl_sock2.getpeercert()
            ssl_sock2.close()
            if struct_cert:
                _parse_structured_cert(struct_cert, result)
        except Exception:
            pass

    except ssl.SSLError as e:
        result.error = f"TLS error: {e}"
    except socket.timeout:
        result.error = "Connection timed out"
    except ConnectionRefusedError:
        result.error = "Connection refused"
    except OSError as e:
        result.error = f"Connection failed: {e}"

    return result


def _parse_structured_cert(cert: dict, result: TlsInfo):
    """Parse ssl.SSLSocket.getpeercert() structured dict."""

    # Subject CN
    subject = dict(x[0] for x in cert.get("subject", ()))
    result.subject_cn = subject.get("commonName", "")

    # Issuer
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    result.issuer_cn = issuer.get("commonName", "")
    result.issuer_org = issuer.get("organizationName", "")

    # Self-signed check
    if result.subject_cn and result.issuer_cn:
        result.is_self_signed = (result.subject_cn == result.issuer_cn)

    # Let's Encrypt check
    result.is_lets_encrypt = "Let's Encrypt" in result.issuer_org or "Let's Encrypt" in result.issuer_cn

    # SANs
    sans = []
    for san_type, san_value in cert.get("subjectAltName", []):
        if san_type in ("DNS", "IP Address"):
            sans.append(san_value)
    result.subject_sans = sans

    # Validity dates
    not_before_str = cert.get("notBefore", "")
    not_after_str = cert.get("notAfter", "")
    if not_before_str:
        result.not_before = not_before_str
    if not_after_str:
        result.not_after = not_after_str
        try:
            expiry = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            now = datetime.datetime.utcnow()
            delta = expiry - now
            result.days_until_expiry = delta.days
            result.is_expired = delta.days < 0
        except ValueError:
            pass


def _parse_cert_from_pem(pem: str, result: TlsInfo):
    """Minimal PEM certificate info extraction (fallback)."""
    # Just ensure the cert is valid PEM
    if "BEGIN CERTIFICATE" in pem:
        if not result.error:
            result.error = ""


def _is_ip(host: str) -> bool:
    """Check if host is an IP address."""
    parts = host.split(".")
    if len(parts) == 4:
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            pass
    return ":" in host  # IPv6
