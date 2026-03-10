"""V2Ray configuration URI parser.

Supports: vless://, vmess://, trojan://, ss:// (Shadowsocks)
"""

import base64
import json
import urllib.parse
from dataclasses import dataclass, field


@dataclass
class ConfigInfo:
    """Normalized representation of any V2Ray proxy configuration."""

    raw_uri: str
    protocol: str  # "vless" | "vmess" | "trojan" | "ss"
    uuid_or_password: str  # UUID for vless/vmess, password for trojan/ss
    server_host: str  # hostname or IP
    server_port: int
    transport: str = "tcp"  # "tcp" | "ws" | "grpc" | "httpupgrade" | "kcp" | "h2"
    tls: str = "none"  # "tls" | "reality" | "none"
    sni: str = ""
    host_header: str = ""  # Host header (CDN/obfuscation indicator)
    path: str = ""  # WebSocket path or gRPC serviceName
    encryption: str = "none"
    header_type: str = ""  # "http" | "none" | "" for TCP header obfuscation
    fingerprint: str = ""  # uTLS fingerprint
    alpn: str = ""
    flow: str = ""  # XTLS flow (e.g., "xtls-rprx-vision")
    remark: str = ""  # Human-readable name
    extra: dict = field(default_factory=dict)
    host_is_ip: bool = False

    @property
    def display_protocol(self) -> str:
        parts = [self.protocol.upper()]
        if self.transport and self.transport != "tcp":
            parts.append(self.transport.upper())
        elif self.header_type == "http":
            parts.append("TCP+HTTP")
        if self.tls not in ("none", ""):
            parts.append(self.tls.upper())
        return " + ".join(parts)

    @property
    def is_reality(self) -> bool:
        return self.tls == "reality"

    @property
    def effective_host(self) -> str:
        """The most meaningful hostname for CDN analysis."""
        return self.host_header or self.sni or self.server_host


def parse_uri(uri: str) -> ConfigInfo:
    """Parse a V2Ray config URI into a ConfigInfo object.

    Args:
        uri: V2Ray URI string (vless://, vmess://, trojan://, ss://)

    Returns:
        ConfigInfo with parsed configuration details.

    Raises:
        ValueError: If the URI scheme is unsupported or parsing fails.
    """
    uri = uri.strip().strip('"').strip("'")

    if uri.startswith("vless://"):
        return _parse_vless(uri)
    elif uri.startswith("vmess://"):
        return _parse_vmess(uri)
    elif uri.startswith("trojan://"):
        return _parse_trojan(uri)
    elif uri.startswith("ss://"):
        return _parse_ss(uri)
    else:
        scheme = uri.split("://")[0] if "://" in uri else uri[:20]
        raise ValueError(f"Unsupported URI scheme: {scheme}")


def _parse_vless(uri: str) -> ConfigInfo:
    """Parse VLESS URI: vless://uuid@host:port?params#remark"""
    # Split off fragment (remark)
    remark = ""
    if "#" in uri:
        uri, fragment = uri.rsplit("#", 1)
        remark = urllib.parse.unquote(fragment)

    # Remove scheme
    body = uri[len("vless://"):]

    # Split user@host:port?query
    if "@" not in body:
        raise ValueError("Invalid VLESS URI: missing @ separator")

    userinfo, rest = body.split("@", 1)
    uuid = urllib.parse.unquote(userinfo)

    # Parse host:port and query
    if "?" in rest:
        hostport, query_str = rest.split("?", 1)
    else:
        hostport, query_str = rest, ""

    host, port = _parse_hostport(hostport)
    params = urllib.parse.parse_qs(query_str, keep_blank_values=True)

    def p(key, default=""):
        vals = params.get(key, [default])
        return vals[0] if vals else default

    transport = p("type", "tcp")
    security = p("security", "none")
    sni = p("sni", "")
    host_header = p("host", "")
    path = p("path", "")
    encryption = p("encryption", "none")
    header_type = p("headerType", "")
    fingerprint = p("fp", "")
    alpn = p("alpn", "")
    flow = p("flow", "")

    # Reality-specific parameters
    extra = {}
    pbk = p("pbk", "")
    sid = p("sid", "")
    spx = p("spx", "")
    if pbk:
        extra["pbk"] = pbk
    if sid:
        extra["sid"] = sid
    if spx:
        extra["spx"] = spx

    return ConfigInfo(
        raw_uri=uri + ("#" + urllib.parse.quote(remark) if remark else ""),
        protocol="vless",
        uuid_or_password=uuid,
        server_host=host,
        server_port=port,
        transport=transport,
        tls=security if security else "none",
        sni=sni,
        host_header=host_header,
        path=path,
        encryption=encryption,
        header_type=header_type,
        fingerprint=fingerprint,
        alpn=alpn,
        flow=flow,
        remark=remark,
        extra=extra,
        host_is_ip=_is_ip_address(host),
    )


def _parse_vmess(uri: str) -> ConfigInfo:
    """Parse VMess URI: vmess://BASE64_JSON"""
    body = uri[len("vmess://"):]
    decoded = _safe_b64decode(body)
    try:
        data = json.loads(decoded)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid VMess JSON: {e}")

    host = str(data.get("add", ""))
    port = int(data.get("port", 0))
    uuid = str(data.get("id", ""))
    transport = str(data.get("net", "tcp"))
    tls = str(data.get("tls", ""))
    sni = str(data.get("sni", ""))
    host_header = str(data.get("host", ""))
    path = str(data.get("path", ""))
    encryption = str(data.get("scy", "auto"))
    header_type = str(data.get("type", ""))
    fingerprint = str(data.get("fp", ""))
    alpn = str(data.get("alpn", ""))
    remark = str(data.get("ps", ""))
    alter_id = data.get("aid", 0)

    # SNI fallback
    if not sni and host_header:
        sni = host_header

    return ConfigInfo(
        raw_uri=uri,
        protocol="vmess",
        uuid_or_password=uuid,
        server_host=host,
        server_port=port,
        transport=transport,
        tls=tls if tls else "none",
        sni=sni,
        host_header=host_header,
        path=path,
        encryption=encryption,
        header_type=header_type,
        fingerprint=fingerprint,
        alpn=alpn,
        remark=remark,
        extra={"alterId": alter_id},
        host_is_ip=_is_ip_address(host),
    )


def _parse_trojan(uri: str) -> ConfigInfo:
    """Parse Trojan URI: trojan://password@host:port?params#remark"""
    remark = ""
    if "#" in uri:
        uri, fragment = uri.rsplit("#", 1)
        remark = urllib.parse.unquote(fragment)

    body = uri[len("trojan://"):]

    if "@" not in body:
        raise ValueError("Invalid Trojan URI: missing @ separator")

    password, rest = body.split("@", 1)
    password = urllib.parse.unquote(password)

    if "?" in rest:
        hostport, query_str = rest.split("?", 1)
    else:
        hostport, query_str = rest, ""

    host, port = _parse_hostport(hostport)
    params = urllib.parse.parse_qs(query_str, keep_blank_values=True)

    def p(key, default=""):
        vals = params.get(key, [default])
        return vals[0] if vals else default

    transport = p("type", "tcp")
    security = p("security", "tls")  # Trojan defaults to TLS
    sni = p("sni", "")
    host_header = p("host", "")
    path = p("path", "")
    header_type = p("headerType", "")
    fingerprint = p("fp", "")
    alpn = p("alpn", "")

    return ConfigInfo(
        raw_uri=uri,
        protocol="trojan",
        uuid_or_password=password,
        server_host=host,
        server_port=port,
        transport=transport,
        tls=security if security else "tls",
        sni=sni if sni else host,
        host_header=host_header,
        path=path,
        header_type=header_type,
        fingerprint=fingerprint,
        alpn=alpn,
        remark=remark,
        host_is_ip=_is_ip_address(host),
    )


def _parse_ss(uri: str) -> ConfigInfo:
    """Parse Shadowsocks URI.

    Supports two formats:
    - SIP002: ss://BASE64(method:password)@host:port#remark
    - Legacy: ss://BASE64(method:password@host:port)#remark
    """
    remark = ""
    if "#" in uri:
        uri, fragment = uri.rsplit("#", 1)
        remark = urllib.parse.unquote(fragment)

    body = uri[len("ss://"):]

    # Try SIP002 format first (has @ after base64 part)
    if "@" in body:
        encoded_part, hostport = body.split("@", 1)
        try:
            decoded = _safe_b64decode(encoded_part)
            if ":" in decoded:
                method, password = decoded.split(":", 1)
                host, port = _parse_hostport(hostport)
                return ConfigInfo(
                    raw_uri=uri,
                    protocol="ss",
                    uuid_or_password=password,
                    server_host=host,
                    server_port=port,
                    encryption=method,
                    remark=remark,
                    host_is_ip=_is_ip_address(host),
                )
        except Exception:
            pass  # Fall through to legacy format

    # Legacy format: entire thing is base64
    try:
        decoded = _safe_b64decode(body)
        # Format: method:password@host:port
        if "@" in decoded:
            method_pass, hostport = decoded.rsplit("@", 1)
            method, password = method_pass.split(":", 1)
            host, port = _parse_hostport(hostport)
            return ConfigInfo(
                raw_uri=uri,
                protocol="ss",
                uuid_or_password=password,
                server_host=host,
                server_port=port,
                encryption=method,
                remark=remark,
                host_is_ip=_is_ip_address(host),
            )
    except Exception:
        pass

    raise ValueError("Could not parse Shadowsocks URI (tried SIP002 and legacy formats)")


def _parse_hostport(hostport: str) -> tuple:
    """Parse host:port string, handling IPv6 brackets."""
    hostport = hostport.strip("/")

    # IPv6: [::1]:443
    if hostport.startswith("["):
        bracket_end = hostport.index("]")
        host = hostport[1:bracket_end]
        port_str = hostport[bracket_end + 2:]  # skip ]:
    elif ":" in hostport:
        parts = hostport.rsplit(":", 1)
        host = parts[0]
        port_str = parts[1]
    else:
        raise ValueError(f"Invalid host:port format: {hostport}")

    try:
        port = int(port_str)
    except ValueError:
        raise ValueError(f"Invalid port number: {port_str}")

    return host, port


def _safe_b64decode(s: str) -> str:
    """Decode base64 with auto-padding and URL-safe variant support."""
    s = s.strip()
    # Add padding if needed
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding

    # Try standard base64 first
    try:
        return base64.b64decode(s).decode("utf-8")
    except Exception:
        pass

    # Try URL-safe base64
    try:
        return base64.urlsafe_b64decode(s).decode("utf-8")
    except Exception:
        pass

    raise ValueError("Failed to decode base64 content")


def _is_ip_address(host: str) -> bool:
    """Check if string is an IPv4 or IPv6 address."""
    # Simple IPv4 check
    parts = host.split(".")
    if len(parts) == 4:
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            pass
    # IPv6 check (contains colons, no dots usually)
    if ":" in host and "." not in host:
        return True
    return False
