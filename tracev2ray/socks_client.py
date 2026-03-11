"""Minimal SOCKS5 client using only stdlib.

Supports SOCKS5 CONNECT with no authentication (for local xray-core proxy).
Reference: RFC 1928 (SOCKS Protocol Version 5)
"""

import socket
import ssl
import struct
import time


class Socks5Error(Exception):
    """SOCKS5 protocol error."""
    pass


def socks5_connect(
    proxy_host: str,
    proxy_port: int,
    dest_host: str,
    dest_port: int,
    timeout: float = 10.0,
) -> socket.socket:
    """Establish a TCP connection through a SOCKS5 proxy.

    Returns:
        Connected socket tunneled through the proxy (raw TCP).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((proxy_host, proxy_port))

        # SOCKS5 greeting: version=5, 1 auth method, no-auth
        sock.sendall(b"\x05\x01\x00")
        resp = _recv_exact(sock, 2)
        if resp[0] != 0x05:
            raise Socks5Error(f"Unexpected SOCKS version: {resp[0]}")
        if resp[1] != 0x00:
            raise Socks5Error(f"SOCKS auth rejected (method {resp[1]})")

        # CONNECT request
        encoded_host = dest_host.encode("ascii")
        req = (
            b"\x05\x01\x00"                                 # VER CMD RSV
            + b"\x03"                                        # ATYP=domain
            + struct.pack("!B", len(encoded_host))           # domain length
            + encoded_host                                   # domain
            + struct.pack("!H", dest_port)                   # port
        )
        sock.sendall(req)

        # CONNECT response
        resp = _recv_exact(sock, 4)
        if resp[1] != 0x00:
            errors = {
                0x01: "General SOCKS server failure",
                0x02: "Connection not allowed",
                0x03: "Network unreachable",
                0x04: "Host unreachable",
                0x05: "Connection refused",
                0x06: "TTL expired",
                0x07: "Command not supported",
                0x08: "Address type not supported",
            }
            raise Socks5Error(errors.get(resp[1], f"Unknown error: {resp[1]}"))

        # Consume bound address
        atyp = resp[3]
        if atyp == 0x01:
            _recv_exact(sock, 4 + 2)
        elif atyp == 0x03:
            domain_len = _recv_exact(sock, 1)[0]
            _recv_exact(sock, domain_len + 2)
        elif atyp == 0x04:
            _recv_exact(sock, 16 + 2)

        return sock

    except Exception:
        sock.close()
        raise


def socks5_connect_tls(
    proxy_host: str,
    proxy_port: int,
    dest_host: str,
    dest_port: int,
    timeout: float = 10.0,
    verify: bool = True,
) -> ssl.SSLSocket:
    """Establish a TLS connection through a SOCKS5 proxy.

    Tunnels TCP through the proxy then wraps with TLS.

    Returns:
        TLS-wrapped socket tunneled through the proxy.
    """
    raw_sock = socks5_connect(proxy_host, proxy_port, dest_host, dest_port, timeout)
    try:
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        ssl_sock = ctx.wrap_socket(raw_sock, server_hostname=dest_host)
        ssl_sock.settimeout(timeout)
        return ssl_sock
    except Exception:
        raw_sock.close()
        raise


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def http_get_through_socks(
    proxy_host: str,
    proxy_port: int,
    host: str,
    path: str,
    timeout: float = 15.0,
) -> str:
    """HTTP GET through SOCKS5. Returns response body string."""
    sock = socks5_connect(proxy_host, proxy_port, host, 80, timeout)
    try:
        _send_http_request(sock, "GET", host, path, port=80)
        _, body = _read_http_response(sock)
        return body
    finally:
        sock.close()


def https_get_through_socks(
    proxy_host: str,
    proxy_port: int,
    host: str,
    path: str,
    timeout: float = 15.0,
    port: int = 443,
) -> str:
    """HTTPS GET through SOCKS5. Returns response body string."""
    sock = socks5_connect_tls(proxy_host, proxy_port, host, port, timeout)
    try:
        _send_http_request(sock, "GET", host, path, port=port)
        _, body = _read_http_response(sock)
        return body
    finally:
        sock.close()


def http_get_with_headers_through_socks(
    proxy_host: str,
    proxy_port: int,
    host: str,
    path: str,
    timeout: float = 15.0,
) -> tuple:
    """HTTP GET through SOCKS5, returns (headers_dict, body_str).

    Header keys are lowercase.
    """
    sock = socks5_connect(proxy_host, proxy_port, host, 80, timeout)
    try:
        _send_http_request(sock, "GET", host, path, port=80)
        return _read_http_response(sock)
    finally:
        sock.close()


def https_get_with_headers_through_socks(
    proxy_host: str,
    proxy_port: int,
    host: str,
    path: str,
    timeout: float = 15.0,
    port: int = 443,
) -> tuple:
    """HTTPS GET through SOCKS5, returns (headers_dict, body_str).

    Header keys are lowercase.
    """
    sock = socks5_connect_tls(proxy_host, proxy_port, host, port, timeout)
    try:
        _send_http_request(sock, "GET", host, path, port=port)
        return _read_http_response(sock)
    finally:
        sock.close()


def tcp_connect_time_through_socks(
    proxy_host: str,
    proxy_port: int,
    dest_host: str,
    dest_port: int,
    timeout: float = 8.0,
) -> float | None:
    """Measure TCP connect time through proxy to a destination.

    Returns round-trip time in milliseconds, or None on failure.
    Used for latency triangulation to estimate exit server location.
    """
    start = time.monotonic()
    try:
        sock = socks5_connect(proxy_host, proxy_port, dest_host, dest_port, timeout)
        elapsed_ms = (time.monotonic() - start) * 1000
        sock.close()
        return elapsed_ms
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _send_http_request(sock, method: str, host: str, path: str, port: int = 80):
    """Send an HTTP/1.1 request over the socket."""
    host_header = host if port in (80, 443) else f"{host}:{port}"
    request = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"User-Agent: TraceV2ray/3.0\r\n"
        f"Accept: application/json, */*\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )
    sock.sendall(request.encode("utf-8"))


def _read_http_response(sock) -> tuple:
    """Read full HTTP response. Returns (headers_dict, body_str)."""
    response = b""
    while True:
        try:
            chunk = sock.recv(8192)
            if not chunk:
                break
            response += chunk
        except (socket.timeout, ssl.SSLError, OSError):
            break

    text = response.decode("utf-8", errors="replace")

    headers = {}
    body = text
    if "\r\n\r\n" in text:
        header_block, body = text.split("\r\n\r\n", 1)
        for line in header_block.split("\r\n")[1:]:  # Skip status line
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()

    # Handle chunked transfer encoding
    if headers.get("transfer-encoding", "").lower() == "chunked":
        body = _decode_chunked(body)

    return headers, body.strip()


def _decode_chunked(data: str) -> str:
    """Decode HTTP chunked transfer encoding."""
    result = []
    lines = data.split("\r\n")
    i = 0
    while i < len(lines):
        try:
            chunk_size = int(lines[i].strip(), 16)
            if chunk_size == 0:
                break
            i += 1
            if i < len(lines):
                result.append(lines[i])
        except ValueError:
            result.append(lines[i])
        i += 1
    return "\n".join(result)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes from socket."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise Socks5Error("Connection closed while reading")
        data += chunk
    return data
