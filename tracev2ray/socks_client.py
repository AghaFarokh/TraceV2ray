"""Minimal SOCKS5 client using only stdlib.

Supports SOCKS5 CONNECT with no authentication (for local xray-core proxy).
Reference: RFC 1928 (SOCKS Protocol Version 5)
"""

import socket
import struct


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

    Args:
        proxy_host: SOCKS5 proxy address (e.g. "127.0.0.1")
        proxy_port: SOCKS5 proxy port (e.g. 10808)
        dest_host: Destination hostname or IP
        dest_port: Destination port
        timeout: Connection timeout in seconds

    Returns:
        Connected socket tunneled through the proxy.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        # Connect to proxy
        sock.connect((proxy_host, proxy_port))

        # Greeting: version=5, 1 auth method, method=0 (no auth)
        sock.sendall(b"\x05\x01\x00")

        # Auth response: version(1) + method(1)
        resp = _recv_exact(sock, 2)
        if resp[0] != 0x05:
            raise Socks5Error(f"Unexpected SOCKS version: {resp[0]}")
        if resp[1] != 0x00:
            raise Socks5Error(f"SOCKS auth method rejected (got {resp[1]})")

        # Connect request
        # VER(1) + CMD(1) + RSV(1) + ATYP(1) + DST.ADDR(var) + DST.PORT(2)
        req = b"\x05\x01\x00"  # version=5, cmd=CONNECT, reserved=0

        # Address type: domain name (0x03)
        encoded_host = dest_host.encode("ascii")
        req += b"\x03" + struct.pack("!B", len(encoded_host)) + encoded_host
        req += struct.pack("!H", dest_port)
        sock.sendall(req)

        # Connect response: VER(1) + REP(1) + RSV(1) + ATYP(1) + BND.ADDR(var) + BND.PORT(2)
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

        # Skip bound address
        atyp = resp[3]
        if atyp == 0x01:  # IPv4
            _recv_exact(sock, 4 + 2)
        elif atyp == 0x03:  # Domain
            domain_len = _recv_exact(sock, 1)[0]
            _recv_exact(sock, domain_len + 2)
        elif atyp == 0x04:  # IPv6
            _recv_exact(sock, 16 + 2)

        return sock

    except Exception:
        sock.close()
        raise


def http_get_through_socks(
    proxy_host: str,
    proxy_port: int,
    host: str,
    path: str,
    timeout: float = 15.0,
) -> str:
    """Make a simple HTTP GET request through a SOCKS5 proxy.

    Args:
        proxy_host: SOCKS5 proxy address
        proxy_port: SOCKS5 proxy port
        host: HTTP host to connect to
        path: HTTP path (e.g. "/json/?fields=query")
        timeout: Timeout in seconds

    Returns:
        Response body as string.
    """
    sock = socks5_connect(proxy_host, proxy_port, host, 80, timeout)

    try:
        # Send HTTP request
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: TraceV2ray/1.0\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        sock.sendall(request.encode("utf-8"))

        # Read response
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break

        text = response.decode("utf-8", errors="replace")

        # Split headers and body
        if "\r\n\r\n" in text:
            _, body = text.split("\r\n\r\n", 1)
            return body.strip()
        return text.strip()

    finally:
        sock.close()


def http_get_with_headers_through_socks(
    proxy_host: str,
    proxy_port: int,
    host: str,
    path: str,
    timeout: float = 15.0,
) -> tuple:
    """Make HTTP GET through SOCKS5, returning (headers_dict, body_str).

    Returns:
        Tuple of (headers: dict[str, str], body: str).
        Header keys are lowercase.
    """
    sock = socks5_connect(proxy_host, proxy_port, host, 80, timeout)

    try:
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: TraceV2ray/1.0\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        sock.sendall(request.encode("utf-8"))

        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
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

        return headers, body.strip()

    finally:
        sock.close()


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes from socket."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise Socks5Error("Connection closed while reading")
        data += chunk
    return data
