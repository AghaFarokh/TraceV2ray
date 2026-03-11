"""Xray-core process management and configuration generation.

Handles finding xray binary, generating JSON configs from parsed URIs,
starting/stopping xray-core, and running exit IP detection tests.
"""

import json
import os
import platform
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass

from . import constants
from .config_parser import ConfigInfo
from .geo_lookup import GeoInfo, lookup_single
from .socks_client import http_get_through_socks, http_get_with_headers_through_socks, Socks5Error


@dataclass
class ConnectionTestResult:
    """Result of a full connection test through xray-core."""

    success: bool = False
    exit_ip: str | None = None
    exit_geo: GeoInfo | None = None
    entry_ip: str = ""
    entry_geo: GeoInfo | None = None
    connection_time_ms: float = 0.0
    error: str | None = None
    xray_log_snippet: str = ""
    xray_version: str = ""
    response_headers: dict | None = None


def find_xray_binary() -> str | None:
    """Search for xray-core binary in common locations.

    Search order:
    1. Same directory as this executable (or script)
    2. Current working directory
    3. System PATH
    """
    # Determine the directory of the running program
    if getattr(sys, "frozen", False):
        # PyInstaller frozen executable
        exe_dir = os.path.dirname(sys.executable)
    else:
        exe_dir = os.path.dirname(os.path.abspath(__file__))
        # Also check parent dir (project root when running as package)
        parent_dir = os.path.dirname(exe_dir)

    search_dirs = [exe_dir]
    if not getattr(sys, "frozen", False):
        search_dirs.append(os.path.dirname(exe_dir))
    search_dirs.append(os.getcwd())

    for directory in search_dirs:
        for name in constants.XRAY_BINARY_NAMES:
            path = os.path.join(directory, name)
            if os.path.isfile(path):
                return os.path.abspath(path)

    # Check PATH
    for name in constants.XRAY_BINARY_NAMES:
        for path_dir in os.environ.get("PATH", "").split(os.pathsep):
            path = os.path.join(path_dir, name)
            if os.path.isfile(path):
                return os.path.abspath(path)

    return None


def get_xray_version(xray_path: str) -> str:
    """Get xray-core version string."""
    try:
        result = subprocess.run(
            [xray_path, "version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        # First line typically: "Xray 1.8.24 (Xray, Penetrates Everything.)"
        for line in result.stdout.splitlines():
            if "xray" in line.lower() or "v2ray" in line.lower():
                return line.strip()
        return result.stdout.splitlines()[0].strip() if result.stdout else "unknown"
    except Exception:
        return "unknown"


def generate_xray_config(config: ConfigInfo) -> dict:
    """Generate a minimal xray-core JSON config from parsed ConfigInfo.

    Creates a config with:
    - SOCKS5 inbound on 127.0.0.1:XRAY_SOCKS_PORT
    - Outbound matching the parsed protocol/transport/TLS settings
    """
    outbound = _build_outbound(config)

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "port": constants.XRAY_SOCKS_PORT,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"udp": True},
            }
        ],
        "outbounds": [outbound],
    }


def run_connection_test(config: ConfigInfo, entry_ip: str = "", entry_geo: GeoInfo | None = None) -> ConnectionTestResult:
    """Run a full connection test through xray-core.

    1. Find xray binary
    2. Generate and write config
    3. Start xray process
    4. Detect exit IP through the proxy
    5. Geo-lookup exit IP
    6. Clean up
    """
    result = ConnectionTestResult(entry_ip=entry_ip, entry_geo=entry_geo)
    xray_path = find_xray_binary()

    if not xray_path:
        result.error = "xray-core binary not found (place xray.exe in the same directory)"
        return result

    result.xray_version = get_xray_version(xray_path)

    # Generate config
    try:
        xray_config = generate_xray_config(config)
    except Exception as e:
        result.error = f"Failed to generate xray config: {e}"
        return result

    # Write config to temp file
    config_file = None
    process = None

    try:
        config_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", prefix="tracev2ray_", delete=False
        )
        json.dump(xray_config, config_file, indent=2)
        config_file.close()

        # Start xray process
        process = _start_xray_process(xray_path, config_file.name)

        # Wait for SOCKS proxy to become available
        if not _wait_for_proxy(constants.XRAY_SOCKS_PORT, constants.XRAY_STARTUP_TIMEOUT):
            # Capture stderr for debugging
            stderr = ""
            try:
                process.terminate()
                _, stderr_bytes = process.communicate(timeout=3)
                stderr = stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else ""
            except Exception:
                pass
            result.error = "xray-core started but SOCKS proxy not available"
            result.xray_log_snippet = stderr[-500:] if stderr else ""
            return result

        # Detect exit IP and capture response headers
        start = time.time()
        exit_ip, resp_headers = _detect_exit_ip_and_headers(constants.XRAY_SOCKS_PORT)
        result.connection_time_ms = (time.time() - start) * 1000
        result.response_headers = resp_headers

        if exit_ip:
            result.success = True
            result.exit_ip = exit_ip
            result.exit_geo = lookup_single(exit_ip)
        else:
            result.error = "Connected to proxy but could not detect exit IP"

    except Exception as e:
        result.error = f"Connection test failed: {e}"
    finally:
        if process:
            _cleanup_process(process)
        elif config_file and os.path.exists(config_file.name):
            try:
                os.unlink(config_file.name)
            except Exception:
                pass

    return result


def _build_outbound(config: ConfigInfo) -> dict:
    """Build xray outbound config from ConfigInfo."""
    protocol = config.protocol

    if protocol == "vless":
        settings = _build_vless_settings(config)
    elif protocol == "vmess":
        settings = _build_vmess_settings(config)
    elif protocol == "trojan":
        settings = _build_trojan_settings(config)
    elif protocol == "ss":
        settings = _build_ss_settings(config)
    else:
        raise ValueError(f"Unsupported protocol: {protocol}")

    outbound = {
        "tag": "proxy",
        "protocol": protocol if protocol != "ss" else "shadowsocks",
        "settings": settings,
        "streamSettings": _build_stream_settings(config),
    }

    return outbound


def _build_vless_settings(config: ConfigInfo) -> dict:
    user = {
        "id": config.uuid_or_password,
        "encryption": config.encryption or "none",
    }
    if config.flow:
        user["flow"] = config.flow

    return {
        "vnext": [
            {
                "address": config.server_host,
                "port": config.server_port,
                "users": [user],
            }
        ]
    }


def _build_vmess_settings(config: ConfigInfo) -> dict:
    return {
        "vnext": [
            {
                "address": config.server_host,
                "port": config.server_port,
                "users": [
                    {
                        "id": config.uuid_or_password,
                        "alterId": config.extra.get("alterId", 0),
                        "security": config.encryption or "auto",
                    }
                ],
            }
        ]
    }


def _build_trojan_settings(config: ConfigInfo) -> dict:
    return {
        "servers": [
            {
                "address": config.server_host,
                "port": config.server_port,
                "password": config.uuid_or_password,
            }
        ]
    }


def _build_ss_settings(config: ConfigInfo) -> dict:
    return {
        "servers": [
            {
                "address": config.server_host,
                "port": config.server_port,
                "method": config.encryption,
                "password": config.uuid_or_password,
            }
        ]
    }


def _build_stream_settings(config: ConfigInfo) -> dict:
    """Build streamSettings from transport and TLS info."""
    stream = {
        "network": config.transport,
    }

    # Transport-specific settings
    transport = config.transport

    if transport == "ws":
        ws_settings = {}
        if config.path:
            ws_settings["path"] = config.path
        if config.host_header:
            ws_settings["headers"] = {"Host": config.host_header}
        if ws_settings:
            stream["wsSettings"] = ws_settings

    elif transport == "grpc":
        grpc_settings = {}
        if config.path:
            grpc_settings["serviceName"] = config.path
        if grpc_settings:
            stream["grpcSettings"] = grpc_settings

    elif transport == "tcp":
        if config.header_type == "http":
            tcp_settings = {
                "header": {
                    "type": "http",
                    "request": {
                        "version": "1.1",
                        "method": "GET",
                        "path": [config.path or "/"],
                        "headers": {
                            "Host": [config.host_header] if config.host_header else [],
                            "User-Agent": [
                                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                "AppleWebKit/537.36 (KHTML, like Gecko) "
                                "Chrome/120.0.0.0 Safari/537.36"
                            ],
                            "Accept-Encoding": ["gzip, deflate"],
                            "Connection": ["keep-alive"],
                            "Pragma": "no-cache",
                        },
                    },
                }
            }
            stream["tcpSettings"] = tcp_settings

    elif transport == "h2" or transport == "http":
        h2_settings = {}
        if config.path:
            h2_settings["path"] = config.path
        if config.host_header:
            h2_settings["host"] = [config.host_header]
        if h2_settings:
            stream["httpSettings"] = h2_settings

    elif transport == "httpupgrade":
        settings = {}
        if config.path:
            settings["path"] = config.path
        if config.host_header:
            settings["host"] = config.host_header
        if settings:
            stream["httpupgradeSettings"] = settings

    elif transport == "kcp":
        kcp_settings = {}
        if config.header_type:
            kcp_settings["header"] = {"type": config.header_type}
        if config.path:
            kcp_settings["seed"] = config.path
        if kcp_settings:
            stream["kcpSettings"] = kcp_settings

    # Security / TLS settings
    security = config.tls
    if security in ("tls", ""):
        if security == "tls" or (config.sni and security != "reality"):
            stream["security"] = "tls"
            tls_settings = {}
            if config.sni:
                tls_settings["serverName"] = config.sni
            if config.fingerprint:
                tls_settings["fingerprint"] = config.fingerprint
            if config.alpn:
                tls_settings["alpn"] = config.alpn.split(",")
            tls_settings["allowInsecure"] = False
            stream["tlsSettings"] = tls_settings
        else:
            stream["security"] = "none"

    elif security == "reality":
        stream["security"] = "reality"
        reality_settings = {}
        if config.sni:
            reality_settings["serverName"] = config.sni
        if config.fingerprint:
            reality_settings["fingerprint"] = config.fingerprint
        if config.extra.get("pbk"):
            reality_settings["publicKey"] = config.extra["pbk"]
        if config.extra.get("sid"):
            reality_settings["shortId"] = config.extra["sid"]
        if config.extra.get("spx"):
            reality_settings["spiderX"] = config.extra["spx"]
        stream["realitySettings"] = reality_settings

    else:
        stream["security"] = "none"

    return stream


def start_proxy_session(config: ConfigInfo) -> "subprocess.Popen | None":
    """Start xray-core and wait for the SOCKS proxy to become ready.

    Returns the Popen process if successful, or None if startup failed.
    The caller MUST call stop_proxy_session() when done.
    """
    xray_path = find_xray_binary()
    if not xray_path:
        return None

    try:
        xray_config = generate_xray_config(config)
    except Exception:
        return None

    try:
        config_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", prefix="tracev2ray_", delete=False
        )
        json.dump(xray_config, config_file, indent=2)
        config_file.close()
        config_file_path = config_file.name
    except Exception:
        return None

    process = _start_xray_process(xray_path, config_file_path)
    process._config_file = config_file_path  # type: ignore

    if not _wait_for_proxy(constants.XRAY_SOCKS_PORT, constants.XRAY_STARTUP_TIMEOUT):
        _cleanup_process(process)
        return None

    return process


def stop_proxy_session(process: "subprocess.Popen") -> None:
    """Stop a proxy session started by start_proxy_session()."""
    if process:
        _cleanup_process(process)


def detect_exit_ip_and_headers(socks_port: int) -> tuple:
    """Public wrapper: detect exit IP and capture response headers.

    Returns (exit_ip: str | None, response_headers: dict).
    """
    return _detect_exit_ip_and_headers(socks_port)


def _cleanup_process(process: subprocess.Popen) -> None:
    """Terminate process and delete its temp config file."""
    config_file = getattr(process, "_config_file", None)
    try:
        process.terminate()
        process.wait(timeout=5)
    except Exception:
        try:
            process.kill()
        except Exception:
            pass
    if config_file and os.path.exists(config_file):
        try:
            os.unlink(config_file)
        except Exception:
            pass


def _start_xray_process(xray_path: str, config_path: str) -> subprocess.Popen:
    """Start xray-core as a subprocess."""
    kwargs = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
    }

    # Prevent console window on Windows
    if platform.system() == "Windows":
        kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW

    return subprocess.Popen(
        [xray_path, "run", "-config", config_path],
        **kwargs,
    )


def _wait_for_proxy(port: int, timeout: float) -> bool:
    """Wait for SOCKS proxy to become available on localhost."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            sock.connect(("127.0.0.1", port))
            sock.close()
            return True
        except (ConnectionRefusedError, socket.timeout, OSError):
            time.sleep(0.5)
    return False


def _detect_exit_ip_and_headers(socks_port: int) -> tuple:
    """Detect exit IP and capture response headers through SOCKS5 proxy.

    Returns:
        Tuple of (exit_ip: str | None, response_headers: dict | None).
    """
    all_headers = {}

    for service in constants.IP_ECHO_SERVICES:
        try:
            headers, body = http_get_with_headers_through_socks(
                "127.0.0.1",
                socks_port,
                service["host"],
                service["path"],
                timeout=constants.SOCKS_CONNECT_TIMEOUT,
            )

            # Accumulate headers from all successful responses
            if headers:
                all_headers.update(headers)

            if service["format"] == "json":
                data = json.loads(body)
                ip = data.get(service.get("key", "query"), "")
            else:
                ip = body.strip()

            # Validate it looks like an IP
            if ip and _looks_like_ip(ip):
                return ip, all_headers if all_headers else None

        except Exception:
            continue

    return None, all_headers if all_headers else None


def _looks_like_ip(s: str) -> bool:
    """Quick check if string looks like an IPv4 address."""
    parts = s.strip().split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False
