"""TraceV2ray - Main entry point and orchestrator.

Runs all diagnostic steps automatically and produces a comprehensive report.
"""

import argparse
import datetime
import os
import sys
import time

from . import __version__
from . import constants
from .config_parser import ConfigInfo, parse_uri
from .dns_resolver import DnsResult, resolve_hostname
from .traceroute import run_traceroute
from .geo_lookup import lookup_batch
from .cdn_detect import detect_cdn
from .xray_manager import find_xray_binary, run_connection_test
from .report import DiagnosticResult, generate_report, save_report


def main():
    """Main entry point."""
    _setup_console()

    parser = argparse.ArgumentParser(
        prog="TraceV2ray",
        description="Network route diagnostic tool for V2Ray configurations",
    )
    parser.add_argument(
        "config",
        nargs="?",
        help="V2Ray config URI (vless://, vmess://, trojan://, ss://) or path to a text file containing the URI",
    )
    parser.add_argument(
        "--no-connection-test",
        action="store_true",
        help="Skip the xray-core connection test even if xray-core is available",
    )
    parser.add_argument(
        "--traceroute-timeout",
        type=int,
        default=120,
        help="Traceroute timeout in seconds (default: 120)",
    )
    args = parser.parse_args()

    _print_banner()

    # Get the config URI
    uri = _get_config_uri(args.config)

    # Initialize result
    result = DiagnosticResult(
        timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )

    # Step 1: Parse config
    config = None
    if uri:
        _status("Parsing V2Ray configuration...")
        try:
            config = parse_uri(uri)
            result.config = config
            _ok(f"Protocol: {config.display_protocol} | Server: {config.server_host}:{config.server_port}")
        except ValueError as e:
            _error(f"Config parsing failed: {e}")
            result.errors.append(f"Config parsing: {e}")

    # Step 2: DNS Resolution
    if config and not config.host_is_ip:
        _status(f"Resolving DNS for {config.server_host}...")
        dns_result = resolve_hostname(config.server_host)
        result.dns_results.append(dns_result)
        if dns_result.ips:
            _ok(f"Resolved to: {', '.join(dns_result.ips)} ({dns_result.resolution_time_ms:.0f}ms)")
            if dns_result.cname_chain:
                _info(f"CNAME chain: {' -> '.join([config.server_host] + dns_result.cname_chain)}")
        elif dns_result.error:
            _error(f"DNS failed: {dns_result.error}")
            result.errors.append(f"DNS: {dns_result.error}")
    elif config and config.host_is_ip:
        _info(f"Server uses direct IP: {config.server_host} (no DNS resolution needed)")
        # Create a dummy DNS result
        result.dns_results.append(DnsResult(
            hostname=config.server_host,
            ips=[config.server_host],
        ))

    # Step 3: Host Header DNS Resolution (if host header differs from server)
    host_header_dns = None
    if config and config.host_header and config.host_header != config.server_host:
        from .config_parser import _is_ip_address
        if not _is_ip_address(config.host_header):
            _status(f"Resolving DNS for host header: {config.host_header}...")
            host_header_dns = resolve_hostname(config.host_header)
            result.host_header_dns = host_header_dns
            if host_header_dns.ips:
                _ok(f"Host header resolved to: {', '.join(host_header_dns.ips)} ({host_header_dns.resolution_time_ms:.0f}ms)")
                if host_header_dns.cname_chain:
                    _info(f"CNAME chain: {' -> '.join([config.host_header] + host_header_dns.cname_chain)}")
            elif host_header_dns.error:
                _info(f"Host header DNS failed: {host_header_dns.error} (not critical)")

    # Step 4: Traceroute
    target_ips = []
    if result.dns_results:
        for dns in result.dns_results:
            if dns.ips:
                target_ips.append(dns.ips[0])  # Trace to primary IP

    if target_ips:
        for target_ip in target_ips:
            _status(f"Running traceroute to {target_ip} (this may take a while)...")
            trace_result = run_traceroute(target_ip, overall_timeout_s=args.traceroute_timeout)
            result.traceroute_results.append(trace_result)

            if trace_result.hops:
                hop_count = len(trace_result.hops)
                completed = "completed" if trace_result.completed else "incomplete"
                _ok(f"Traceroute {completed}: {hop_count} hops ({trace_result.duration_seconds:.1f}s)")
            elif trace_result.error:
                _error(f"Traceroute: {trace_result.error}")
                result.errors.append(f"Traceroute: {trace_result.error}")
    else:
        _info("No target IP for traceroute (DNS resolution failed or no config provided)")

    # Step 5: IP Geolocation
    all_ips = set()
    for dns in result.dns_results:
        all_ips.update(dns.ips)
    for trace in result.traceroute_results:
        for hop in trace.hops:
            if hop.ip:
                all_ips.add(hop.ip)
    # Include host header DNS IPs
    if host_header_dns and host_header_dns.ips:
        all_ips.update(host_header_dns.ips)

    if all_ips:
        _status(f"Looking up geolocation for {len(all_ips)} IPs...")
        try:
            result.geo_data = lookup_batch(list(all_ips))
            _ok(f"Geolocation data retrieved for {len(result.geo_data)} IPs")
        except Exception as e:
            _error(f"Geolocation lookup failed: {e}")
            result.errors.append(f"Geolocation: {e}")

    # Step 6: Full Connection Test (if xray-core available) — runs BEFORE routing detection
    if config and not args.no_connection_test:
        xray_path = find_xray_binary()
        if xray_path:
            _status(f"xray-core found. Running full connection test...")

            # Get entry IP for comparison
            entry_ip = ""
            entry_geo = None
            if result.dns_results and result.dns_results[0].ips:
                entry_ip = result.dns_results[0].ips[0]
                entry_geo = result.geo_data.get(entry_ip)

            conn_result = run_connection_test(config, entry_ip, entry_geo)
            result.connection_test = conn_result

            if conn_result.success:
                _ok(f"Connection successful! Exit IP: {conn_result.exit_ip}")
                if conn_result.exit_geo:
                    g = conn_result.exit_geo
                    _info(f"Exit location: {g.country} ({g.city}), {g.org_display}")
                if conn_result.entry_ip and conn_result.exit_ip:
                    if conn_result.entry_ip != conn_result.exit_ip:
                        _info("Entry and exit IPs differ (traffic is relayed/tunneled)")
                    else:
                        _info("Entry and exit IPs are the same (direct proxy)")
            else:
                _error(f"Connection test failed: {conn_result.error}")
                result.errors.append(f"Connection test: {conn_result.error}")
        else:
            _info("xray-core not found in program directory (skipping connection test)")
            _info("To enable: place xray.exe next to TraceV2ray.exe")

    # Step 7: Routing Pattern Detection (uses connection test response headers)
    if config:
        _status("Analyzing routing pattern...")
        try:
            response_headers = None
            if result.connection_test and result.connection_test.response_headers:
                response_headers = result.connection_test.response_headers

            result.cdn_info = detect_cdn(
                config, result.geo_data, result.dns_results,
                host_header_dns=host_header_dns,
                response_headers=response_headers,
                connection_test=result.connection_test,
            )

            cdn = result.cdn_info
            pattern_labels = {
                "direct": "Direct connection",
                "cdn_fronted": f"CDN-Fronted ({cdn.provider})",
                "cloudflare_workers": "Cloudflare Workers",
                "cloudflare_pages": "Cloudflare Pages",
                "cloudflare_tunnel": "Cloudflare Tunnel",
                "http_obfuscation_relay": "HTTP Obfuscation Relay",
                "ip_forwarding_relay": "IP Forwarding Relay",
                "reality": "Reality/XTLS",
                "multi_layer": f"Multi-Layer ({cdn.provider})",
            }
            label = pattern_labels.get(cdn.routing_pattern, cdn.routing_pattern)
            _ok(f"Routing: {label} [{cdn.confidence} confidence]")
        except Exception as e:
            _error(f"Routing detection failed: {e}")
            result.errors.append(f"Routing detection: {e}")

    # Step 8: Generate Report
    _status("Generating report...")
    report_text = generate_report(result)

    # Print report
    print("\n")
    print(report_text)

    # Save to file
    try:
        filename = save_report(report_text)
        print(f"\n  Report saved to: {os.path.abspath(filename)}")
        print(f"  Send this file to your support contact for analysis.\n")
    except Exception as e:
        _error(f"Could not save report file: {e}")
        print("\n  (Copy the report text above instead)\n")

    # Keep console open on Windows
    if getattr(sys, "frozen", False) and sys.platform == "win32":
        input("Press Enter to exit...")


def _get_config_uri(arg: str | None) -> str | None:
    """Get V2Ray config URI from argument, file, or user input."""
    if arg:
        # Check if it's a file path
        if os.path.isfile(arg):
            try:
                with open(arg, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                # Find the first line that looks like a V2Ray URI
                for line in content.splitlines():
                    line = line.strip()
                    if any(line.startswith(s) for s in ["vless://", "vmess://", "trojan://", "ss://"]):
                        return line
                _error(f"No V2Ray URI found in file: {arg}")
            except Exception as e:
                _error(f"Could not read file: {e}")
        else:
            return arg

    # Interactive prompt
    print(f"  Paste your V2Ray config URI (or press Enter to skip):")
    print(f"  Supported: vless://, vmess://, trojan://, ss://\n")
    try:
        uri = input("  > ").strip().strip('"').strip("'")
        if uri:
            return uri
    except (EOFError, KeyboardInterrupt):
        pass

    _info("No config provided. Running basic diagnostics only.\n")
    return None


def _setup_console():
    """Configure console for proper Unicode output."""
    if sys.platform == "win32":
        try:
            # Enable UTF-8 output on Windows
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def _print_banner():
    """Print the startup banner."""
    print(f"\n  {constants.TOOL_NAME} v{constants.VERSION}")
    print(f"  Network Route Diagnostic Tool for V2Ray")
    print(f"  {'=' * 50}\n")


def _status(msg: str):
    print(f"  [..] {msg}")


def _ok(msg: str):
    print(f"  [OK] {msg}")


def _error(msg: str):
    print(f"  [!!] {msg}")


def _info(msg: str):
    print(f"  [--] {msg}")


if __name__ == "__main__":
    main()
