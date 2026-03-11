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
from .geo_lookup import lookup_batch, ptr_lookup
from .cdn_detect import detect_cdn
from .xray_manager import (
    find_xray_binary, run_connection_test,
    start_proxy_session, stop_proxy_session,
    detect_exit_ip_and_headers, get_xray_version,
    ConnectionTestResult,
)
from .tls_inspect import inspect_tls
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
        help="V2Ray config URI (vless://, vmess://, trojan://, ss://) or path to a text file",
    )
    parser.add_argument(
        "--no-connection-test",
        action="store_true",
        help="Skip the xray-core connection test",
    )
    parser.add_argument(
        "--no-probe",
        action="store_true",
        help="Skip the deep proxy intelligence probe (BGP, Shodan, latency)",
    )
    parser.add_argument(
        "--traceroute-timeout",
        type=int,
        default=120,
        help="Traceroute timeout in seconds (default: 120)",
    )
    args = parser.parse_args()

    _print_banner()

    uri = _get_config_uri(args.config)

    result = DiagnosticResult(
        timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )

    # -------------------------------------------------------------------------
    # Step 1: Parse config
    # -------------------------------------------------------------------------
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

    # -------------------------------------------------------------------------
    # Step 2: DNS Resolution
    # -------------------------------------------------------------------------
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
        result.dns_results.append(DnsResult(
            hostname=config.server_host,
            ips=[config.server_host],
        ))

    # -------------------------------------------------------------------------
    # Step 3: Host Header DNS Resolution
    # -------------------------------------------------------------------------
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

    # -------------------------------------------------------------------------
    # Step 4: Traceroute
    # -------------------------------------------------------------------------
    target_ips = []
    if result.dns_results:
        for dns in result.dns_results:
            if dns.ips:
                target_ips.append(dns.ips[0])

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
        _info("No target IP for traceroute")

    # -------------------------------------------------------------------------
    # Step 5: IP Geolocation (direct)
    # -------------------------------------------------------------------------
    all_ips = set()
    for dns in result.dns_results:
        all_ips.update(dns.ips)
    for trace in result.traceroute_results:
        for hop in trace.hops:
            if hop.ip:
                all_ips.add(hop.ip)
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

    # -------------------------------------------------------------------------
    # Step 6: TLS Certificate Inspection (direct, no proxy)
    # -------------------------------------------------------------------------
    if config and config.tls in ("tls", "reality"):
        _status(f"Inspecting TLS certificate on {config.server_host}:{config.server_port}...")
        try:
            tls_sni = config.sni or (config.server_host if not config.host_is_ip else "")
            tls_info = inspect_tls(
                host=config.server_host,
                port=config.server_port,
                sni=tls_sni,
                timeout=10.0,
            )
            result.tls_info = tls_info
            if tls_info.error:
                _info(f"TLS inspection: {tls_info.error} (may be expected for Reality/obfuscated endpoints)")
            else:
                cn = tls_info.subject_cn or "(no CN)"
                issuer = tls_info.issuer_org or tls_info.issuer_cn or "unknown"
                _ok(f"TLS cert: CN={cn}, Issuer={issuer}, TLS={tls_info.tls_version}")
        except Exception as e:
            _info(f"TLS inspection failed: {e} (not critical)")

    # -------------------------------------------------------------------------
    # Step 7: Full Proxy Session — connection test + deep probe
    #
    # Start xray ONCE, reuse the same proxy port for both:
    #   7a. Connection test (exit IP, response headers)
    #   7b. Deep intelligence probe (BGP, Shodan, latency, XFF chain, geo via proxy)
    # -------------------------------------------------------------------------
    if config and not args.no_connection_test:
        xray_path = find_xray_binary()
        if not xray_path:
            _info("xray-core not found in program directory (skipping connection test & probe)")
            _info("To enable: place xray.exe next to TraceV2ray.exe")
        else:
            _status(f"xray-core found. Starting proxy session...")
            xray_process = start_proxy_session(config)

            if not xray_process:
                _error("Failed to start xray-core proxy")
                result.errors.append("xray-core failed to start")
            else:
                try:
                    xray_version = get_xray_version(xray_path)

                    # 7a: Connection test
                    _status("Detecting exit IP through proxy...")
                    entry_ip = ""
                    entry_geo = None
                    if result.dns_results and result.dns_results[0].ips:
                        entry_ip = result.dns_results[0].ips[0]
                        entry_geo = result.geo_data.get(entry_ip)

                    from .geo_lookup import lookup_single
                    exit_ip, resp_headers = detect_exit_ip_and_headers(constants.XRAY_SOCKS_PORT)

                    conn_result = ConnectionTestResult(
                        entry_ip=entry_ip,
                        entry_geo=entry_geo,
                        xray_version=xray_version,
                        response_headers=resp_headers,
                    )

                    if exit_ip:
                        conn_result.success = True
                        conn_result.exit_ip = exit_ip
                        conn_result.exit_geo = lookup_single(exit_ip)
                        _ok(f"Connection successful! Exit IP: {exit_ip}")
                        if conn_result.exit_geo:
                            g = conn_result.exit_geo
                            _info(f"Exit location: {g.country} ({g.city}), {g.org_display}")
                        if entry_ip and exit_ip:
                            if entry_ip != exit_ip:
                                _info("Entry and exit IPs differ (traffic is relayed/tunneled)")
                            else:
                                _info("Entry and exit IPs are the same (direct proxy)")
                    else:
                        conn_result.error = "Connected to proxy but could not detect exit IP"
                        _error(conn_result.error)
                        result.errors.append(f"Connection test: {conn_result.error}")

                    result.connection_test = conn_result

                    # 7b: Deep proxy probe
                    if conn_result.success and not args.no_probe:
                        _status("Running deep proxy intelligence probe...")
                        _info("  → BGP route lookup, Shodan scan, PTR records, latency triangulation, X-Forwarded-For chain...")

                        # Collect all key IPs to analyze
                        key_ips = list(all_ips)
                        if exit_ip and exit_ip not in key_ips:
                            key_ips.append(exit_ip)

                        from .proxy_probe import run_proxy_probe
                        try:
                            probe = run_proxy_probe(
                                socks_port=constants.XRAY_SOCKS_PORT,
                                key_ips=key_ips,
                                existing_geo=result.geo_data,
                            )
                            result.proxy_probe = probe

                            # Merge geo from proxy into main geo_data
                            result.geo_data.update(probe.proxy_geo)

                            # Status summary
                            bgp_count = len([b for b in probe.bgp_data.values() if b.asn])
                            shodan_count = len(probe.shodan_data)
                            ptr_count = len(probe.ptr_records)
                            _ok(f"Probe complete: BGP data for {bgp_count} IPs, Shodan for {shodan_count} IPs, {ptr_count} PTR records")

                            if probe.forwarded_chain:
                                _info(f"X-Forwarded-For chain: {' -> '.join(probe.forwarded_chain)}")
                            if probe.estimated_city:
                                _info(f"Latency estimate: exit near {probe.estimated_city} ({probe.estimated_country})")
                            if probe.ipv6_exit:
                                _info(f"IPv6 exit: {probe.ipv6_exit}")

                        except Exception as e:
                            _error(f"Proxy probe failed: {e}")
                            result.errors.append(f"Proxy probe: {e}")

                finally:
                    stop_proxy_session(xray_process)

    # -------------------------------------------------------------------------
    # Step 8: Routing Pattern Detection
    # -------------------------------------------------------------------------
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

    # -------------------------------------------------------------------------
    # Step 9: Generate Report
    # -------------------------------------------------------------------------
    _status("Generating report...")
    report_text = generate_report(result)

    print("\n")
    print(report_text)

    try:
        filename = save_report(report_text)
        print(f"\n  Report saved to: {os.path.abspath(filename)}")
        print(f"  Send this file to your support contact for analysis.\n")
    except Exception as e:
        _error(f"Could not save report file: {e}")
        print("\n  (Copy the report text above instead)\n")

    if getattr(sys, "frozen", False) and sys.platform == "win32":
        input("Press Enter to exit...")


def _get_config_uri(arg: str | None) -> str | None:
    """Get V2Ray config URI from argument, file, or user input."""
    if arg:
        if os.path.isfile(arg):
            try:
                with open(arg, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                for line in content.splitlines():
                    line = line.strip()
                    if any(line.startswith(s) for s in ["vless://", "vmess://", "trojan://", "ss://"]):
                        return line
                _error(f"No V2Ray URI found in file: {arg}")
            except Exception as e:
                _error(f"Could not read file: {e}")
        else:
            return arg

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
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def _print_banner():
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
