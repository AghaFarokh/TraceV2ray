"""Report generation for TraceV2ray.

Produces a comprehensive text report with all diagnostic results,
formatted for easy reading and sharing via Telegram.
"""

import datetime
import os
import platform
from dataclasses import dataclass, field

from . import constants
from .config_parser import ConfigInfo
from .cdn_detect import CdnInfo
from .dns_resolver import DnsResult
from .geo_lookup import GeoInfo
from .traceroute import TracerouteResult
from .xray_manager import ConnectionTestResult


@dataclass
class DiagnosticResult:
    """Aggregates all diagnostic data for report generation."""

    config: ConfigInfo | None = None
    dns_results: list = field(default_factory=list)  # List[DnsResult]
    host_header_dns: object = None  # DnsResult for host header
    traceroute_results: list = field(default_factory=list)  # List[TracerouteResult]
    geo_data: dict = field(default_factory=dict)  # Dict[str, GeoInfo]
    cdn_info: CdnInfo | None = None
    connection_test: ConnectionTestResult | None = None
    timestamp: str = ""
    errors: list = field(default_factory=list)  # Non-fatal errors


def generate_report(result: DiagnosticResult) -> str:
    """Generate the full text diagnostic report."""
    sections = []

    sections.append(_section_header(result))

    if result.config:
        sections.append(_section_config(result.config))

    if result.dns_results:
        sections.append(_section_dns(result.dns_results))

    # Server location (from geo data of resolved IPs)
    if result.dns_results and result.geo_data:
        sections.append(_section_server_location(result.dns_results, result.geo_data))

    # Host header DNS (if resolved separately)
    if result.host_header_dns:
        sections.append(_section_host_header_dns(result.host_header_dns, result.geo_data))

    if result.traceroute_results:
        sections.append(_section_traceroute(result.traceroute_results, result.geo_data))

    if result.connection_test:
        sections.append(_section_connection_test(result.connection_test))

    if result.cdn_info:
        sections.append(_section_routing_analysis(result.cdn_info, result.config))

    sections.append(_section_traffic_summary(result))

    if result.errors:
        sections.append(_section_errors(result.errors))

    sections.append(_section_footer(result))

    return "\n".join(sections)


def save_report(report_text: str) -> str:
    """Save report to file. Returns the filename."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{constants.REPORT_PREFIX}_{timestamp}.txt"

    with open(filename, "w", encoding="utf-8") as f:
        f.write(report_text)

    return filename


# --- Section Generators ---


def _section_header(result: DiagnosticResult) -> str:
    sep = constants.REPORT_SEPARATOR
    ts = result.timestamp or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    system_info = f"{platform.system()} {platform.release()}"
    try:
        system_info += f" ({platform.version()})"
    except Exception:
        pass

    return (
        f"{sep}\n"
        f"{'TraceV2ray Network Diagnostic Report':^80}\n"
        f"{'Version ' + constants.VERSION:^80}\n"
        f"{'Generated: ' + ts:^80}\n"
        f"{'System: ' + system_info:^80}\n"
        f"{sep}\n"
    )


def _section_config(config: ConfigInfo) -> str:
    sep = constants.REPORT_SECTION_SEP
    lines = [
        f"\n[1] CONFIG ANALYSIS\n{sep}",
        f"  Protocol:       {config.display_protocol}",
        f"  Server:         {config.server_host}:{config.server_port}",
        f"  Transport:      {config.transport}",
    ]

    if config.header_type:
        lines.append(f"  Header Type:    {config.header_type}")

    if config.tls and config.tls != "none":
        sni_info = f" (SNI: {config.sni})" if config.sni else ""
        lines.append(f"  Security:       {config.tls.upper()}{sni_info}")
    else:
        lines.append(f"  Security:       None")

    if config.host_header:
        lines.append(f"  Host Header:    {config.host_header}")

    if config.path:
        lines.append(f"  Path:           {config.path}")

    lines.append(f"  Encryption:     {config.encryption}")

    if config.fingerprint:
        lines.append(f"  Fingerprint:    {config.fingerprint}")

    if config.alpn:
        lines.append(f"  ALPN:           {config.alpn}")

    if config.flow:
        lines.append(f"  Flow:           {config.flow}")

    if config.remark:
        lines.append(f"  Remark:         {config.remark}")

    # Add notes about the config
    lines.append("")
    notes = _config_notes(config)
    for note in notes:
        lines.append(f"  Note: {note}")

    return "\n".join(lines)


def _config_notes(config: ConfigInfo) -> list:
    """Generate explanatory notes about the config."""
    notes = []

    if config.host_header and config.host_header != config.server_host:
        if config.host_header.lower() in constants.IRANIAN_DECOY_HOSTS:
            notes.append(
                f"Host header '{config.host_header}' is a known Iranian website "
                f"used as camouflage in HTTP header obfuscation"
            )
        else:
            notes.append(
                f"Host header differs from server address "
                f"(possible CDN fronting or obfuscation)"
            )

    if config.transport == "tcp" and config.header_type == "http":
        notes.append(
            "TCP with HTTP header obfuscation - traffic disguised as normal HTTP. "
            "This is a tunnel pattern commonly used in Iran."
        )

    if config.host_is_ip:
        notes.append("Server uses direct IP (no DNS resolution needed)")

    return notes


def _section_dns(dns_results: list) -> str:
    sep = constants.REPORT_SECTION_SEP
    lines = [f"\n[2] DNS RESOLUTION\n{sep}"]

    for dns in dns_results:
        lines.append(f"  Hostname:       {dns.hostname}")

        if dns.cname_chain:
            chain = " -> ".join([dns.hostname] + dns.cname_chain)
            lines.append(f"  CNAME Chain:    {chain}")

        if dns.ips:
            lines.append(f"  Resolved IPs:   {dns.ips[0]}")
            for ip in dns.ips[1:]:
                lines.append(f"                  {ip}")
        elif dns.error:
            lines.append(f"  Error:          {dns.error}")

        lines.append(f"  Resolution:     {dns.resolution_time_ms:.0f}ms")

    return "\n".join(lines)


def _section_traceroute(traceroute_results: list, geo_data: dict) -> str:
    sep = constants.REPORT_SECTION_SEP
    lines = []

    for i, trace in enumerate(traceroute_results):
        section_num = 3 + i
        lines.append(f"\n[{section_num}] TRACEROUTE TO {trace.target_ip}\n{sep}")

        # Table header
        lines.append(
            f"  {'Hop':<5} {'IP Address':<18} {'RTT':<10} "
            f"{'Country':<10} {'City':<14} {'ASN / Organization'}"
        )
        lines.append(
            f"  {'---':<5} {'--'*9:<18} {'---':<10} "
            f"{'---':<10} {'---':<14} {'---'*8}"
        )

        for hop in trace.hops:
            ip_str = hop.ip or "*"
            rtt_str = hop.rtt_display

            # Get geo info
            geo = geo_data.get(hop.ip) if hop.ip else None
            if geo and geo.is_private:
                country = "(Private)"
                city = "-"
                org = "Local Network"
            elif geo:
                country = geo.country_code or "-"
                city = geo.city or "-"
                asn_str = f"AS{geo.asn}" if geo.asn else ""
                org_str = geo.org_display
                org = f"{asn_str} / {org_str}" if asn_str else org_str
            else:
                country = "-"
                city = "-"
                org = "(Timed out)" if hop.is_timeout else ""

            lines.append(
                f"  {hop.hop_number:<5} {ip_str:<18} {rtt_str:<10} "
                f"{country:<10} {city:<14} {org}"
            )

        # Status
        status = "YES" if trace.completed else "NO (did not reach destination)"
        lines.append(f"\n  Traceroute completed: {status} ({len(trace.hops)} hops)")
        if trace.error:
            lines.append(f"  Warning: {trace.error}")
        lines.append(f"  Duration: {trace.duration_seconds:.1f}s")

    return "\n".join(lines)


def _section_server_location(dns_results: list, geo_data: dict) -> str:
    """Show geolocation of the server's resolved IPs."""
    sep = constants.REPORT_SECTION_SEP
    lines = [f"\n[SERVER LOCATION]\n{sep}"]
    found_any = False

    for dns in dns_results:
        for ip in dns.ips:
            geo = geo_data.get(ip)
            if geo and not geo.is_private:
                found_any = True
                lines.append(f"  IP:             {ip}")
                if geo.country or geo.country_code:
                    country_str = geo.country or ""
                    code_str = f" ({geo.country_code})" if geo.country_code else ""
                    lines.append(f"  Country:        {country_str}{code_str}")
                if geo.city:
                    lines.append(f"  City:           {geo.city}")
                if geo.isp:
                    lines.append(f"  ISP:            {geo.isp}")
                if geo.org:
                    lines.append(f"  Organization:   {geo.org}")
                if geo.asn:
                    as_name = f" ({geo.as_name})" if geo.as_name else ""
                    lines.append(f"  ASN:            AS{geo.asn}{as_name}")

                # Iranian IP detection
                if geo.country_code == "IR" or geo.asn in constants.IRANIAN_ISPS:
                    isp_name = constants.IRANIAN_ISPS.get(geo.asn, "")
                    lines.append(f"")
                    lines.append(f"  *** SERVER IS LOCATED IN IRAN ***")
                    if isp_name:
                        lines.append(f"  Iranian ISP: {isp_name}")
                    lines.append(
                        f"  This indicates the server is a local tunnel entry point."
                    )
                    lines.append(
                        f"  Traffic likely tunnels from this Iranian server to an"
                    )
                    lines.append(
                        f"  external server before reaching the internet."
                    )
                lines.append("")
            elif not geo:
                # IP not in geo data yet (lookup pending/failed)
                found_any = True
                lines.append(f"  IP:             {ip}")
                lines.append(f"  Location:       (geo lookup unavailable)")
                lines.append("")

    if not found_any:
        lines.append("  (No public server IPs to geolocate)")

    return "\n".join(lines)


def _section_host_header_dns(dns_result, geo_data: dict) -> str:
    """Show DNS resolution for the host header domain."""
    sep = constants.REPORT_SECTION_SEP
    lines = [f"\n[HOST HEADER DNS]\n{sep}"]
    lines.append(f"  Domain:         {dns_result.hostname}")

    if dns_result.cname_chain:
        chain = " -> ".join([dns_result.hostname] + dns_result.cname_chain)
        lines.append(f"  CNAME Chain:    {chain}")

    if dns_result.ips:
        lines.append(f"  Resolved IPs:   {dns_result.ips[0]}")
        for ip in dns_result.ips[1:]:
            lines.append(f"                  {ip}")

        # Show geo for resolved IPs
        for ip in dns_result.ips[:3]:  # Limit to first 3
            geo = geo_data.get(ip)
            if geo and not geo.is_private:
                lines.append(f"  IP {ip}: {geo.location_display}, {geo.org_display} {geo.asn_display}")
    elif dns_result.error:
        lines.append(f"  Error:          {dns_result.error}")

    lines.append(f"  Resolution:     {dns_result.resolution_time_ms:.0f}ms")

    return "\n".join(lines)


def _section_routing_analysis(cdn_info: CdnInfo, config: ConfigInfo | None) -> str:
    """Comprehensive routing pattern analysis section."""
    sep = constants.REPORT_SECTION_SEP
    lines = [f"\n[ROUTING ANALYSIS]\n{sep}"]

    # Pattern name
    pattern_labels = {
        "direct": "Direct Connection",
        "cdn_fronted": f"CDN-Fronted ({cdn_info.provider})",
        "cloudflare_workers": "Cloudflare Workers",
        "cloudflare_pages": "Cloudflare Pages",
        "cloudflare_tunnel": "Cloudflare Tunnel",
        "http_obfuscation_relay": "HTTP Header Obfuscation Relay",
        "ip_forwarding_relay": "IP Forwarding Relay",
        "reality": "Reality/XTLS Stealth Protocol",
        "multi_layer": f"Multi-Layer Setup ({cdn_info.provider})",
        "unknown": "Unknown",
    }
    label = pattern_labels.get(cdn_info.routing_pattern, cdn_info.routing_pattern)
    lines.append(f"  Pattern:        {label}")
    lines.append(f"  Confidence:     {cdn_info.confidence.upper()}")

    if cdn_info.is_cdn:
        lines.append(f"  CDN Provider:   {cdn_info.provider}")
    if config:
        lines.append(f"  Transport:      {config.transport.upper()}")

    # Routing chain visualization
    if cdn_info.routing_chain:
        lines.append(f"")
        lines.append(f"  Routing Chain:")
        for i, node in enumerate(cdn_info.routing_chain):
            lines.append(f"    [{node}]")
            if i < len(cdn_info.routing_chain) - 1:
                lines.append(f"        |")
                lines.append(f"        v")

    # Detection signals
    if cdn_info.indicators:
        lines.append(f"")
        lines.append(f"  Detection Signals:")
        for indicator in cdn_info.indicators:
            lines.append(f"    + {indicator}")

    return "\n".join(lines)


def _section_connection_test(conn: ConnectionTestResult) -> str:
    sep = constants.REPORT_SECTION_SEP
    lines = [f"\n[CONNECTION TEST]\n{sep}"]

    if conn.xray_version:
        lines.append(f"  xray-core:      {conn.xray_version}")

    if conn.success:
        lines.append(f"  Connection:     SUCCESS ({conn.connection_time_ms:.0f}ms)")
        lines.append(f"")

        # Entry point
        entry_info = conn.entry_ip
        if conn.entry_geo:
            g = conn.entry_geo
            entry_info += f" ({g.location_display}, {g.org_display} {g.asn_display})"
        lines.append(f"  Entry Point:    {entry_info}")

        # Exit point
        exit_info = conn.exit_ip or "unknown"
        if conn.exit_geo:
            g = conn.exit_geo
            exit_info += f" ({g.location_display}, {g.org_display} {g.asn_display})"
        lines.append(f"  Exit Point:     {exit_info}")

        # Comparison
        if conn.entry_ip and conn.exit_ip:
            if conn.entry_ip == conn.exit_ip:
                lines.append(f"\n  Entry vs Exit:  SAME IP (direct proxy, no tunnel/CDN relay)")
            else:
                lines.append(f"\n  Entry vs Exit:  DIFFERENT")
                if conn.entry_geo:
                    lines.append(f"                  Entry: {conn.entry_geo.country or 'unknown'} ({conn.entry_geo.org_display})")
                if conn.exit_geo:
                    lines.append(f"                  Exit:  {conn.exit_geo.country or 'unknown'} ({conn.exit_geo.org_display})")
    else:
        lines.append(f"  Connection:     FAILED")
        if conn.error:
            lines.append(f"  Error:          {conn.error}")
        if conn.xray_log_snippet:
            lines.append(f"  xray log:")
            for log_line in conn.xray_log_snippet.splitlines()[-5:]:
                lines.append(f"    {log_line}")

    return "\n".join(lines)


def _section_traffic_summary(result: DiagnosticResult) -> str:
    sep = constants.REPORT_SEPARATOR
    lines = [f"\n[TRAFFIC FLOW SUMMARY]\n{sep}\n"]

    flow_nodes = []

    # Start: user's PC
    flow_nodes.append(("Your PC", ""))

    # Traceroute hops grouped by ISP/network
    has_traceroute_hops = False
    if result.traceroute_results:
        trace = result.traceroute_results[0]
        if trace.hops:
            has_traceroute_hops = True
            current_org = None
            current_hops = []

            for hop in trace.hops:
                if hop.is_timeout and not hop.ip:
                    continue

                geo = result.geo_data.get(hop.ip) if hop.ip else None

                if geo and geo.is_private:
                    org_key = "Local Network"
                elif geo:
                    org_key = geo.org_display or "Unknown"
                else:
                    org_key = "Unknown"

                if org_key != current_org:
                    if current_org and current_hops:
                        hop_range = f"hop{'s' if len(current_hops) > 1 else ''} {current_hops[0]}"
                        if len(current_hops) > 1:
                            hop_range += f"-{current_hops[-1]}"
                        geo_ref = result.geo_data.get(current_hops[-1]) if current_hops else None
                        if geo_ref and not geo_ref.is_private:
                            loc = f"{geo_ref.country_code}, {geo_ref.city}" if geo_ref.city else geo_ref.country_code
                            flow_nodes.append((current_org, f"{loc} ({hop_range})"))
                        else:
                            flow_nodes.append((current_org, f"({hop_range})"))
                    current_org = org_key
                    current_hops = []

                current_hops.append(hop.ip or f"hop{hop.hop_number}")

            # Last group — annotate CDN info when detected
            if current_org and current_hops:
                hop_range = f"hop{'s' if len(current_hops) > 1 else ''} {current_hops[0]}"
                if len(current_hops) > 1:
                    hop_range += f"-{current_hops[-1]}"
                geo_ref = result.geo_data.get(current_hops[-1]) if current_hops else None
                # Determine label: use CDN/routing context if available
                cdn = result.cdn_info
                if current_hops[-1] == trace.target_ip and cdn:
                    if cdn.is_cdn and cdn.provider and cdn.provider != "Direct":
                        label = f"{cdn.provider} Edge / Proxy Entry"
                    elif cdn.server_is_iran:
                        label = "Iranian Relay Entry"
                    else:
                        label = "Proxy Server"
                else:
                    label = current_org
                if geo_ref and not geo_ref.is_private:
                    loc = f"{geo_ref.country_code}, {geo_ref.city}" if geo_ref.city else geo_ref.country_code
                    flow_nodes.append((label, f"{geo_ref.ip} ({loc}, {geo_ref.org_display} {geo_ref.asn_display})"))
                else:
                    flow_nodes.append((label, f"({hop_range})"))

            # If CDN is detected and server is NOT the CDN origin, add origin note
            if result.cdn_info and result.cdn_info.is_cdn and result.config:
                cdn = result.cdn_info
                if not cdn.server_is_iran and cdn.routing_pattern not in ("direct",):
                    # Show that traffic flows through CDN to origin
                    host_hdr = result.config.host_header
                    if host_hdr and result.host_header_dns and result.host_header_dns.ips:
                        cdn_ips = ", ".join(result.host_header_dns.ips[:2])
                        flow_nodes.append((f"{cdn.provider} CDN Network", f"host: {host_hdr} → {cdn_ips}"))
                    elif host_hdr:
                        flow_nodes.append((f"{cdn.provider} CDN Network", f"host: {host_hdr}"))

    # If no traceroute hops, build flow from CDN routing chain or DNS
    if not has_traceroute_hops:
        cdn = result.cdn_info
        if cdn and cdn.routing_chain and len(cdn.routing_chain) > 2:
            # Use CDN routing chain (skip "Your PC" which we already added, skip last "Internet")
            for node in cdn.routing_chain[1:-1]:
                # Enrich CDN edge node with resolved IPs if available
                if "CDN Edge" in node and result.host_header_dns and result.host_header_dns.ips:
                    cdn_ips = ", ".join(result.host_header_dns.ips[:2])
                    flow_nodes.append((node, f"IPs: {cdn_ips}"))
                elif ("Origin Server" in node or "Relay" in node) and result.config:
                    server_ip = result.config.server_host
                    geo = result.geo_data.get(server_ip)
                    detail_parts = []
                    if geo and not geo.is_private:
                        if geo.location_display:
                            detail_parts.append(geo.location_display)
                        if "Relay" in node:
                            isp = constants.IRANIAN_ISPS.get(geo.asn, geo.org_display)
                            if isp:
                                detail_parts.append(isp)
                        elif geo.org_display:
                            detail_parts.append(geo.org_display)
                        if geo.asn_display:
                            detail_parts.append(geo.asn_display)
                    # Only add detail if it has useful content (not just the IP already in node name)
                    if detail_parts and server_ip not in node:
                        flow_nodes.append((node, f"{server_ip} ({', '.join(detail_parts)})"))
                    elif detail_parts:
                        flow_nodes.append((node, f"({', '.join(detail_parts)})"))
                    else:
                        flow_nodes.append((node, ""))
                else:
                    flow_nodes.append((node, ""))
        elif result.dns_results:
            # Fallback: show proxy server from DNS + geo
            flow_nodes.append(("...", "(traceroute unavailable - intermediate hops unknown)"))
            for dns in result.dns_results:
                for ip in dns.ips:
                    geo = result.geo_data.get(ip)
                    label = "Proxy Server"
                    if cdn and cdn.is_cdn and cdn.provider and cdn.provider != "Direct":
                        label = f"{cdn.provider} Edge / Proxy Server"
                    if geo and not geo.is_private and geo.country:
                        loc = geo.location_display
                        org = geo.org_display
                        asn = geo.asn_display
                        detail = f"{ip} ({loc}, {org} {asn})" if loc else f"{ip} ({org} {asn})"
                        flow_nodes.append((label, detail))
                    else:
                        flow_nodes.append((label, ip))

    # Connection test exit node — only add when exit IP differs from server IP
    # (different exit = CDN relay, tunnel, or IP forwarding revealed)
    if result.connection_test and result.connection_test.success:
        ct = result.connection_test
        entry_ip = result.config.server_host if result.config else ""
        if ct.exit_ip and ct.exit_ip != entry_ip:
            if ct.exit_geo and ct.exit_geo.country:
                loc = f"{ct.exit_geo.country_code}, {ct.exit_geo.city}" if ct.exit_geo.city else (ct.exit_geo.country_code or "")
                flow_nodes.append(("Actual Exit Point", f"{ct.exit_ip} ({loc}, {ct.exit_geo.org_display} {ct.exit_geo.asn_display})"))
            else:
                flow_nodes.append(("Actual Exit Point", ct.exit_ip))

    # Internet
    flow_nodes.append(("Internet", ""))

    # Render the flow
    for i, (name, detail) in enumerate(flow_nodes):
        if detail:
            lines.append(f"  [{name}] {detail}")
        else:
            lines.append(f"  [{name}]")
        if i < len(flow_nodes) - 1:
            lines.append(f"      |")
            lines.append(f"      v")

    # Config type summary
    lines.append("")
    if result.config:
        lines.append(f"  Protocol:       {result.config.display_protocol}")

    if result.cdn_info:
        pattern_labels = {
            "direct": "Direct connection",
            "cdn_fronted": f"CDN-fronted ({result.cdn_info.provider})",
            "cloudflare_workers": "Cloudflare Workers",
            "cloudflare_pages": "Cloudflare Pages",
            "cloudflare_tunnel": "Cloudflare Tunnel",
            "http_obfuscation_relay": "HTTP Obfuscation Relay",
            "ip_forwarding_relay": "IP Forwarding Relay",
            "reality": "Reality/XTLS",
            "multi_layer": f"Multi-Layer ({result.cdn_info.provider})",
        }
        config_type = pattern_labels.get(result.cdn_info.routing_pattern, result.cdn_info.routing_pattern)
        lines.append(f"  Config Type:    {config_type}")
        if result.cdn_info.is_tunnel and result.config and result.config.host_header:
            lines.append(f"  Decoy Host:     {result.config.host_header}")

    if result.traceroute_results and result.traceroute_results[0].hops:
        total_hops = len(result.traceroute_results[0].hops)
        lines.append(f"  Hops to proxy:  {total_hops}")

        # Latency to last hop
        last_hop = result.traceroute_results[0].hops[-1]
        if last_hop.avg_rtt is not None:
            lines.append(f"  Latency:        ~{last_hop.avg_rtt:.0f}ms")

    return "\n".join(lines)


def _section_errors(errors: list) -> str:
    lines = [f"\n[WARNINGS]\n{constants.REPORT_SECTION_SEP}"]
    for error in errors:
        lines.append(f"  - {error}")
    return "\n".join(lines)


def _section_footer(result: DiagnosticResult) -> str:
    sep = constants.REPORT_SEPARATOR
    return (
        f"\n{sep}\n"
        f"  Report generated by {constants.TOOL_NAME} v{constants.VERSION}\n"
        f"  Send this file to your support contact for analysis.\n"
        f"{sep}\n"
    )
