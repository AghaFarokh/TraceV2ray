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
    dns_results: list = field(default_factory=list)          # List[DnsResult]
    host_header_dns: object = None                            # DnsResult for host header
    traceroute_results: list = field(default_factory=list)   # List[TracerouteResult]
    geo_data: dict = field(default_factory=dict)             # Dict[str, GeoInfo]
    cdn_info: CdnInfo | None = None
    connection_test: ConnectionTestResult | None = None
    tls_info: object = None                                   # TlsInfo | None
    proxy_probe: object = None                                # ProbeResult | None
    timestamp: str = ""
    errors: list = field(default_factory=list)


def generate_report(result: DiagnosticResult) -> str:
    """Generate the full text diagnostic report."""
    sections = []

    sections.append(_section_header(result))

    if result.config:
        sections.append(_section_config(result.config))

    if result.dns_results:
        sections.append(_section_dns(result.dns_results))

    if result.dns_results and result.geo_data:
        sections.append(_section_server_location(result.dns_results, result.geo_data, result))

    if result.host_header_dns:
        sections.append(_section_host_header_dns(result.host_header_dns, result.geo_data))

    if result.traceroute_results:
        sections.append(_section_traceroute(result.traceroute_results, result.geo_data))

    if result.tls_info:
        sections.append(_section_tls(result.tls_info))

    if result.connection_test:
        sections.append(_section_connection_test(result.connection_test))

    if result.proxy_probe:
        sections.append(_section_proxy_intelligence(result.proxy_probe, result.geo_data))

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

    lines.append("")
    notes = _config_notes(config)
    for note in notes:
        lines.append(f"  Note: {note}")

    return "\n".join(lines)


def _config_notes(config: ConfigInfo) -> list:
    notes = []

    if config.host_header and config.host_header != config.server_host:
        host_lower = config.host_header.lower()
        if host_lower in constants.IRANIAN_DECOY_HOSTS:
            notes.append(
                f"Host header '{config.host_header}' is a known Iranian website "
                f"used as camouflage in HTTP header obfuscation"
            )
        elif host_lower.endswith(".ir"):
            notes.append(
                f"Host header '{config.host_header}' uses .ir TLD — Iranian decoy site"
            )
        else:
            notes.append(
                f"Host header differs from server address "
                f"(possible CDN fronting or obfuscation)"
            )

    if config.transport == "tcp" and config.header_type == "http":
        notes.append(
            "TCP with HTTP header obfuscation — traffic disguised as normal HTTP. "
            "Common tunnel pattern used for censorship circumvention."
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

        status = "YES" if trace.completed else "NO (did not reach destination)"
        lines.append(f"\n  Traceroute completed: {status} ({len(trace.hops)} hops)")
        if trace.error:
            lines.append(f"  Warning: {trace.error}")
        lines.append(f"  Duration: {trace.duration_seconds:.1f}s")

    return "\n".join(lines)


def _section_server_location(dns_results: list, geo_data: dict, result: DiagnosticResult) -> str:
    sep = constants.REPORT_SECTION_SEP
    lines = [f"\n[SERVER LOCATION]\n{sep}"]
    found_any = False

    for dns in dns_results:
        for ip in dns.ips:
            geo = geo_data.get(ip)
            if geo and not geo.is_private:
                found_any = True
                lines.append(f"  IP:             {ip}")

                # PTR record
                ptr = getattr(geo, "ptr", "") or ""
                if not ptr and result.proxy_probe:
                    ptr = result.proxy_probe.ptr_records.get(ip, "")
                if ptr:
                    lines.append(f"  PTR:            {ptr}")

                if geo.country or geo.country_code:
                    country_str = geo.country or ""
                    code_str = f" ({geo.country_code})" if geo.country_code else ""
                    lines.append(f"  Country:        {country_str}{code_str}")
                else:
                    lines.append(f"  Country:        (unavailable)")

                if geo.city:
                    lines.append(f"  City:           {geo.city}")
                if geo.isp:
                    lines.append(f"  ISP:            {geo.isp}")
                if geo.org:
                    lines.append(f"  Organization:   {geo.org}")
                if geo.asn:
                    as_name = f" ({geo.as_name})" if geo.as_name else ""
                    lines.append(f"  ASN:            AS{geo.asn}{as_name}")

                # BGP enrichment
                if result.proxy_probe:
                    bgp = result.proxy_probe.bgp_data.get(ip)
                    if bgp and bgp.asn and not geo.asn:
                        lines.append(f"  BGP ASN:        AS{bgp.asn} ({bgp.asn_name})")
                    if bgp and bgp.prefix:
                        lines.append(f"  BGP Prefix:     {bgp.prefix}")
                    if bgp and bgp.rir:
                        lines.append(f"  RIR:            {bgp.rir}")

                # Iranian IP detection (multi-signal)
                is_iran = (
                    geo.country_code == "IR"
                    or (geo.asn and geo.asn in constants.IRANIAN_ISPS)
                )
                if is_iran:
                    isp_name = constants.IRANIAN_ISPS.get(geo.asn, geo.org or "Iranian ISP")
                    lines.append(f"")
                    lines.append(f"  *** SERVER IS LOCATED IN IRAN ***")
                    lines.append(f"  Iranian ISP:    {isp_name}")
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
                found_any = True
                lines.append(f"  IP:             {ip}")
                # Try CIDR lookup
                from .geo_lookup import cidr_isp_lookup
                cidr_isp = cidr_isp_lookup(ip)
                if cidr_isp:
                    lines.append(f"  ISP (offline):  {cidr_isp} (Iran)")
                    lines.append(f"  *** SERVER IS LOCATED IN IRAN (CIDR match) ***")
                else:
                    lines.append(f"  Location:       (geo lookup unavailable)")
                lines.append("")

    if not found_any:
        lines.append("  (No public server IPs to geolocate)")

    return "\n".join(lines)


def _section_host_header_dns(dns_result, geo_data: dict) -> str:
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

        for ip in dns_result.ips[:3]:
            geo = geo_data.get(ip)
            if geo and not geo.is_private:
                lines.append(f"  IP {ip}: {geo.location_display}, {geo.org_display} {geo.asn_display}")
    elif dns_result.error:
        lines.append(f"  Error:          {dns_result.error}")

    lines.append(f"  Resolution:     {dns_result.resolution_time_ms:.0f}ms")

    return "\n".join(lines)


def _section_tls(tls_info) -> str:
    sep = constants.REPORT_SECTION_SEP
    lines = [f"\n[TLS CERTIFICATE]\n{sep}"]

    if tls_info.error:
        lines.append(f"  Status:         FAILED ({tls_info.error})")
        lines.append(f"  Note: This may be expected for Reality/obfuscated endpoints.")
        return "\n".join(lines)

    lines.append(f"  TLS Version:    {tls_info.tls_version or 'unknown'}")
    lines.append(f"  Cipher Suite:   {tls_info.cipher_suite or 'unknown'}")
    lines.append(f"")

    if tls_info.subject_cn:
        lines.append(f"  Subject CN:     {tls_info.subject_cn}")

    if tls_info.subject_sans:
        lines.append(f"  Subject SANs:")
        for san in tls_info.subject_sans[:8]:
            lines.append(f"    - {san}")
        if len(tls_info.subject_sans) > 8:
            lines.append(f"    ... (+{len(tls_info.subject_sans) - 8} more)")

    lines.append(f"")
    if tls_info.issuer_org or tls_info.issuer_cn:
        issuer = tls_info.issuer_org or tls_info.issuer_cn
        lines.append(f"  Issuer:         {issuer}")

    if tls_info.is_lets_encrypt:
        lines.append(f"  Certificate:    Let's Encrypt (automated, free CA)")
    elif tls_info.is_self_signed:
        lines.append(f"  Certificate:    SELF-SIGNED (common for Reality/custom setups)")

    if tls_info.not_before:
        lines.append(f"  Valid From:     {tls_info.not_before}")
    if tls_info.not_after:
        expiry_note = ""
        if tls_info.is_expired:
            expiry_note = " *** EXPIRED ***"
        elif tls_info.days_until_expiry > 0:
            expiry_note = f" (expires in {tls_info.days_until_expiry} days)"
        lines.append(f"  Valid Until:    {tls_info.not_after}{expiry_note}")

    if tls_info.cert_sha256:
        lines.append(f"")
        lines.append(f"  SHA-256:        {tls_info.cert_sha256[:32]}...")

    # Interpretation
    lines.append(f"")
    if tls_info.subject_cn:
        cn_lower = tls_info.subject_cn.lower()
        if any(isp_name.lower() in cn_lower for isp_name in ["mci", "irancell", "tci", "parsonline"]):
            lines.append(f"  *** CN matches Iranian ISP — likely Iranian decoy TLS target ***")
        elif ".ir" in cn_lower:
            lines.append(f"  *** CN is an Iranian domain — likely used as Reality/obfuscation target ***")

    return "\n".join(lines)


def _section_connection_test(conn: ConnectionTestResult) -> str:
    sep = constants.REPORT_SECTION_SEP
    lines = [f"\n[CONNECTION TEST]\n{sep}"]

    if conn.xray_version:
        lines.append(f"  xray-core:      {conn.xray_version}")

    if conn.success:
        lines.append(f"  Connection:     SUCCESS ({conn.connection_time_ms:.0f}ms)")
        lines.append(f"")

        entry_info = conn.entry_ip
        if conn.entry_geo:
            g = conn.entry_geo
            entry_info += f" ({g.location_display}, {g.org_display} {g.asn_display})"
        lines.append(f"  Entry Point:    {entry_info}")

        exit_info = conn.exit_ip or "unknown"
        if conn.exit_geo:
            g = conn.exit_geo
            exit_info += f" ({g.location_display}, {g.org_display} {g.asn_display})"
        lines.append(f"  Exit Point:     {exit_info}")

        if conn.entry_ip and conn.exit_ip:
            if conn.entry_ip == conn.exit_ip:
                lines.append(f"\n  Entry vs Exit:  SAME IP (direct proxy, no relay)")
            else:
                lines.append(f"\n  Entry vs Exit:  DIFFERENT — traffic is being RELAYED")
                if conn.entry_geo:
                    lines.append(f"    Entry: {conn.entry_geo.country or 'unknown'} ({conn.entry_geo.org_display})")
                if conn.exit_geo:
                    lines.append(f"    Exit:  {conn.exit_geo.country or 'unknown'} ({conn.exit_geo.org_display})")
    else:
        lines.append(f"  Connection:     FAILED")
        if conn.error:
            lines.append(f"  Error:          {conn.error}")
        if conn.xray_log_snippet:
            lines.append(f"  xray log:")
            for log_line in conn.xray_log_snippet.splitlines()[-5:]:
                lines.append(f"    {log_line}")

    return "\n".join(lines)


def _section_proxy_intelligence(probe, geo_data: dict) -> str:
    sep = constants.REPORT_SECTION_SEP
    lines = [f"\n[PROXY INTELLIGENCE]\n{sep}"]

    # --- Exit IP consistency ---
    if probe.exit_ips:
        if probe.exit_ip_consistent:
            lines.append(f"  Exit IP:        {probe.exit_ips[0]} (consistent across {len(probe.exit_ips)} checks)")
        else:
            lines.append(f"  Exit IPs:       INCONSISTENT (load balancer / multiple exit nodes detected)")
            for ip in probe.exit_ips:
                geo = geo_data.get(ip)
                geo_str = f" ({geo.location_display}, {geo.org_display})" if geo else ""
                lines.append(f"    - {ip}{geo_str}")

    # --- IPv6 exit ---
    if probe.ipv6_exit:
        lines.append(f"  IPv6 Exit:      {probe.ipv6_exit}")

    # --- X-Forwarded-For relay chain ---
    if probe.forwarded_chain:
        lines.append(f"")
        lines.append(f"  X-Forwarded-For Relay Chain:")
        lines.append(f"  (IPs added by intermediate proxies/relays, innermost first)")
        for ip in probe.forwarded_chain:
            geo = geo_data.get(ip)
            if geo:
                org = geo.org_display or geo.isp
                loc = geo.location_display
                detail = f" → {loc}, {org} {geo.asn_display}" if loc else f" → {org} {geo.asn_display}"
                lines.append(f"    {ip}{detail}")
            else:
                lines.append(f"    {ip} (geo unavailable)")

    if probe.via_headers:
        lines.append(f"")
        lines.append(f"  Via Headers:")
        for via in probe.via_headers:
            lines.append(f"    {via}")

    # --- Latency triangulation ---
    if probe.latency_measurements:
        lines.append(f"")
        lines.append(f"  Latency Triangulation (RTT from exit through proxy):")
        for m in probe.latency_measurements[:6]:
            bar = "█" * min(int(m.rtt_ms / 20), 30)
            lines.append(f"    {m.city:<20} ({m.country_code})  {m.rtt_ms:>7.0f}ms  {bar}")
        if probe.estimated_city:
            lines.append(f"")
            lines.append(f"  Estimated Exit Location: {probe.estimated_city} ({probe.estimated_country})")
            lines.append(f"  (Location with lowest RTT is closest to exit server)")

    # --- PTR records ---
    if probe.ptr_records:
        lines.append(f"")
        lines.append(f"  PTR Records (Reverse DNS):")
        for ip, hostname in probe.ptr_records.items():
            lines.append(f"    {ip:<20} → {hostname}")

    # --- Shodan InternetDB ---
    if probe.shodan_data:
        lines.append(f"")
        lines.append(f"  Shodan Scan Results:")
        for ip, entry in probe.shodan_data.items():
            lines.append(f"")
            lines.append(f"    IP: {ip}")
            if entry.ports:
                lines.append(f"    Open Ports:   {', '.join(str(p) for p in sorted(entry.ports))}")
            if entry.hostnames:
                lines.append(f"    Hostnames:    {', '.join(entry.hostnames[:4])}")
            if entry.tags:
                lines.append(f"    Tags:         {', '.join(entry.tags)}")
            if entry.cpes:
                lines.append(f"    Software:     {', '.join(entry.cpes[:3])}")
            if entry.vulns:
                lines.append(f"    CVEs:         {', '.join(entry.vulns[:5])}")
                if len(entry.vulns) > 5:
                    lines.append(f"                  (+{len(entry.vulns)-5} more)")

    # --- BGP Analysis ---
    if probe.bgp_data:
        lines.append(f"")
        lines.append(f"  BGP Route Analysis:")
        for ip, bgp in probe.bgp_data.items():
            if not bgp.asn:
                continue
            lines.append(f"")
            lines.append(f"    IP: {ip}")
            lines.append(f"    Prefix:       {bgp.prefix or 'unknown'}")
            lines.append(f"    ASN:          AS{bgp.asn} — {bgp.asn_name}")
            if bgp.asn_description and bgp.asn_description != bgp.asn_name:
                lines.append(f"    Description:  {bgp.asn_description}")
            if bgp.country_code:
                lines.append(f"    Country:      {bgp.country_code}")
            if bgp.rir:
                lines.append(f"    RIR:          {bgp.rir}")
            if bgp.ptr_record:
                lines.append(f"    PTR:          {bgp.ptr_record}")

            # ASN type labels
            type_labels = []
            if bgp.is_iranian:
                type_labels.append("IRANIAN ISP")
            if bgp.is_cdn:
                cdn_name = constants.CDN_ASN_MAP.get(bgp.asn, "CDN")
                type_labels.append(f"CDN ({cdn_name})")
            if bgp.is_backbone:
                backbone_name = constants.BACKBONE_ASNS.get(bgp.asn, "Transit")
                type_labels.append(f"BACKBONE TRANSIT ({backbone_name})")
            if bgp.is_satellite:
                sat_name = constants.SATELLITE_ASNS.get(bgp.asn, "Satellite")
                type_labels.append(f"SATELLITE ({sat_name})")
            if type_labels:
                lines.append(f"    Type:         {' | '.join(type_labels)}")

            if bgp.upstreams_v4:
                lines.append(f"    Upstreams:")
                for upstream in bgp.upstreams_v4[:5]:
                    upstream_type = ""
                    if upstream.asn in constants.BACKBONE_ASNS:
                        upstream_type = f" [backbone: {constants.BACKBONE_ASNS[upstream.asn]}]"
                    elif upstream.asn in constants.CDN_ASN_MAP:
                        upstream_type = f" [CDN: {constants.CDN_ASN_MAP[upstream.asn]}]"
                    lines.append(f"      AS{upstream.asn} {upstream.name} [{upstream.country_code}]{upstream_type}")

    # --- Probe errors ---
    if probe.errors:
        lines.append(f"")
        lines.append(f"  Probe Notes:")
        for err in probe.errors:
            lines.append(f"    - {err}")

    return "\n".join(lines)


def _section_routing_analysis(cdn_info: CdnInfo, config: ConfigInfo | None) -> str:
    sep = constants.REPORT_SECTION_SEP
    lines = [f"\n[ROUTING ANALYSIS]\n{sep}"]

    pattern_labels = {
        "direct": "Direct Connection",
        "cdn_fronted": f"CDN-Fronted ({cdn_info.provider})",
        "cloudflare_workers": "Cloudflare Workers",
        "cloudflare_pages": "Cloudflare Pages",
        "cloudflare_tunnel": "Cloudflare Tunnel",
        "http_obfuscation_relay": "HTTP Header Obfuscation Relay",
        "ip_forwarding_relay": "IP Forwarding / Relay",
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

    if cdn_info.routing_chain:
        lines.append(f"")
        lines.append(f"  Routing Chain:")
        for i, node in enumerate(cdn_info.routing_chain):
            lines.append(f"    [{node}]")
            if i < len(cdn_info.routing_chain) - 1:
                lines.append(f"        |")
                lines.append(f"        v")

    if cdn_info.indicators:
        lines.append(f"")
        lines.append(f"  Detection Signals:")
        for indicator in cdn_info.indicators:
            lines.append(f"    + {indicator}")

    return "\n".join(lines)


def _section_traffic_summary(result: DiagnosticResult) -> str:
    sep = constants.REPORT_SEPARATOR
    lines = [f"\n[TRAFFIC FLOW SUMMARY]\n{sep}\n"]

    flow_nodes = []
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

            if current_org and current_hops:
                hop_range = f"hop{'s' if len(current_hops) > 1 else ''} {current_hops[0]}"
                if len(current_hops) > 1:
                    hop_range += f"-{current_hops[-1]}"
                geo_ref = result.geo_data.get(current_hops[-1]) if current_hops else None
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

            if result.cdn_info and result.cdn_info.is_cdn and result.config:
                cdn = result.cdn_info
                if not cdn.server_is_iran and cdn.routing_pattern not in ("direct",):
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
            for node in cdn.routing_chain[1:-1]:
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
                    if detail_parts and server_ip not in node:
                        flow_nodes.append((node, f"{server_ip} ({', '.join(detail_parts)})"))
                    elif detail_parts:
                        flow_nodes.append((node, f"({', '.join(detail_parts)})"))
                    else:
                        flow_nodes.append((node, ""))
                else:
                    flow_nodes.append((node, ""))
        elif result.dns_results:
            flow_nodes.append(("...", "(traceroute unavailable — intermediate hops unknown)"))
            for dns in result.dns_results:
                for ip in dns.ips:
                    geo = result.geo_data.get(ip)
                    label = "Proxy Server"
                    if cdn and cdn.is_cdn and cdn.provider and cdn.provider != "Direct":
                        label = f"{cdn.provider} Edge / Proxy Server"
                    elif cdn and cdn.server_is_iran:
                        label = "Iranian Relay Server"
                    if geo and not geo.is_private and (geo.country or geo.org):
                        loc = geo.location_display
                        org = geo.org_display
                        asn = geo.asn_display
                        detail = f"{ip} ({loc}, {org} {asn})" if loc else f"{ip} ({org} {asn})"
                        flow_nodes.append((label, detail))
                    else:
                        flow_nodes.append((label, ip))

    # X-Forwarded-For relay chain nodes (from proxy probe)
    if result.proxy_probe and result.proxy_probe.forwarded_chain:
        for relay_ip in result.proxy_probe.forwarded_chain:
            geo = result.geo_data.get(relay_ip)
            if geo and not geo.is_private:
                loc = geo.location_display
                org = geo.org_display
                detail = f"{relay_ip} ({loc}, {org} {geo.asn_display})" if loc else f"{relay_ip} ({org} {geo.asn_display})"
                flow_nodes.append(("Relay Layer (X-Forwarded-For)", detail))
            else:
                flow_nodes.append(("Relay Layer (X-Forwarded-For)", relay_ip))

    # Connection test exit node — only when exit differs from entry
    if result.connection_test and result.connection_test.success:
        ct = result.connection_test
        entry_ip = result.config.server_host if result.config else ""
        if ct.exit_ip and ct.exit_ip != entry_ip:
            if ct.exit_geo and ct.exit_geo.country:
                loc = f"{ct.exit_geo.country_code}, {ct.exit_geo.city}" if ct.exit_geo.city else (ct.exit_geo.country_code or "")
                bgp_note = ""
                if result.proxy_probe:
                    bgp = result.proxy_probe.bgp_data.get(ct.exit_ip)
                    if bgp and bgp.asn_name:
                        bgp_note = f" [AS{bgp.asn} {bgp.asn_name}]"
                flow_nodes.append((
                    "Actual Exit Point",
                    f"{ct.exit_ip} ({loc}, {ct.exit_geo.org_display} {ct.exit_geo.asn_display}){bgp_note}"
                ))
            else:
                flow_nodes.append(("Actual Exit Point", ct.exit_ip))

    # Internet
    flow_nodes.append(("Internet", ""))

    for i, (name, detail) in enumerate(flow_nodes):
        if detail:
            lines.append(f"  [{name}] {detail}")
        else:
            lines.append(f"  [{name}]")
        if i < len(flow_nodes) - 1:
            lines.append(f"      |")
            lines.append(f"      v")

    # Summary stats
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
            "ip_forwarding_relay": "IP Forwarding / Relay",
            "reality": "Reality/XTLS",
            "multi_layer": f"Multi-Layer ({result.cdn_info.provider})",
        }
        config_type = pattern_labels.get(result.cdn_info.routing_pattern, result.cdn_info.routing_pattern)
        lines.append(f"  Config Type:    {config_type}")
        if result.cdn_info.is_tunnel and result.config and result.config.host_header:
            lines.append(f"  Decoy Host:     {result.config.host_header}")

    if result.proxy_probe and result.proxy_probe.estimated_city:
        lines.append(f"  Exit Region:    ~{result.proxy_probe.estimated_city} ({result.proxy_probe.estimated_country}) [latency estimate]")

    if result.traceroute_results and result.traceroute_results[0].hops:
        total_hops = len(result.traceroute_results[0].hops)
        lines.append(f"  Hops to proxy:  {total_hops}")
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
