"""Deep routing pattern detection.

Detects all V2Ray routing patterns: CDN-fronted (Cloudflare, Fastly,
ArvanCloud, etc.), Cloudflare Workers/Pages/Tunnel, HTTP header obfuscation,
Iranian relay/tunnel, Reality/XTLS, IP forwarding, and multi-layer setups.
"""

from dataclasses import dataclass, field

from . import constants
from .config_parser import ConfigInfo
from .dns_resolver import DnsResult
from .geo_lookup import GeoInfo, cidr_isp_lookup


@dataclass
class CdnInfo:
    """Routing pattern detection result."""

    is_cdn: bool = False
    is_tunnel: bool = False
    is_relay: bool = False
    is_reality: bool = False
    is_serverless: bool = False
    provider: str = "Direct"
    confidence: str = "low"
    indicators: list = field(default_factory=list)
    tunnel_type: str = ""
    routing_pattern: str = "unknown"
    routing_chain: list = field(default_factory=list)
    cdn_from_host_header: str = ""
    cdn_from_response_headers: str = ""
    server_is_iran: bool = False
    host_header_dns: object = None


def detect_cdn(
    config: ConfigInfo,
    geo_data: dict,
    dns_results: list,
    host_header_dns: DnsResult | None = None,
    response_headers: dict | None = None,
    connection_test=None,
) -> CdnInfo:
    """Deep multi-signal routing pattern detection.

    Checks (in order):
    1. Server IP ASN against known CDN ASNs
    2. Host header / SNI domain suffix matching against CDN patterns
    3. Config-level indicators (host headers, transport type)
    4. CNAME chains (server + host header DNS)
    5. Anycast detection (multiple resolved IPs)
    6. HTTP response headers from connection test
    7. HTTP header obfuscation / tunnel patterns
    8. Reality/XTLS protocol detection
    9. Server location in Iran (relay indicator)
    10. Final routing pattern classification
    """
    result = CdnInfo()

    # 1. ASN check
    asn_provider = _check_asn(config, geo_data, result)

    # 2. Host header / SNI domain matching (THE KEY FIX)
    _check_host_header_domain(config, result)

    # 3. Config indicators
    _check_config_indicators(config, result)

    # 4. CNAME chains
    _check_cname(dns_results, result)
    if host_header_dns:
        result.host_header_dns = host_header_dns
        _check_cname([host_header_dns], result)

    # 5. Anycast
    _check_anycast(dns_results, result)

    # 6. Response headers
    _check_response_headers(response_headers, result)

    # 7. Tunnel pattern
    _check_tunnel_pattern(config, result)

    # 8. Reality protocol
    _check_reality(config, result)

    # 9. Server in Iran (multi-signal: geo + CIDR + ASN + .ir TLD + host header)
    _check_server_in_iran(config, geo_data, result)

    # 10. .ir TLD / known Iranian decoy on host header
    _check_iranian_decoy(config, result)

    # 11. Classify routing pattern (uses entry!=exit signal from connection_test)
    _classify_routing_pattern(config, result, connection_test)

    # Determine confidence
    _determine_confidence(result, asn_provider)

    return result


# --- Detection Functions ---


def _find_server_geo(config: ConfigInfo, geo_data: dict) -> GeoInfo | None:
    """Find GeoInfo for the server's IP."""
    # Direct match on server_host
    for ip, geo in geo_data.items():
        if ip == config.server_host:
            return geo
    # First non-private IP with ASN
    for ip, geo in geo_data.items():
        if not geo.is_private and geo.asn:
            return geo
    return None


def _check_asn(config: ConfigInfo, geo_data: dict, result: CdnInfo) -> str | None:
    """Check if server IP's ASN matches a known CDN."""
    server_geo = _find_server_geo(config, geo_data)
    if not server_geo or not server_geo.asn:
        return None

    provider = constants.CDN_ASN_MAP.get(server_geo.asn)
    if provider:
        result.is_cdn = True
        result.provider = provider
        result.indicators.append(
            f"Server IP ASN (AS{server_geo.asn}) belongs to {provider}"
        )
        return provider

    return None


def _check_host_header_domain(config: ConfigInfo, result: CdnInfo):
    """Match host_header and SNI against CDN domain suffix patterns."""
    for domain_to_check, source_label in [
        (config.host_header, "Host header"),
        (config.sni, "SNI"),
    ]:
        if not domain_to_check:
            continue
        domain_lower = domain_to_check.lower()

        # Check Cloudflare serverless patterns first (more specific)
        for suffix, provider in constants.CLOUDFLARE_SERVERLESS_PATTERNS.items():
            if domain_lower.endswith(suffix):
                result.is_cdn = True
                result.is_serverless = True
                result.provider = provider
                result.cdn_from_host_header = provider
                result.indicators.append(
                    f"{source_label} '{domain_to_check}' matches {provider} "
                    f"pattern (*{suffix})"
                )
                return

        # Check general CDN domain patterns
        for suffix, provider in constants.CDN_DOMAIN_PATTERNS.items():
            if domain_lower.endswith(suffix):
                result.is_cdn = True
                if not result.provider or result.provider == "Direct":
                    result.provider = provider
                result.cdn_from_host_header = provider
                result.indicators.append(
                    f"{source_label} '{domain_to_check}' matches {provider} "
                    f"domain pattern (*{suffix})"
                )
                return


def _check_config_indicators(config: ConfigInfo, result: CdnInfo):
    """Check config-level CDN/tunnel indicators."""
    if (
        config.host_header
        and config.host_header != config.server_host
        and config.host_header != config.sni
    ):
        if config.host_header.lower() in constants.IRANIAN_DECOY_HOSTS:
            result.indicators.append(
                f"Host header '{config.host_header}' is a known Iranian decoy site "
                f"(HTTP header obfuscation)"
            )
        elif not result.cdn_from_host_header:
            # Only add generic indicator if we didn't already identify the CDN
            result.indicators.append(
                f"Host header '{config.host_header}' differs from server address "
                f"'{config.server_host}' (possible CDN fronting)"
            )

    if config.transport == "ws":
        result.indicators.append(
            "WebSocket transport (commonly used with CDN providers)"
        )

    if config.transport == "grpc":
        result.indicators.append(
            "gRPC transport (commonly used with CDN providers)"
        )

    if config.transport == "httpupgrade":
        result.indicators.append(
            "HTTPUpgrade transport (commonly used with CDN providers)"
        )


def _check_cname(dns_results: list, result: CdnInfo):
    """Check CNAME chain for CDN-related domains."""
    for dns_result in dns_results:
        for cname in dns_result.cname_chain:
            cname_lower = cname.lower()
            for indicator, provider in constants.CDN_CNAME_INDICATORS.items():
                if indicator in cname_lower:
                    result.is_cdn = True
                    if not result.provider or result.provider == "Direct":
                        result.provider = provider
                    result.indicators.append(
                        f"CNAME chain includes '{cname}' ({provider})"
                    )
                    break


def _check_anycast(dns_results: list, result: CdnInfo):
    """Multiple resolved IPs suggest CDN anycast."""
    for dns_result in dns_results:
        if len(dns_result.ips) > 1:
            result.indicators.append(
                f"Hostname resolves to {len(dns_result.ips)} IPs "
                f"(typical of CDN anycast)"
            )


def _check_response_headers(response_headers: dict | None, result: CdnInfo):
    """Check HTTP response headers for CDN indicators."""
    if not response_headers:
        return

    for header_name, header_value in response_headers.items():
        header_lower = header_name.lower()

        # Presence-based detection
        if header_lower in constants.CDN_RESPONSE_HEADERS:
            provider = constants.CDN_RESPONSE_HEADERS[header_lower]
            result.is_cdn = True
            if not result.provider or result.provider == "Direct":
                result.provider = provider
            result.cdn_from_response_headers = provider
            result.indicators.append(
                f"Response header '{header_name}: {header_value[:80]}' "
                f"indicates {provider}"
            )

        # Value-based detection (server header)
        if header_lower == "server":
            value_lower = header_value.lower()
            for pattern, provider in constants.CDN_SERVER_HEADER_VALUES.items():
                if pattern in value_lower:
                    result.is_cdn = True
                    if not result.provider or result.provider == "Direct":
                        result.provider = provider
                    result.cdn_from_response_headers = provider
                    result.indicators.append(
                        f"Server header '{header_value}' indicates {provider}"
                    )
                    break


def _check_tunnel_pattern(config: ConfigInfo, result: CdnInfo):
    """Detect HTTP header obfuscation / tunnel patterns."""
    if config.transport == "tcp" and config.header_type == "http":
        result.is_tunnel = True
        result.tunnel_type = "HTTP Header Obfuscation"

        if config.host_header:
            if config.host_header.lower() in constants.IRANIAN_DECOY_HOSTS:
                result.indicators.append(
                    f"TCP + HTTP header obfuscation using Iranian decoy host "
                    f"'{config.host_header}' (tunnel pattern)"
                )
            else:
                result.indicators.append(
                    f"TCP + HTTP header obfuscation with host '{config.host_header}' "
                    f"(tunnel pattern)"
                )
        else:
            result.indicators.append(
                "TCP + HTTP header obfuscation (tunnel pattern)"
            )


def _check_reality(config: ConfigInfo, result: CdnInfo):
    """Detect Reality/XTLS-Vision stealth protocol."""
    if config.tls != "reality":
        return

    result.is_reality = True
    parts = ["security=reality"]
    if config.extra.get("pbk"):
        parts.append("publicKey present")
    if config.extra.get("sid"):
        parts.append("shortId present")
    if config.fingerprint:
        parts.append(f"fingerprint={config.fingerprint}")
    if config.flow:
        parts.append(f"flow={config.flow}")

    result.indicators.append(f"REALITY protocol detected ({', '.join(parts)})")
    if config.sni:
        result.indicators.append(
            f"REALITY target SNI: {config.sni} "
            f"(traffic mimics HTTPS to this site)"
        )


def _check_server_in_iran(config: ConfigInfo, geo_data: dict, result: CdnInfo):
    """Check if the server IP is located in Iran.

    Uses three independent signals:
    1. Geo API country code == IR
    2. ASN in known Iranian ISP list
    3. CIDR offline range check (works even when geo API is down)
    """
    server_geo = _find_server_geo(config, geo_data)
    server_ip = config.server_host if config.host_is_ip else ""
    if not server_ip and server_geo:
        server_ip = server_geo.ip

    is_iran = False
    isp_name = "Unknown ISP"

    if server_geo:
        if server_geo.country_code == "IR":
            is_iran = True
            isp_name = server_geo.org or server_geo.isp or "Iranian ISP"
        if server_geo.asn and server_geo.asn in constants.IRANIAN_ISPS:
            is_iran = True
            isp_name = constants.IRANIAN_ISPS[server_geo.asn]

    # CIDR offline check — reliable even when geo API returns nothing
    if server_ip and not is_iran:
        cidr_isp = cidr_isp_lookup(server_ip)
        if cidr_isp:
            is_iran = True
            isp_name = cidr_isp

    if is_iran:
        result.server_is_iran = True
        result.indicators.append(
            f"Server IP {server_ip or 'unknown'} is in Iran ({isp_name}) — "
            f"this is a relay/tunnel entry point"
        )


def _check_iranian_decoy(config: ConfigInfo, result: CdnInfo):
    """Detect Iranian decoy hostnames in host header, including .ir TLD auto-detection."""
    host = config.host_header or ""
    if not host or host == config.server_host:
        return

    host_lower = host.lower()

    # Known Iranian decoy sites
    if host_lower in constants.IRANIAN_DECOY_HOSTS:
        result.indicators.append(
            f"Host header '{host}' is a known Iranian decoy/popular site "
            f"(HTTP header obfuscation for censorship bypass)"
        )
        return

    # Any .ir TLD domain is almost certainly an Iranian decoy
    if host_lower.endswith(".ir"):
        result.indicators.append(
            f"Host header '{host}' uses .ir TLD — very likely an Iranian decoy site "
            f"(HTTP header obfuscation for censorship bypass)"
        )


def _classify_routing_pattern(config: ConfigInfo, result: CdnInfo, connection_test=None):
    """Classify the overall routing pattern and build the routing chain.

    Key signals (in priority order):
    - Reality protocol
    - Cloudflare serverless
    - Server in Iran (relay)
    - CDN fronting
    - entry_ip != exit_ip (proven relay/forwarding even without other signals)
    - Direct connection
    """
    chain = ["Your PC"]
    RP = constants.RoutingPattern

    # Check if connection test proves relay (entry != exit)
    entry_exit_differ = False
    if connection_test and getattr(connection_test, "success", False):
        entry_ip = getattr(connection_test, "entry_ip", "")
        exit_ip = getattr(connection_test, "exit_ip", "")
        if entry_ip and exit_ip and entry_ip != exit_ip:
            entry_exit_differ = True

    # Reality protocol
    if result.is_reality:
        result.routing_pattern = RP.REALITY.value
        if result.server_is_iran:
            result.routing_pattern = RP.MULTI_LAYER.value
            chain.append(f"Iranian Relay ({config.server_host})")
        chain.append(f"V2Ray Server (REALITY -> mimics {config.sni or 'target'})")
        chain.append("Internet")
        result.routing_chain = chain
        return

    # Cloudflare Workers/Pages/Tunnel (serverless)
    if result.is_serverless:
        if "Workers" in result.provider:
            result.routing_pattern = RP.CLOUDFLARE_WORKERS.value
        elif "Pages" in result.provider:
            result.routing_pattern = RP.CLOUDFLARE_PAGES.value
        elif "Tunnel" in result.provider:
            result.routing_pattern = RP.CLOUDFLARE_TUNNEL.value
        else:
            result.routing_pattern = RP.CDN_FRONTED.value

        if result.server_is_iran:
            chain.append(f"Iranian Relay ({config.server_host})")
            result.routing_pattern = RP.MULTI_LAYER.value
        chain.append("Cloudflare Edge")
        chain.append(f"{result.provider}")
        chain.append("Internet")
        result.routing_chain = chain
        return

    # Iranian server relay patterns
    if result.server_is_iran:
        if result.is_tunnel:
            result.routing_pattern = RP.HTTP_OBFUSCATION_RELAY.value
            chain.append(f"Iranian Relay ({config.server_host})")
            if result.is_cdn:
                result.routing_pattern = RP.MULTI_LAYER.value
                chain.append(f"{result.provider} CDN Edge")
                chain.append("Origin Server")
            else:
                chain.append("External V2Ray Server")
            chain.append("Internet")
            result.routing_chain = chain
            return
        elif result.is_cdn:
            result.routing_pattern = RP.MULTI_LAYER.value
            chain.append(f"Iranian Relay ({config.server_host})")
            chain.append(f"{result.provider} CDN Edge")
            chain.append("Origin Server")
            chain.append("Internet")
            result.routing_chain = chain
            return
        else:
            result.routing_pattern = RP.IP_FORWARDING_RELAY.value
            result.is_relay = True
            chain.append(f"Iranian Relay ({config.server_host})")
            chain.append("External V2Ray Server")
            chain.append("Internet")
            result.routing_chain = chain
            return

    # CDN-fronted (non-Iranian server)
    if result.is_cdn:
        result.routing_pattern = RP.CDN_FRONTED.value
        transport_label = config.transport.upper()
        if config.tls == "tls":
            transport_label += " + TLS"
        chain.append(f"{result.provider} CDN Edge ({transport_label})")
        chain.append(f"Origin Server ({config.server_host})")
        chain.append("Internet")
        result.routing_chain = chain
        return

    # Connection test proves relay even though we couldn't identify the CDN
    if entry_exit_differ:
        result.routing_pattern = RP.IP_FORWARDING_RELAY.value
        result.is_relay = True
        chain.append(f"Entry Server ({config.server_host})")
        chain.append("Relay/Forwarding Layer")
        chain.append("Exit Server")
        chain.append("Internet")
        result.routing_chain = chain
        result.indicators.append(
            f"Connection test shows entry IP differs from exit IP — "
            f"traffic is forwarded through at least one relay layer"
        )
        return

    # Direct connection (default)
    result.routing_pattern = RP.DIRECT.value
    chain.append(f"V2Ray Server ({config.server_host})")
    chain.append("Internet")
    result.routing_chain = chain


def _determine_confidence(result: CdnInfo, asn_provider: str | None):
    """Set confidence based on signal strength."""
    strong_signals = 0
    if result.cdn_from_host_header:
        strong_signals += 1
    if result.cdn_from_response_headers:
        strong_signals += 1
    if asn_provider:
        strong_signals += 1
    if result.server_is_iran:
        strong_signals += 1
    if result.is_reality:
        strong_signals += 1
    if result.is_tunnel:
        strong_signals += 1

    if strong_signals >= 2:
        result.confidence = "high"
    elif strong_signals == 1:
        result.confidence = "high" if (result.is_reality or result.server_is_iran) else "medium"
    elif len(result.indicators) >= 2:
        result.confidence = "medium"
    else:
        result.confidence = "low" if result.indicators else "high"
