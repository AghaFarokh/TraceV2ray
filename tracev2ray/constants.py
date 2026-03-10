"""Shared constants for TraceV2ray."""

from enum import Enum

VERSION = "2.0.0"
TOOL_NAME = "TraceV2ray"

# --- Network Timeouts (seconds) ---
DNS_TIMEOUT = 10
TRACERT_TIMEOUT = 120
GEO_API_TIMEOUT = 15
WHOIS_TIMEOUT = 5
XRAY_STARTUP_TIMEOUT = 15
SOCKS_CONNECT_TIMEOUT = 10
HTTP_TIMEOUT = 15

# --- Xray-core Local Proxy ---
XRAY_SOCKS_PORT = 10808
import platform as _platform
if _platform.system() == "Windows":
    XRAY_BINARY_NAMES = ["xray.exe", "xray-core.exe", "xray"]
else:
    XRAY_BINARY_NAMES = ["xray", "xray-core", "xray.exe", "xray-core.exe"]

# --- IP Echo Services (HTTP only, tried in order) ---
IP_ECHO_SERVICES = [
    {"host": "ip-api.com", "path": "/json/?fields=query", "format": "json", "key": "query"},
    {"host": "ifconfig.me", "path": "/ip", "format": "text"},
    {"host": "icanhazip.com", "path": "/", "format": "text"},
]

# --- Routing Pattern Classification ---
class RoutingPattern(Enum):
    DIRECT = "direct"
    CDN_FRONTED = "cdn_fronted"
    CLOUDFLARE_WORKERS = "cloudflare_workers"
    CLOUDFLARE_PAGES = "cloudflare_pages"
    CLOUDFLARE_TUNNEL = "cloudflare_tunnel"
    HTTP_OBFUSCATION_RELAY = "http_obfuscation_relay"
    IP_FORWARDING_RELAY = "ip_forwarding_relay"
    REALITY = "reality"
    MULTI_LAYER = "multi_layer"
    UNKNOWN = "unknown"

# --- CDN / Hosting Provider ASN Map ---
CDN_ASN_MAP = {
    # Cloudflare
    13335: "Cloudflare",
    132892: "Cloudflare",
    395747: "Cloudflare",
    # ArvanCloud
    208006: "ArvanCloud",
    205585: "ArvanCloud",
    202468: "ArvanCloud",
    210296: "ArvanCloud",
    209459: "ArvanCloud",
    # Fastly
    54113: "Fastly",
    # Gcore
    199524: "Gcore",
    202422: "Gcore",
    # Amazon CloudFront / AWS
    16509: "Amazon/AWS",
    14618: "Amazon/AWS",
    # Google
    15169: "Google",
    396982: "Google",
    # Microsoft / Azure
    8075: "Microsoft/Azure",
    8068: "Microsoft/Azure",
    # Akamai
    20940: "Akamai",
    16625: "Akamai",
    # DigitalOcean
    14061: "DigitalOcean",
    # Hetzner
    24940: "Hetzner",
    # OVH
    16276: "OVH",
    # Linode / Akamai Connected Cloud
    63949: "Linode",
    # Vultr
    20473: "Vultr",
}

# --- CDN Domain Indicators (found in CNAME chains) ---
CDN_CNAME_INDICATORS = {
    "cloudflare": "Cloudflare",
    "cloudflare.net": "Cloudflare",
    "cloudflare.com": "Cloudflare",
    "arvancloud": "ArvanCloud",
    "arvancloud.ir": "ArvanCloud",
    "arvancloud.com": "ArvanCloud",
    "cdn.ir": "ArvanCloud",
    "fastly.net": "Fastly",
    "fastly.com": "Fastly",
    "akamai.net": "Akamai",
    "akamaiedge.net": "Akamai",
    "cloudfront.net": "Amazon CloudFront",
    "azureedge.net": "Microsoft Azure CDN",
    "gcore.com": "Gcore",
    "gcdn.co": "Gcore",
}

# --- CDN Domain Suffix Patterns (matched against host_header, SNI) ---
# Ordered: more specific patterns first
CDN_DOMAIN_PATTERNS = {
    # Cloudflare
    ".cdn.cloudflare.net": "Cloudflare",
    ".cloudflare.com": "Cloudflare",
    ".cloudflare-dns.com": "Cloudflare",
    # Fastly
    ".global.ssl.fastly.net": "Fastly",
    ".fastly.net": "Fastly",
    ".fastlylb.net": "Fastly",
    # ArvanCloud
    ".arvancloud.ir": "ArvanCloud",
    ".arvancloud.com": "ArvanCloud",
    ".cdn.ir": "ArvanCloud",
    # Gcore
    ".gcdn.co": "Gcore",
    ".gcore.com": "Gcore",
    # Amazon CloudFront
    ".cloudfront.net": "Amazon CloudFront",
    # Akamai
    ".akamai.net": "Akamai",
    ".akamaiedge.net": "Akamai",
    ".akamaized.net": "Akamai",
    # Azure CDN
    ".azureedge.net": "Azure CDN",
    # Google
    ".googleapis.com": "Google Cloud",
    ".googlevideo.com": "Google",
}

# --- Cloudflare Serverless / Tunnel Patterns ---
CLOUDFLARE_SERVERLESS_PATTERNS = {
    ".workers.dev": "Cloudflare Workers",
    ".pages.dev": "Cloudflare Pages",
    ".trycloudflare.com": "Cloudflare Tunnel",
}

# --- CDN Response Headers (checked in HTTP responses through proxy) ---
# header_name_lower -> provider_name (presence-based detection)
CDN_RESPONSE_HEADERS = {
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "x-served-by": "Fastly",
    "x-fastly-request-id": "Fastly",
    "x-amz-cf-id": "Amazon CloudFront",
    "x-amz-cf-pop": "Amazon CloudFront",
    "x-akamai-transformed": "Akamai",
    "ar-atime": "ArvanCloud",
    "ar-cache": "ArvanCloud",
    "ar-sid": "ArvanCloud",
}

# --- CDN Server Header Values (value-based detection) ---
CDN_SERVER_HEADER_VALUES = {
    "cloudflare": "Cloudflare",
    "akamaighost": "Akamai",
    "arvancloud": "ArvanCloud",
    "fastly": "Fastly",
    "gcore": "Gcore",
}

# --- Known Iranian Decoy Hostnames (used in HTTP header obfuscation) ---
IRANIAN_DECOY_HOSTS = {
    "soft98.ir",
    "dl.soft98.ir",
    "download.soft98.ir",
    "p30download.ir",
    "dl.p30download.ir",
    "uploadboy.ir",
    "dl.uploadboy.ir",
    "sakhtafzarmag.com",
    "bfrss.ir",
    "mci.ir",
    "hamrahaval.ir",
    "irancell.ir",
    "myirancell.ir",
    "shaparak.ir",
    "digikala.com",
    "snapp.ir",
    "telewebion.com",
    "filimo.com",
    "namasha.com",
    "aparat.com",
    "varzesh3.com",
    "tebyan.net",
    "yjc.ir",
    "isna.ir",
    "mehrnews.com",
    "farsnews.ir",
}

# --- Known Iranian ISP ASNs ---
IRANIAN_ISPS = {
    44244: "Irancell (MTN)",
    197207: "MCCI (Hamrah-e-Aval)",
    58224: "TCI (Telecommunication Company of Iran)",
    12880: "DCI (Information Technology Company)",
    48434: "Parsonline",
    49666: "Pishgaman Toseeh (Pishgaman)",
    56402: "Dadeh Gostar Asr Novin (Rayeneh Gostar)",
    43754: "Asiatech",
    16322: "ParsOnline",
    57218: "Rightel",
    205647: "Rightel",
    39501: "Shatel",
    25124: "Afranet",
    62442: "Respina",
}

# --- Report Constants ---
REPORT_PREFIX = "TraceV2ray_Report"
REPORT_SEPARATOR = "=" * 80
REPORT_SECTION_SEP = "-" * 80
