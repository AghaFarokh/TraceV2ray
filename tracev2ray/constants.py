"""Shared constants for TraceV2ray."""

import platform as _platform
from enum import Enum

VERSION = "3.0.0"
TOOL_NAME = "TraceV2ray"

# --- Network Timeouts (seconds) ---
DNS_TIMEOUT = 10
TRACERT_TIMEOUT = 120
GEO_API_TIMEOUT = 15
WHOIS_TIMEOUT = 5
XRAY_STARTUP_TIMEOUT = 15
SOCKS_CONNECT_TIMEOUT = 10
HTTP_TIMEOUT = 15
PROBE_TIMEOUT = 8       # Per-request timeout for proxy probe operations
BGP_TIMEOUT = 10        # BGP API call timeout

# --- Xray-core Local Proxy ---
XRAY_SOCKS_PORT = 10808
if _platform.system() == "Windows":
    XRAY_BINARY_NAMES = ["xray.exe", "xray-core.exe", "xray"]
else:
    XRAY_BINARY_NAMES = ["xray", "xray-core", "xray.exe", "xray-core.exe"]

# --- IP Echo Services (HTTP, tried in order for exit IP detection) ---
IP_ECHO_SERVICES = [
    {"host": "ip-api.com", "path": "/json/?fields=query", "format": "json", "key": "query"},
    {"host": "ifconfig.me", "path": "/ip", "format": "text"},
    {"host": "icanhazip.com", "path": "/", "format": "text"},
    {"host": "api.ipify.org", "path": "/", "format": "text"},
    {"host": "checkip.amazonaws.com", "path": "/", "format": "text"},
]

# --- Header-echo services: return all request headers (reveal X-Forwarded-For chains) ---
HEADER_ECHO_SERVICES = [
    {"host": "httpbin.org", "path": "/headers", "format": "json"},
    {"host": "ifconfig.me", "path": "/all.json", "format": "json"},
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

# --- Internet Backbone / Transit Provider ASNs ---
BACKBONE_ASNS = {
    174:    "Cogent Communications",
    701:    "Verizon/UUNET",
    1239:   "Sprint",
    1273:   "Vodafone",
    1299:   "Telia Carrier",
    2828:   "XO Communications",
    2914:   "NTT Communications",
    3257:   "GTT Communications",
    3320:   "Deutsche Telekom",
    3356:   "Lumen Technologies (Level3)",
    3491:   "PCCW Global",
    4134:   "China Telecom",
    4837:   "China Unicom",
    5511:   "Orange S.A.",
    6453:   "TATA Communications",
    6461:   "Zayo Bandwidth",
    6762:   "Telecom Italia Sparkle",
    6830:   "Liberty Global",
    6939:   "Hurricane Electric",
    7018:   "AT&T",
    7922:   "Comcast",
    9002:   "RETN",
    12389:  "Rostelecom",
    12956:  "Telefonica",
    20764:  "RASCOM",
    31133:  "MegaFon",
    57463:  "NetIX",
}

# --- Satellite / Special Network ASNs ---
SATELLITE_ASNS = {
    14593:  "SpaceX Starlink",
    10489:  "Intelsat",
    22351:  "Intelsat",
    26824:  "Intelsat",
    36351:  "SoftLayer (IBM)",
    40676:  "Psychz Networks",
    45102:  "Alibaba Cloud",
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
# Note: Any .ir TLD domain is ALSO automatically treated as a potential decoy.
IRANIAN_DECOY_HOSTS = {
    # Download / software sites
    "soft98.ir", "dl.soft98.ir", "download.soft98.ir",
    "p30download.ir", "dl.p30download.ir",
    "uploadboy.ir", "dl.uploadboy.ir",
    "sakhtafzarmag.com", "bfrss.ir",
    "downloadha.com", "dl.downloadha.com",
    "4downfile.com", "dl.4downfile.com",
    "mobilism.org",
    # ISP sites
    "mci.ir", "hamrahaval.ir", "irancell.ir", "myirancell.ir",
    "mtn.ir", "rightel.com",
    # Payment / banking
    "shaparak.ir", "behpardakht.com", "sadadpsp.ir",
    # Streaming / media
    "filimo.com", "telewebion.com", "namasha.com", "aparat.com",
    "filmnet.ir", "neonline.ir", "fandango.ir",
    "tamasha.com", "fidibo.com",
    # E-commerce
    "digikala.com", "snapp.ir", "bamilo.com", "torob.com",
    "divar.ir", "sheypoor.com",
    # News / media
    "varzesh3.com", "tebyan.net", "yjc.ir", "isna.ir",
    "mehrnews.com", "farsnews.ir", "tasnimnews.com",
    "mashreghnews.ir", "khabaronline.ir", "tabnak.ir",
    "salamno.com", "bartarinha.ir",
    # Government / education
    "iums.ac.ir", "sharif.edu", "ut.ac.ir",
    # Social / communication
    "eitaa.com", "bale.ai", "rubika.ir",
}

# --- Known Iranian ISP ASNs ---
IRANIAN_ISPS = {
    44244:  "Irancell (MTN)",
    197207: "MCCI (Hamrah-e-Aval)",
    58224:  "TCI (Telecommunication Company of Iran)",
    12880:  "DCI (Information Technology Company)",
    48434:  "Parsonline",
    49666:  "Pishgaman Toseeh",
    56402:  "Dadeh Gostar Asr Novin",
    43754:  "Asiatech",
    16322:  "ParsOnline",
    57218:  "Rightel",
    205647: "Rightel",
    39501:  "Shatel",
    25124:  "Afranet",
    62442:  "Respina",
    50810:  "Mobinnet",
    47262:  "Pars Online",
    201150: "Pars Online",
    60474:  "Arvancloud",
    59587:  "Aria Shatel",
    24631:  "Iran Cell Services",
    21341:  "Farahoosh Dena",
    48309:  "Fanava Group",
    31549:  "Aria Telecom",
    44285:  "Aria Telecom",
    197737: "Iran Telecommunication",
    25335:  "Sepanta Net",
    43407:  "Shabakeh Ertebatat Zirsakht",
}

# --- Iranian ISP IP CIDR Ranges (offline detection, no API needed) ---
# Format: {cidr_string: isp_name}
IRANIAN_ISP_CIDRS = {
    # Irancell (MTN) — AS44244
    "5.56.0.0/13":      "Irancell (MTN)",
    "37.32.0.0/11":     "Irancell (MTN)",
    "37.255.0.0/16":    "Irancell (MTN)",
    "185.86.80.0/21":   "Irancell (MTN)",
    "185.162.128.0/22": "Irancell (MTN)",
    "188.158.0.0/15":   "Irancell (MTN)",
    # MCI / MCCI (Hamrah-e-Aval) — AS197207
    "188.0.0.0/11":     "MCI (Hamrah-e-Aval)",
    "185.55.224.0/19":  "MCI (Hamrah-e-Aval)",
    "5.200.64.0/18":    "MCI (Hamrah-e-Aval)",
    # TCI (Telecommunication Company of Iran) — AS58224
    "78.38.0.0/15":     "TCI",
    "85.185.0.0/16":    "TCI",
    "2.144.0.0/13":     "TCI",
    "2.176.0.0/12":     "TCI",
    "80.191.0.0/16":    "TCI",
    "91.99.0.0/16":     "TCI",
    "217.218.0.0/15":   "TCI",
    "194.225.0.0/16":   "TCI",
    # Rightel — AS57218
    "5.125.0.0/16":     "Rightel",
    "185.112.32.0/22":  "Rightel",
    # Shatel — AS39501
    "94.182.0.0/15":    "Shatel",
    "109.122.192.0/18": "Shatel",
    # Asiatech — AS43754
    "82.99.192.0/18":   "Asiatech",
    "5.160.0.0/14":     "Asiatech",
    # Parsonline — AS48434
    "89.42.208.0/21":   "Parsonline",
    "185.16.128.0/21":  "Parsonline",
    # Respina — AS62442
    "31.14.80.0/20":    "Respina",
    "46.143.192.0/18":  "Respina",
    # Afranet — AS25124
    "194.104.0.0/16":   "Afranet",
    "5.63.8.0/21":      "Afranet",
    # Mobinnet — AS50810
    "185.2.12.0/22":    "Mobinnet",
    "91.186.232.0/21":  "Mobinnet",
    # DCI — AS12880
    "194.104.192.0/18": "DCI",
    "195.146.32.0/19":  "DCI",
}

# --- Latency Triangulation Targets ---
# Used to estimate exit server location by measuring RTT through the proxy
# Format: (hostname, port, city, country_code)
LATENCY_TARGETS = [
    ("speedtest.fra1.digitalocean.com", 80, "Frankfurt", "DE"),
    ("speedtest.ams3.digitalocean.com", 80, "Amsterdam", "NL"),
    ("speedtest.lon1.digitalocean.com", 80, "London", "GB"),
    ("speedtest.nyc1.digitalocean.com", 80, "New York", "US"),
    ("speedtest.sfo3.digitalocean.com", 80, "San Francisco", "US"),
    ("speedtest.sgp1.digitalocean.com", 80, "Singapore", "SG"),
    ("speedtest.tor1.digitalocean.com", 80, "Toronto", "CA"),
    ("speedtest.blr1.digitalocean.com", 80, "Bangalore", "IN"),
    ("hetzner-speedtest.hetzner.com", 80, "Nuremberg", "DE"),
]

# --- Report Constants ---
REPORT_PREFIX = "TraceV2ray_Report"
REPORT_SEPARATOR = "=" * 80
REPORT_SECTION_SEP = "-" * 80
