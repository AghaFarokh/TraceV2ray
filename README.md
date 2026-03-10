# TraceV2ray

Network route diagnostic tool for V2Ray proxy configurations.

Traces the full network path of a V2Ray config — showing every hop, CDN layer, tunnel entry point, and exit IP — and generates a portable report you can share for support.

## Features

- **Deep CDN detection** — Cloudflare, Fastly, ArvanCloud, Akamai, Amazon CloudFront, Azure, Gcore, and more
- **Cloudflare serverless** — Workers, Pages, Tunnel pattern detection
- **Reality / XTLS** — Detects REALITY protocol with public key and fingerprint info
- **HTTP header obfuscation** — Identifies TCP+HTTP tunnel patterns with Iranian decoy hosts
- **Iranian relay detection** — Flags when the server IP is inside Iran (tunnel entry point)
- **Multi-layer setups** — e.g. Iran relay → ArvanCloud → Cloudflare → origin
- **Host header DNS** — Resolves the CDN domain from the host header, showing actual CDN IPs
- **Response header analysis** — Detects CDN from HTTP response headers (`cf-ray`, `x-served-by`, etc.)
- **Full traceroute** — Shows every hop with country, city, ASN, and ISP
- **Connection test** — Uses xray-core to verify the config works and reveals the actual exit IP
- **Portable report** — Saves a `.txt` file suitable for sending via Telegram

## Supported Protocols

| Protocol | Transports | Security |
|---|---|---|
| VLESS | TCP, WS, gRPC, HTTPUpgrade, H2, KCP | None, TLS, REALITY |
| VMess | TCP, WS, gRPC, HTTPUpgrade, H2, KCP | None, TLS |
| Trojan | TCP, WS, gRPC | TLS |
| Shadowsocks | TCP | — |

## Requirements

- Python 3.10+ (no third-party packages needed — pure stdlib)
- `xray-core` binary placed next to the script for connection testing (optional)

## Usage

### Run directly (Python)

```bash
python3 -m tracev2ray "vless://..."
```

```bash
# Faster traceroute timeout for quick testing
python3 -m tracev2ray "vless://..." --traceroute-timeout 15

# Skip connection test (no xray-core needed)
python3 -m tracev2ray "vless://..." --no-connection-test

# Interactive mode — prompts for config URI
python3 -m tracev2ray
```

### Run the built Windows executable

```
TraceV2ray.exe "vless://..."
```

Or double-click `TraceV2ray.exe` — it will prompt for the URI interactively.

The report is saved as `TraceV2ray_Report_YYYYMMDD_HHMMSS.txt` in the current directory.

## Building the Windows Executable

PyInstaller must run **on Windows** (no cross-compilation).

```bat
pip install pyinstaller
pyinstaller build.spec
```

Output: `dist\TraceV2ray.exe`

Place `xray.exe` next to `TraceV2ray.exe` for full connection testing:

```
📁 distribute/
├── TraceV2ray.exe
└── xray.exe
```

## xray-core

Download the appropriate binary from the [xray-core releases](https://github.com/XTLS/Xray-core/releases):

- Windows: `Xray-windows-64.zip` → `xray.exe`
- macOS ARM: `Xray-macos-arm64-v8a.zip` → `xray`
- Linux: `Xray-linux-64.zip` → `xray`

Place it in the same directory as the script or executable.

## Report Sections

| Section | Description |
|---|---|
| CONFIG ANALYSIS | Parsed protocol, transport, security, host header |
| DNS RESOLUTION | Resolved IPs and CNAME chain for server hostname |
| SERVER LOCATION | Country, ISP, ASN for the server IP |
| HOST HEADER DNS | Resolved IPs for the CDN/host header domain |
| TRACEROUTE | Full hop-by-hop path with geo info |
| CONNECTION TEST | Live test via xray-core, reveals actual exit IP |
| ROUTING ANALYSIS | Detected pattern, routing chain, detection signals |
| TRAFFIC FLOW SUMMARY | Visual end-to-end flow diagram |

## Project Structure

```
tracev2ray/
├── __init__.py         # Package version
├── __main__.py         # Entry point (python -m tracev2ray)
├── main.py             # Orchestrator and CLI
├── config_parser.py    # VLESS / VMess / Trojan / SS URI parsing
├── dns_resolver.py     # DNS + raw CNAME chain detection
├── traceroute.py       # Cross-platform traceroute runner
├── geo_lookup.py       # IP geolocation via ip-api.com
├── cdn_detect.py       # Deep routing pattern detection
├── socks_client.py     # Pure stdlib SOCKS5 client
├── xray_manager.py     # xray-core process and connection test
├── report.py           # Report generation
└── constants.py        # CDN/ISP knowledge base, shared constants
```

## License

MIT
