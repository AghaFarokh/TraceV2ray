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

---

## Download & Run (Pre-built Binaries)

Download the latest release from the [Releases page](../../releases/latest).

| File | Platform |
|------|----------|
| `TraceV2ray-windows-x64.zip` | Windows 10/11 (64-bit) |
| `TraceV2ray-macos-arm64.zip` | macOS Apple Silicon (M1 / M2 / M3) |
| `TraceV2ray-macos-x64.zip` | macOS Intel |
| `TraceV2ray-linux-x64.zip` | Linux (64-bit) |

Each zip contains `TraceV2ray` (or `TraceV2ray.exe`) and `xray-core` — no installation or Python required.

---

### Windows

1. Download `TraceV2ray-windows-x64.zip`
2. Right-click the zip → **Extract All** → choose a folder
3. Open the extracted folder — you will see:
   ```
   TraceV2ray.exe
   xray.exe
   ```
4. **Option A — Interactive (easiest):** Double-click `TraceV2ray.exe`. A console window opens and asks you to paste your config URI.
5. **Option B — Command line:** Open the folder in Terminal / Command Prompt and run:
   ```
   TraceV2ray.exe "vless://..."
   ```

> **Windows Defender warning:** Windows may show a SmartScreen warning because the executable is not signed. Click **"More info"** → **"Run anyway"** to proceed. This is expected for unsigned open-source tools.

The report is saved as `TraceV2ray_Report_YYYYMMDD_HHMMSS.txt` in the same folder. Send this file for support analysis.

---

### macOS

1. Download the correct zip for your Mac:
   - **Apple Silicon (M1/M2/M3):** `TraceV2ray-macos-arm64.zip`
   - **Intel Mac:** `TraceV2ray-macos-x64.zip`
2. Double-click the zip to extract it. You will see:
   ```
   TraceV2ray
   xray
   ```
3. Open **Terminal** (Applications → Utilities → Terminal)
4. Navigate to the extracted folder:
   ```bash
   cd ~/Downloads/TraceV2ray-macos-arm64   # adjust folder name
   ```
5. Make the files executable (first run only):
   ```bash
   chmod +x TraceV2ray xray
   ```
6. Run it:
   ```bash
   ./TraceV2ray "vless://..."
   ```
   Or without arguments for interactive mode:
   ```bash
   ./TraceV2ray
   ```

> **macOS Gatekeeper warning:** macOS may block the executable with _"cannot be opened because it is from an unidentified developer"_.
> To fix this, run once in Terminal:
> ```bash
> xattr -dr com.apple.quarantine TraceV2ray xray
> ```
> Then run `./TraceV2ray` normally.

---

### Linux

1. Download `TraceV2ray-linux-x64.zip`
2. Extract:
   ```bash
   unzip TraceV2ray-linux-x64.zip -d TraceV2ray
   cd TraceV2ray
   ```
3. Make executable (first run only):
   ```bash
   chmod +x TraceV2ray xray
   ```
4. Run:
   ```bash
   ./TraceV2ray "vless://..."
   ```
   Or interactive mode:
   ```bash
   ./TraceV2ray
   ```

> **Traceroute on Linux** requires raw socket access. If traceroute shows a permission error, run with `sudo`:
> ```bash
> sudo ./TraceV2ray "vless://..."
> ```

---

### How to get your config URI

Your V2Ray config URI starts with `vless://`, `vmess://`, `trojan://`, or `ss://`. You can copy it from your V2Ray client app (Nekobox, v2rayN, Streisand, etc.) by long-pressing the config and selecting "Copy URI" or "Share".

---

## Supported Protocols

| Protocol | Transports | Security |
|---|---|---|
| VLESS | TCP, WS, gRPC, HTTPUpgrade, H2, KCP | None, TLS, REALITY |
| VMess | TCP, WS, gRPC, HTTPUpgrade, H2, KCP | None, TLS |
| Trojan | TCP, WS, gRPC | TLS |
| Shadowsocks | TCP | — |

---

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

---

## Run from Source (Python)

Requires Python 3.10+ — no third-party packages needed.

```bash
python3 -m tracev2ray "vless://..."
```

```bash
# Shorter traceroute timeout for quick testing
python3 -m tracev2ray "vless://..." --traceroute-timeout 15

# Skip connection test (no xray-core needed)
python3 -m tracev2ray "vless://..." --no-connection-test

# Interactive mode — prompts for config URI
python3 -m tracev2ray
```

Place `xray` (or `xray.exe` on Windows) in the project root for the connection test to work.

---

## Build from Source

PyInstaller must run **on the target OS** — no cross-compilation.

```bash
pip install pyinstaller
pyinstaller build.spec
```

Output: `dist/TraceV2ray` (or `dist\TraceV2ray.exe` on Windows).

Pre-built binaries for all platforms are also provided on the [Releases page](../../releases/latest) via GitHub Actions.

---

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
