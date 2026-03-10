"""System traceroute wrapper with output parsing.

Uses `tracert` on Windows, `traceroute` on macOS/Linux.
"""

import platform
import re
import subprocess
import time
from dataclasses import dataclass, field


@dataclass
class HopInfo:
    """A single hop in a traceroute."""

    hop_number: int
    ip: str | None = None  # None if timed out
    rtts: list = field(default_factory=list)  # RTT values in ms (None for timeout)
    is_timeout: bool = False

    @property
    def avg_rtt(self) -> float | None:
        valid = [r for r in self.rtts if r is not None]
        return sum(valid) / len(valid) if valid else None

    @property
    def rtt_display(self) -> str:
        if self.is_timeout:
            return "* * *"
        parts = []
        for r in self.rtts:
            if r is None:
                parts.append("*")
            elif r < 1:
                parts.append("<1ms")
            else:
                parts.append(f"{r:.0f}ms")
        return " ".join(parts)


@dataclass
class TracerouteResult:
    """Complete traceroute result."""

    target_ip: str
    hops: list = field(default_factory=list)  # List[HopInfo]
    completed: bool = False  # True if reached destination
    error: str | None = None
    duration_seconds: float = 0.0


# Windows tracert line patterns
# "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
# "  2     *        *        *     Request timed out."
# "  3    12 ms    11 ms    12 ms  10.0.0.1"
_TRACERT_RE = re.compile(
    r"^\s*(\d+)"  # hop number
    r"\s+([\s\S]*?)$"  # rest of line
)

_TRACERT_RTT_RE = re.compile(r"(<?\d+)\s*ms|(\*)")

_TRACERT_IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

# macOS/Linux traceroute line patterns
# " 1  gateway (192.168.1.1)  1.234 ms  1.456 ms  1.789 ms"
# " 2  * * *"
_TRACEROUTE_RE = re.compile(r"^\s*(\d+)\s+(.*)")


def run_traceroute(
    target_ip: str,
    max_hops: int = 30,
    timeout_per_hop_ms: int = 3000,
    overall_timeout_s: int = 120,
) -> TracerouteResult:
    """Execute system traceroute and parse output.

    Args:
        target_ip: IP address to trace to
        max_hops: Maximum number of hops
        timeout_per_hop_ms: Timeout per hop in milliseconds (Windows only)
        overall_timeout_s: Kill entire process after this many seconds

    Returns:
        TracerouteResult with all hops found.
    """
    result = TracerouteResult(target_ip=target_ip)
    start = time.time()

    is_windows = platform.system() == "Windows"

    if is_windows:
        cmd = [
            "tracert",
            "-d",  # Don't resolve hostnames (faster)
            "-w", str(timeout_per_hop_ms),
            "-h", str(max_hops),
            target_ip,
        ]
    else:
        cmd = [
            "traceroute",
            "-n",  # Don't resolve hostnames
            "-w", "3",  # Timeout per probe
            "-m", str(max_hops),
            target_ip,
        ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=overall_timeout_s,
            encoding="utf-8",
            errors="replace",
        )
        output = proc.stdout or ""
        stderr = proc.stderr or ""

        if is_windows:
            result.hops = _parse_tracert_output(output)
        else:
            result.hops = _parse_traceroute_output(output)

        # Check if we reached the destination
        if result.hops:
            last_hop = result.hops[-1]
            if last_hop.ip == target_ip:
                result.completed = True

        if not result.hops and stderr:
            result.error = f"Traceroute error: {stderr.strip()[:200]}"

    except subprocess.TimeoutExpired:
        result.error = f"Traceroute timed out after {overall_timeout_s}s (network may be filtering ICMP)"
    except FileNotFoundError:
        if is_windows:
            result.error = "tracert command not found"
        else:
            result.error = "traceroute command not found (install with: apt install traceroute / brew install traceroute)"
    except Exception as e:
        result.error = f"Traceroute failed: {e}"

    result.duration_seconds = time.time() - start
    return result


def _parse_tracert_output(output: str) -> list:
    """Parse Windows tracert output into list of HopInfo."""
    hops = []
    in_trace = False

    for line in output.splitlines():
        line = line.strip()

        # Skip header lines, wait for trace to start
        if not in_trace:
            if line.startswith("1") or (line and line[0].isdigit()):
                in_trace = True
            elif "Tracing route" in line or "over a maximum" in line:
                continue
            else:
                continue

        if not line or line.startswith("Trace complete"):
            continue

        # Try to match hop number
        m = _TRACERT_RE.match(line)
        if not m:
            continue

        hop_num = int(m.group(1))
        rest = m.group(2)

        # Extract RTTs
        rtts = []
        for rtt_match in _TRACERT_RTT_RE.finditer(rest):
            if rtt_match.group(2):  # *
                rtts.append(None)
            else:
                val = rtt_match.group(1)
                if val.startswith("<"):
                    rtts.append(0.5)  # <1 ms
                else:
                    rtts.append(float(val))

        # Extract IP
        ip_match = _TRACERT_IP_RE.search(rest)
        ip = ip_match.group(1) if ip_match else None

        is_timeout = all(r is None for r in rtts) if rtts else ("*" in rest or "Request timed out" in rest)

        hops.append(HopInfo(
            hop_number=hop_num,
            ip=ip,
            rtts=rtts,
            is_timeout=is_timeout,
        ))

    return hops


def _parse_traceroute_output(output: str) -> list:
    """Parse Unix traceroute output into list of HopInfo."""
    hops = []

    for line in output.splitlines():
        m = _TRACEROUTE_RE.match(line)
        if not m:
            continue

        hop_num = int(m.group(1))
        rest = m.group(2)

        # All-timeout line
        if rest.strip() == "* * *":
            hops.append(HopInfo(
                hop_number=hop_num,
                rtts=[None, None, None],
                is_timeout=True,
            ))
            continue

        # Extract IPs and RTTs
        ip = None
        rtts = []

        # Look for IP addresses
        ip_match = _TRACERT_IP_RE.search(rest)
        if ip_match:
            ip = ip_match.group(1)

        # Look for RTT values
        for rtt_match in re.finditer(r"([\d.]+)\s*ms", rest):
            rtts.append(float(rtt_match.group(1)))

        # Count timeouts
        rtts.extend([None] * rest.count("*"))

        hops.append(HopInfo(
            hop_number=hop_num,
            ip=ip,
            rtts=rtts[:3],
            is_timeout=not ip,
        ))

    return hops
