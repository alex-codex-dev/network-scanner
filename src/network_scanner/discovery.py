"""Host discovery using one ordinary ICMP echo request per address."""

from __future__ import annotations

import ipaddress
import platform
import subprocess


def ping_command(address: str, timeout: float) -> list[str]:
    """Build a one-packet ping command for the current operating system."""
    system = platform.system()
    if system == "Windows":
        return ["ping", "-n", "1", "-w", str(round(timeout * 1000)), address]
    if system == "Darwin":
        return ["ping", "-c", "1", "-W", str(round(timeout * 1000)), address]
    return ["ping", "-c", "1", "-W", str(max(1, round(timeout))), address]


def is_reachable(address: str, timeout: float = 1.0) -> bool:
    """Return whether a single host replies to a ping before the timeout."""
    try:
        result = subprocess.run(
            ping_command(address, timeout),
            capture_output=True,
            check=False,
            timeout=timeout + 1,
        )
    except FileNotFoundError as error:
        raise RuntimeError("ping command was not found") from error
    except subprocess.TimeoutExpired:
        return False
    return result.returncode == 0


def discover_hosts(
    network: ipaddress.IPv4Network,
    timeout: float = 1.0,
) -> list[str]:
    """Return responding host addresses from an IPv4 network, in address order."""
    return [
        str(address)
        for address in network.hosts()
        if is_reachable(str(address), timeout)
    ]
