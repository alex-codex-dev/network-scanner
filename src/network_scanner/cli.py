"""Command-line interface for the network scanner."""

from __future__ import annotations

import argparse
import ipaddress
import sys

from network_scanner.discovery import discover_hosts

DEFAULT_MAX_HOSTS = 256


def parse_network(value: str) -> ipaddress.IPv4Network:
    """Parse a strict IPv4 CIDR network or raise a helpful error."""
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error
    if not isinstance(network, ipaddress.IPv4Network):
        raise argparse.ArgumentTypeError("only IPv4 networks are supported")
    return network


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="network-scanner",
        description="Discover ping-responsive hosts on an authorized IPv4 network.",
    )
    parser.add_argument(
        "network", type=parse_network, help="IPv4 network in CIDR notation"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="seconds to wait for each host (default: 1.0)",
    )
    parser.add_argument(
        "--max-hosts",
        type=int,
        default=DEFAULT_MAX_HOSTS,
        help=f"maximum addresses to check (default: {DEFAULT_MAX_HOSTS})",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if args.max_hosts <= 0:
        parser.error("--max-hosts must be greater than zero")

    host_count = args.network.num_addresses
    if args.network.prefixlen < 31:
        host_count -= 2
    if host_count > args.max_hosts:
        parser.error(
            f"network contains {host_count} hosts, exceeding --max-hosts {args.max_hosts}"
        )

    print(f"Scanning {args.network} ({host_count} host addresses)")
    try:
        reachable = discover_hosts(args.network, args.timeout)
    except RuntimeError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    if reachable:
        print("Reachable hosts:")
        for address in reachable:
            print(f"  {address}")
    else:
        print("No ping-responsive hosts found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
