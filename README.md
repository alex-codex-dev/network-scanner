# Network Scanner

A small, educational command-line tool for discovering hosts that reply to an
ICMP echo request on an IPv4 network. Use it only on networks and systems you
are authorized to scan.

## Requirements

- Python 3.12 or newer
- [uv](https://docs.astral.sh/uv/)
- The operating system's `ping` command

## Setup

```sh
uv sync
```

## Usage

```sh
uv run network-scanner 192.168.1.0/24
```

The scanner checks up to 256 host addresses by default. Increase that limit
explicitly for a larger authorized network. Each address is checked in order,
with a one-second timeout by default:

```sh
uv run network-scanner 192.168.1.0/24 --timeout 2 --max-hosts 512
```

The command prints addresses that respond to ping. A host that does not reply
may still be online if ICMP is filtered or disabled. This first version does
not scan TCP ports, resolve hostnames, or export results.

## Development

```sh
uv run pytest
uv run ruff check .
uv run ruff format --check .
```
