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

## Rust V2

The experimental Rust implementation is in `rust-scanner/`. It uses the
operating system's `ping` command and a bounded worker pool. Its defaults match
the Python limits: 256 host addresses maximum, a one-second per-host timeout,
and 32 concurrent workers.

```sh
cargo run --manifest-path rust-scanner/Cargo.toml -- 192.168.1.0/24
cargo run --manifest-path rust-scanner/Cargo.toml -- 192.168.1.0/24 \
  --timeout 2 --max-hosts 512 --concurrency 16
```

Rust keeps the `v2` engine as the default. Select `--engine icmp` to use the
Rust V3 multiplexed ICMP engine over a Linux ping socket; it uses the same CIDR,
timeout, concurrency and `--max-hosts` options. The ICMP engine requires Linux
and permission from the system's ping socket policy. Socket open or runtime
errors are reported directly. On other platforms the option is rejected with
an explanatory error.

```sh
cargo run --manifest-path rust-scanner/Cargo.toml -- 192.168.1.0/24 --engine icmp
```

Use the Rust scanner only on networks and systems you are authorized to
scan. A host that does not reply may still be online if ICMP is filtered or
disabled. The Rust version performs host discovery only; it does not scan
ports, resolve hostnames, or export results. Its tests do not require a live
network.
