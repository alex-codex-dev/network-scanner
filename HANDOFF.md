# Handoff

## Done

- Integrated Rust V3 as the explicit `--engine icmp` option, retaining V2 as
  the default and sharing the CLI's CIDR, timeout, concurrency and host limit.
- Added network-free CLI engine-selection tests and documented Linux socket
  requirements.

- Added a Python 3.12+ `uv` project with an IPv4 CIDR command-line interface.
- Added sequential ICMP host discovery through the system `ping` command.
- Added input, timeout, missing-command, and maximum-scope handling.
- Added tests that mock ping and discovery; no automated test scans an external
  system.
- Added usage documentation and recorded the implementation decisions.

## Not done

- TCP port scanning, hostname resolution, concurrency, and result export remain
  outside this first iteration.
- The pytest suite is written but could not run: `uv sync` timed out while
  fetching pytest from PyPI. Ruff checks pass.

## Decisions

- See [DECISIONS.md](DECISIONS.md) for the discovery method, scan-size limit,
  and sequential execution choice.

## Resume

```sh
uv sync
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

Retry `uv sync` when PyPI is reachable, then run the checks above.

For the Rust implementation, run:

```sh
cargo fmt --manifest-path rust-scanner/Cargo.toml -- --check
cargo clippy --manifest-path rust-scanner/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path rust-scanner/Cargo.toml
```
