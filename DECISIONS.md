# Decisions

## 2026-09-29 — Use the system ping command for discovery

Use one ICMP echo request through the platform's ordinary `ping` utility per
address. This keeps the implementation small and avoids raw-socket privileges
or an external dependency. Command flags vary by operating system, so the
discovery module builds the appropriate basic command for Windows, macOS, and
Unix-like systems. A missing utility is reported as a clear error.

## 2026-09-29 — Bound the number of addresses checked

Limit scans to 256 host addresses by default and require an explicit
`--max-hosts` increase for larger networks. This makes the scope visible and
avoids accidentally iterating a very large CIDR range.

## 2026-10-02 — Use a bounded worker pool in the Rust V2

Keep the system `ping` utility for comparable discovery behavior and to avoid
raw-socket privileges. Rust uses a fixed number of worker threads (default 32)
to run at most that many ping processes concurrently. The positive
`--concurrency` option is configurable, and `--max-hosts` defaults to the same
256 host addresses as Python. Workers write results into a shared collection;
the CLI sorts IPv4 addresses before printing so output order is deterministic.

The implementation uses `clap` for conventional argument parsing and
`wait-timeout` to bound ping process waits. Standard-library threads and
synchronization keep the worker pool explicit and suitable for learning.
Platform-specific ordinary ping flags are used; tests exercise parsing and
address enumeration without requiring a network. An absent ping executable is
reported as an error. Ping exit failures and timeouts mean the host is not
reported as reachable.
