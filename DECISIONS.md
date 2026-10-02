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

## 2026-09-29 — Keep checks sequential

Check one address at a time. Sequential execution makes the flow easy to learn
and understand; concurrency can be considered in a later iteration.
