# Network Scanner — Project Instructions

## Goal
Build a simple, readable network scanner for learning and for use only on networks and systems where the user is authorized to perform scans.

## Safety
- Do not implement exploitation, credential attacks, persistence, stealth, evasion, or destructive actions.
- Do not attempt to bypass firewalls, authentication, access controls, or security monitoring.
- Keep scanning functionality transparent and easy to understand.
- Tests must use localhost, mocks, or clearly controlled test targets when possible.

## Development workflow
- Work only on the current feature/* branch.
- Never commit or push directly to main or develop.
- Never force-push.
- Never use --no-verify.
- Keep changes small and understandable.
- Explain important implementation choices.
- Add tests for new functionality.
- Keep the project documentation updated.

## Version 1
Create a small command-line network scanner.

Initial capabilities:
- Accept an IPv4 network in CIDR notation, for example 192.168.1.0/24.
- Validate the supplied network.
- Discover reachable hosts using a simple and understandable method.
- Display results clearly in the terminal.
- Handle invalid input and common errors cleanly.
- Keep the architecture ready for later features such as TCP port scanning, hostname resolution, and result export.

## Python
Use Python 3.12.
Use uv for project/dependency management.
Use pytest for tests.
Use ruff for linting and formatting.
Prefer the Python standard library unless an external dependency provides a clear benefit.
