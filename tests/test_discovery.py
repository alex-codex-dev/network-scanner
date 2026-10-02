import ipaddress
import subprocess

import pytest

from network_scanner import discovery


def test_ping_command_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(discovery.platform, "system", lambda: "Linux")

    assert discovery.ping_command("127.0.0.1", 1.0) == [
        "ping",
        "-c",
        "1",
        "-W",
        "1",
        "127.0.0.1",
    ]


def test_is_reachable_uses_ping(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(discovery.subprocess, "run", fake_run)
    monkeypatch.setattr(discovery.platform, "system", lambda: "Linux")

    assert discovery.is_reachable("127.0.0.1")
    assert calls == [["ping", "-c", "1", "-W", "1", "127.0.0.1"]]


def test_is_reachable_handles_missing_ping(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing_ping(*args: object, **kwargs: object) -> None:
        raise FileNotFoundError

    monkeypatch.setattr(discovery.subprocess, "run", missing_ping)
    with pytest.raises(RuntimeError, match="ping command was not found"):
        discovery.is_reachable("127.0.0.1")


def test_discover_hosts_uses_only_network_hosts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checked: list[str] = []

    def fake_reachable(address: str, timeout: float) -> bool:
        checked.append(address)
        return address == "192.0.2.2"

    monkeypatch.setattr(discovery, "is_reachable", fake_reachable)

    found = discovery.discover_hosts(ipaddress.ip_network("192.0.2.0/30"), 0.25)

    assert checked == ["192.0.2.1", "192.0.2.2"]
    assert found == ["192.0.2.2"]
