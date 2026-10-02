import argparse
import ipaddress

import pytest

from network_scanner import cli


def test_parse_network_accepts_ipv4() -> None:
    assert cli.parse_network("192.168.1.0/24") == ipaddress.ip_network("192.168.1.0/24")


@pytest.mark.parametrize("value", ["192.168.1.2/24", "not-a-network", "2001:db8::/32"])
def test_parse_network_rejects_invalid_input(value: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        cli.parse_network(value)


def test_main_prints_reachable_hosts(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "discover_hosts", lambda network, timeout: ["127.0.0.1"])

    assert cli.main(["127.0.0.0/30"]) == 0
    assert "127.0.0.1" in capsys.readouterr().out


def test_main_rejects_large_network() -> None:
    with pytest.raises(SystemExit) as error:
        cli.main(["10.0.0.0/8"])
    assert error.value.code == 2


def test_main_reports_missing_ping(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail(network: ipaddress.IPv4Network, timeout: float) -> list[str]:
        raise RuntimeError("ping command was not found")

    monkeypatch.setattr(cli, "discover_hosts", fail)

    assert cli.main(["127.0.0.0/30"]) == 1
    assert "ping command was not found" in capsys.readouterr().err
