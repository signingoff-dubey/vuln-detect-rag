import socket

import pytest
from fastapi import HTTPException

from services import target_validation as tv


def _fake_dns(mapping):
    def getaddrinfo(host, *args, **kwargs):
        if host not in mapping:
            raise socket.gaierror("no such host")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in mapping[host]]

    return getaddrinfo


@pytest.mark.parametrize(
    "target",
    [
        "127.0.0.1",
        "10.0.0.5",
        "192.168.1.1",
        "172.16.0.9",
        "169.254.169.254",
        "0.0.0.0",
        "100.64.0.1",
        "::1",
        "fe80::1",
        "::ffff:127.0.0.1",
        "224.0.0.1",
        "localhost",
        "LOCALHOST.",
        "printer.local",
        "db.internal",
        "app.localhost",
        "",
        "   ",
        "999.999.999.999",
        "not a host",
        "a" * 300,
        "exa_mple.com",
        "-bad.example.com",
    ],
)
def test_rejects_forbidden_targets(target):
    with pytest.raises(HTTPException) as exc:
        tv.validate_target(target, resolve=False)
    assert exc.value.status_code == 400


def test_accepts_public_ip_and_hostname():
    assert tv.validate_target("8.8.8.8", resolve=False) == "8.8.8.8"
    assert tv.validate_target("Example.COM.", resolve=False) == "example.com"


def test_hostname_resolving_to_private_ip_is_rejected(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_dns({"evil.example.com": ["127.0.0.1"]}))
    with pytest.raises(HTTPException):
        tv.validate_target("evil.example.com")


def test_any_private_record_rejects(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", _fake_dns({"mixed.example.com": ["93.184.216.34", "10.1.1.1"]})
    )
    with pytest.raises(HTTPException):
        tv.validate_target("mixed.example.com")


def test_unresolvable_hostname_is_rejected(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_dns({}))
    with pytest.raises(HTTPException):
        tv.validate_target("nope.example.com")


def test_public_hostname_passes(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_dns({"ok.example.com": ["93.184.216.34"]}))
    assert tv.validate_target("ok.example.com") == "ok.example.com"


def test_resolve_target_pins_ip_literal(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_dns({"ok.example.com": ["93.184.216.34"]}))
    host, ip = tv.resolve_target("ok.example.com")
    assert host == "ok.example.com"
    assert ip == "93.184.216.34"


def test_resolve_target_rejects_ip_already_passed_through():
    host, ip = tv.resolve_target("8.8.8.8")
    assert (host, ip) == ("8.8.8.8", "8.8.8.8")


def test_resolve_target_catches_dns_rebinding(monkeypatch):
    """A hostname that resolves to a private IP by the time a scanner is
    about to run must be rejected, even though an earlier check (at
    submission time, with a different DNS answer) passed. This is the
    rebinding window resolve_target exists to close: every caller that is
    about to hand a target to a scanner must call it immediately beforehand
    rather than reusing a hostname validated earlier.
    """
    monkeypatch.setattr(socket, "getaddrinfo", _fake_dns({"rebind.example.com": ["93.184.216.34"]}))
    assert tv.validate_target("rebind.example.com") == "rebind.example.com"

    # DNS answer changes between the initial check and the scanner's turn.
    monkeypatch.setattr(socket, "getaddrinfo", _fake_dns({"rebind.example.com": ["169.254.169.254"]}))
    with pytest.raises(HTTPException):
        tv.resolve_target("rebind.example.com")
