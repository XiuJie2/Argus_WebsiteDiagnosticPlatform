"""目標驗證（深層防禦第二道）的單元測試。"""
from __future__ import annotations

import pytest

from app.target_guard import TargetRejected, assert_scannable


@pytest.mark.parametrize(
    "url,code",
    [
        ("ftp://example.com", "scheme_not_allowed"),
        ("file:///etc/passwd", "scheme_not_allowed"),
        ("http://user:pass@example.com", "userinfo_not_allowed"),
        ("http://example.com:8080", "port_not_allowed"),
        ("http://", "missing_host"),
    ],
)
def test_static_rejects(url, code):
    with pytest.raises(TargetRejected) as exc:
        assert_scannable(url, allow_private=False)
    assert str(exc.value) == code


def test_allow_private_bypasses_dns(monkeypatch):
    # allow_private=True 時不做 DNS 檢查（隔離 demo 掃私網靶機）。
    assert assert_scannable("http://localhost/juice", allow_private=True) == (
        "http://localhost/juice"
    )


def test_private_ip_rejected_when_not_allowed(monkeypatch):
    # DNS 解析到私網 → target_not_public。
    monkeypatch.setattr(
        "app.target_guard.socket.getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("10.0.0.5", 443))],
    )
    with pytest.raises(TargetRejected) as exc:
        assert_scannable("https://internal.example.com", allow_private=False)
    assert str(exc.value) == "target_not_public"


def test_public_ip_passes(monkeypatch):
    monkeypatch.setattr(
        "app.target_guard.socket.getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443))],
    )
    assert assert_scannable("https://example.com/app", allow_private=False) == (
        "https://example.com/app"
    )
