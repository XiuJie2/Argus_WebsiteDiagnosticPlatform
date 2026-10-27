"""目標 URL 的深層防禦驗證（第二道；Argus strix client 已驗第一道）。

比照 Argus `apps/scans/services.assert_public_http_url` 的精神：只允許公開 HTTP(S)、
標準埠、無 userinfo、DNS 不解析到私網／保留網段。任何不符即拒絕——Strix 偏主動，
一旦目標被竄改成內網位址就可能打進內網，故在送 Strix 之前再驗一次。
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

_ALLOWED_SCHEMES = {"http", "https"}
_ALLOWED_PORTS = {80, 443, None}


class TargetRejected(ValueError):
    """安全錯誤碼（snake_case），不外洩細節。"""


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def assert_scannable(url: str, *, allow_private: bool = False) -> str:
    """驗證並回傳正規化後的 URL；不合規則丟 TargetRejected（帶安全錯誤碼）。"""
    parts = urlsplit((url or "").strip())

    if parts.scheme not in _ALLOWED_SCHEMES:
        raise TargetRejected("scheme_not_allowed")
    if parts.username or parts.password:
        raise TargetRejected("userinfo_not_allowed")
    host = parts.hostname
    if not host:
        raise TargetRejected("missing_host")
    try:
        port = parts.port
    except ValueError as exc:
        raise TargetRejected("bad_port") from exc
    if port not in _ALLOWED_PORTS:
        raise TargetRejected("port_not_allowed")

    if allow_private:
        return url.strip()

    # DNS 解析必須全部指向公網；任一私網／保留位址即拒（防 DNS rebinding 的第一步）。
    try:
        infos = socket.getaddrinfo(host, port or (443 if parts.scheme == "https" else 80))
    except socket.gaierror as exc:
        raise TargetRejected("dns_resolution_failed") from exc

    resolved = {info[4][0] for info in infos}
    if not resolved:
        raise TargetRejected("dns_resolution_failed")
    for ip in resolved:
        if not _is_public_ip(ip):
            raise TargetRejected("target_not_public")

    return url.strip()
