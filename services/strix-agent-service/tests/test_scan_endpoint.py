"""/scan 端點（stub 模式）的契約測試——驗證 Argus ↔ 服務接線。"""
from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient


def _client(monkeypatch, **env) -> TestClient:
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    # 重載 config/main 讓 env 生效（Settings 是凍結 dataclass，於 import 時讀 env）。
    import app.config as config_mod

    importlib.reload(config_mod)
    import app.main as main_mod

    importlib.reload(main_mod)
    return TestClient(main_mod.app)


def test_healthz(monkeypatch):
    c = _client(monkeypatch, STRIX_STUB="true", STRIX_SERVICE_API_KEY="")
    r = c.get("/healthz")
    assert r.status_code == 200
    assert r.json()["stub"] is True


def test_deep_authorized_returns_security_finding(monkeypatch):
    c = _client(monkeypatch, STRIX_STUB="true", STRIX_SERVICE_API_KEY="",
                STRIX_ALLOW_PRIVATE_TARGETS="true")
    r = c.post("/scan", json={"url": "http://localhost/app", "mode": "deep",
                              "authorized": True})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "completed"
    cats = {f["category"] for f in body["findings"]}
    assert "security" in cats
    assert any(f["severity"] == "high" for f in body["findings"])


def test_deep_unauthorized_no_attack_finding(monkeypatch):
    c = _client(monkeypatch, STRIX_STUB="true", STRIX_SERVICE_API_KEY="",
                STRIX_ALLOW_PRIVATE_TARGETS="true")
    r = c.post("/scan", json={"url": "http://localhost/app", "mode": "deep",
                              "authorized": False})
    body = r.json()
    # 未授權：只回 info 說明被收斂，不產生 high/critical 攻擊發現。
    assert all(f["severity"] == "info" for f in body["findings"])


def test_both_mode_returns_ux_and_security(monkeypatch):
    c = _client(monkeypatch, STRIX_STUB="true", STRIX_SERVICE_API_KEY="",
                STRIX_ALLOW_PRIVATE_TARGETS="true")
    r = c.post("/scan", json={"url": "http://localhost/app", "mode": "both",
                              "authorized": True})
    cats = {f["category"] for f in r.json()["findings"]}
    assert cats == {"security", "ux"}


def test_auth_enforced_when_key_set(monkeypatch):
    c = _client(monkeypatch, STRIX_STUB="true", STRIX_SERVICE_API_KEY="topsecret",
                STRIX_ALLOW_PRIVATE_TARGETS="true")
    payload = {"url": "http://localhost/app", "mode": "deep", "authorized": True}
    assert c.post("/scan", json=payload).status_code == 401
    ok = c.post("/scan", json=payload, headers={"Authorization": "Bearer topsecret"})
    assert ok.status_code == 200


def test_bad_contract_version_rejected(monkeypatch):
    c = _client(monkeypatch, STRIX_STUB="true", STRIX_SERVICE_API_KEY="",
                STRIX_ALLOW_PRIVATE_TARGETS="true")
    r = c.post("/scan", json={"url": "http://localhost/app", "contract_version": "2.0"})
    assert r.status_code == 400


def test_target_rejected_returns_error_status_not_5xx(monkeypatch):
    c = _client(monkeypatch, STRIX_STUB="true", STRIX_SERVICE_API_KEY="",
                STRIX_ALLOW_PRIVATE_TARGETS="false")
    r = c.post("/scan", json={"url": "ftp://example.com", "mode": "deep"})
    assert r.status_code == 200  # 契約：非致命用 status，不用非 2xx
    assert r.json()["status"] == "error"
    assert r.json()["error"] == "scheme_not_allowed"


@pytest.fixture(autouse=True)
def _restore_modules():
    yield
    import app.config as config_mod
    import app.main as main_mod

    importlib.reload(config_mod)
    importlib.reload(main_mod)
