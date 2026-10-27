"""非同步 v2 流程（start → poll/trace → result → cancel）的契約測試，全在 stub 模式。"""
from __future__ import annotations

import importlib
import time

import pytest
from fastapi.testclient import TestClient


def _client(monkeypatch, **env) -> TestClient:
    env.setdefault("STRIX_STUB", "true")
    env.setdefault("STRIX_SERVICE_API_KEY", "")
    env.setdefault("STRIX_ALLOW_PRIVATE_TARGETS", "true")
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    import app.config as config_mod

    importlib.reload(config_mod)
    import app.main as main_mod

    importlib.reload(main_mod)
    return TestClient(main_mod.app)


def _poll_until_terminal(c, scan_id, timeout=15.0):
    deadline = time.time() + timeout
    seen_running = False
    while time.time() < deadline:
        r = c.get(f"/v1/scans/{scan_id}")
        assert r.status_code == 200
        st = r.json()["status"]
        if st == "running":
            seen_running = True
        if st in {"succeeded", "partial", "failed", "cancelled"}:
            return st, seen_running
        time.sleep(0.2)
    raise AssertionError("scan did not reach terminal state in time")


def test_start_poll_result_flow(monkeypatch):
    c = _client(monkeypatch)
    r = c.post("/v1/scans", json={"url": "http://localhost/app", "mode": "both",
                                  "authorized": True})
    assert r.status_code == 202
    scan_id = r.json()["scan_id"]
    assert r.json()["status"] in {"queued", "running"}

    status, _ = _poll_until_terminal(c, scan_id)
    assert status == "succeeded"

    # trace 累積了事件
    tr = c.get(f"/v1/scans/{scan_id}/trace")
    assert tr.status_code == 200
    assert len(tr.json()["events"]) >= 3
    assert any(e["agent"] for e in tr.json()["events"])

    # result 拿到 findings（both → 有 security 與 ux）
    res = c.get(f"/v1/scans/{scan_id}/result")
    assert res.status_code == 200
    cats = {f["category"] for f in res.json()["findings"]}
    assert cats == {"security", "ux"}
    assert res.json()["status"] == "completed"


def test_trace_incremental_after_cursor(monkeypatch):
    c = _client(monkeypatch)
    scan_id = c.post("/v1/scans", json={"url": "http://localhost/a", "authorized": True}).json()[
        "scan_id"
    ]
    time.sleep(0.6)
    first = c.get(f"/v1/scans/{scan_id}/trace").json()
    assert first["events"]
    nxt = first["next"]
    _poll_until_terminal(c, scan_id)
    # 從 next 之後拉，不應重複拿到先前的事件
    more = c.get(f"/v1/scans/{scan_id}/trace", params={"after": nxt}).json()
    assert all(e["seq"] > nxt for e in more["events"])


def test_result_before_finished_is_409(monkeypatch):
    c = _client(monkeypatch)
    scan_id = c.post("/v1/scans", json={"url": "http://localhost/a", "authorized": True}).json()[
        "scan_id"
    ]
    # 立刻取 result（還在跑）→ 409
    r = c.get(f"/v1/scans/{scan_id}/result")
    assert r.status_code == 409
    _poll_until_terminal(c, scan_id)


def test_cancel(monkeypatch):
    c = _client(monkeypatch)
    scan_id = c.post("/v1/scans", json={"url": "http://localhost/a", "authorized": True}).json()[
        "scan_id"
    ]
    assert c.post(f"/v1/scans/{scan_id}/cancel").status_code == 202
    status, _ = _poll_until_terminal(c, scan_id)
    assert status == "cancelled"


def test_unknown_scan_404(monkeypatch):
    c = _client(monkeypatch)
    assert c.get("/v1/scans/nope").status_code == 404
    assert c.get("/v1/scans/nope/trace").status_code == 404
    assert c.get("/v1/scans/nope/result").status_code == 404


def test_bad_target_rejected_at_start(monkeypatch):
    c = _client(monkeypatch, STRIX_ALLOW_PRIVATE_TARGETS="false")
    r = c.post("/v1/scans", json={"url": "ftp://x.example.com"})
    assert r.status_code == 400
    assert r.json()["detail"] == "scheme_not_allowed"


def test_auth_enforced(monkeypatch):
    c = _client(monkeypatch, STRIX_SERVICE_API_KEY="k")
    body = {"url": "http://localhost/a", "authorized": True}
    assert c.post("/v1/scans", json=body).status_code == 401
    ok = c.post("/v1/scans", json=body, headers={"Authorization": "Bearer k"})
    assert ok.status_code == 202


@pytest.fixture(autouse=True)
def _restore(monkeypatch):
    yield
    import app.config as config_mod
    import app.main as main_mod

    importlib.reload(config_mod)
    importlib.reload(main_mod)
