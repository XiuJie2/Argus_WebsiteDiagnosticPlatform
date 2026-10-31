"""real_runner 狀態判定：預算/回合上限截斷 → partial（不可謊報 completed）。"""
from __future__ import annotations

import json
from pathlib import Path

from app import real_runner
from app.config import settings
from app.contract import ScanRequest


def _fake_popen_factory(vulns, run_json, log):
    class _FakePopen:
        def __init__(self, cmd, *, stdout=None, stderr=None, cwd=None, env=None,
                     start_new_session=None):
            self.pid = 4321
            d = Path(cwd) / "strix_runs" / "run1"
            d.mkdir(parents=True, exist_ok=True)
            (d / "vulnerabilities.json").write_text(json.dumps(vulns), encoding="utf-8")
            (d / "run.json").write_text(json.dumps(run_json), encoding="utf-8")
            (d / "strix.log").write_text(log, encoding="utf-8")

        def wait(self, timeout=None):
            return 2 if vulns else 0

    return _FakePopen


def _run(monkeypatch, tmp_path, *, vulns, run_json, log):
    monkeypatch.setattr(real_runner.subprocess, "Popen",
                        _fake_popen_factory(vulns, run_json, log))
    req = ScanRequest(url="https://example.com", mode="deep", authorized=True)
    return real_runner.run_strix(req, scan_cwd=tmp_path / "cwd")


def test_budget_stop_reported_as_partial(monkeypatch, tmp_path):
    resp = _run(monkeypatch, tmp_path, vulns=[],
                run_json={"turns": 3, "summary": "s"},
                log="... token budget of $30 exceeded, wrapping up ...")
    assert resp.status == "partial", resp.status  # 不可是 completed（否則上游當成全清）


def test_turn_limit_reported_as_partial(monkeypatch, tmp_path):
    resp = _run(monkeypatch, tmp_path, vulns=[{"id": "v1", "title": "x", "severity": "high"}],
                run_json={"turns": settings.max_turns, "summary": "s"},
                log="normal run log, no budget marker")
    assert resp.status == "partial", resp.status


def test_clean_run_is_completed(monkeypatch, tmp_path):
    resp = _run(monkeypatch, tmp_path, vulns=[{"id": "v1", "title": "x", "severity": "high"}],
                run_json={"turns": max(1, settings.max_turns - 1), "summary": "s"},
                log="normal run log")
    assert resp.status == "completed", resp.status
    assert len(resp.findings) == 1
