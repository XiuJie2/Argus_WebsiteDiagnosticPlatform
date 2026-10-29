"""Strix 漏洞 → 契約 Finding 映射與遮罩的測試。"""
from __future__ import annotations

from app.mapping import redact, strix_vuln_to_finding


def test_redact_strips_secrets_and_truncates():
    text = (
        "Authorization: Bearer abcdef1234567890abcdef1234567890\n"
        "user alice@example.com logged in\n"
        "token=QWxhZGRpbjpvcGVuIHNlc2FtZQ1234567890abcd"
    )
    out = redact(text, extra_secrets=["s3cr3tpw"])
    assert "alice@example.com" not in out
    assert "Bearer abcdef" not in out
    assert "[REDACTED_EMAIL]" in out
    assert "[REDACTED" in out


def test_redact_removes_explicit_secret():
    assert "s3cr3tpw" not in redact("login with s3cr3tpw here", extra_secrets=["s3cr3tpw"])


def test_vuln_mapping_core_fields():
    report = {
        "id": "vuln-001",
        "title": "SQL Injection in login",
        "severity": "critical",
        "cwe": "CWE-89",
        "cvss": 9.1,
        "endpoint": "/login",
        "method": "POST",
        "confidence": "high",
        "description": "Injectable parameter.",
        "evidence": "payload ' OR 1=1 -- succeeded",
        "poc_description": "Automated PoC confirmed.",
    }
    report["remediation_steps"] = "1. Use parameterized queries.\n2. Add tests."
    f = strix_vuln_to_finding(report)
    assert f.category == "security"
    assert f.severity == "critical"
    # Strix 用 remediation_steps 命名；必須映射到 Finding.remediation（否則 argus「怎麼修」空白）
    assert "parameterized queries" in f.remediation
    assert f.cwe_id == "CWE-89"
    assert f.cvss == 9.1
    assert f.url == "/login"
    assert f.rule_id == "strix:vuln-001"
    assert f.confidence == 0.95
    assert f.evidence_json["confirmed"] is True
    assert f.evidence_source == "strix"


def test_vuln_mapping_defaults_and_confidence_numeric():
    f = strix_vuln_to_finding({"severity": "medium", "confidence": 0.42})
    assert f.title == "Untitled"
    assert f.rule_id == "strix"
    assert f.confidence == 0.42
    assert f.evidence_json["confirmed"] is False


def test_real_runner_passes_cost_optimization_env(monkeypatch):
    """real_runner 必須把成本優化旋鈕打進 strix 子程序環境。"""
    import importlib
    import app.config as config_mod
    monkeypatch.setenv("STRIX_REASONING_EFFORT", "medium")
    monkeypatch.setenv("LLM_DISABLE_STREAMING", "true")
    importlib.reload(config_mod)
    import app.real_runner as rr
    importlib.reload(rr)

    captured = {}

    class FakeProc:
        returncode = 0
        def wait(self, timeout=None):
            return 0

    def fake_popen(cmd, **kw):
        captured["env"] = kw.get("env")
        return FakeProc()

    monkeypatch.setattr(rr.subprocess, "Popen", fake_popen)
    from app.contract import ScanRequest
    rr.run_strix(ScanRequest(url="https://example.com", authorized=True))
    env = captured["env"]
    assert env["STRIX_REASONING_EFFORT"] == "medium"
    assert env["LLM_DISABLE_STREAMING"] == "true"
    assert env["STRIX_PROMPT_CACHE"] in ("true", "false")
    # reload 還原
    importlib.reload(config_mod); importlib.reload(rr)


def test_build_instruction_generic_focus_and_operator_passthrough():
    """授權掃描要帶 target-agnostic 類別級聚焦（不含路徑）＋操作者 per-scan 聚焦。"""
    from app.real_runner import _build_instruction
    from app.contract import ScanRequest
    ins = _build_instruction(ScanRequest(url="https://x.example", authorized=True,
                                         instruction="poke /api/files/upload"))
    # 類別級聚焦存在、且含防過擬合的「自行探索」語句
    assert "file upload" in ins.lower()
    assert "do not assume any specific path" in ins.lower()
    # 操作者 per-scan 聚焦被帶入
    assert "poke /api/files/upload" in ins
    # 未授權時不加攻擊性類別聚焦
    ins2 = _build_instruction(ScanRequest(url="https://x.example", authorized=False))
    assert "give extra priority" not in ins2
