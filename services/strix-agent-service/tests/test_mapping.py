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


def test_build_instruction_prior_findings_verify_and_deepen():
    """prior_findings 要產生『先驗證、再深挖』的指令，並列出項目。"""
    from app.real_runner import _build_instruction
    from app.contract import ScanRequest
    ins = _build_instruction(ScanRequest(
        url="https://x.example", authorized=True,
        prior_findings=[{"title": "IDOR on /api/updatePassword", "severity": "high",
                         "endpoint": "/api/updatePassword"}],
    ))
    assert "re-verify" in ins.lower()
    assert "IDOR on /api/updatePassword" in ins
    assert "/api/updatePassword" in ins
    # 沒有 prior_findings 時不加這段
    ins2 = _build_instruction(ScanRequest(url="https://x.example", authorized=True))
    assert "earlier scans" not in ins2


def test_detect_provider_trouble(tmp_path):
    from app.real_runner import _detect_provider_trouble
    rd = tmp_path / "run"
    rd.mkdir()
    # 無 log → 空
    assert _detect_provider_trouble(rd) == ""
    # persistent rate limit → 明確錯誤碼
    (rd / "strix.log").write_text("... Scan stopped: persistent rate limit from the LLM provider\n")
    assert _detect_provider_trouble(rd) == "llm_provider_rate_limited"
    # 多次 provider 錯誤 → 一般錯誤碼
    (rd / "strix.log").write_text("outcome=error\noutcome=error\noutcome=error host=api.minimax.io\n")
    assert _detect_provider_trouble(rd) == "llm_provider_errors"
    # 正常 log → 空（不誤判）
    (rd / "strix.log").write_text("INFO scan progressing nicely, found stuff\n")
    assert _detect_provider_trouble(rd) == ""


def test_detect_budget_stop(tmp_path):
    from app.real_runner import _detect_budget_stop
    rd = tmp_path / "r"; rd.mkdir()
    assert _detect_budget_stop(rd) is False
    (rd / "strix.log").write_text("Scan foo stopped: Token budget of $8.00 exceeded\n")
    assert _detect_budget_stop(rd) is True
    (rd / "strix.log").write_text("agent reached the scan budget limit; stopping the scan\n")
    assert _detect_budget_stop(rd) is True


def test_secrets_redacted_in_all_freetext_fields():
    """憑證/secret 不只在 evidence，title/description/remediation 都要遮掉。"""
    creds = "test:testtest"
    report = {
        "id": "vuln-9",
        "title": f"Login works with {creds}",
        "severity": "high",
        "description": f"The app accepts the injected credentials {creds} and returns a token.",
        "remediation_steps": f"Rotate {creds} and stop echoing credentials.",
        "evidence": f"POST /api/login body: {creds}",
    }
    f = strix_vuln_to_finding(report, secrets=[creds])
    assert creds not in f.title
    assert creds not in f.description
    assert creds not in f.remediation
    assert creds not in f.evidence
    assert "[REDACTED]" in f.title


def test_long_description_not_truncated_by_redaction():
    """正文欄位 max_len=None：長說明不應被 evidence 的 2000 字上限截斷。"""
    # 用有空白的正常文句（非 token-like 長串，否則會被 _LONG_TOKEN_RE 當成 token 遮掉）
    long_desc = "The endpoint leaks data to any authenticated user. " * 100
    f = strix_vuln_to_finding({"id": "v", "title": "t", "severity": "low",
                               "description": long_desc})
    assert len(f.description) == len(long_desc) and len(f.description) > 2000
