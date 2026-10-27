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
