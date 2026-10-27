"""把 Strix 的漏洞報告（``strix_runs/<run>/vulnerabilities.json`` 的一筆）映射成
契約的 ``Finding``。

Strix 報告 dict 的欄位（來自開源 `strix/report/writer.py`）：
``id, title, severity(小寫五級), timestamp, target, endpoint, method, cve, cwe,
cvss, confidence(字串), fix_effort, description, evidence, impact, poc_description,
poc_script_code, code_locations`` 等。Strix 不帶 OWASP，但有 CWE＋CVSS，契約吃得下。
"""
from __future__ import annotations

import re
from typing import Any

from .contract import Finding

# confidence 字串 → 0–1 浮點
_CONFIDENCE_WORD = {"high": 0.95, "medium": 0.6, "low": 0.3, "info": 0.2}

# 遮罩：Authorization／Cookie／Set-Cookie 標頭值、email、長 hex/base64 token。
_AUTH_HEADER_RE = re.compile(
    r"(?im)^(authorization|cookie|set-cookie|x-api-key)\s*:\s*.+$"
)
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_LONG_TOKEN_RE = re.compile(r"\b[A-Za-z0-9+/=_-]{32,}\b")
_MAX_EVIDENCE = 2000


def redact(text: str, *, extra_secrets: list[str] | None = None) -> str:
    """服務端第一道遮罩：抹掉憑證／email／長 token，並截斷長度。"""
    if not text:
        return ""
    out = str(text)
    for secret in extra_secrets or []:
        if secret:
            out = out.replace(secret, "[REDACTED]")
    out = _AUTH_HEADER_RE.sub(lambda m: f"{m.group(1)}: [REDACTED]", out)
    out = _EMAIL_RE.sub("[REDACTED_EMAIL]", out)
    out = _LONG_TOKEN_RE.sub("[REDACTED_TOKEN]", out)
    if len(out) > _MAX_EVIDENCE:
        out = out[:_MAX_EVIDENCE] + "…[truncated]"
    return out


def _confidence(raw: Any) -> float:
    if isinstance(raw, (int, float)):
        try:
            return max(0.0, min(1.0, float(raw)))
        except (TypeError, ValueError):
            return 1.0
    word = str(raw or "").strip().lower()
    return _CONFIDENCE_WORD.get(word, 1.0)


def strix_vuln_to_finding(
    report: dict[str, Any], *, secrets: list[str] | None = None
) -> Finding:
    """單筆 Strix 漏洞 → 契約 Finding。evidence 已遮罩。"""
    strix_id = str(report.get("id") or "")
    cwe = str(report.get("cwe") or "").strip()
    endpoint = str(report.get("endpoint") or "")
    url = endpoint or str(report.get("target") or "")

    evidence_parts = []
    if report.get("evidence"):
        evidence_parts.append(str(report["evidence"]))
    if report.get("impact"):
        evidence_parts.append(f"Impact: {report['impact']}")
    if report.get("poc_description"):
        evidence_parts.append(f"PoC: {report['poc_description']}")
    evidence = redact("\n\n".join(evidence_parts), extra_secrets=secrets)

    evidence_json = {
        "strix_id": strix_id,
        "endpoint": endpoint,
        "method": report.get("method") or "",
        "cve": report.get("cve") or "",
        "cwe": cwe,
        "cvss": report.get("cvss"),
        "fix_effort": report.get("fix_effort") or "",
        # 有 PoC ＝ Strix 以實際利用驗證過；Argus 可據此判斷是否放寬嚴重度封頂。
        "confirmed": bool(report.get("poc_description") or report.get("poc_script_code")),
    }

    rule_id = f"strix:{strix_id}" if strix_id else (f"strix:{cwe}" if cwe else "strix")

    return Finding(
        category="security",
        severity=str(report.get("severity") or "low").strip().lower(),
        title=str(report.get("title") or "Untitled")[:255],
        description=str(report.get("description") or ""),
        # Strix 的修補建議欄位名是 remediation_steps（非 remediation）——不對齊會讓
        # argus 的「怎麼修」整欄空白（2026-10-27 實測發現）。保留舊名當 fallback。
        remediation=str(report.get("remediation_steps") or report.get("remediation") or ""),
        evidence=evidence,
        evidence_json=evidence_json,
        url=url,
        rule_id=rule_id,
        cwe_id=cwe,
        cvss=report.get("cvss") if isinstance(report.get("cvss"), (int, float)) else None,
        confidence=_confidence(report.get("confidence")),
        evidence_source="strix",
    )
