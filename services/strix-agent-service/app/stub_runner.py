"""Phase 0 stub：回確定性假結果，零 LLM／零 Docker／零真實攻擊流量。

用途：把 Argus ↔ 本服務的 HTTP 接線、契約解析、Finding 落地、計費閘門整條焊死並可測，
完全不花錢也不碰真目標。驗證通過後把 STRIX_STUB=false 換上 real_runner。

stub 仍尊重契約語義：
- mode="ux" 回 UX 類 finding；"deep" 回 security 類；"both" 兩者都回。
- authorized=false 時不產生「需送攻擊 payload 才找得到」的 finding（只回一筆 info 說明被收斂）。
"""
from __future__ import annotations

from .contract import Finding, ScanRequest, ScanResponse


def run_stub(req: ScanRequest) -> ScanResponse:
    findings: list[Finding] = []

    wants_deep = req.mode in {"deep", "both"}
    wants_ux = req.mode in {"ux", "both"}

    if wants_deep:
        if req.authorized:
            findings.append(
                Finding(
                    category="security",
                    severity="high",
                    title="[STUB] IDOR on order endpoint",
                    description="Stub 資安發現：示範契約落地，非真實漏洞。",
                    remediation="Enforce object-level authorization.",
                    evidence="GET /api/orders/42 returned another user's order (stubbed).",
                    evidence_json={"endpoint": "/api/orders/42", "confirmed": True},
                    url=req.url.rstrip("/") + "/api/orders/42",
                    rule_id="strix:stub-idor",
                    cwe_id="CWE-639",
                    owasp_category="A01:2021",
                    cvss=7.5,
                    confidence=0.95,
                    evidence_source="strix-stub",
                )
            )
        else:
            findings.append(
                Finding(
                    category="security",
                    severity="info",
                    title="[STUB] Active testing not authorized",
                    description="authorized=false，stub 僅回被動觀察，不送攻擊 payload。",
                    rule_id="strix:stub-passive-note",
                    confidence=1.0,
                    evidence_source="strix-stub",
                )
            )

    if wants_ux:
        findings.append(
            Finding(
                category="ux",
                severity="medium",
                title="[STUB] 登入按鈕對比度不足",
                description="Stub UX 發現：示範 UX 類 finding 落 top_actions。",
                impact_area="usability",
                url=req.url,
                rule_id="strix:stub-ux-contrast",
                confidence=0.8,
                evidence_source="strix-stub",
            )
        )

    return ScanResponse(
        status="completed",
        steps=0,
        total_tokens=0,
        summary=f"[STUB] mode={req.mode} authorized={req.authorized}：回 {len(findings)} 筆示範發現。",
        findings=findings,
        cost_usd=0.0,
        engine="strix-stub",
    )
