"""呼叫獨立的 argus-agent 服務（HTTP），取代原本 in-process 的 Hermes-Agent 引擎。

引擎（recon→指揮官→專家＋UX，LLM＋Playwright）已抽離成獨立服務 argus-agent；Argus 這端
只負責：組請求 → POST /scan → 把回傳的發現落地成 Finding → 交給計分／報告／跨層去重。

Graceful degrade：未設定 ARGUS_AGENT_SERVICE_URL 時直接回 None（agent 階段略過、不 crash、
不計費——settle 只有在 agent 真的跑了才收 agent 費）。服務連不到／逾時也只記錯誤、不中斷掃描。
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

import requests
from django.conf import settings

from apps.scans.models import Finding, ScanJob

logger = logging.getLogger(__name__)


@dataclass
class AgentServiceResult:
    """與舊 AgentRunResult 相容的精簡結果，供 tasks.stage_agent 沿用。"""

    session_id: int = 0  # 相容欄位（舊 AgentRunResult 有；本服務端不產生，恆 0）
    status: str = "completed"
    steps: int = 0
    total_tokens: int = 0
    final_summary: str = ""
    error: str = ""
    issues: list[dict] = field(default_factory=list)  # UX 發現 dict（餵 top_actions）
    security_findings: list[dict] = field(default_factory=list)  # 資安發現 dict（餵計分）


def _mode(run_deep: bool, run_ux: bool) -> str:
    if run_deep and run_ux:
        return "both"
    return "deep" if run_deep else "ux"


def run_agent_via_service(
    scan_job: ScanJob,
    *,
    run_deep: bool,
    run_ux: bool,
    recon_intel: list[str] | None = None,
    known_findings: list[dict] | None = None,
    may_submit_forms: bool = False,
) -> AgentServiceResult | None:
    """呼叫 argus-agent 服務並把發現落地。未設定服務位址回 None（略過）。"""
    base = (getattr(settings, "ARGUS_AGENT_SERVICE_URL", "") or "").rstrip("/")
    if not base:
        return None

    from apps.scans.models import decrypt_test_auth

    payload = {
        "url": scan_job.normalized_url or scan_job.original_url,
        "mode": _mode(run_deep, run_ux),
        "authorized": bool(run_deep),
        "submit_forms": bool(may_submit_forms),
        "recon_intel": recon_intel or None,
        "known_findings": known_findings or None,
        "test_auth_email": decrypt_test_auth(scan_job.test_auth_email_encrypted) or None,
        "test_auth_password": decrypt_test_auth(scan_job.test_auth_password_encrypted) or None,
    }
    headers = {}
    key = getattr(settings, "ARGUS_AGENT_SERVICE_KEY", "")
    if key:
        headers["Authorization"] = f"Bearer {key}"
    timeout = getattr(settings, "ARGUS_AGENT_SERVICE_TIMEOUT", 1800)

    resp = requests.post(f"{base}/scan", json=payload, headers=headers, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()

    findings = data.get("findings") or []
    ux_dicts: list[dict] = []
    sec_dicts: list[dict] = []
    for item in findings:
        persisted = _persist_finding(scan_job, item)
        if persisted is None:
            continue
        if persisted["category"] == "ux":
            ux_dicts.append(persisted)
        elif persisted["category"] == "security":
            sec_dicts.append(persisted)

    return AgentServiceResult(
        status=data.get("status", "completed"),
        steps=int(data.get("steps", 0) or 0),
        total_tokens=int(data.get("total_tokens", 0) or 0),
        final_summary=(data.get("summary") or "")[:1000],
        error=(data.get("error") or ""),
        issues=ux_dicts,
        security_findings=sec_dicts,
    )


def _persist_finding(scan_job: ScanJob, item: dict) -> dict | None:
    """把服務回傳的一筆發現落地成 Finding，並回傳對應 dict（供計分）。

    沿用 make_finding 產生標準欄位，再覆寫服務已算好的 rule_id／OWASP／CWE／優先序，
    讓計分、跨層去重與報告與 in-process 時代一致。
    """
    from apps.scans.scanners import make_finding

    category = item.get("category") or ""
    if category not in {"ux", "security"}:
        return None
    url = item.get("url") or ""
    page = None
    if url:
        page = (
            scan_job.pages.filter(final_url=url).first()
            or scan_job.pages.filter(url=url).first()
        )
    built = make_finding(
        category=category,
        severity=item.get("severity", "low"),
        title=(item.get("title") or "")[:255],
        description=item.get("description", ""),
        remediation=item.get("remediation", ""),
        evidence=item.get("evidence", ""),
        rule_id=item.get("rule_id", ""),
        impact_area=item.get("impact_area", ""),
        confidence=float(item.get("confidence", 1.0) or 1.0),
        evidence_json=item.get("evidence_json") or None,
        evidence_source="agent_service",
    )
    if item.get("priority_score") is not None:
        built["priority_score"] = item["priority_score"]
    if item.get("ai_handoff_prompt"):
        built["ai_handoff_prompt"] = item["ai_handoff_prompt"]
    built["owasp_category"] = item.get("owasp_category", "") or ""
    built["cwe_id"] = item.get("cwe_id", "") or ""

    try:
        Finding.objects.create(scan_job=scan_job, page=page, **built)
    except Exception:  # noqa: BLE001 — 單筆落地失敗不影響其餘發現與掃描
        logger.exception("落地 agent 服務發現失敗 scan_job_id=%s", scan_job.id)
        return None
    return built
