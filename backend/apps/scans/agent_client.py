"""呼叫獨立的 AI pentest/UX 服務（HTTP），取代原本 in-process 的 Hermes-Agent 引擎。

Argus 這端**只講一條 HTTP 契約**（`POST {ARGUS_AGENT_SERVICE_URL}/scan`），不綁定任何特定引擎：
- argus-agent（自家服務）直接實作此契約。
- 要接 Strix（usestrix/strix，只有 CLI＋Docker）等外部引擎時，另外跑一個薄的 wrapper 服務
  包住該引擎、對外實作同一條契約即可；Argus 完全不必改。

契約（請求／回應欄位、finding 正規化規則）見 `docs/agent-service-contract.md`。本模組對回應做
backend-agnostic 正規化（severity／OWASP／CWE／CVSS），讓不同引擎回傳的字串格式都能正確落地。

Graceful degrade：未設定 ARGUS_AGENT_SERVICE_URL 時直接回 None（agent 階段略過、不 crash、
不計費——settle 只有在 agent 真的跑了才收 agent 費）。服務連不到／逾時也只記錯誤、不中斷掃描。
"""
from __future__ import annotations

import contextlib
import logging
import re
from dataclasses import dataclass, field

import requests
from django.conf import settings

from apps.scans.models import Finding, ScanJob

logger = logging.getLogger(__name__)

# 契約版本：wrapper 可讀此值做相容性判斷（請求帶 contract_version）
CONTRACT_VERSION = "1.0"

# 五個合法嚴重度（apps.scans.models.Finding.Severity）
_VALID_SEVERITY = {"critical", "high", "medium", "low", "info"}
# 不同引擎常見的同義詞 → 正規值
_SEVERITY_SYNONYMS = {
    "informational": "info",
    "information": "info",
    "note": "info",
    "none": "info",
    "trivial": "low",
    "minor": "low",
    "moderate": "medium",
    "warning": "medium",
    "warn": "medium",
    "important": "high",
    "error": "high",
    "severe": "high",
    "crit": "critical",
    "blocker": "critical",
}
_OWASP_RE = re.compile(r"A0?(\d{1,2})")  # 接受 A1／A01／A01:2021／A01:2021-xxx
_CWE_RE = re.compile(r"(\d{1,6})")


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


def _normalize_severity(raw) -> str:
    """把任意引擎的嚴重度字串正規成五個合法值之一；無法判斷時退回 low。"""
    s = str(raw or "").strip().lower()
    if s in _VALID_SEVERITY:
        return s
    if s in _SEVERITY_SYNONYMS:
        return _SEVERITY_SYNONYMS[s]
    return "low"


def _normalize_owasp(raw) -> str:
    """接受 A1／A01／A01:2021／`A01:2021-Broken Access Control` 等 → `A01`..`A10`；否則空字串。

    （Argus 的 Finding.owasp_category 存兩位數代號 A01~A10。）
    """
    m = _OWASP_RE.search(str(raw or "").upper())
    if not m:
        return ""
    n = int(m.group(1))
    if 1 <= n <= 10:
        return f"A{n:02d}"
    return ""


def _normalize_cwe(raw) -> str:
    """接受 `CWE-862`／`862`／`CWE 862` → `CWE-862`；否則空字串。"""
    m = _CWE_RE.search(str(raw or ""))
    return f"CWE-{int(m.group(1))}" if m else ""


def _priority_from_item(item: dict) -> float | None:
    """明確給了 priority_score 就用它；否則若有 CVSS（0–10）換算成 0–100 的優先序。"""
    if item.get("priority_score") is not None:
        try:
            return float(item["priority_score"])
        except (TypeError, ValueError):
            return None
    cvss = item.get("cvss") if item.get("cvss") is not None else item.get("cvss_score")
    if cvss is not None:
        try:
            return max(0.0, min(10.0, float(cvss))) * 10.0
        except (TypeError, ValueError):
            return None
    return None


def _resolve_service() -> tuple[str, str, int, bool, str] | None:
    """解析 agent 服務連線設定，回 (base_url, api_key, timeout, verify_tls, protocol)；停用／未設回 None。

    優先讀後台執行期設定（`apps.agent.models.AgentServiceConfig`）：
    - 後台已填 `base_url` → 以後台為準；`enabled=False` 時回 None（明確關閉，不退回 .env）。
    - 後台未填 `base_url` → 退回 `.env`（`ARGUS_AGENT_SERVICE_*`，protocol 固定 sync），向後相容。
    """
    try:
        from apps.agent.models import AgentServiceConfig

        cfg = AgentServiceConfig.load()
    except Exception:  # noqa: BLE001 — 設定表不存在／DB 問題時退回 .env
        cfg = None

    if cfg is not None and cfg.base_url:
        if not cfg.enabled:
            return None
        return (
            cfg.base_url.rstrip("/"),
            cfg.get_api_key(),
            int(cfg.timeout_seconds or 1800),
            bool(cfg.verify_tls),
            str(cfg.protocol or "sync"),
        )

    base = (getattr(settings, "ARGUS_AGENT_SERVICE_URL", "") or "").rstrip("/")
    if not base:
        return None
    return (
        base,
        getattr(settings, "ARGUS_AGENT_SERVICE_KEY", "") or "",
        int(getattr(settings, "ARGUS_AGENT_SERVICE_TIMEOUT", 1800) or 1800),
        True,
        "sync",
    )


# agent 服務輪詢間隔（秒）。
_ASYNC_POLL_INTERVAL = 3.0
_ASYNC_TERMINAL = frozenset({"succeeded", "partial", "failed", "cancelled", "completed", "error"})


def _run_sync(base, headers, payload, timeout, verify) -> dict:
    """同步契約：POST /scan，一次回結果。"""
    resp = requests.post(
        f"{base}/scan", json=payload, headers=headers, timeout=timeout, verify=verify
    )
    resp.raise_for_status()
    return resp.json()


def _run_async(base, headers, payload, timeout, verify, *, scan_job_id, progress_cb) -> dict:
    """非同步契約：POST /v1/scans → 輪詢 status/trace → GET result。

    每輪拉 trace 事件丟給 progress_cb（即時顯示 agent 在做什麼）；偵測到掃描被取消時
    通知服務取消並停止輪詢。整體受 timeout 限制。
    """
    import time

    from apps.scans.cancellation import ScanCancelled, raise_if_cancelled

    def _cancelled() -> bool:
        try:
            raise_if_cancelled(scan_job_id)
            return False
        except ScanCancelled:
            return True

    start = requests.post(
        f"{base}/v1/scans", json=payload, headers=headers, timeout=60, verify=verify
    )
    start.raise_for_status()
    scan_id = start.json()["scan_id"]

    after = 0
    deadline = time.monotonic() + timeout
    cancel_sent = False
    status = "running"
    while True:
        try:
            tr = requests.get(
                f"{base}/v1/scans/{scan_id}/trace", params={"after": after},
                headers=headers, timeout=30, verify=verify,
            ).json()
            for ev in tr.get("events", []):
                if progress_cb:
                    try:
                        progress_cb(ev)
                    except Exception:  # noqa: BLE001 — 進度回寫失敗不影響掃描
                        pass
            after = int(tr.get("next", after) or after)
            status = tr.get("status", status)
        except requests.RequestException:
            status = status  # 暫時讀 trace 失敗：下一輪重試

        if status in _ASYNC_TERMINAL:
            break
        if not cancel_sent and (_cancelled() or time.monotonic() > deadline):
            cancel_sent = True
            with contextlib.suppress(requests.RequestException):
                requests.post(f"{base}/v1/scans/{scan_id}/cancel",
                              headers=headers, timeout=15, verify=verify)
        time.sleep(_ASYNC_POLL_INTERVAL)

    res = requests.get(
        f"{base}/v1/scans/{scan_id}/result", headers=headers, timeout=60, verify=verify
    )
    res.raise_for_status()
    return res.json()


def _build_result(scan_job: ScanJob, data: dict) -> AgentServiceResult:
    """把服務回應（同步或非同步 result）正規化落地成 AgentServiceResult。"""
    # 契約欄位是 findings；容忍 wrapper 以 vulnerabilities 命名（Strix 慣用語）
    findings = data.get("findings")
    if findings is None:
        findings = data.get("vulnerabilities") or []
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
        final_summary=(data.get("summary") or data.get("final_summary") or "")[:1000],
        error=(data.get("error") or ""),
        issues=ux_dicts,
        security_findings=sec_dicts,
    )


def run_agent_via_service(
    scan_job: ScanJob,
    *,
    run_deep: bool,
    run_ux: bool,
    recon_intel: list[str] | None = None,
    known_findings: list[dict] | None = None,
    may_submit_forms: bool = False,
    progress_cb=None,
) -> AgentServiceResult | None:
    """呼叫 agent 服務並把發現落地。未設定服務位址回 None（略過）。

    依後台設定的 protocol 走同步（POST /scan）或非同步（下單→輪詢→即時 trace）。
    progress_cb(event_dict) 只在非同步時被呼叫，供外層回寫即時進度。
    """
    resolved = _resolve_service()
    if resolved is None:
        return None
    base, api_key, timeout, verify_tls, protocol = resolved

    from apps.scans.models import decrypt_test_auth

    payload = {
        "contract_version": CONTRACT_VERSION,
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
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    if protocol == "async":
        data = _run_async(
            base, headers, payload, timeout, verify_tls,
            scan_job_id=scan_job.id, progress_cb=progress_cb,
        )
    else:
        data = _run_sync(base, headers, payload, timeout, verify_tls)

    return _build_result(scan_job, data)


def _persist_finding(scan_job: ScanJob, item: dict) -> dict | None:
    """把服務回傳的一筆發現落地成 Finding，並回傳對應 dict（供計分）。

    沿用 make_finding 產生標準欄位，再覆寫服務已算好的 rule_id／OWASP／CWE／優先序，
    並把各引擎的 severity／OWASP／CWE／CVSS 正規化，讓計分、跨層去重與報告保持一致。
    """
    from apps.scans.scanners import make_finding

    category = (item.get("category") or "").strip().lower()
    # 資安引擎（如 Strix）常不標 category；預設當 security（UX 必須明確標 ux）
    if category not in {"ux", "security"}:
        category = "security"
    url = item.get("url") or ""
    page = None
    if url:
        page = (
            scan_job.pages.filter(final_url=url).first()
            or scan_job.pages.filter(url=url).first()
        )
    built = make_finding(
        category=category,
        severity=_normalize_severity(item.get("severity")),
        title=(item.get("title") or "")[:255],
        description=item.get("description", ""),
        remediation=item.get("remediation", ""),
        evidence=item.get("evidence", ""),
        rule_id=item.get("rule_id", ""),
        impact_area=item.get("impact_area", ""),
        confidence=float(item.get("confidence", 1.0) or 1.0),
        evidence_json=item.get("evidence_json") or None,
        evidence_source=item.get("evidence_source") or "agent_service",
    )
    priority = _priority_from_item(item)
    if priority is not None:
        built["priority_score"] = priority
    if item.get("ai_handoff_prompt"):
        built["ai_handoff_prompt"] = item["ai_handoff_prompt"]
    built["owasp_category"] = _normalize_owasp(
        item.get("owasp_category") or item.get("owasp")
    )
    built["cwe_id"] = _normalize_cwe(item.get("cwe_id") or item.get("cwe"))

    try:
        Finding.objects.create(scan_job=scan_job, page=page, **built)
    except Exception:  # noqa: BLE001 — 單筆落地失敗不影響其餘發現與掃描
        logger.exception("落地 agent 服務發現失敗 scan_job_id=%s", scan_job.id)
        return None
    return built
