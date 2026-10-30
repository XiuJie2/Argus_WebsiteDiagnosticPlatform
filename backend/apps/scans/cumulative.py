"""跨掃描累積：把同站歷來「仍未修復」的 AI/Agent 資安發現帶進本次掃描。

為什麼需要：確定性層（標頭、TLS、缺漏設定…）每次掃描都會可靠地重測，少了就是真的修好了，
argus 既有的 resolved 比對已能處理。但 **AI Agent / Strix 的發現是非確定性的** —— 同一個站
每次掃描抽到的子集不同（這次 3 條、上次 10 條），於是「上次找到、這次沒抽到」的洞會從報告
消失，讓人誤以為修好了。

資安工具的正確行為：**發現在「確認修復」前都算開著。** 所以本模組在計分前，把這個站歷來
（同 user+origin、已完成掃描）**非確定性**資安發現中、本次沒有重新確認、且尚未被判定修復的，
以「carried_over」身分補進本次掃描 —— 報告與分數就會呈現完整的累積清單，不受單次運氣影響。

去重用 `finding_identity`（跨掃描正規鍵）。確定性發現不在此列（交由既有重測/resolved 流程）。
"""
from __future__ import annotations

import logging

from apps.scans.finding_identity import finding_identity
from apps.scans.models import Finding, ScanJob

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# 非確定性層的 rule_id 前綴：這些才需要跨掃描帶（確定性層每次重測、不帶）。
_NONDETERMINISTIC_PREFIXES = ("strix:", "agent-observed")


def _is_nondeterministic(rule_id: str) -> bool:
    return str(rule_id or "").startswith(_NONDETERMINISTIC_PREFIXES)


def carry_forward_open_findings(scan_job: ScanJob, current_findings: list[dict]) -> list[dict]:
    """把仍開著的歷史非確定性資安發現補進本次掃描。

    建立 carried_over 的 Finding 列並回傳對應 dict（供計分與報告）。本次已重新確認的
    （同 finding_identity）不重複帶。回傳空清單代表沒有可帶的歷史發現。
    """
    current_ids = {
        finding_identity(f)
        for f in current_findings
        if (f.get("category") or "") == "security"
    }

    prior_scan_ids = list(
        ScanJob.objects.filter(
            user_id=scan_job.user_id,
            origin=scan_job.origin,
            status=ScanJob.Status.COMPLETED,
        )
        .exclude(pk=scan_job.pk)
        .values_list("id", flat=True)
    )
    if not prior_scan_ids:
        return []

    # 歷來非確定性資安發現，依 finding_identity 去重，保留最嚴重那筆並記首見/最近。
    best: dict[str, dict] = {}
    qs = (
        Finding.objects.filter(scan_job_id__in=prior_scan_ids, category="security")
        .exclude(severity="info")
        .order_by("scan_job_id")
    )
    for f in qs.iterator():
        if not _is_nondeterministic(f.rule_id):
            continue
        ident = finding_identity({
            "category": "security", "title": f.title,
            "description": f.description or "", "owasp_category": f.owasp_category,
            "cwe_id": f.cwe_id, "url": (f.evidence_json or {}).get("endpoint") or "",
        })
        rank = _SEVERITY_ORDER.get(f.severity, 4)
        cur = best.get(ident)
        if cur is None:
            best[ident] = {"f": f, "rank": rank, "first_scan": f.scan_job_id,
                           "last_scan": f.scan_job_id}
        else:
            cur["last_scan"] = max(cur["last_scan"], f.scan_job_id)
            cur["first_scan"] = min(cur["first_scan"], f.scan_job_id)
            if rank < cur["rank"]:
                cur["f"], cur["rank"] = f, rank

    carried: list[dict] = []
    for ident, rec in best.items():
        if ident in current_ids:
            continue  # 本次已重新確認，不重複帶
        f = rec["f"]
        note = (
            f"【前次掃描發現、本次未重新確認】此問題最早見於掃描 #{rec['first_scan']}、"
            f"最近見於 #{rec['last_scan']}。AI 深度測試為非確定性，本次掃描未重新觸及此項，"
            f"但在確認修復前仍視為存在。原始說明：{f.description or ''}"
        )
        try:
            obj = Finding.objects.create(
                scan_job=scan_job,
                page=None,
                category="security",
                severity=f.severity,
                title=f.title[:255],
                description=note[:300],
                evidence=f.evidence,
                evidence_type=f.evidence_type,
                evidence_json={**(f.evidence_json or {}), "carried_over": True,
                               "first_seen_scan": rec["first_scan"],
                               "last_seen_scan": rec["last_scan"]},
                evidence_source="carried_over",
                rule_id=f.rule_id,
                owasp_category=f.owasp_category,
                cwe_id=f.cwe_id,
                confidence=f.confidence,
                priority_score=f.priority_score,
                impact_area=f.impact_area,
                ai_handoff_prompt=f.ai_handoff_prompt or "",
            )
        except Exception:  # noqa: BLE001 — 單筆帶入失敗不影響掃描
            logger.exception("carry_forward 落地失敗 scan=%s ident=%s", scan_job.id, ident)
            continue
        carried.append({
            "category": "security", "severity": obj.severity, "title": obj.title,
            "rule_id": obj.rule_id, "owasp_category": obj.owasp_category,
            "cwe_id": obj.cwe_id, "carried_over": True,
        })
    return carried
