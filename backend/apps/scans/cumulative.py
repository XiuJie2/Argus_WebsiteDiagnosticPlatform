"""跨掃描累積 + 自動重驗/消解：把同站歷來「仍未修復」的 AI/Agent 資安發現帶進本次掃描，
並讓**已修復的自動消失**。

為什麼需要：確定性層（標頭、TLS、缺漏設定…）每次掃描都會可靠地重測，少了就是真的修好了，
argus 既有的 resolved 比對已能處理。但 **AI Agent / Strix 的發現是非確定性的** —— 同一個站
每次掃描抽到的子集不同（這次 3 條、上次 10 條），於是「上次找到、這次沒抽到」的洞會從報告
消失，讓人誤以為修好了。

資安工具的正確行為：**發現在「確認修復」前都算開著。** 所以本模組在計分前，把這個站歷來
（同 user+origin、已完成掃描）**非確定性**資安發現中、本次沒有重新確認、且尚未被判定修復的，
以「carried_over」身分補進本次掃描 —— 報告與分數就會呈現完整的累積清單，不受單次運氣影響。

自動消解（使用者修好了要能反映）：每個 finding_identity 的重驗狀態記在 `AgentFindingState`。
- 本次重新打到（出現在 current_ids）→ miss_streak 歸零、resolved 取消、更新 last_confirmed。
- 本次沒打到，且 **agent 這次有正常跑完**（agent_ran_ok）→ miss_streak +1；
  連續達 `RESOLVE_THRESHOLD`（2）次 → 判定已修復，停止帶入（洞從累積清單消失）。
- 本次沒打到，且 agent 失敗／被限流／略過（agent_ran_ok=False）→ **不算一次驗證**，照帶、不扣 miss。
  （否則一次 MiniMax 掛掉就會把真實的洞誤判成已修復。）

去重用 `finding_identity`（跨掃描正規鍵）。確定性發現不在此列（交由既有重測/resolved 流程）。
"""
from __future__ import annotations

import logging

from django.db import transaction

from apps.scans.finding_identity import finding_identity
from apps.scans.models import AgentFindingState, Finding, ScanJob

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# 非確定性層的 rule_id 前綴：這些才需要跨掃描帶（確定性層每次重測、不帶）。
_NONDETERMINISTIC_PREFIXES = ("strix:", "agent-observed")


def _is_nondeterministic(rule_id: str) -> bool:
    return str(rule_id or "").startswith(_NONDETERMINISTIC_PREFIXES)


def _identity_of_row(f: Finding) -> str:
    return finding_identity({
        "category": "security", "title": f.title,
        "description": f.description or "", "owasp_category": f.owasp_category,
        "cwe_id": f.cwe_id, "url": (f.evidence_json or {}).get("endpoint") or "",
    })


def carry_forward_open_findings(
    scan_job: ScanJob,
    current_findings: list[dict],
    agent_ran_ok: bool = False,
) -> list[dict]:
    """把仍開著的歷史非確定性資安發現補進本次掃描，並自動消解已修復的。

    Args:
        scan_job: 本次掃描。
        current_findings: 本次所有發現（dict）。
        agent_ran_ok: 本次 agent 是否正常跑完（才算一次「有效重驗」；失敗/略過不扣 miss）。

    回傳 carried dict 清單（供計分與報告）。本次已重新確認、或已判定修復的不帶。
    """
    # 本次所有資安發現的身分（含確定性：一個洞被確定性層重新打到也算「仍在」）。
    current_ids = {
        finding_identity(f)
        for f in current_findings
        if (f.get("category") or "") == "security"
    }
    # 本次「全新非確定性」發現的身分（用來初始化／刷新狀態）。
    fresh_nd_ids = {
        finding_identity(f)
        for f in current_findings
        if (f.get("category") or "") == "security" and _is_nondeterministic(f.get("rule_id") or "")
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

    # 歷來非確定性資安發現，依 finding_identity 去重，保留最嚴重那筆並記首見/最近。
    best: dict[str, dict] = {}
    if prior_scan_ids:
        qs = (
            Finding.objects.filter(scan_job_id__in=prior_scan_ids, category="security")
            .exclude(severity="info")
            .order_by("scan_job_id")
        )
        for f in qs.iterator():
            if not _is_nondeterministic(f.rule_id):
                continue
            ident = _identity_of_row(f)
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
    resolved_now = 0

    with transaction.atomic():
        # 1) 本次確認仍在的全新非確定性發現：刷新狀態（歸零 miss、取消 resolved）。
        for ident in fresh_nd_ids:
            _confirm_state(scan_job, ident, best.get(ident))

        # 2) 歷史累積：逐一驗證 → 確認仍在 / 判定修復 / 照帶。
        for ident, rec in best.items():
            f = rec["f"]
            state = _get_or_seed_state(scan_job, ident, rec)

            if ident in current_ids:
                # 本次重新確認（確定性或非確定性層打到）→ 已在步驟 1 處理 fresh_nd，
                # 但確定性重新確認的也要歸零；統一在這裡再刷一次無妨。
                _mark_confirmed(state, scan_job)
                continue  # 不重複帶（本次已是一筆真發現）

            if state.resolved:
                continue  # 先前已判定修復 → 不再帶入（已從累積清單消失）

            if agent_ran_ok:
                state.miss_streak = (state.miss_streak or 0) + 1
                if state.miss_streak >= AgentFindingState.RESOLVE_THRESHOLD:
                    state.resolved = True
                    state.resolved_scan_id = scan_job.id
                    state.save(update_fields=["miss_streak", "resolved",
                                              "resolved_scan_id", "updated_at"])
                    resolved_now += 1
                    continue  # 連續多次成功掃描未複現 → 視為已修復，停止帶入
                state.save(update_fields=["miss_streak", "updated_at"])
            # agent 失敗/略過：不扣 miss，照帶（這次沒驗證成功，不能當作修好）。

            row = _materialize_carried(scan_job, f, rec, verified=agent_ran_ok,
                                       miss_streak=state.miss_streak)
            if row is not None:
                carried.append(row)

    if resolved_now:
        logger.info("carry_forward 自動消解 %s 項（連續 %s 次成功掃描未複現）scan=%s",
                    resolved_now, AgentFindingState.RESOLVE_THRESHOLD, scan_job.id)
    return carried


def _get_or_seed_state(scan_job: ScanJob, ident: str, rec: dict) -> AgentFindingState:
    f = rec["f"]
    state, created = AgentFindingState.objects.get_or_create(
        user_id=scan_job.user_id, origin=scan_job.origin, identity=ident,
        defaults={
            "title": (f.title or "")[:255], "severity": f.severity,
            "first_seen_scan_id": rec["first_scan"],
            "last_confirmed_scan_id": rec["last_scan"],
            "miss_streak": 0, "resolved": False,
        },
    )
    if not created:
        # 保持首見/標題最新（顯示用），不動 miss/resolved。
        dirty = []
        if state.first_seen_scan_id is None or rec["first_scan"] < state.first_seen_scan_id:
            state.first_seen_scan_id = rec["first_scan"]; dirty.append("first_seen_scan_id")
        if (f.title or "")[:255] and state.title != (f.title or "")[:255]:
            state.title = (f.title or "")[:255]; dirty.append("title")
        if f.severity and state.severity != f.severity:
            state.severity = f.severity; dirty.append("severity")
        if dirty:
            dirty.append("updated_at"); state.save(update_fields=dirty)
    return state


def _confirm_state(scan_job: ScanJob, ident: str, rec: dict | None) -> None:
    """本次確認仍在：建立/刷新狀態，miss 歸零、取消 resolved。"""
    defaults = {"miss_streak": 0, "resolved": False, "resolved_scan_id": None,
                "last_confirmed_scan_id": scan_job.id, "first_seen_scan_id": scan_job.id}
    if rec is not None:
        f = rec["f"]
        defaults["title"] = (f.title or "")[:255]
        defaults["severity"] = f.severity
        defaults["first_seen_scan_id"] = rec["first_scan"]
    state, created = AgentFindingState.objects.get_or_create(
        user_id=scan_job.user_id, origin=scan_job.origin, identity=ident,
        defaults=defaults,
    )
    if not created:
        _mark_confirmed(state, scan_job)


def _mark_confirmed(state: AgentFindingState, scan_job: ScanJob) -> None:
    state.miss_streak = 0
    state.resolved = False
    state.resolved_scan_id = None
    state.last_confirmed_scan_id = scan_job.id
    state.save(update_fields=["miss_streak", "resolved", "resolved_scan_id",
                              "last_confirmed_scan_id", "updated_at"])


_ORIG_MARKER = "原始說明："


def _original_description(f) -> str:
    """取回「原始說明」，剝掉舊版帶入時加的前言。

    f 可能本身就是前次帶入（carried_over）的列，其 description 會是舊版前言。優先讀
    evidence_json.original_description；否則從舊前言的「原始說明：」之後取；都沒有才用整段。
    """
    ej = f.evidence_json or {}
    raw = ej.get("original_description")
    if raw is not None:
        return str(raw)
    desc = f.description or ""
    if _ORIG_MARKER in desc:
        return desc.split(_ORIG_MARKER, 1)[1].strip()
    return desc


def _materialize_carried(scan_job, f, rec, *, verified: bool, miss_streak: int) -> dict | None:
    original = _original_description(f)
    try:
        obj = Finding.objects.create(
            scan_job=scan_job,
            page=None,
            category="security",
            severity=f.severity,
            title=f.title[:255],
            description=original[:300],
            evidence=f.evidence,
            evidence_type=f.evidence_type,
            evidence_json={**(f.evidence_json or {}), "carried_over": True,
                           "original_description": original,
                           "first_seen_scan": rec["first_scan"],
                           "last_seen_scan": rec["last_scan"],
                           "reverify_attempted": verified,
                           "reverify_miss_streak": miss_streak},
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
        logger.exception("carry_forward 落地失敗 scan=%s", scan_job.id)
        return None
    return {
        "category": "security", "severity": obj.severity, "title": obj.title,
        "rule_id": obj.rule_id, "owasp_category": obj.owasp_category,
        "cwe_id": obj.cwe_id, "carried_over": True,
    }
