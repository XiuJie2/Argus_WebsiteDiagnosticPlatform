"""Agent 服務 HTTP 契約 v1.0 的 Pydantic 模型。

權威來源：Argus repo `docs/agent-service-contract.md` 與呼叫端
`backend/apps/scans/agent_client.py`（`CONTRACT_VERSION = "1.0"`）。

本服務（Strix wrapper）對外實作同一條契約：Argus 完全不必改程式，只要把
``ARGUS_AGENT_SERVICE_URL`` 指向本服務即可。
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

CONTRACT_VERSION = "1.0"


class ScanRequest(BaseModel):
    """POST /scan 的請求 body（見契約文件「請求 body」）。"""

    contract_version: str = CONTRACT_VERSION
    url: str
    mode: Literal["deep", "ux", "both"] = "deep"
    # 主動測試是否已授權（＝可送攻擊 payload）。false 時服務不得送攻擊流量。
    authorized: bool = False
    # 是否允許實際送出表單。false 時只填欄位不送出。
    submit_forms: bool = False
    recon_intel: list[str] | None = None
    known_findings: list[dict[str, Any]] | None = None
    # 授權測試帳密：只用於登入注入，絕不寫入 log／回應／報告。
    test_auth_email: str | None = None
    test_auth_password: str | None = None
    # per-scan 操作者聚焦（選填，預設空）。由 Argus 的 scan.agent_focus 帶入，
    # 針對「這一次掃描的這個目標」；不是全域設定，掃別站留空即可（不過擬合）。
    instruction: str = ""
    # 同站歷次掃描的資安發現聯集（選填）：叫 agent 先驗證還在不在、再從這些線索深挖，
    # 讓覆蓋跨掃描累積。每筆至少 {title, severity}，可含 endpoint/rule_id。
    prior_findings: list[dict[str, Any]] | None = None


class Finding(BaseModel):
    """單筆發現。欄位對齊契約「單筆 finding」表；Argus 端會再正規化。"""

    category: Literal["security", "ux"] = "security"
    severity: str = "low"
    title: str = ""
    description: str = ""
    remediation: str = ""
    evidence: str = ""
    evidence_json: dict[str, Any] | None = None
    url: str = ""
    rule_id: str = ""
    owasp_category: str = ""
    cwe_id: str = ""
    cvss: float | None = None
    priority_score: float | None = None
    impact_area: str = ""
    confidence: float = 1.0
    ai_handoff_prompt: str = ""
    evidence_source: str = "strix"


class ScanResponse(BaseModel):
    """POST /scan 的回應 body（見契約文件「回應 body」）。"""

    status: Literal["completed", "partial", "error"] = "completed"
    steps: int = 0
    total_tokens: int = 0
    summary: str = ""
    error: str = ""
    findings: list[Finding] = Field(default_factory=list)
    # 服務自述的成本（USD）；僅記錄，Argus 的計費以固定附加點數為準。
    cost_usd: float = 0.0
    engine: str = "strix"


# ---- 非同步契約 v2（app.strix.ai 式：start → poll/trace → result → cancel/message）----

CONTRACT_VERSION_ASYNC = "2.0"


class ScanStartResponse(BaseModel):
    """POST /v1/scans 的回應（立即返回，不阻塞）。"""

    scan_id: str
    status: str = "queued"


class ScanStatusResponse(BaseModel):
    """GET /v1/scans/{id}：狀態與粗進度，不含 findings。"""

    scan_id: str
    status: str  # queued|running|succeeded|partial|failed|cancelled
    phase: str = ""
    steps: int = 0
    cost_usd: float = 0.0
    total_tokens: int = 0
    error: str = ""
    engine: str = "strix"


class TraceEventModel(BaseModel):
    seq: int
    ts: float
    kind: str
    message: str
    agent: str = ""


class TraceResponse(BaseModel):
    """GET /v1/scans/{id}/trace：自 after 之後的即時事件。"""

    scan_id: str
    status: str
    events: list[TraceEventModel] = Field(default_factory=list)
    next: int = 0  # 下次輪詢帶的 after


class ScanResultResponse(ScanResponse):
    """GET /v1/scans/{id}/result：終端後的完整結果（findings 同 v1 shape）。"""

    scan_id: str = ""


class MessageRequest(BaseModel):
    """POST /v1/scans/{id}/message：掃描進行中對 agent 下指令／補充。"""

    message: str
