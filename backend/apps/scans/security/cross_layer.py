"""跨層資安發現去重：確定性探測與 AI Agent 打到同一端點時只留一筆。

為什麼需要：確定性層（例如 `exposure-file-apidoc` 主動探測）與 Agent 層
（`agent-observed-security-<雜湊>`）可能各自報同一個 API 文件端點。兩者 rule_id 不同，
`scanners._dedupe_findings_for_scoring`（以 rule_id 為鍵）看不出是同一個問題，於是同一端點
在計分被扣兩次、在報告與問題清單各列一次（某授權掃描實測：同一個 API 規格端點
同時出現在確定性 high 與 Agent high 兩筆）。

做法：對同一端點路徑，**只丟掉 Agent 那筆**——
- 確定性探測可重現（實際下載到檔案內容當證據），是穩定訊號；
- 其 rule_id 可能涵蓋多個端點（v2／v3 api-docs 共用 `exposure-file-apidoc`），刪 DB 列不精準；
- Agent 的雜湊 rule_id 對應單一端點，刪得乾淨。

比對只針對確定性層的「敏感檔案外洩」類發現（exposure，對某個 URL「可被公開讀取」的判定）：
這類端點（如 api-docs）本身就只有「被公開」這一個問題，Agent 對同一個 URL 的觀察必然是
同一件事，因此以端點路徑比對即可，不需再比對弱點類型（Agent 措辭含「未授權」時弱點類型
會被歸成 auth，與確定性的 exposure 對不上，反而漏併）。端點比對沿用 Agent 的
`endpoint_path` 正規化，確保跨層一致。
"""

from __future__ import annotations


def _is_exposure(finding: dict) -> bool:
    """確定性層的敏感檔案外洩類發現（某個 URL 可被公開讀取）。"""
    rule_id = str(finding.get("rule_id") or "")
    return (
        rule_id.startswith("exposure-")
        or finding.get("evidence_source") == "exposure_probe"
        or finding.get("impact_area") == "information_exposure"
    )


def _endpoint_of(finding: dict) -> str:
    """發現對應的端點路徑：exposure 存在 `endpoint`、Agent 存在 `observed_endpoint`。"""
    evidence_json = finding.get("evidence_json") or {}
    return str(evidence_json.get("endpoint") or evidence_json.get("observed_endpoint") or "")


def consolidate_cross_layer(findings: list[dict]) -> tuple[list[dict], list[dict]]:
    """回傳（保留的發現, 被丟掉的 Agent 發現）。

    只在「確定性層已有同端點的敏感檔案外洩發現」時丟掉 Agent 那筆；沒有端點資訊的發現
    （站台層級、無 URL）一律保留，不會被誤併。
    """
    from apps.agent.findings import is_agent_security_rule

    exposed_endpoints: set[str] = set()
    for finding in findings:
        if finding.get("category") != "security":
            continue
        if is_agent_security_rule(finding.get("rule_id")) or not _is_exposure(finding):
            continue
        endpoint = _endpoint_of(finding)
        if endpoint:
            exposed_endpoints.add(endpoint)

    kept: list[dict] = []
    dropped: list[dict] = []
    for finding in findings:
        if (
            finding.get("category") == "security"
            and is_agent_security_rule(finding.get("rule_id"))
            and _endpoint_of(finding) in exposed_endpoints
            and _endpoint_of(finding)
        ):
            dropped.append(finding)
            continue
        kept.append(finding)
    return kept, dropped
