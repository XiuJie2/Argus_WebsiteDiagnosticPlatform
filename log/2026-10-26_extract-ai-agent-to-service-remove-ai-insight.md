# 2026-10-26 把 AI Agent 引擎抽離成 API 呼叫、移除 AI 解讀

## 需求（使用者）

把 Argus 的「AI Agent」完全移除、改成呼叫獨立的 argus-agent 服務（API）；「AI 解讀」
（AiInsight）一併去掉。資料表／欄位保留不刪（遵守 Migration 鐵律、可逆）。

## 做法：外科式移除（不是砍整包）

釐清後，`apps/agent` 一半是**發現資料層**（計分／去重／報告仍用），只有**執行引擎**該移走：

**刪除（引擎，已搬到 argus-agent 服務）**
- `apps/agent/runner.py`、`loop.py`、`tools.py`
- `apps/agent/management/commands/smoke_providers.py`、`apps/agent/knowledge/`（引擎專用）
- 引擎測試：`apps/agent/tests.py`、`tests_progress_callback.py`、`tests_known_findings.py`

**保留（資料層／共用層）**
- `apps/agent/findings.py`：發現落地、去重、正典身分、嚴重度封頂、`scanner_ip_disclosure`
  （從 tools.py 移入——migration 0035→finding_normalization→本檔有依賴鏈，不可斷）
- `apps/agent/providers.py`：LLM provider chain，`apps/scans/fixgen` 共用（fixgen 非 agent、保留）

**新增／改寫**
- `apps/scans/agent_client.py`：`run_agent_via_service()` HTTP `POST {ARGUS_AGENT_SERVICE_URL}/scan`，
  回傳發現→以 `make_finding`＋`owasp_mapper` 落地成 Finding→交給既有計分／跨層去重。
  **graceful degrade**：未設定服務位址回 None（agent 階段略過、不 crash、不計費）。
- `tasks.stage_agent`：改呼叫 agent_client（不再 in-process `run_agent_for_scan`）。
- `config/settings.py`：新增 `ARGUS_AGENT_SERVICE_URL/KEY/TIMEOUT`。

**移除 AI 解讀**
- 刪 `apps/scans/ai_insight.py`、`tasks.run_ai_insight_task`、`views` 的 `/ai-insight` action、
  前端 `AiInsightPanel.tsx`(+test)、`ScanExperience` 的 AI 解讀面板與 AiTriageNote、
  重新產生 `apiTypes.ts`（ai-insight path 已消失）。
- `ScanJob.ai_insight` 欄位保留不刪（歷史資料、Migration 鐵律）。

**保留**：計費（agent_deep_fee／agent_ux_fee，深度/UX 仍提供、只是遠端跑；settle 本就「agent
真的跑了才收」）、`deep_agent_requested`、`AgentSession`／`AgentStep` 模型（不再寫入，但不刪表）。

## ⚠️ 重要後果

argus-agent 服務目前尚未部署。此改動後，**正式環境的深度/UX agent 會暫時關閉**，直到部署
argus-agent 並設定 `ARGUS_AGENT_SERVICE_URL` 才恢復（未設定時 graceful skip、不計費）。

## 驗證

- `ruff check` 乾淨；`manage.py check` 乾淨。
- 後端測試全綠：`apps.scans`（全套）、`apps.admin_api`、`apps.mcp_access`、`apps.billing`、
  `apps.agent`、`tests_scan_plan`、`tests_kali_pipeline`、`tests_coverage`、`tests_fixgen(_api)`、
  `tests_cross_layer`（修正：把 patch 目標由 `apps.agent.runner.run_agent_for_scan` 改為
  `apps.scans.agent_client.run_agent_via_service`、AsyncMock→Mock、AgentRunResult→AgentServiceResult；
  刪除 `tests_ai_insight.py` 與 billing 的 `SpecialistDispatchLimitTests`）。
- 前端：`npm run lint`／`typecheck` 乾淨、`vitest` 49 檔 303 項全綠（移除 AiInsightPanel.test）。

## 尚待（非本次）

- 部署 argus-agent 服務並設定 URL，才能恢復 agent 功能、做真實端到端驗證。
- `docs/hermes-agent-architecture.md` 與 `apps/scans/CLAUDE.md`、`frontend/CLAUDE.md` 的引擎段落
  為歷史內容；已在 `apps/agent/CLAUDE.md` 頂部加「引擎已抽離」說明，詳細段落待後續整理。
- 競賽 Word 內容 md：對外功能異動（AI 解讀移除、agent 改遠端）待同步。
