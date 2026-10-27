# 2026-10-26 文件清理：AI Agent 引擎抽離、AI 解讀移除後的 CLAUDE.md 同步

## 需求（使用者）

前一筆（`5c26866`）把 AI Agent 引擎抽離成 API 呼叫、移除 AI 解讀後，相關文件仍描述
舊的 in-process 引擎與 AI 解讀功能。使用者要求「清一下那些文件」。

## 改了什麼（只動程式面文件，不動程式）

- `backend/CLAUDE.md`：
  - `/api/scans/` 端點列移除 `ai-insight/`。
  - `agent` app 職責改為「執行引擎已抽離成 argus-agent 服務，Argus 改 `agent_client.py` HTTP 呼叫」，
    關鍵檔案由 `runner.py loop.py tools.py providers.py findings.py` 改為只剩 `findings.py providers.py`。
  - `ScanJob.ai_insight` 欄位註明功能已移除、欄位依 Migration 鐵律保留不刪。
- `backend/apps/scans/CLAUDE.md`：
  - `ai_insight.py` 列改為「已移除」說明。
  - Agent 兩道閘門段落：改寫成 `stage_agent` 呼叫 `agent_client.run_agent_via_service`
    （mode deep／ux／both），未設 `ARGUS_AGENT_SERVICE_URL` 時略過不計費；落地改由 `agent_client._persist_finding`。
  - 進度欄位說明：Agent 階段改為遠端、無逐步回呼，進度粗粒度（`agent_total=1`）。
  - `SCAN_PIPELINE` 的 `agent` 階段列、coverage 兩處「由 runner 落 DB」改為「由 agent_client 落地」。
- `docs/hermes-agent-architecture.md`：頂部加「執行引擎已抽離（2026-10-26）」橫幅，說明本文件為歷史設計。
- `frontend/CLAUDE.md`：移除掃描報告的「AI 解讀 / AiInsightPanel」敘述、`AiInsightPanel.tsx` 檔案列、
  PageLoader 的「08 · Thought Spark」AI 解讀用途。

## 範圍決定（使用者）

- **競賽 Word 內容 md 先不動**（使用者選擇）：`專題文件生成/` 下仍描述 AI 解讀與 AI Agent 的
  需求書、系統手冊、附錄、展示腳本維持現狀，待使用者決定參賽敘述方向再同步。

## 驗證

- 純文件改動；`grep` 確認 `frontend/CLAUDE.md`、`backend/*/CLAUDE.md` 已無殘留的
  `ai-insight`／`AiInsightPanel`／`run_agent_for_scan` 引用。
- 已對照實際程式（`agent_client.py`、`tasks.stage_agent`、`apps/agent/` 現存檔案）確認敘述屬實。

## 尚待

- 競賽 Word 內容 md 同步（使用者決定參賽敘述後）。
- 部署 argus-agent 服務並設 `ARGUS_AGENT_SERVICE_URL`，恢復深度/UX agent。
- ~~前端殘留的 `.ai-insight-*`／Thought Spark 樣式孤兒 CSS~~ → **已於同日清除**（見下）。

## 追加：清除 AI 解讀孤兒 CSS

AI 解讀元件移除後，樣式沒跟著刪。確認 `frontend/src` 的 JS/JSX/TS 已無任何引用後清除：

- `frontend/src/styles/legacy-member/92-layout.css`：刪除整段 AI 解讀樣式（`.ai-insight-*`、
  `.ai-verdict*`、`.ai-triage-note`、`.ai-watch*`、`.ai-spark-stage`、`.ag-spark`、
  `@keyframes ai-watch-pip`，共 120 行）。PageLoader 的「01 · Signal Bars」樣式（`.ag-signal` 等，
  其後）完整保留，`--ag-pack-*` 變數在 `.ag-signal` 內另有定義，不受影響。
- `frontend/src/styles/05-brand.css`：載入動畫註解刪掉「08 · Thought Spark＝AI 分析」那行，只留 Signal Bars。
