# 2026-10-27 Agent 服務統一 HTTP 契約（兼容 argus-agent 與 Strix）

## 需求（使用者）

寫 API 對接，要兼容 argus-agent 與 Strix（usestrix/strix）。

## 關鍵事實

Strix 開源版**只有 CLI＋Docker**（`strix -n --target <url>`，結果寫 `strix_runs/<run>`），
沒有 REST `POST /scan`；REST API 只在付費的 Strix Cloud。所以三者無法用同一條路直接接。

## 決定（使用者）：統一 HTTP 契約

Argus 端**只講一條 HTTP 契約**（`POST {ARGUS_AGENT_SERVICE_URL}/scan`），不綁任何引擎：
- argus-agent 直接實作契約。
- 要接 Strix 時，另跑一個薄的 wrapper 服務包住 `strix` CLI／Docker、對外實作同一契約；
  Argus 完全不改。wrapper 本體在 argus-agent 專案實作，不在本 repo。

## 本 repo 的改動

- `backend/apps/scans/agent_client.py`：加 backend-agnostic 正規化層，讓不同引擎的字串格式都能落地：
  - `_normalize_severity`：五級＋同義詞（informational→info、moderate→medium、error→high…），未知→low。
  - `_normalize_owasp`：`A1`／`A01`／`A01:2021`／`A01:2021-xxx` → `A01`~`A10`，超範圍→空。
  - `_normalize_cwe`：`CWE-862`／`862`／`CWE 862` → `CWE-862`。
  - `_priority_from_item`：priority_score 顯式 > `cvss×10`（夾 0–10）> make_finding 依 severity 預設。
  - category 省略／不明 → 預設 `security`（資安引擎常不標）；回應容忍 `vulnerabilities` 別名、`final_summary`。
  - 請求加 `contract_version`（`CONTRACT_VERSION="1.0"`）。argus-agent 既有行為不變（它本來就回正規欄位）。
- `docs/agent-service-contract.md`（新）：契約單一事實來源——端點、請求／回應 schema、finding 欄位、
  正規化規則、計費與閘門、Strix wrapper 對應備忘表。
- `backend/apps/scans/CLAUDE.md`：agent 段落補「統一 HTTP 契約」說明與契約文件連結。
- `backend/apps/scans/tests_agent_client.py`（新）：正規化單元測試＋Strix 風格回應（vulnerabilities／CVSS／
  A01:2021／無前綴 CWE／同義詞 severity／無 category）端到端落地、mode=both／contract_version 有送出、
  未設 URL 略過、無 category 預設 security。

## 驗證

- `ruff check` 乾淨。
- `apps.scans.tests_agent_client` 7 項全綠。
- 回歸 `tests_scan_plan`＋`tests_coverage`＋`tests_kali_pipeline` 共 66 項全綠（patch 目標 run_agent_via_service 不受影響）。

## 尚待（非本次）

- 在 argus-agent 專案實作 Strix wrapper 服務（包 CLI／Docker、對外實作本契約、解析 strix_runs 輸出）。
- 部署服務並設 `ARGUS_AGENT_SERVICE_URL`／`ARGUS_AGENT_SERVICE_KEY` 才能恢復 agent 功能、做真實端到端驗證。
