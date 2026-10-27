# Agent 服務 HTTP 契約（argus-agent／Strix 等共用）

Argus 把 AI pentest／UX 測試引擎抽離成獨立服務後（見 `backend/apps/agent/CLAUDE.md`「引擎已抽離」、
`log/2026-10-26_extract-ai-agent-to-service-remove-ai-insight.md`），Argus 這端**只講一條 HTTP 契約**。
任何引擎只要跑一個服務、對外實作本契約，就能接上 Argus，Argus 不必改程式：

- **argus-agent**：自家服務，直接實作本契約。
- **Strix（usestrix/strix）**：開源版只有 CLI＋Docker、沒有 REST API，所以要再跑一個薄的 **wrapper
  服務**包住 `strix -n --target …`、解析 `strix_runs/<run>` 的結果、對外實作本契約。Argus 端無感。

> 呼叫端實作：`backend/apps/scans/agent_client.py`（`run_agent_via_service`／`_persist_finding`）。
> 設定：`ARGUS_AGENT_SERVICE_URL`（空＝停用、略過、不計費）、`ARGUS_AGENT_SERVICE_KEY`（選填 Bearer）、
> `ARGUS_AGENT_SERVICE_TIMEOUT`（秒，預設 1800）。契約版本 `agent_client.CONTRACT_VERSION`（目前 `1.0`）。

---

## 端點

```
POST {ARGUS_AGENT_SERVICE_URL}/scan
Content-Type: application/json
Authorization: Bearer {ARGUS_AGENT_SERVICE_KEY}   # 僅在 Argus 有設定金鑰時帶
```

- 同步回應：請求會阻塞到掃描完成（受 `ARGUS_AGENT_SERVICE_TIMEOUT` 限制）。逾時／連線錯誤由
  Argus 視為「agent 階段失敗、不中斷掃描」處理，不計 agent 費。
- 非 2xx 一律當失敗（`raise_for_status`）。服務若要回報「部分完成」，用 `status` 欄位，HTTP 仍回 200。

### 請求 body

| 欄位 | 型別 | 說明 |
|---|---|---|
| `contract_version` | string | 契約版本（目前 `"1.0"`），wrapper 可據此判斷相容性 |
| `url` | string | 目標網址（已正規化） |
| `mode` | string | `"deep"`＝資安滲透；`"ux"`＝擬真使用者體驗；`"both"`＝兩者都跑 |
| `authorized` | bool | 是否為「主動測試已授權」（＝可送攻擊 payload）。`false` 時服務**不得**送出具攻擊性的請求 |
| `submit_forms` | bool | 是否允許實際送出表單（登入／提交）。`false` 時只填欄位、不送出 |
| `recon_intel` | string[]｜null | Argus 已偵察到的端點／線索，供服務省略重複偵察 |
| `known_findings` | object[]｜null | Argus 確定性工具這次已找到的資安問題（叫服務別重報，減少重複與事後去重） |
| `test_auth_email` | string｜null | 授權測試帳號（服務解讀後用於登入；**不得**寫入 log／回應／報告） |
| `test_auth_password` | string｜null | 授權測試密碼（同上） |

> `mode`／`authorized`／`submit_forms` 的閘門由 Argus 的 `scan_plan.py` 算好（見
> `apps/scans/CLAUDE.md`「掃描範圍與工具矩陣」）。**服務必須尊重這三個旗標**——例如 Strix wrapper
> 應只在 `authorized=true` 時送攻擊流量，並把 `test_auth_*` 轉成 `strix --instruction "...credentials..."`。

### 回應 body

| 欄位 | 型別 | 說明 |
|---|---|---|
| `status` | string | `"completed"`／`"partial"`／`"error"`（Argus 覆蓋契約據此標 completed／partial／failed） |
| `steps` | int | 執行步數（僅記錄，進度為粗粒度） |
| `total_tokens` | int | LLM token 用量（僅記錄） |
| `summary` | string | 服務自述的結果摘要／受阻說明（也接受別名 `final_summary`） |
| `error` | string | 錯誤說明（`status="error"` 時） |
| `findings` | object[] | 發現清單（見下；也接受別名 `vulnerabilities`） |

### 單筆 finding

| 欄位 | 型別 | 必填 | 說明 |
|---|---|---|---|
| `category` | string | 否 | `"security"` 或 `"ux"`；**省略或無法識別時 Argus 預設當 `security`**（UX 問題必須明確標 `ux`） |
| `severity` | string | 是 | 五級：`critical`／`high`／`medium`／`low`／`info`。Argus 會正規化常見同義詞（`informational`→`info`、`moderate`→`medium`、`error`→`high`…），無法判斷退回 `low` |
| `title` | string | 是 | 問題標題（截斷 255 字） |
| `description` | string | 是 | 問題說明 |
| `remediation` | string | 否 | 修補建議 |
| `evidence` | string | 否 | 證據片段（**服務端應先遮罩個資／秘鑰**；Argus 另有遮罩但以服務端為第一道） |
| `evidence_json` | object | 否 | 結構化證據（端點、請求／回應摘要等） |
| `url` | string | 否 | 對應頁面網址；Argus 以 `final_url`→`url` 比對掛上 `Page` |
| `rule_id` | string | 否 | 問題代號；省略時 Argus 依 category＋title 自動產生 |
| `owasp_category` | string | 否 | OWASP Top 10 代號。接受 `A1`／`A01`／`A01:2021`／`A01:2021-Broken Access Control`，Argus 正規成 `A01`~`A10`（超出範圍或無法解析＝空） |
| `cwe_id` | string | 否 | CWE 編號。接受 `CWE-862`／`862`／`CWE 862`，Argus 正規成 `CWE-862` |
| `cvss`／`cvss_score` | number | 否 | CVSS 0–10；當 `priority_score` 未提供時 Argus 以 `cvss×10` 當優先序（0–100） |
| `priority_score` | number | 否 | 直接指定排序優先序（0–100），優先於 CVSS 換算 |
| `impact_area` | string | 否 | 影響面向（UX 用，如 `usability`） |
| `confidence` | number | 否 | 0–1，預設 1.0 |
| `ai_handoff_prompt` | string | 否 | 給使用者貼進 ChatGPT／Claude 的提示詞；省略時 Argus 自動產生 |
| `evidence_source` | string | 否 | 證據來源標示，預設 `agent_service` |

---

## 正規化規則（Argus 端 `agent_client` 已做，wrapper 不必自己對齊）

- **severity**：小寫、同義詞對映到五級，未知→`low`。
- **owasp_category**：抽出 `A` 後的數字，限 1–10，輸出兩位數 `A0N`；否則空字串。
- **cwe_id**：抽出數字，輸出 `CWE-N`；否則空字串。
- **priority_score**：顯式 > `cvss×10` > 依 severity 的預設值（`make_finding`）。
- **category**：只收 `ux`／`security`；其餘（含空值）一律當 `security`。

因此 wrapper 盡量照上面欄位送即可；字串格式的小差異（大小寫、`A01:2021` 後綴、`CWE-` 前綴有無、
CVSS vs priority）Argus 都吃得下。

---

## 計費與閘門（服務端須知）

- Argus 只有在**服務真的回了結果**（非 None）時才結算 agent 費；服務未部署（`ARGUS_AGENT_SERVICE_URL`
  空）時整個 agent 階段略過、不計費。
- 資安發現進 Argus 的「AI Agent 觀察」層（`agent-observed-security-*`），**不進確定性基準分**、嚴重度
  在報告封頂中風險、會與確定性層跨層去重（見 `apps/scans/CLAUDE.md`「分數分離」「跨層去重」）。
- UX 發現進 `top_actions`（優先序預設 50）。

---

## Strix wrapper 對應備忘（實作在 argus-agent 專案，非本 repo）

| 本契約 | Strix（`strix -n --target <url>`） |
|---|---|
| `url` | `--target <url>` |
| `authorized=false` | wrapper 應限制／關閉攻擊性測試（Strix 本身偏主動，需在 instruction／範圍上收斂） |
| `submit_forms` / `test_auth_*` | `--instruction "Perform authenticated testing using credentials: user:pass"` |
| 回應 `findings` | 解析 `strix_runs/<run>` 的結構化結果（Strix 提供 CVSS＋OWASP classification），映射到上表欄位 |
| `status` | headless 退出碼／報告狀態 → `completed`／`partial`／`error` |

Strix 需要 Docker 與 `STRIX_LLM`／`LLM_API_KEY`（或 `strix auth login`）；這些是 wrapper 服務的部署
需求，不是 Argus 的。
