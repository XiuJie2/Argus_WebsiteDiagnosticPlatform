# AI Agent 不重做主動層已做過的事（告知式覆蓋摘要）

**日期**：2026-10-18
**操作者**：Claude
**來源**：使用者反映 agent 階段太久、問「能不能從底層優化，把確定性主動資安已做過的事就別在 agent
重複做」。選擇「告知式」強度（不硬跳過角色）。

## 背景
原本 orchestrator 已會吃「確定性層**已找到**的問題」清單（ADR-0005 §2），叫它別重報。但缺的是
「哪些端點／面相**已被主動層系統性測過**（即使乾淨）」——所以專家仍會把 authz 探測、敏感檔探測、
Nuclei 已覆蓋的面「無腦重掃」一遍，白燒步數（agent 階段慢的主因之一）。

## 修法（從底層餵「已做過」給 agent）
- `tasks._active_coverage_summary(ctx)`：在 agent 之前（SCAN_PIPELINE 順序：active_probe→deep_security→
  zap_active→exposure→…→agent 都已跑完），讀 `ctx.coverage.status_of()` 組出摘要——Nuclei／ZAP 主動／
  敏感檔探測／未授權探測各自的狀態（已完整執行／部分／略過／失敗），未授權探測附「已涵蓋約 N 個觀察到的
  API 端點」。沒有任何主動檢查跑過回空字串。
- `tasks.stage_agent`：把摘要以 `coverage_summary=` 傳進 `run_agent_for_scan`。
- `runner.run_agent_for_scan(coverage_summary=...)`：組 `coverage_block`，接在 recon 與 orchestrator 的
  prompt 尾端，明確叫專家別重做這些面相的「逐一端點無腦重掃」，把步數花在它們做不到的：差異式未授權、
  多步驟商業邏輯、跨端點串接、對已知發現做驗證／升級。

**告知式、不硬跳過角色**：覆蓋 100% 不變（確定性層照跑），只是減少 agent 的重複探測、把步數導向高價值推理。

## 驗證
- `tests_pipeline_stages.ActiveCoverageSummaryTests`（2）：有跑的檢查進摘要、沒跑的不進；全沒跑回空。
  `apps.agent`（101）＋`tests_pipeline_stages` 通過；`ruff check backend` 乾淨。文件同步 `agent/CLAUDE.md`。

## 與「時間上限」的關係
這是「省掉重複工作」的根因優化；時間安全閥（`ARGUS_AGENT_MAX_SECONDS`）仍未做，之後要再疊可另開一刀。
兩者互補：本刀讓每次跑得更有效率，安全閥擋失控極端值。

## 備註
不影響掃描範圍、授權閘門、嚴重度；待 rebuild backend image 後生效。
