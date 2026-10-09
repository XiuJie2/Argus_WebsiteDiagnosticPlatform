# 2026-10-09 快速檢查頁：測速串接 Google PageSpeed Insights、導流文字更新

## 需求
- 快速檢查頁結果下方的導流文字仍寫「可直接貼上的修正內容（JSON-LD、llms.txt…）」，要依現況改寫。
- 快速檢查頁的「網站測速」要使用已設定好的 PageSpeed API。

## 設計
- 完整掃描已有 `apps/scans/pagespeed.py`（`fetch`／`parse`），直接共用，不另寫一套。
- PSI 單次 20～60 秒，正式站 web 只有 2 workers × 4 threads（`k8s/04-backend.yaml`）。在免登入請求裡同步等待，幾個請求就能卡滿網站。所以改成：
  - `speed-test/` 照舊即時回 Argus 輕量量測，另附 `pagespeed` 狀態。
    - 平台沒有金鑰時回 `unavailable`，前端不顯示。
    - 有金鑰時排入 Celery `run_public_pagespeed`，回 `pending`＋job 代號。
  - 結果放 Django cache（正式環境是 Redis）：job 保留 15 分鐘，同網址成功結果快取 10 分鐘，以節省與完整掃描共用的配額。
  - 新增 GET `speed-test/pagespeed/<job>/` 輪詢：`insights_poll` 節流預設 600/hour；job 不存在、過期或格式不符回 404。
  - 量測由 Google 機房發出，我們的主機不會連到受測網址；送 PSI 的是已通過 `assert_public_url`／`_safe_get` 的 `final_url`。
- 前端 `components/public/PageSpeedResult.jsx`：
  - 每 3 秒輪詢，最多 2.5 分鐘。
  - 顯示 Lighthouse 四個分數、五個實驗室指標、CrUX 真實使用者資料與前幾項改善機會。
  - 失敗時顯示原因，例如配額用完或逾時。
  - 有 PSI 時，後端把原本「需接入 PageSpeed 才更精準」的說明改成兩種量測的差異。
- 文字更新：
  - 導流文字改成「完整掃描看得更完整：整站爬取與逐頁截圖、五個面向的問題與修正順序、防偽 PDF 報告，還能針對單一頁面產出優化後的版本；註冊後第一次完整掃描免費」。
  - 頁首說明與測速空白狀態加註 PageSpeed Insights。

## 文件
- `backend/apps/insights/CLAUDE.md`：新增端點與設計理由，包括不可同步呼叫，以及本機 LocMemCache 與 worker 不共用。
- 一併同步：
  - `backend/CLAUDE.md` 路由表（順便補上早已存在但漏列的 `quick-scan/`）
  - `backend/apps/scans/CLAUDE.md`
  - `frontend/CLAUDE.md`
  - `.env.example`（`THROTTLE_INSIGHTS_POLL`）
  - 需求書 md 免費工具段落

## 驗證
- 後端：`ruff check backend` 通過；`apps.insights` 11 項測試通過，其中新增 4 項：
  - 沒有金鑰時回 unavailable
  - 排入背景量測、輪詢、同網址快取
  - 失敗原因回報且不快取
  - 錯誤或不存在的 job 回 404
- 前端：lint（0 error）、typecheck、vitest 263 項（新增 PageSpeedResult 3 項）、vite build 全部通過。
- Playwright：攔截 API 模擬「pending → done」完整流程，在夜間 1440、日間 1440 與手機 390 截圖，畫面正確，scrollWidth 等於視窗寬。手機版指標改成兩欄。
- 未做：沙盒沒有 PSI 金鑰，沒有對真實 Google 實測。部署後需要在正式站 `/free-tools` 測一次，確認 worker 有收到 `apps.insights.tasks.run_public_pagespeed`，約一分鐘內出現分數。
