# 掃描管道重構：相位分離與工具去重疊（Pipeline Phasing & Tool De-overlap）

Argus 的 `SCAN_PIPELINE` 目前有 21 個階段（前端進度條顯示 17 個細分步驟），其中資安相關有 8 個：
`site_security`、`active_probe`（Nuclei／Katana）、`deep_security`、`zap_passive`、`zap_active`、
`exposure`、`agent`、`kali`。這些階段是**一個一個工具疊加上去**的：每個工具自帶「發現攻擊面 →
偵測 → 產出 finding」整條流程，彼此的重疊**在事後清理**（`zap_passive` 的 `OVERLAP_RULES` 手動
抑制表、`cross_layer.consolidate_cross_layer` 跨層去重、`findings.consolidate_security_findings`
Agent 內部合併）。結果是同一個問題可能被多個工具各測一次、各報一次，再靠去重把重複刪掉。

> 更正常見誤解：目前的去重**都是確定性的**（欄位比對、規則表），不是「AI Agent 事後再審一遍」。
> 但「重疊是事後清、不是一開始就不產生」這個架構債確實存在，本 ADR 處理它。

本 ADR 從第一性原理重排管道，定義**相位分離**與**單一攻擊面模型**，讓重疊從源頭不發生，而不是
產生後再刪。與 [ADR-0004 智慧動態掃描](0004-smart-dynamic-scan.md) 正交：0004 決定「依網站特徵
加掃哪些模組」，本 ADR 決定「這些模組怎麼排、怎麼不互相重複」。

> 這份文件是**實作計劃**，撰寫時尚未改動任何掃描程式。所有「現況」敘述對照 2026-10-17 的
> `backend/apps/scans/`。落地時每一刀完成都要回來更新本檔與 `backend/apps/scans/CLAUDE.md`。
>
> **前提（使用者 2026-10-17 裁定）**：對授權目標**不限制重複請求／重抓**。因此凡是「為了省請求數
> 而縮小範圍」的既有設計（Nuclei 只掃根網址、authz 探測 20 個端點上限等）都可以放寬，換取更高涵蓋率。
> 但請求量放寬**不能解決 Cloudflare 攔截**——那是「非真瀏覽器會吃 challenge」的問題，只能靠真瀏覽器
> （crawler）或瀏覽器 context 重抓解決，見決策 §2。

---

## 原則（先定錨，其餘服從）

1. **發現一次、共享給所有人**：攻擊面（頁面、端點、表單、技術、JS、HAR）只由 crawler 建立一次，
   當作唯一真相來源餵給所有下游工具。任何工具都不自己再爬一遍去建立自己的攻擊面。
2. **一個 (端點 × 弱點類) 只由一個工具負責**：主動探測與利用階段要有明確分工，從源頭不重疊；
   事後去重只當**最後一道保險**，不當主要手段。
3. **CF 盲區靠真瀏覽器補，不靠加請求**：繞過 Cloudflare 的唯一管道是 crawler（真瀏覽器、帶 clearance）。
   需要 CF 後面資料的分析，一律走 crawler 已抓到的 bytes 或瀏覽器 context 重抓，不交給會被 challenge
   的獨立 HTTP client（Katana、ZAP spider、Nuclei）。
4. **Agent 吃前面的結果當輸入**：Agent 不重新發現、不重跑確定性檢查；它拿到「攻擊面＋已找到的
   deterministic findings」，只做「要推理才找得到的」與「驗證／升級既有發現」。

---

## 第一性原理：只有五種偵測機制

每一筆資安發現本質上只來自其中一種，先把工具按機制歸位，重疊就現形：

| 機制 | 本質 | 現在誰做 | 應該屬於的相位 |
|---|---|---|---|
| A 被動分析已抓到的 bytes | 0 新請求、確定性 | `site_security`、`deep_security`、`zap_passive` | 相位 2 被動 |
| B 主動探測已知/猜測路徑 | 發請求、無推理 | `exposure`（檔案/authz）、Nuclei(KEV) | 相位 3 主動探測 |
| C 主動爬行找攻擊面 | 發請求找端點 | crawler、Katana、ZAP spider | 相位 1 發現 |
| D 送 payload 打弱點 | 攻擊流量 | ZAP ascan、Nuclei(fuzz)、sqlmap、agent | 相位 4 利用 |
| E 代理推理 | 情境判斷、串接 | Hermes-Agent | 相位 5 推理 |

---

## 現況的四個重疊（問題陳述）

1. **被動分析做兩遍**：`site_security`＋`deep_security` 已從回應算出 header/cookie/TLS/CSP/CORS/SRI/
   JS-CVE/PII……，`zap_passive` 又把同一份 HAR 餵進 ZAP 的被動規則**再算一遍**。證據：`zap_passive.py`
   有 13 條 `OVERLAP_RULES` 手動抑制＋10 條 `IGNORED_RULES`。ZAP 被動真正獨有的只剩約 5 條（混合內容
   10040、註解殘留 10027、debug 錯誤頁 10023/90022、URL 帶敏感資訊 10024、Permissions-Policy 10063）。
2. **爬行做三遍**：crawler（真瀏覽器、繞得過 CF，已抽 XHR 端點＋JS 靜態路徑）、Katana（主動重爬，CF 後
   歸零）、ZAP spider（主動重爬，CF 後歸零，所以 `zap_active` 才改用 crawler HAR 建站台樹）。
3. **利用沒有分工表**：Nuclei、ZAP ascan、sqlmap、agent 各自對重疊端點送各自 payload（同一個 XSS 可能
   被三個引擎各打一次），撞了才由 `cross_layer`／`consolidate_security_findings` 事後刪。
4. **Katana JS 功能與 crawler 半重疊、又有真漏洞**：Katana 的「JS 端點挖掘（-jc）」與 crawler 的
   `extract_api_paths_from_js` 重疊（jsluice AST 較深、crawler regex 較淺）；但 Katana 的「JS 秘鑰（-jsl）」
   **crawler 完全沒做**——`_collect_js_api_paths` 讀完 JS body「抽完路徑就丟」，Argus 自家 `secret_scanner`
   只掃 HTML＋inline script，**不掃外部 .js bundle**。而 Katana 這塊在 CF 後面又歸零——等於「需要它的場景
   它失效，它有效的場景 crawler 也有效」。

---

## 決策：五相位管道 ＋ 單一攻擊面模型

重排資安階段為清楚的相位，前一相位的產出是後一相位的輸入：

```
相位 1 發現（crawler 唯一真相來源）
  → 頁面、表單、XHR/fetch 端點、JS（透過瀏覽器 context 抓齊）、技術指紋、HAR
相位 2 被動分析（單一引擎，0 新請求）
  → header/cookie/TLS/DNS/CSP/CORS/SRI/JS-CVE/service-CVE/secret(HTML+JS)/PII/混合內容/debug 洩漏
相位 3 主動探測（確定性、發請求、無推理）
  → 檔案內容探測、API-docs、未授權存取(authz)、Nuclei KEV
相位 4 利用（送 payload，由「利用計畫」分工）
  → 每個 (端點 × 弱點類) 指派給唯一工具：ZAP ascan / Nuclei fuzz / sqlmap
相位 5 Agent 推理（吃相位 1–4 的全部產出當輸入）
  → 只做情境判斷（差異式未授權、串接）與既有發現的驗證／升級
```

### §1 發現相位：JS 分析搬進 crawler，取代 Katana JS 功能
- crawler 新增「抓齊所有發現到的 .js（透過瀏覽器 request API，帶 CF clearance）→ 端點抽取＋秘鑰偵測」。
  因為使用者不限重抓，crawler 可主動抓頁面沒自然載入的 JS，不只被動攔截到的。
- JS 端點與 JS 秘鑰的**唯一真相來源**改為 crawler。補上「外部 .js 秘鑰偵測」這個現有真實漏報。
- Katana **不刪**，降為非 CF 站的補充：主動爬到瀏覽器沒點進去的頁、較廣的技術辨識（`-td`）。
  CF 後面它本就歸零，降級不損失覆蓋。

### §2 被動相位：ZAP 被動與自家被動二選一
- 不再兩個引擎並存＋手動抑制。決策方向：**保留 Argus 自家被動**（可控、已與計分/覆蓋/報告整合），
  把 ZAP 被動**獨有的約 5 條規則移植**成自家規則，然後 `zap_passive` 階段退役。
- 理由：自家被動已是計分與覆蓋契約的一等公民；留 ZAP 要維護對照表、版本綁定與重複運算。
  （替代方案「改用 ZAP 當被動引擎、退自家」成本更高：要重接計分/覆蓋/報告/遮罩，不採。）

### §3 主動探測相位：合併為一個「主動探測」階段，放寬預算
- `exposure`（檔案/authz）、Nuclei 收斂到同一相位，共用同一份攻擊面與同一個 RPS/取消時鐘。
- 不限重抓 → Nuclei 可放寬模板集與掃描範圍（不再只 KEV、只根網址）；authz 探測解除 20 端點上限。
  以涵蓋率為目標，逾時與預算改為「盡量跑完」而非「省請求」。

### §4 利用相位：ZAP active 併入、加「利用計畫」分工
- `zap_active` 不再是獨立頂層階段，與 Nuclei fuzz／sqlmap 併入**利用相位**。
- 新增**利用計畫（exploitation plan）**：以攻擊面為輸入，把每個 (端點 × 弱點類) 指派給唯一一個工具，
  避免 XSS/SQLi 被多引擎重打。分工原則（初版）：SQLi→sqlmap（最專）、一般注入/XSS/設定類→ZAP ascan、
  已知 CVE/KEV→Nuclei。
- `zap_passive` 的被動部分已於 §2 處理；ZAP 在新架構只保留 active 這一半。

### §5 Agent 相位：吃既有結果，不盲跑
- `run_agent_for_scan` 的輸入除了 `recon_intel`，加上「本次 deterministic findings 摘要」與完整攻擊面。
- prompt 明示：這些已被確定性層找到，不要重報；你的工作是（a）情境判斷找出確定性層找不到的
  （差異式未授權、邏輯串接），（b）對既有發現做工具驗證/升級。
- 這直接消掉「Agent 盲跑 → 撞一堆重複 → 事後去重」的浪費（使用者最在意的點）。

### §6 階段順序
相依順序固定為 **發現 → 被動 → 主動探測 → 利用 → Agent → 計分**。修掉現況「`zap_active`（利用）排在
`exposure`（探測）之前」「Agent 排最後卻重新發現前面已找到的端點」兩個倒置。非資安階段
（seo_links、geo_site、pagespeed、favicon、aeo_answers）與資安相位正交，維持現狀交錯即可。

---

## 非目標與不可消除的重疊（誠實邊界）
- **零事後對帳做不到**：Nuclei/ZAP/sqlmap 是各自帶規則庫的獨立引擎，連商業 DAST 也得去重。
  `cross_layer` 這類最後保險**保留**，但只處理「分工計畫沒攔住的殘餘」，不再是主要手段。
- **不重寫掃描引擎**：不自己實作一套 DAST 取代 ZAP/Nuclei；只調度它們、分工、共享攻擊面。
- **jsluice 等級的 JS 解析**：crawler 端若 regex 不夠，可移植 jsluice 邏輯，但不保證完全等價；
  以「補上秘鑰漏報」為第一優先，解析深度逐步逼近。

---

## 遷移計畫（逐刀，依價值／風險排序）

每一刀都獨立可上、可回滾，完成後更新本檔進度與 `CLAUDE.md`，跑全套測試。

| # | 刀 | 價值 | 風險 | 說明 |
|---|---|---|---|---|
| 1 | crawler 抓齊 JS → 端點＋秘鑰分析 | 高（補真實漏報＋CF 盲區） | 低（純增偵測） | §1；Katana 降級但不刪 |
| 2 | Agent 吃既有 findings 當輸入、prompt 不重報 | 高（消浪費） | 中（改 runner/prompt） | §5 |
| 3 | ZAP 被動二選一、移植獨有規則、退 `zap_passive` | 中（刪一個引擎＋抑制表） | 中（少數規則行為變） | §2；注意 `RENDERER_VERSION`/覆蓋 |
| 4 | 主動探測合併階段＋放寬 Nuclei/authz 預算 | 中（涵蓋率） | 中（逾時/計分） | §3 |
| 5 | 利用相位＋利用計畫分工（ZAP active 併入） | 中（源頭去重） | 高（動到授權/計分/取消） | §4；最後做 |
| 6 | 階段順序校正 | 低 | 低 | §6；併在前幾刀一起 |

**建議先做第 1 刀**（低風險、純補洞、CF 內外都生效），再做第 2 刀。第 3–5 刀動到計分與覆蓋契約，
要逐一驗證 `SCORING_VERSION`／`RULESET_VERSION`／`RENDERER_VERSION`／覆蓋狀態。

---

## 風險
- 任一刀改到「找出哪些問題／多嚴重」就要調 `RULESET_VERSION`；改計分公式調 `SCORING_VERSION`；
  改報告版面調 `RENDERER_VERSION`。歷史比較靠 `versions.comparable`，版本一變就不可直接比分。
- 退 `zap_passive`、合併階段會改覆蓋契約的 check 名單，`coverage.py` 與歷史比較要同步，舊掃描的
  coverage 仍要讀得動。
- 利用相位的分工若把某工具原本會測的 (端點×類) 指派錯，可能漏檢；每刀都要有對照測試。

---

## 狀態／進度（2026-10-17）
- 本 ADR 建立，**尚未改動掃描程式**。
- 既有相關已落地（本輪稍早）：`cross_layer` 跨層去重（最後保險，將保留）、`zap_active` 觀測性
  skip 原因、`authz_probe` 未授權存取確定性探測。
- 下一步：依遷移計畫第 1 刀（crawler JS 抓齊＋秘鑰）開始。
