# 2026-10-27 strix-agent-service：把 Strix 接成 Argus 的 AI pentest/UX 引擎（Phase 0）

## 要做什麼
使用者要「把開源 Strix 當 Argus 的主動滲透測試 AI agent，和 Argus 拆開，像 app.strix.ai」。
依 `docs/superpowers/specs/2026-10-26-strix-active-pentest-service-design.md`。

## 關鍵發現（校正了 spec）
spec 初稿對著舊 clone 寫，提議平行的 `strix_policy/strix_client/strix_contracts`。但 live 樹
（本 repo）已於 2026-10-26 把 AI agent 引擎抽離成獨立服務，並做好 backend-agnostic 的
**agent 服務 HTTP 契約**：
- 契約文件：`docs/agent-service-contract.md`（v1.0）
- 呼叫端：`backend/apps/scans/agent_client.py`（`run_agent_via_service`／`_persist_finding`），
  已明確設計成「兼容 argus-agent 與 Strix」，Argus 端不需改。
- 設定：`ARGUS_AGENT_SERVICE_URL`（空＝略過、不計費）／`ARGUS_AGENT_SERVICE_KEY`／`_TIMEOUT`。

結論：**不新增平行架構**，只補真正缺的一塊——一個講這條契約、底層跑 Strix 的 wrapper 服務。

## 做了什麼（Phase 0）
新增獨立服務 `services/strix-agent-service/`（FastAPI，自帶 Dockerfile，可獨立部署）：
- `app/contract.py`：契約 v1.0 Pydantic 模型（request/response/finding）。
- `app/config.py`：env 設定；`STRIX_STUB` 預設 true（零 LLM／零 Docker）。
- `app/target_guard.py`：目標深層防禦第二道（public HTTP、無 userinfo、標準埠、DNS 非私網）。
- `app/mapping.py`：Strix `vulnerabilities.json` 一筆 → 契約 Finding；evidence 服務端先遮罩。
- `app/stub_runner.py`：Phase 0 確定性假結果（尊重 mode／authorized 語義）。
- `app/real_runner.py`：Phase 1 真實包裝 `strix -n --target …` ＋解析 `strix_runs/<run>`。
- `app/main.py`：FastAPI、Bearer 驗證、目標再驗、任何引擎錯誤回契約 error（不中斷 Argus 掃描）。
- `tests/`：19 passed（target_guard／mapping／scan 端點 stub）。
- `Dockerfile`／`requirements*.txt`／`.env.example`／`README.md`。

接線（不改 Argus 程式）：
- `docker-compose.strix.yml` override（profile `strix`）：跑服務，並把 worker 的
  `ARGUS_AGENT_SERVICE_URL` 指向 `http://strix-agent-service:8099`。
- docker.sock 只在 Phase 1 掛給本服務，**不掛 worker**（危險能力關在拆開的服務邊界內）。

## 驗證
- `pytest -q` → 19 passed。
- 實際 `uvicorn` 起服務 + curl：`/healthz` OK、無金鑰 `/scan` 回 401、帶金鑰回契約 findings
  （欄位與 `agent_client._persist_finding` 預期一致：category/severity/title/.../cwe_id/owasp_category）。
- `docker compose -f docker-compose.yml -f docker-compose.strix.yml --profile strix config` → VALID。

## 安全
- `authorized=false` → 服務把 Strix instruction 收斂為「只做被動偵察、不送攻擊 payload」。
- `test_auth_*` 只進 `--instruction`，不落 log／回應／報告。
- evidence 回傳前遮罩憑證／email／長 token。
- 仍受 Argus 既有閘門：deep 需 active＋authorized＋deep_agent_requested；本服務對 authorized 二次收斂。

## 下一步（Phase 1）
- `services/strix-agent-service/Dockerfile` 解除 `strix-agent` 安裝、設 `STRIX_STUB=false`。
- 部署時掛 docker.sock、提供 `STRIX_LLM`／`LLM_API_KEY`（只給本服務）。
- 先對自架 Juice Shop（`docker-compose.juice.yml`，`STRIX_ALLOW_PRIVATE_TARGETS=true`）end-to-end。
- 用真實 `vulnerabilities.json` 樣本補 `real_runner` 的解析測試。
