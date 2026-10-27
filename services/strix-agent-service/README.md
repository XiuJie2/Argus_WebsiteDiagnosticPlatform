# strix-agent-service

把開源 **Strix**（`usestrix/strix`，autonomous AI pentester，只有 CLI＋Docker）包成一個
**獨立服務**，對 Argus 實作 `docs/agent-service-contract.md` 的 HTTP 契約（v1.0）。

這就是「把 Strix 當 Argus 的主動滲透測試 AI agent、和 Argus 拆開」的落地——概念等同
自架一個 `app.strix.ai`：Argus 只透過 HTTP 下單，不碰 Docker、拿不到 LLM 金鑰。

```
Argus (apps/scans/agent_client.py)  ──POST /scan──▶  strix-agent-service  ──▶ strix -n --target …
        ARGUS_AGENT_SERVICE_URL                         (本服務)                 (Docker 沙箱)
```

## 為什麼要拆開

- **權限隔離**：Strix 需要 Docker（近 root）。危險能力關在本服務邊界，Argus worker 不碰 docker.sock。
- **成本隔離**：LLM 金鑰只在本服務；成本上限由本服務統一 clamp。
- **零改動接入**：Argus 端 `agent_client.py` 已是 backend-agnostic，只要指向本服務即可。

## 兩階段

| | STRIX_STUB | 行為 |
|---|---|---|
| **Phase 0** | `true`（預設） | 回確定性假結果，零 LLM／零 Docker／零真實攻擊流量。用來把 Argus↔服務接線、契約落地、計費閘門焊死並可測。 |
| **Phase 1** | `false` | 真的跑 `strix -n --target …`，解析 `strix_runs/<run>/vulnerabilities.json` 回契約。需 Docker ＋ `STRIX_LLM`／`LLM_API_KEY`。 |

## 本機跑（stub）

```bash
cd services/strix-agent-service
uv venv .venv && . .venv/bin/activate
uv pip install -r requirements-dev.txt
pytest -q                                   # 19 passed
STRIX_STUB=true STRIX_ALLOW_PRIVATE_TARGETS=true \
  uvicorn app.main:app --host 127.0.0.1 --port 8099
# curl -s -XPOST localhost:8099/scan -H 'Content-Type: application/json' \
#   -d '{"url":"https://example.com","mode":"both","authorized":true}'
```

## 跟 Argus 一起跑（docker compose）

```bash
# 專案根目錄
docker compose -f docker-compose.yml -f docker-compose.strix.yml --profile strix up -d --build
```

override 會把 worker 的 `ARGUS_AGENT_SERVICE_URL` 指向本服務。Argus 掃描走到 `stage_agent`
時就會呼叫這裡（deep 模式仍受 Argus 三重閘＋本服務對 `authorized` 二次收斂）。

## 契約摘要（完整見 `docs/agent-service-contract.md`）

- `POST /scan`：body `{url, mode(deep|ux|both), authorized, submit_forms, recon_intel,
  known_findings, test_auth_email, test_auth_password}`；回 `{status, findings[], summary, ...}`。
- `GET /healthz`、`GET /readyz`。
- 設 `STRIX_SERVICE_API_KEY` 時要求 `Authorization: Bearer <key>`（＝Argus 的 `ARGUS_AGENT_SERVICE_KEY`）。

## 檔案

| 檔案 | 職責 |
|---|---|
| `app/contract.py` | 契約 v1.0 的 Pydantic 模型 |
| `app/config.py` | 環境變數設定（stub 開關、金鑰、Strix 參數、預算上限） |
| `app/target_guard.py` | 目標 URL 深層防禦驗證（公網 HTTP、無 userinfo、標準埠、DNS 非私網） |
| `app/mapping.py` | Strix 漏洞 → 契約 Finding；evidence 服務端第一道遮罩 |
| `app/stub_runner.py` | Phase 0 假結果 |
| `app/real_runner.py` | Phase 1 真實 `strix` 包裝＋產出解析 |
| `app/main.py` | FastAPI app、Bearer 驗證、目標再驗、graceful error |

## 安全注意

- `authorized=false` 時本服務把 Strix 收斂為被動偵察（instruction 明確禁止攻擊 payload）。
- `test_auth_*` 只進 Strix `--instruction`，不落 log／回應／報告。
- evidence 回傳前先遮罩憑證／email／長 token。
- 目標即使 Argus 已驗，本服務仍自己再驗一次（防竄改打內網）。
