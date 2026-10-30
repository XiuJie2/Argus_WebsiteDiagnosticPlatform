# 部署 strix-agent-service（內網 + 選擇性經 Cloudflare Tunnel 公開）

## 拓樸

```
argus worker ──(docker 網路, 內網)──▶ strix-agent-service:8099   ← 正式連線走這條
                                          │ 同機發佈 127.0.0.1:8099
Cloudflare ──Tunnel──▶ nginx ──▶ http://127.0.0.1:8099           ← 選擇性公開
  (https://strix.clouda.dpdns.org)
```

**重點**：argus 連 Strix 不必走 Cloudflare。worker 透過 docker 服務名
`http://strix-agent-service:8099` 直接連，最快、攻擊面最小。公開只是額外選項。

## A. 起服務（先 stub，零成本驗證）

```bash
# 專案根目錄；先設一把金鑰（公開時必設）
export ARGUS_AGENT_SERVICE_KEY="$(openssl rand -hex 24)"
docker compose -f docker-compose.yml -f docker-compose.strix.yml --profile strix up -d --build

# 本機健康檢查
curl -s http://127.0.0.1:8099/healthz
```

`docker-compose.strix.yml` 會：
- 跑 `strix-agent-service`，發佈 `127.0.0.1:8099`（只綁 loopback）。
- 把 argus worker 的 `ARGUS_AGENT_SERVICE_URL` 指向 `http://strix-agent-service:8099`（內網）。

## B.（選擇性）經 Cloudflare Tunnel 公開

1. 複製 nginx server block：
   ```bash
   sudo mkdir -p /var/log/nginx/clouda.dpdns.org/strix
   sudo cp services/strix-agent-service/deploy/nginx-strix.clouda.dpdns.org.conf \
           /etc/nginx/sites-available/strix.clouda.dpdns.org.conf
   sudo ln -s /etc/nginx/sites-available/strix.clouda.dpdns.org.conf /etc/nginx/sites-enabled/
   sudo nginx -t && sudo systemctl reload nginx
   ```
2. Cloudflare Tunnel 把 `strix.clouda.dpdns.org` 指到這台 nginx（與 argus 同一條 tunnel 即可）。
3. 驗證：`curl -s https://strix.clouda.dpdns.org/healthz` 應回 `{"ok": true, ...}`。

### 公開的硬性要求
- **一定要設 `ARGUS_AGENT_SERVICE_KEY`**：沒設的話 `/scan`、`/v1/scans` 無需授權就能觸發
  真實滲透掃描與 LLM 花費。設了之後服務對每個請求要求 `Authorization: Bearer <key>`。
- **`STRIX_ALLOW_PRIVATE_TARGETS` 維持 `false`**：避免被誘導去打內網（SSRF）。
- 建議再加一層 **Cloudflare Access（Zero Trust）**，只放行你自己的身分。

## C. argus 後台指到它

`/admin/agent-service`（超級管理員）：
- 協定：**非同步**（公開走 async；同步的長連線容易撞 Cloudflare 逾時）。
- 服務位址：
  - 內網（建議）：`http://strix-agent-service:8099`，TLS 驗證關（純內網 HTTP）。
  - 公開：`https://strix.clouda.dpdns.org`，TLS 驗證開（Cloudflare 憑證）。
- API 金鑰：填 `ARGUS_AGENT_SERVICE_KEY` 那把。
- 啟用打勾、儲存。

## D. 換上真引擎（會花 MiniMax 的錢）

1. 編 `services/strix-agent-service/Dockerfile`：解除 `strix-agent` 安裝那行。
2. `docker-compose.strix.yml`：設 `STRIX_STUB=false`、解除 `docker.sock` 掛載、
   提供 `STRIX_LLM` / `LLM_API_KEY`（只給本服務）。
3. ⚠ MiniMax 下 `--max-budget` 無效，成本靠 `STRIX_MAX_TURNS`（預設 25）控制。
4. `docker compose ... up -d --build` 重建。

## 注意
- run 狀態存**單 process 記憶體**：服務以單一 uvicorn worker 跑（預設即是）。
  要多 worker / 多副本得改接 Redis 或 sqlite 共享存放。

---

## E. pip 版引擎 + 讓 --max-budget 生效（2026-10-30）

獨立執行檔的 litellm 不認得 MiniMax 的價格 → 成本恆 0 → `--max-budget` 失效，
掃描會一路燒到時間上限或把額度用爆。改用 pip 版 strix + 啟動器解決：

```bash
# 1) 建 pip 引擎 venv（與獨立執行檔同版本）
uv venv /root/.strix-engine-venv
VIRTUAL_ENV=/root/.strix-engine-venv uv pip install "strix-agent==1.7.0"
# 2) 放啟動器（註冊 MiniMax 合成定價後再跑 strix）
install -D -m755 services/strix-agent-service/deploy/strix-engine-launch.py /root/strix-engine/launch.py
# 3) 服務 .env 設 STRIX_BIN=/root/strix-engine/launch.py、STRIX_MAX_BUDGET_USD、STRIX_PRICE_PER_MTOKEN
sudo systemctl restart strix-agent-service
```

效果（實測）：budget=$8 時，token 爬到約 800 萬，strix 自己發
「Token budget exceeded / scan budget limit」、各子代理在 budget reserve 停、整場乾淨收尾
——**是 strix 自己停、不是 argus 砍**。budget 是成本/完整度旋鈕；quick 比 deep 省很多。
