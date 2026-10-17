# 修 ZAP API 回 HTTP 502（api.addrs 缺索引）

**日期**：2026-10-18
**操作者**：Claude
**來源**：使用者實機掃描 zap_active 失敗——`ZAP API core/version 回應 HTTP 502`；提供 ZAP pod log。

## 決定性證據
ZAP pod log 出現：
```
[ZAP-PassiveScan-1] WARN  PassiveScanTask - ... took 21 seconds to scan
http://zap.argus-zap.svc.cluster.local:8090/JSON/core/view/version/
```
ZAP **被動掃描了它自己的 version URL**——代表 worker 送的 `GET /JSON/core/view/version/` 被 ZAP
當成「要轉發／掃描的流量」，不是「呼叫自己的 API」。

## 根因
`api.addrs` 是清單，ZAP 的 `-config` 必須帶索引：`api.addrs.addr(0).name`／`api.addrs.addr(0).regex`。
`12-zap-passive.yaml`（與 `docker-compose.yml`）原本寫成**沒有索引**的 `api.addrs.addr.name=.*`，
ZAP 不會註冊這條，預設只認 `localhost`／`127.0.0.1`。worker 以服務 FQDN
`zap.argus-zap.svc.cluster.local` 連進來，Host 不在自身位址集合內 → ZAP 走 forward-proxy 路徑把請求
轉發出去 → 失敗回 502，且被 passive 規則掃到（log 印出）。先前懷疑的 Host/proxy 判讀問題獲 log 證實，
而真正的開關是這個缺了 `(0)` 的設定鍵。

## 修法（只動設定，不碰程式與 image）
- `k8s/12-zap-passive.yaml`：`api.addrs.addr(0).name=.*` ＋ `api.addrs.addr(0).regex=true`。
- `docker-compose.yml` zap service：同步改成帶索引。
- `tests/test_zap_contract.py`：K8s 與 compose 兩處各加斷言鎖定帶索引格式（回歸防線）。
- `docs/zap-passive.md`：新增「疑難排解：ZAP API 回 HTTP 502」一節。

只改 `k8s/**` 不觸發 image build，但 Deployment 的啟動參數變了，Argo 同步時 ZAP Pod 會重建並讀到正確
設定。部署後對已授權的全站主動掃描重跑，`zap_active` 應不再 502。

## 驗證
- `tests/test_zap_contract.py` 7 項通過（含新斷言）。
- 實機驗證待使用者部署後重掃（容器內無法連叢集）。

## 備註
不含真實站名／路徑／機密值；ZAP API key 仍只在叢集 Secret，未進 Git。
