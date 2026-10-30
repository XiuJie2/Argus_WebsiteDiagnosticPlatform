#!/root/.strix-engine-venv/bin/python
"""Strix 啟動器：先把 MiniMax 的合成每 token 價格註冊進 litellm，再啟動 strix。

這樣 --max-budget 會即時生效：strix 以 litellm 估成本、達到上限時自己發 wrap-up、
乾淨收尾（不是靠外部砍）。合成價 $1 / 1M token（可用 STRIX_PRICE_PER_MTOKEN 調），
所以 --max-budget 的美元值 ≈ 百萬 token 數。放在啟動器（而非 sitecustomize）是因為
litellm 會在匯入後才載入並可能重置 model_cost；這裡在真正啟動 strix 前一刻才覆寫。
"""
import os
import sys


def _register_pricing() -> None:
    try:
        import litellm
    except Exception:
        return
    _ = litellm.model_cost  # 觸發載入
    pt = float(os.environ.get("STRIX_PRICE_PER_MTOKEN", "1.0")) / 1_000_000.0
    names = {m.strip() for m in os.environ.get(
        "STRIX_PRICE_MODELS",
        "MiniMax-M3.1-Flash,MiniMax-M3,MiniMax-M2.7,MiniMax-Text-01",
    ).split(",") if m.strip()}
    price = {"input_cost_per_token": pt, "output_cost_per_token": pt,
             "litellm_provider": "openai", "mode": "chat"}
    for k in list(litellm.model_cost):
        e = litellm.model_cost.get(k)
        if isinstance(e, dict) and k.split("/")[-1] in names:
            e["input_cost_per_token"] = pt
            e["output_cost_per_token"] = pt
    for n in names:
        for key in (n, f"openai/{n}"):
            litellm.model_cost[key] = dict(price)
    try:
        from strix.report.pricing import resolve_litellm_model
        for n in names:
            for v in (n, f"openai/{n}"):
                r = resolve_litellm_model(v)
                if r:
                    litellm.model_cost[r] = dict(price)
    except Exception:
        pass


_register_pricing()
from strix.interface.main import main  # noqa: E402

sys.exit(main())
