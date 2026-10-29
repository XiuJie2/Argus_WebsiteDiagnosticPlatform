"""服務設定（全部走環境變數，比照 Argus 的 .env 慣例）。

部署需求（見契約文件末節）：Strix 需要 Docker 與 ``STRIX_LLM`` / ``LLM_API_KEY``。
這些是本 wrapper 服務的部署需求，**不是** Argus 的——Argus 永遠拿不到 LLM 金鑰。
"""
from __future__ import annotations

import os
from dataclasses import dataclass


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    # Phase 0：stub 模式回確定性假結果，零 LLM／零 Docker／零真實攻擊流量。
    # 預設開啟，接線驗證完再把 STRIX_STUB=false 換上真引擎。
    stub: bool = _bool("STRIX_STUB", True)

    # Argus → 本服務的 Bearer 金鑰（對應 ARGUS_AGENT_SERVICE_KEY）。
    # 設定後，/scan 一律要求相符的 Authorization header。
    api_key: str = os.getenv("STRIX_SERVICE_API_KEY", "").strip()

    # Strix headless 設定（真實模式用）。
    strix_bin: str = os.getenv("STRIX_BIN", "strix").strip()
    strix_scan_mode: str = os.getenv("STRIX_SCAN_MODE", "quick").strip()  # quick|standard|deep
    # ⚠ 成本上限（USD）：**只對 Strix 內建 pricing 表認得的 model 有效**。
    # 實測 MiniMax API → Strix 回報 cost=0、providers=[]，--max-budget 完全不生效
    # （一次 quick 掃描 10 分鐘燒了 1,276 萬 tokens 都沒被攔）。接 MiniMax／任何
    # Strix 不認得的 provider 時，真正的硬煞車是下面的 max_turns，不是這個。
    max_budget_usd: float = float(os.getenv("STRIX_MAX_BUDGET_USD", "10"))
    # 回合數硬上限＝對所有 provider 都有效的成本煞車（agent 每回合會重送成長中的 context，
    # input token 是成本主因）。預設壓低到 25；要更深再逐步放大並盯 run.json 的 total_tokens。
    max_turns: int = int(os.getenv("STRIX_MAX_TURNS", "25"))
    # 單次 strix 執行的 wall-clock 上限（秒）；需 < Argus 的 ARGUS_AGENT_SERVICE_TIMEOUT。
    run_timeout_s: int = int(os.getenv("STRIX_RUN_TIMEOUT", "1500"))
    # strix_runs 產出的根目錄（容器內）。
    runs_dir: str = os.getenv("STRIX_RUNS_DIR", "/work/strix_runs").strip()

    # 深層防禦：即使 Argus 已驗過目標，本服務仍自己再驗一次。
    # 允許打私網目標（僅限隔離 demo，如掃自架 Juice Shop）；生產一律 false。
    allow_private_targets: bool = _bool("STRIX_ALLOW_PRIVATE_TARGETS", False)

    # ── 成本優化旋鈕（2026-10-29）───────────────────────────────────────────
    # 背景：standard 模式會開 ~45 個平行子代理，Strix 沒有「限制 agent 數量」的旗標，
    # 所以「比 quick 深」必然更多 agent、更多 token。實測 standard 一次燒 1.148 億 token，
    # 其中 input:output ≈ 370:1 —— 絕大多數是「重送 context」：被 streaming 重試放大、
    # 加上 MiniMax M3 是思考型模型、reasoning_effort=high 每次呼叫吐超多 reasoning token。
    # 這三個 env 直接打在根因上（strix 子程序會繼承本服務的環境變數）：
    #   - LLM_DISABLE_STREAMING：關掉 streaming，消掉「streamed request 重試重送全部 context」
    #     那類浪費（實測 40 分鐘內 272 次重試）。
    #   - STRIX_REASONING_EFFORT：high→medium，思考型模型每次呼叫的 token 大降。
    #   - STRIX_PROMPT_CACHE：維持開啟（Strix 預設即 true），重複 context 走快取。
    reasoning_effort: str = os.getenv("STRIX_REASONING_EFFORT", "medium").strip()
    disable_streaming: bool = _bool("LLM_DISABLE_STREAMING", True)
    prompt_cache: bool = _bool("STRIX_PROMPT_CACHE", True)


settings = Settings()
