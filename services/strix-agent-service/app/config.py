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
    # 成本硬上限（USD）。Argus 不傳預算，由本服務統一 clamp，避免 LLM 成本失控。
    max_budget_usd: float = float(os.getenv("STRIX_MAX_BUDGET_USD", "10"))
    max_turns: int = int(os.getenv("STRIX_MAX_TURNS", "200"))
    # 單次 strix 執行的 wall-clock 上限（秒）；需 < Argus 的 ARGUS_AGENT_SERVICE_TIMEOUT。
    run_timeout_s: int = int(os.getenv("STRIX_RUN_TIMEOUT", "1500"))
    # strix_runs 產出的根目錄（容器內）。
    runs_dir: str = os.getenv("STRIX_RUNS_DIR", "/work/strix_runs").strip()

    # 深層防禦：即使 Argus 已驗過目標，本服務仍自己再驗一次。
    # 允許打私網目標（僅限隔離 demo，如掃自架 Juice Shop）；生產一律 false。
    allow_private_targets: bool = _bool("STRIX_ALLOW_PRIVATE_TARGETS", False)


settings = Settings()
