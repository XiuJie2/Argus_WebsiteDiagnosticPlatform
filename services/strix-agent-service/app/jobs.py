"""背景執行：把一個 Run 跑起來，邊跑邊寫 trace 事件、結束寫 findings。

- stub 模式：發幾個擬真 trace 事件（偵察→專家→回報），約 3 秒走完，產生示範 findings。
  讓 argus 的「下單→輪詢→即時進度→取結果」整條非同步路徑可被測，零 LLM／零真實流量。
- real 模式：在背景執行緒跑既有的同步 `run_strix`，並 tail 該 run 的 strix.log，
  把「Starting turn N, current_agent=X」這類行轉成 trace 事件（agent 在做什麼的即時來源）。
"""
from __future__ import annotations

import re
import threading
import time
from pathlib import Path

from .config import settings
from .contract import ScanRequest
from .runstore import Run

# strix.log 內「開始第 N 回合、目前 agent=X」的行，拿來當即時 trace。
_TURN_RE = re.compile(r"Starting turn (\d+).*?current_agent=(.+?)\s*$")


def start_run(run: Run) -> None:
    """spawn 一個 daemon thread 跑這個 run。"""
    t = threading.Thread(target=_execute, args=(run,), daemon=True)
    t.start()


def _execute(run: Run) -> None:
    run.status = "running"
    run.phase = "starting"
    run.started_at = time.time()
    try:
        req = ScanRequest(**run.request)
        if settings.stub:
            _run_stub(run, req)
        else:
            _run_real(run, req)
    except Exception as exc:  # noqa: BLE001 — 任何錯誤都落成 run 的 error，不讓執行緒炸掉
        run.status = "failed"
        run.error = type(exc).__name__
        run.add_event("error", f"engine error: {type(exc).__name__}")
    finally:
        if not run.is_terminal:
            run.status = "succeeded"
        run.phase = "done"
        run.ended_at = time.time()


def _run_stub(run: Run, req: ScanRequest) -> None:
    from .stub_runner import run_stub

    steps = [
        ("phase", "偵察目標與端點探索", ""),
        ("agent", "對應認證與 API 介面", "Auth & API Mapper"),
        ("tool", "送出受控測試請求", "Injection Specialist"),
        ("agent", "彙整與驗證發現", "Orchestrator"),
    ]
    for i, (kind, msg, agent) in enumerate(steps, start=1):
        if run.cancel_event.is_set():
            run.status = "cancelled"
            run.add_event("info", "已取消")
            return
        run.phase = msg
        run.steps = i
        run.add_event(kind, msg, agent)
        # 讓呼叫端有機會輪詢到中間狀態。
        time.sleep(0.5)

    resp = run_stub(req)
    run.findings = [f.model_dump() for f in resp.findings]
    run.summary = resp.summary
    run.total_tokens = resp.total_tokens
    run.cost_usd = resp.cost_usd
    run.status = resp.status if resp.status in {"succeeded", "partial", "failed"} else "succeeded"
    if run.status == "succeeded" and resp.status == "completed":
        run.status = "succeeded"
    run.add_event("info", f"完成，{len(run.findings)} 筆發現")


def _run_real(run: Run, req: ScanRequest) -> None:
    """real：背景跑 run_strix，同時 tail strix.log 轉 trace。"""
    from . import real_runner

    result_box: dict[str, object] = {}

    def _worker() -> None:
        try:
            scan_cwd = Path(settings.runs_dir) / f"argus-{run.scan_id[:12]}"
            scan_cwd.mkdir(parents=True, exist_ok=True)
            run.request["_scan_cwd"] = str(scan_cwd)  # 供 tail 定位
            result_box["resp"] = real_runner.run_strix(req, scan_cwd=scan_cwd,
                                                        cancel_event=run.cancel_event)
        except Exception as exc:  # noqa: BLE001
            result_box["error"] = exc

    worker = threading.Thread(target=_worker, daemon=True)
    worker.start()

    last_turn = 0
    while worker.is_alive():
        if run.cancel_event.is_set():
            run.add_event("info", "收到取消請求")
        last_turn = _tail_strix_log(run, last_turn)
        time.sleep(1.0)
    worker.join(timeout=5)
    _tail_strix_log(run, last_turn)

    if "error" in result_box:
        run.status = "failed"
        run.error = type(result_box["error"]).__name__
        return
    resp = result_box.get("resp")
    if resp is None:
        run.status = "failed"
        run.error = "no_result"
        return
    run.findings = [f.model_dump() for f in resp.findings]  # type: ignore[attr-defined]
    run.summary = resp.summary  # type: ignore[attr-defined]
    run.cost_usd = resp.cost_usd  # type: ignore[attr-defined]
    run.steps = resp.steps  # type: ignore[attr-defined]
    mapping = {"completed": "succeeded", "partial": "partial", "error": "failed"}
    run.status = "cancelled" if run.cancel_event.is_set() else mapping.get(resp.status, "succeeded")  # type: ignore[attr-defined]
    run.add_event("info", f"完成，{len(run.findings)} 筆發現")


def _tail_strix_log(run: Run, last_turn: int) -> int:
    """讀 strix.log 的回合行，發新回合的 trace 事件。回傳目前最後回合數。"""
    scan_cwd = run.request.get("_scan_cwd")
    if not scan_cwd:
        return last_turn
    runs_root = Path(scan_cwd) / "strix_runs"
    if not runs_root.is_dir():
        return last_turn
    logs = list(runs_root.glob("*/strix.log"))
    if not logs:
        return last_turn
    try:
        text = logs[0].read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return last_turn
    newest = last_turn
    for m in _TURN_RE.finditer(text):
        turn = int(m.group(1))
        if turn > last_turn:
            agent = m.group(2).strip()
            run.steps = turn
            run.phase = f"第 {turn} 回合：{agent}"
            run.add_event("agent", f"第 {turn} 回合", agent=agent)
            newest = max(newest, turn)
    return newest
