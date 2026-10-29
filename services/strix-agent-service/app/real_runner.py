"""Phase 1 真實 adapter：包住 ``strix -n --target <url>``、解析產出、回契約。

對應契約文件「Strix wrapper 對應備忘」：
- url            → ``--target <url>``
- authorized     → false 時收斂攻擊性（instruction 明確限制為被動偵察）
- submit_forms / test_auth_* → ``--instruction "...authenticated testing credentials..."``
- 回應 findings  → 解析 ``strix_runs/<run>/vulnerabilities.json``（＋ run.json 的 status／cost）
- status         → headless 退出碼／run.json 狀態 → completed／partial／error

Strix 的部署需求（Docker、STRIX_LLM／LLM_API_KEY）是本服務的事，不是 Argus 的。
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import time
import uuid
from pathlib import Path

from .config import settings
from .contract import ScanRequest, ScanResponse
from .mapping import strix_vuln_to_finding

logger = logging.getLogger("strix-agent-service.runner")

# Argus 契約 mode → Strix 掃描深度（可由 STRIX_SCAN_MODE 覆蓋基準）。
_MODE_TO_STRIX = {"deep": settings.strix_scan_mode, "both": settings.strix_scan_mode}


def _build_instruction(req: ScanRequest) -> str:
    parts: list[str] = []
    if not req.authorized:
        # authorized=false：Strix 偏主動，明確要求只做被動偵察、不送攻擊 payload。
        parts.append(
            "Authorization NOT granted: perform passive reconnaissance only. "
            "Do NOT send exploitation payloads or intrusive requests."
        )
    if req.test_auth_email and req.test_auth_password:
        # 帳密只進 instruction，不落 log（append_log 不印本字串）。
        parts.append(
            "Perform authenticated testing using credentials: "
            f"{req.test_auth_email}:{req.test_auth_password}"
        )
    if req.submit_forms:
        parts.append("Form submission is permitted.")
    else:
        parts.append("Do NOT submit forms; fill fields only.")
    if req.recon_intel:
        parts.append("Known endpoints to focus on: " + ", ".join(req.recon_intel[:50]))
    if req.known_findings:
        titles = [str(f.get("title") or "") for f in req.known_findings[:20]]
        parts.append(
            "These issues are already found by deterministic tools — do NOT re-report, "
            "focus on deeper/chained findings: " + "; ".join(t for t in titles if t)
        )
    if req.authorized:
        # Target-AGNOSTIC 類別級聚焦：只點「容易被有限回合漏掉的高影響漏洞類別」，
        # **不含任何特定路徑**，所以對每個目標都適用、不會過擬合。最後一句明確要求
        # 自行探索、不要假設路徑存在——這就是防止「對某站過度針對」的關鍵。
        parts.append(
            "In this time-bounded run, give extra priority to commonly-missed high-impact "
            "classes: unrestricted file upload / path traversal / arbitrary file write; "
            "default or weak credentials; IDOR and missing object- or function-level "
            "authorization on state-changing endpoints; and stored XSS in user-editable "
            "content fields. Do NOT assume any specific path or parameter exists — "
            "discover them for this target."
        )
    # 同站歷次掃描的資安發現：先驗證還在不在（回歸），再當線索往深/串接挖（跨掃描累積）。
    if req.prior_findings:
        lines = []
        for f in req.prior_findings[:40]:
            title = str(f.get("title") or "").strip()
            if not title:
                continue
            sev = str(f.get("severity") or "").strip()
            ep = str(f.get("endpoint") or "").strip()
            lines.append(f"[{sev}] {title}" + (f" @ {ep}" if ep else ""))
        if lines:
            parts.append(
                "Issues found on THIS target in earlier scans. First re-verify each is "
                "still present and exploitable (report which are now fixed); then use them "
                "as leads to find deeper, chained, or related vulnerabilities (e.g., the "
                "same authorization flaw on other endpoints, or privilege escalation built "
                "on an existing IDOR). Prior findings: " + "; ".join(lines)
            )
    # 操作者針對「這一次掃描」的自由聚焦（per-scan，預設空；放最後、權重最高）。
    # 由 Argus 的 scan.agent_focus 經契約帶入——不是全域設定，掃別的站留空即可。
    if req.instruction:
        parts.append("Operator focus for this scan: " + req.instruction.strip())
    return " ".join(parts)


def _strix_command(req: ScanRequest) -> list[str]:
    # strix 1.7 沒有「設定 run name」的旗標——`-r`/`--resume` 是續跑既有 run。
    # 新掃描一律由 strix 自動命名，輸出到執行時 CWD 下的 ./strix_runs/<auto>。
    # 本服務替每次掃描開一個乾淨 CWD，再從裡面挑出唯一那個 run dir。
    scan_mode = _MODE_TO_STRIX.get(req.mode, settings.strix_scan_mode)
    cmd = [
        settings.strix_bin,
        "-n",  # headless，必用
        "--target", req.url,
        "--scan-mode", scan_mode,
        "--max-budget", str(settings.max_budget_usd),
        "--max-turns", str(settings.max_turns),
    ]
    instruction = _build_instruction(req)
    if instruction:
        cmd += ["--instruction", instruction]
    return cmd


def _load_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _latest_run_dir(runs_root: Path) -> Path | None:
    """挑出 strix 自動命名的那個 run dir（取 run.json mtime 最新者）。"""
    if not runs_root.is_dir():
        return None
    candidates = [d for d in runs_root.iterdir() if (d / "run.json").is_file()]
    if not candidates:
        # 還沒寫 run.json 時退而取任何子目錄，讓解析仍能嘗試 vulnerabilities.json
        candidates = [d for d in runs_root.iterdir() if d.is_dir()]
    if not candidates:
        return None
    return max(candidates, key=lambda d: (d / "run.json").stat().st_mtime
               if (d / "run.json").is_file() else d.stat().st_mtime)


_PROVIDER_TROUBLE_MARKERS = (
    "persistent rate limit",
    "rate limit",
    "rate_limit",
    "429",
    "insufficient balance",
    "insufficient_quota",
    "quota",
    "too many requests",
)


def _detect_provider_trouble(run_dir: Path | None) -> str:
    """掃 strix.log 判斷本次是否被 LLM 供應商擋住（限流／餘額／配額）。

    回安全錯誤碼（不外洩細節）；沒有徵兆回空字串。只在「0 發現」時才會被用到，
    避免把正常掃描誤標成供應商問題。門檻：出現多次錯誤徵兆才算（單一偶發不算）。
    """
    if run_dir is None:
        return ""
    log = run_dir / "strix.log"
    try:
        text = log.read_text(encoding="utf-8", errors="ignore").lower()
    except OSError:
        return ""
    if "persistent rate limit" in text:
        return "llm_provider_rate_limited"
    hits = sum(text.count(m) for m in _PROVIDER_TROUBLE_MARKERS)
    # outcome=error 針對 LLM 請求的計數（strix.llm.request_log）
    hits += text.count("outcome=error")
    if hits >= 3:
        return "llm_provider_errors"
    return ""


def run_strix(req: ScanRequest, *, scan_cwd: Path | None = None,
              cancel_event=None) -> ScanResponse:
    """同步跑一次 Strix headless，解析產出並回契約回應。

    scan_cwd：指定執行目錄（非同步模式由 jobs 傳入，方便 tail strix.log）；None 則自建。
    cancel_event：threading.Event，設定時盡快終止 strix 子程序（非同步取消用）。
    """
    if scan_cwd is None:
        scan_cwd = Path(settings.runs_dir) / f"argus-{uuid.uuid4().hex[:12]}"
    scan_cwd.mkdir(parents=True, exist_ok=True)
    cmd = _strix_command(req)

    secrets = [s for s in (req.test_auth_email, req.test_auth_password) if s]

    exit_code: int | None = None
    timed_out = False
    cancelled = False
    deadline = time.monotonic() + settings.run_timeout_s
    # 成本優化旋鈕：明確打進子程序環境（不只靠繼承），讓這些設定可被測試、可被 .env 覆寫。
    # 見 config.py 的說明——直擊 standard 模式「重送 context」的 token 浪費根因。
    env = {
        **os.environ,
        "STRIX_REASONING_EFFORT": settings.reasoning_effort,
        "LLM_DISABLE_STREAMING": "true" if settings.disable_streaming else "false",
        "STRIX_PROMPT_CACHE": "true" if settings.prompt_cache else "false",
    }
    proc = subprocess.Popen(  # noqa: S603 — 參數化、無 shell
        cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=str(scan_cwd), env=env,
    )
    while True:
        try:
            exit_code = proc.wait(timeout=1.0)
            break
        except subprocess.TimeoutExpired:
            if cancel_event is not None and cancel_event.is_set():
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                cancelled = True
                break
            if time.monotonic() > deadline:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                timed_out = True
                break

    # 退出碼：0 clean / 2 found vulnerabilities / 1 fatal。逾時＝partial。
    run_dir = _latest_run_dir(scan_cwd / "strix_runs")
    vulns = _load_json(run_dir / "vulnerabilities.json", default=[]) if run_dir else []
    run_record = _load_json(run_dir / "run.json", default={}) if run_dir else {}

    findings = []
    for item in vulns if isinstance(vulns, list) else []:
        if isinstance(item, dict):
            findings.append(strix_vuln_to_finding(item, secrets=secrets))

    # 偵測「跑了但被 LLM 供應商擋住」：strix 可能 exit 0、卻因持續限流/餘額不足/供應商錯誤
    # 而 0 發現。這種「看起來完成、其實被外部掐死」要讓上層看得懂，不要只顯示「0 發現/執行失敗」。
    provider_trouble = _detect_provider_trouble(run_dir) if not findings else ""

    if cancelled:
        status = "error"
    elif provider_trouble and not findings:
        # 完成與否都一樣：沒有有效工作。標 error 讓 argus 顯示可讀原因。
        status = "error"
    elif timed_out:
        status = "partial"
    elif exit_code in (0, 2):
        status = "completed"
    else:
        status = "error"

    cost = 0.0
    usage = run_record.get("llm_usage") if isinstance(run_record, dict) else None
    if isinstance(usage, dict):
        try:
            cost = float(usage.get("cost") or 0.0)
        except (TypeError, ValueError):
            cost = 0.0

    summary = str((run_record or {}).get("summary") or "")[:1000]
    if provider_trouble and not findings:
        summary = (
            "AI 引擎未能完成：LLM 供應商持續回錯（限流或餘額/配額不足），本次 0 發現。"
            "請檢查 LLM 供應商的餘額與速率限制後重試。"
        )
    elif not summary:
        summary = f"Strix run: {len(findings)} findings, status={status}."

    error = ""
    if provider_trouble and not findings:
        error = provider_trouble  # 例：llm_provider_rate_limited
    elif status == "error":
        error = f"strix exit_code={exit_code}"

    return ScanResponse(
        status=status,
        steps=int((run_record or {}).get("turns") or 0),
        total_tokens=0,
        summary=summary,
        error=error,
        findings=findings,
        cost_usd=cost,
        engine="strix",
    )
