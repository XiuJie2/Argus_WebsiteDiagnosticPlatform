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
import subprocess
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
    return " ".join(parts)


def _strix_command(req: ScanRequest, run_name: str) -> list[str]:
    scan_mode = _MODE_TO_STRIX.get(req.mode, settings.strix_scan_mode)
    cmd = [
        settings.strix_bin,
        "-n",  # headless，必用
        "--target", req.url,
        "--scan-mode", scan_mode,
        "--max-budget", str(settings.max_budget_usd),
        "--max-turns", str(settings.max_turns),
        "-r", run_name,
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


def run_strix(req: ScanRequest) -> ScanResponse:
    """同步跑一次 Strix headless，解析產出並回契約回應。"""
    run_name = f"argus-{uuid.uuid4().hex[:12]}"
    run_dir = Path(settings.runs_dir) / run_name
    cmd = _strix_command(req, run_name)

    secrets = [s for s in (req.test_auth_email, req.test_auth_password) if s]

    try:
        proc = subprocess.run(  # noqa: S603 — 參數化、無 shell
            cmd,
            capture_output=True,
            text=True,
            timeout=settings.run_timeout_s,
            check=False,
        )
        exit_code = proc.returncode
        timed_out = False
    except subprocess.TimeoutExpired:
        exit_code = None
        timed_out = True

    # 退出碼：0 clean / 2 found vulnerabilities / 1 fatal。逾時＝partial。
    vulns = _load_json(run_dir / "vulnerabilities.json", default=[])
    run_record = _load_json(run_dir / "run.json", default={})

    findings = []
    for item in vulns if isinstance(vulns, list) else []:
        if isinstance(item, dict):
            findings.append(strix_vuln_to_finding(item, secrets=secrets))

    if timed_out:
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
    if not summary:
        summary = f"Strix run {run_name}: {len(findings)} findings, status={status}."

    return ScanResponse(
        status=status,
        steps=int((run_record or {}).get("turns") or 0),
        total_tokens=0,
        summary=summary,
        error="" if status != "error" else f"strix exit_code={exit_code}",
        findings=findings,
        cost_usd=cost,
        engine="strix",
    )
