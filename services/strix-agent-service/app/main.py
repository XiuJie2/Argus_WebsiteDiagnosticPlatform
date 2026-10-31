"""Strix agent 服務：對 Argus 實作 agent-service HTTP 契約 v1.0。

啟動：``uvicorn app.main:app --host 0.0.0.0 --port 8099``
Argus 端設定 ``ARGUS_AGENT_SERVICE_URL=http://strix-agent-service:8099``。
"""
from __future__ import annotations

import hmac
import logging

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse

from .config import settings
from .contract import (
    CONTRACT_VERSION,
    CONTRACT_VERSION_ASYNC,
    Finding,
    MessageRequest,
    ScanRequest,
    ScanResponse,
    ScanResultResponse,
    ScanStartResponse,
    ScanStatusResponse,
    TraceEventModel,
    TraceResponse,
)
from .target_guard import TargetRejected, assert_scannable

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("strix-agent-service")

app = FastAPI(title="Strix Agent Service", version=CONTRACT_VERSION)


def _check_auth(authorization: str | None) -> None:
    """設定了 STRIX_SERVICE_API_KEY 時，要求相符的 Bearer（常數時間比較）。"""
    if not settings.api_key:
        return
    expected = f"Bearer {settings.api_key}"
    if not hmac.compare_digest(authorization or "", expected):
        raise HTTPException(status_code=401, detail="unauthorized")


@app.get("/healthz")
def healthz() -> dict:
    return {
        "ok": True,
        "contract_version": CONTRACT_VERSION,
        "contract_version_async": CONTRACT_VERSION_ASYNC,
        "protocols": ["sync", "async"],
        "stub": settings.stub,
    }


@app.get("/readyz")
def readyz() -> dict:
    # stub 永遠 ready；真實模式下可在此加 strix / docker 探測（Phase 1+）。
    return {"ready": True, "engine": "strix-stub" if settings.stub else "strix"}


@app.post("/scan", response_model=ScanResponse)
def scan(req: ScanRequest, authorization: str | None = Header(default=None)) -> ScanResponse:
    _check_auth(authorization)

    # 契約版本相容性檢查（主版本不同就拒）。
    if req.contract_version.split(".")[0] != CONTRACT_VERSION.split(".")[0]:
        raise HTTPException(status_code=400, detail="unsupported_contract_version")

    # 深層防禦：Argus 已驗過目標，本服務再驗一次。
    try:
        assert_scannable(req.url, allow_private=settings.allow_private_targets)
    except TargetRejected as exc:
        # 回 200 + status=error（契約：非致命問題用 status，不要用非 2xx）。
        logger.warning("target rejected: %s", exc)
        return ScanResponse(
            status="error",
            summary="target rejected by service-side policy",
            error=str(exc),
            engine="strix-stub" if settings.stub else "strix",
        )

    try:
        if settings.stub:
            from .stub_runner import run_stub

            return run_stub(req)
        from .real_runner import run_strix

        return run_strix(req)
    except Exception as exc:  # noqa: BLE001 — 任何引擎錯誤都回契約 error，不讓 Argus 掃描中斷
        logger.exception("scan failed")
        return ScanResponse(
            status="error",
            summary="engine error",
            error=type(exc).__name__,
            engine="strix-stub" if settings.stub else "strix",
        )


@app.exception_handler(Exception)
async def _unhandled(_request, exc: Exception) -> JSONResponse:  # pragma: no cover
    logger.exception("unhandled error")
    return JSONResponse(status_code=500, content={"status": "error", "error": type(exc).__name__})


# ---- 非同步 API v2（app.strix.ai 式）----

def _validate_and_guard(req: ScanRequest) -> str | None:
    """契約版本 + 目標驗證。通過回 None，否則回安全錯誤碼字串。"""
    major = req.contract_version.split(".")[0]
    if major not in {"1", "2"}:
        return "unsupported_contract_version"
    try:
        assert_scannable(req.url, allow_private=settings.allow_private_targets)
    except TargetRejected as exc:
        return str(exc)
    return None


@app.post("/v1/scans", response_model=ScanStartResponse, status_code=202)
def start_scan(req: ScanRequest, authorization: str | None = Header(default=None)) -> ScanStartResponse:
    """下單：立即返回 scan_id，掃描在背景執行。"""
    _check_auth(authorization)
    err = _validate_and_guard(req)
    if err:
        # 下單期就能判定的拒絕：直接 400，呼叫端不必再輪詢。
        raise HTTPException(status_code=400, detail=err)
    from .jobs import start_run
    from .runstore import store

    run = store.create(req.model_dump())
    start_run(run)
    return ScanStartResponse(scan_id=run.scan_id, status=run.status)


def _get_run_or_404(scan_id: str):
    from .runstore import store

    run = store.get(scan_id)
    if run is None:
        raise HTTPException(status_code=404, detail="scan_not_found")
    return run


@app.get("/v1/scans/{scan_id}", response_model=ScanStatusResponse)
def scan_status(scan_id: str, authorization: str | None = Header(default=None)) -> ScanStatusResponse:
    _check_auth(authorization)
    run = _get_run_or_404(scan_id)
    return ScanStatusResponse(
        scan_id=run.scan_id, status=run.status, phase=run.phase, steps=run.steps,
        cost_usd=run.cost_usd, total_tokens=run.total_tokens, error=run.error,
        engine="strix-stub" if settings.stub else "strix",
    )


@app.get("/v1/scans/{scan_id}/trace", response_model=TraceResponse)
def scan_trace(scan_id: str, after: int = 0,
               authorization: str | None = Header(default=None)) -> TraceResponse:
    """自 after 序號之後的即時事件（agent 在做什麼）。"""
    _check_auth(authorization)
    run = _get_run_or_404(scan_id)
    events = run.events_after(after)
    return TraceResponse(
        scan_id=run.scan_id,
        status=run.status,
        events=[TraceEventModel(seq=e.seq, ts=e.ts, kind=e.kind, message=e.message, agent=e.agent)
                for e in events],
        next=events[-1].seq if events else after,
    )


@app.get("/v1/scans/{scan_id}/result", response_model=ScanResultResponse)
def scan_result(scan_id: str, authorization: str | None = Header(default=None)) -> ScanResultResponse:
    """終端後取完整結果；未終端回 409（呼叫端應繼續輪詢）。"""
    _check_auth(authorization)
    run = _get_run_or_404(scan_id)
    if not run.is_terminal:
        raise HTTPException(status_code=409, detail="scan_not_finished")
    status_map = {"succeeded": "completed", "partial": "partial",
                  "failed": "error", "cancelled": "error"}
    return ScanResultResponse(
        scan_id=run.scan_id,
        status=status_map.get(run.status, "completed"),
        steps=run.steps, total_tokens=run.total_tokens, summary=run.summary, error=run.error,
        findings=[Finding(**f) for f in run.findings], cost_usd=run.cost_usd,
        engine="strix-stub" if settings.stub else "strix",
    )


@app.post("/v1/scans/{scan_id}/cancel", status_code=202)
def scan_cancel(scan_id: str, authorization: str | None = Header(default=None)) -> dict:
    """請求取消；背景執行緒在下個檢查點停下。"""
    _check_auth(authorization)
    run = _get_run_or_404(scan_id)
    run.cancel_event.set()
    run.add_event("info", "收到取消請求")
    return {"scan_id": run.scan_id, "status": run.status, "cancel_requested": True}


@app.post("/v1/scans/{scan_id}/message", status_code=202)
def scan_message(scan_id: str, body: MessageRequest,
                 authorization: str | None = Header(default=None)) -> dict:
    """掃描進行中對 agent 補充指令（記錄下來供引擎取用；stub 僅存不處理）。"""
    _check_auth(authorization)
    run = _get_run_or_404(scan_id)
    run.messages.append(body.message)
    run.add_event("info", "收到使用者留言")
    return {"scan_id": run.scan_id, "accepted": True}
