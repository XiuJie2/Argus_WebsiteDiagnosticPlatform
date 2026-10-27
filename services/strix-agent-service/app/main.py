"""Strix agent 服務：對 Argus 實作 agent-service HTTP 契約 v1.0。

啟動：``uvicorn app.main:app --host 0.0.0.0 --port 8099``
Argus 端設定 ``ARGUS_AGENT_SERVICE_URL=http://strix-agent-service:8099``。
"""
from __future__ import annotations

import logging

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse

from .config import settings
from .contract import CONTRACT_VERSION, ScanRequest, ScanResponse
from .target_guard import TargetRejected, assert_scannable

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("strix-agent-service")

app = FastAPI(title="Strix Agent Service", version=CONTRACT_VERSION)


def _check_auth(authorization: str | None) -> None:
    """設定了 STRIX_SERVICE_API_KEY 時，要求相符的 Bearer。"""
    if not settings.api_key:
        return
    expected = f"Bearer {settings.api_key}"
    if authorization != expected:
        raise HTTPException(status_code=401, detail="unauthorized")


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True, "contract_version": CONTRACT_VERSION, "stub": settings.stub}


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
