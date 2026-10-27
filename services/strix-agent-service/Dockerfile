# Strix agent 服務。
# Phase 0（STRIX_STUB=true，預設）：只需 FastAPI，不裝 Strix、不碰 Docker。
# Phase 1（STRIX_STUB=false）：解除下方 strix-agent 安裝，並在部署時掛 docker.sock
#   與提供 STRIX_LLM / LLM_API_KEY（這些是本服務的部署需求，不是 Argus 的）。
FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    STRIX_STUB=true

WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- Phase 1：真實引擎（預設不裝，保持 image 輕量且無需 Docker） ---
# RUN pip install --no-cache-dir "strix-agent>=1.7,<2"
# Strix real mode 另需 host docker socket（部署時 -v /var/run/docker.sock:/var/run/docker.sock）
# 與 STRIX_LLM / LLM_API_KEY 環境變數。

COPY app ./app

EXPOSE 8099

# 非 root 執行。
RUN useradd --uid 65532 --create-home strix
USER 65532:65532

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8099"]
