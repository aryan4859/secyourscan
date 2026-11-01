FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_DEFAULT_TIMEOUT=120 PIP_RETRIES=10

WORKDIR /srv
COPY requirements.txt .
# Optional pre-downloaded wheels (backend/wheels/, git-ignored) for hosts where
# Docker's network is slow; when the folder has none, pip uses PyPI as normal.
COPY wheels/ /tmp/wheels/
# Cache mount: a rerun after a network failure reuses what was already downloaded.
RUN --mount=type=cache,target=/root/.cache/pip \
    if ls /tmp/wheels/*.whl >/dev/null 2>&1; then \
      pip install --no-index --find-links /tmp/wheels -r requirements.txt; \
    else \
      pip install -r requirements.txt; \
    fi && rm -rf /tmp/wheels

COPY app ./app
COPY mcp_server.py .

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app
USER 10001

EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
  CMD python -c "import urllib.request,json,sys; sys.exit(0 if json.load(urllib.request.urlopen('http://127.0.0.1:8000/system/status'))['status']=='operational' else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
