FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_DEFAULT_TIMEOUT=120 PIP_RETRIES=10

WORKDIR /srv
COPY requirements.txt .
# Cache mount: a rerun after a network failure reuses what was already downloaded.
RUN --mount=type=cache,target=/root/.cache/pip pip install -r requirements.txt

COPY app ./app
COPY mcp_server.py .

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app
USER 10001

EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
  CMD python -c "import urllib.request,json,sys; sys.exit(0 if json.load(urllib.request.urlopen('http://127.0.0.1:8000/system/status'))['status']=='operational' else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
