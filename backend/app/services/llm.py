"""OpenAI-compatible chat client (Ollama, LM Studio, vLLM, …).

Point ``AI_ENDPOINT`` at a server you run. If it points at a hosted API, leak
content leaves your infrastructure — nothing in the code can stop that, so
that variable is the one to watch.
"""

import re

import httpx

from ..config import settings
from .breaker import ai_breaker

_THINK_RE = re.compile(r"<think>(.*?)</think>|<\|think\|>(.*?)<\|/think\|>", re.S)


class AIUnavailable(Exception):
    pass


def _headers() -> dict:
    return {"Authorization": f"Bearer {settings.AI_API_KEY}"} if settings.AI_API_KEY else {}


async def chat(messages: list[dict], *, tools: list[dict] | None = None, temperature: float = 0.1) -> dict:
    """One non-streaming completion. Returns the assistant ``message`` dict."""
    if not settings.ai_enabled:
        raise AIUnavailable("AI_ENDPOINT is not configured")
    payload = {"model": settings.AI_MODEL, "messages": messages, "temperature": temperature}
    if tools:
        payload["tools"] = tools
        payload["tool_choice"] = "auto"

    async def _do():
        async with httpx.AsyncClient(timeout=settings.AI_TIMEOUT_SECONDS) as client:
            resp = await client.post(f"{settings.AI_ENDPOINT.rstrip('/')}/chat/completions", json=payload, headers=_headers())
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]

    try:
        return await ai_breaker.call(_do)
    except Exception as exc:
        raise AIUnavailable(str(exc)) from exc


def split_thinking(content: str) -> tuple[str, str]:
    m = _THINK_RE.search(content or "")
    if not m:
        return "", (content or "").strip()
    thought = (m.group(1) or m.group(2) or "").strip()
    return thought, content.replace(m.group(0), "").strip()


async def health() -> dict:
    if not settings.ai_enabled:
        return {"status": "disabled", "endpoint": None, "active_model": settings.AI_MODEL, "available_models": []}
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{settings.AI_ENDPOINT.rstrip('/')}/models", headers=_headers())
            resp.raise_for_status()
            models = [m.get("id") for m in resp.json().get("data", [])]
        return {"status": "online", "endpoint": settings.AI_ENDPOINT, "active_model": settings.AI_MODEL, "available_models": models}
    except Exception:
        return {"status": "offline", "endpoint": settings.AI_ENDPOINT, "active_model": settings.AI_MODEL, "available_models": []}
