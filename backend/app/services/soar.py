"""Outbound alert webhook for SIEM / SOAR.

Fires when a leak scores at or above ``SOAR_THRESHOLD`` (default 90), or when
it touches a VIP — then below the threshold, tagged ``[VIP]``. The payload is
SecYourScan's own JSON shape; it is not STIX. Secrets in it are masked.
"""

import logging

import httpx

from ..config import settings

logger = logging.getLogger("secyourscan.soar")


def build_payload(leak, *, vip: bool) -> dict:
    return {
        "alert_type": "VIP_EXPOSURE" if vip else "CRITICAL_EXPOSURE",
        "tag": "[VIP]" if vip else None,
        "leak": {
            "id": leak.id,
            "tenant_id": leak.tenant_id,
            "source": leak.source,
            "source_url": leak.source_url,
            "title": leak.title,
            "severity": leak.severity,
            "category": leak.category,
            "sha256": leak.sha256,
            "discovered_at": leak.discovered_at.isoformat(),
            "watch_matches": leak.watch_matches,
            "yara_rules": [m["rule"] for m in leak.yara_matches or []],
            "emails": (leak.entities or {}).get("emails", [])[:50],
            "credential_count": (leak.entities or {}).get("credential_count", 0),
        },
    }


async def fire(leak, *, vip: bool) -> bool:
    if not settings.SOAR_WEBHOOK_URL:
        return False
    try:
        async with httpx.AsyncClient(timeout=3.0) as c:
            r = await c.post(settings.SOAR_WEBHOOK_URL, json=build_payload(leak, vip=vip))
            r.raise_for_status()
        return True
    except Exception as exc:
        logger.error("SOAR webhook failed: %s", exc)
        return False
