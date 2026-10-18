"""CTI enrichment: wallet balances (keyless, mempool.space), IP reputation
(ThreatFox, needs THREATFOX_AUTH_KEY) and host exposure (Shodan InternetDB,
keyless). Every call is best-effort with a short timeout; enrichment never
fails the pipeline."""

import logging

import httpx

from ..config import settings

logger = logging.getLogger("secyourscan.cti")
_TIMEOUT = httpx.Timeout(6.0)


async def btc_balance(address: str) -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.get(f"https://mempool.space/api/address/{address}")
            r.raise_for_status()
            stats = r.json().get("chain_stats", {})
        return {
            "address": address,
            "balance_sats": stats.get("funded_txo_sum", 0) - stats.get("spent_txo_sum", 0),
            "tx_count": stats.get("tx_count", 0),
            "source": "mempool.space",
        }
    except Exception as exc:
        logger.info("BTC enrichment failed for %s: %s", address, exc)
        return None


async def threatfox_ioc(ip: str) -> dict | None:
    if not settings.THREATFOX_AUTH_KEY:
        return None
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": ip},
                headers={"Auth-Key": settings.THREATFOX_AUTH_KEY},
            )
            r.raise_for_status()
            data = r.json()
        if data.get("query_status") != "ok":
            return {"ip": ip, "found": False}
        iocs = data.get("data") or []
        return {
            "ip": ip,
            "found": True,
            "malware": sorted({i.get("malware_printable") for i in iocs if i.get("malware_printable")}),
            "threat_types": sorted({i.get("threat_type") for i in iocs if i.get("threat_type")}),
            "confidence": max((i.get("confidence_level") or 0 for i in iocs), default=0),
        }
    except Exception as exc:
        logger.info("ThreatFox enrichment failed for %s: %s", ip, exc)
        return None


async def shodan_internetdb(ip: str) -> dict:
    """Open ports, CPEs, tags and known CVEs for an IP. Keyless."""
    async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
        r = await c.get(f"https://internetdb.shodan.io/{ip}")
        if r.status_code == 404:
            return {"ip": ip, "found": False}
        r.raise_for_status()
        return {"found": True, **r.json()}


async def enrich(entities: dict) -> dict:
    out: dict = {}
    if entities.get("btc_wallets"):
        if bal := await btc_balance(entities["btc_wallets"][0]):
            out["btc"] = bal
    if entities.get("ips"):
        if tf := await threatfox_ioc(entities["ips"][0]):
            out["threatfox"] = tf
    return out
