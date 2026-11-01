"""Are any of *our* hosts or IPs listed in public threat feeds?

abuse.ch publishes three feeds that matter for an organisation's own assets:
URLhaus (URLs serving malware — a compromised web server), Feodo Tracker
(botnet command-and-control IPs, keyless) and ThreatFox (recent IOCs of every
kind). URLhaus and ThreatFox need the free auth.abuse.ch key. Each feed is
downloaded once per scan and matched locally, so nothing about your assets is
sent to the feed operators.
"""

import logging
from urllib.parse import urlsplit

import httpx

from ..config import settings

logger = logging.getLogger("secyourscan.reputation")
UA = {"User-Agent": "SecYourScan/1.0 (+self-hosted exposure monitoring)"}


def _host(value: str) -> str:
    v = value.strip()
    try:
        return (urlsplit(v if "://" in v else f"http://{v}").hostname or "").lower()
    except ValueError:
        return ""


def _abusech_key() -> str | None:
    return settings.ABUSECH_AUTH_KEY or settings.THREATFOX_AUTH_KEY


def _api_ok(j: dict, feed: str) -> None:
    # "no_result" is a valid empty answer; anything else (unknown_auth_key, …) is a failure.
    if j.get("query_status") not in ("ok", "no_result", "no_results"):
        raise ValueError(f"{feed}: {j.get('query_status')}")


async def urlhaus() -> list[dict]:
    """Recent malware URLs. abuse.ch retired the open text export (410 Gone),
    so this uses the URLhaus API with the free auth.abuse.ch key."""
    key = _abusech_key()
    if not key:
        raise ValueError("urlhaus needs ABUSECH_AUTH_KEY (free at auth.abuse.ch)")
    async with httpx.AsyncClient(timeout=60, headers={**UA, "Auth-Key": key}) as c:
        r = await c.get(settings.URLHAUS_API_RECENT_URL)
        r.raise_for_status()
        j = r.json()
        _api_ok(j, "urlhaus")
        return [{"feed": "urlhaus", "indicator": u["url"], "host": (u.get("host") or _host(u["url"])).lower(),
                 "threat": u.get("threat") or "malware_download"}
                for u in j.get("urls") or [] if u.get("url")]


async def feodo() -> list[dict]:
    async with httpx.AsyncClient(timeout=60, headers=UA) as c:
        r = await c.get(settings.FEODO_URL)
        r.raise_for_status()
        return [{"feed": "feodo", "indicator": e["ip_address"], "host": e["ip_address"], "malware": e.get("malware"),
                 "threat": f"botnet C2 ({e.get('status', 'unknown')})"} for e in r.json() if e.get("ip_address")]


async def threatfox() -> list[dict]:
    """IOCs of the last few days from the ThreatFox API (the open JSON export
    was retired). Hash IOCs are skipped: only hosts and IPs can match an asset."""
    key = _abusech_key()
    if not key:
        raise ValueError("threatfox needs ABUSECH_AUTH_KEY (free at auth.abuse.ch)")
    async with httpx.AsyncClient(timeout=90, headers={**UA, "Auth-Key": key}) as c:
        r = await c.post(settings.THREATFOX_API_URL, json={"query": "get_iocs", "days": settings.THREATFOX_DAYS})
        r.raise_for_status()
        j = r.json()
        _api_ok(j, "threatfox")
        out = []
        for e in j.get("data") or []:
            kind = e.get("ioc_type") or ""
            if kind.endswith("_hash"):
                continue
            ioc = str(e.get("ioc", ""))
            host = ioc.rsplit(":", 1)[0] if kind == "ip:port" else _host(ioc)
            out.append({"feed": "threatfox", "indicator": ioc, "host": host, "malware": e.get("malware_printable"),
                        "threat": e.get("threat_type")})
        return out


FEEDS = ("urlhaus", "feodo", "threatfox")


async def check(hosts: list[str], ips: list[str]) -> dict:
    """{host or ip: [listing, …]} plus ``_feeds``: {feed: entries checked, or "error"}."""
    wanted = {h.lower() for h in hosts} | set(ips)
    out: dict = {"_feeds": {}}
    fns = {"urlhaus": urlhaus, "feodo": feodo, "threatfox": threatfox}
    for name in FEEDS:
        try:
            entries = await fns[name]()
        except (httpx.HTTPError, ValueError, KeyError, AttributeError) as exc:
            logger.warning("%s feed failed: %s", name, exc)
            out["_feeds"][name] = "error"
            continue
        out["_feeds"][name] = len(entries)
        for e in entries:
            if e["host"] in wanted:
                out.setdefault(e["host"], []).append({k: v for k, v in e.items() if k != "host"})
    return out
