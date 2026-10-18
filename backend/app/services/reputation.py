"""Are any of *our* hosts or IPs listed in public threat feeds?

abuse.ch publishes three keyless feeds that matter for an organisation's own
assets: URLhaus (URLs serving malware — a compromised web server), Feodo
Tracker (botnet command-and-control IPs) and ThreatFox (recent IOCs of every
kind). Each is downloaded once per scan and matched locally, so nothing about
your assets is sent to the feed operators.
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


async def urlhaus() -> list[dict]:
    async with httpx.AsyncClient(timeout=60, headers=UA) as c:
        r = await c.get(settings.URLHAUS_RECENT_URL)
        r.raise_for_status()
        return [{"feed": "urlhaus", "indicator": line.strip(), "host": _host(line), "threat": "malware_download"}
                for line in r.text.splitlines() if line.strip() and not line.startswith("#")]


async def feodo() -> list[dict]:
    async with httpx.AsyncClient(timeout=60, headers=UA) as c:
        r = await c.get(settings.FEODO_URL)
        r.raise_for_status()
        return [{"feed": "feodo", "indicator": e["ip_address"], "host": e["ip_address"], "malware": e.get("malware"),
                 "threat": f"botnet C2 ({e.get('status', 'unknown')})"} for e in r.json() if e.get("ip_address")]


async def threatfox() -> list[dict]:
    async with httpx.AsyncClient(timeout=90, headers=UA) as c:
        r = await c.get(settings.THREATFOX_RECENT_URL)
        r.raise_for_status()
        out = []
        for entries in r.json().values():
            for e in entries:
                ioc = str(e.get("ioc_value", ""))
                host = ioc.split(":")[0] if e.get("ioc_type") == "ip:port" else _host(ioc)
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
