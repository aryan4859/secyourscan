"""abuse.ch API feeds and CDN-edge handling on the attack surface."""

from unittest.mock import patch

import httpx
import respx
from sqlalchemy import select

from app.config import settings
from app.database import SessionLocal
from app.models import Incident, SurfaceHost, VulnFinding
from app.services import asm, incidents, reputation

from .test_intel import Net

WORDPRESS_ON_CDN = ["CVE-2016-10033", "CVE-2026-87902", "CVE-2019-8943"]


# ── CDN detection ────────────────────────────────────────────────────────────


def test_cdn_provider():
    assert asm.cdn_provider("104.21.75.197") == "Cloudflare"
    assert asm.cdn_provider("172.67.1.1") == "Cloudflare"
    assert asm.cdn_provider("151.101.1.69") == "Fastly"
    assert asm.cdn_provider("185.199.108.153") == "GitHub Pages"
    assert asm.cdn_provider("93.184.216.34") is None
    assert asm.cdn_provider("93.184.216.34", ["cdn"]) == "CDN"  # Shodan's own tag
    assert asm.cdn_provider("not-an-ip") is None and asm.cdn_provider(None) is None


async def test_cdn_edge_cves_are_not_attributed_and_stale_ones_withdrawn(client, admin):
    await client.post("/watchlist", headers=admin, json={"type": "domain", "value": "example.com"})

    async def resolve_a(h):
        return {"www": ["104.21.75.197"], "vpn": ["1.1.1.1"]}.get(h.split(".")[0], ["93.184.216.34"] if h.count(".") == 1 else [])

    async def internetdb(ip):
        if ip == "104.21.75.197":  # a Cloudflare edge serving thousands of sites
            return {"ports": [80, 443, 2083, 8443], "vulns": WORDPRESS_ON_CDN, "cpes": ["cpe:/a:wordpress:wordpress"],
                    "tags": ["cdn"]}
        return {"ports": [22], "vulns": [], "cpes": []} if ip == "1.1.1.1" else {"ports": [443]}

    # A stale finding from before CDN handling, with its incident.
    async with SessionLocal() as db:
        from app.models import Tenant
        tid = (await db.execute(select(Tenant.id))).scalars().first()
        db.add(VulnFinding(tenant_id=tid, host="www.example.com", ip="104.21.75.197", cve="CVE-2016-10033",
                           kev=True, priority="critical"))
        await db.commit()
        await incidents.sync(db, tid)

    with Net(), patch("app.services.easm.resolve_a", resolve_a), patch("app.services.easm.internetdb", internetdb):
        r = await client.post("/intel/scan/surface", headers=admin)
        assert r.status_code == 202, r.text

    hosts = {h["hostname"]: h for h in (await client.get("/surface/hosts", headers=admin)).json()}
    www = hosts["www.example.com"]
    assert www["cves"] == [] and www["cpes"] == [] and www["ports"] == [] and "cdn:Cloudflare" in www["tags"]
    assert hosts["vpn.example.com"]["ports"] == [22]  # origin IPs still count

    vulns = (await client.get("/vulns", headers=admin, params={"status": "all"})).json()
    assert not any(v["host"] == "www.example.com" for v in vulns)  # removed, not "fixed"
    status = (await client.get("/intel/status", headers=admin)).json()
    assert status["vulns"]["result"]["withdrawn"] == 1

    inc = (await client.get("/incidents", headers=admin, params={"status": "false_positive"})).json()
    assert any("CVE-2016-10033" in i["title"] for i in inc)
    async with SessionLocal() as db:
        assert (await db.scalar(select(SurfaceHost.tags).where(SurfaceHost.hostname == "www.example.com")))
        assert (await db.scalar(select(Incident.status).where(Incident.source_type == "vuln"))) == "false_positive"


# ── abuse.ch APIs ────────────────────────────────────────────────────────────


@respx.mock
async def test_urlhaus_and_threatfox_use_the_authenticated_apis(monkeypatch):
    monkeypatch.setattr(settings, "ABUSECH_AUTH_KEY", "k")
    uh = respx.get(settings.URLHAUS_API_RECENT_URL).mock(return_value=httpx.Response(200, json={
        "query_status": "ok", "urls": [{"url": "http://www.example.com/x.exe", "host": "www.example.com", "threat": "malware_download"}]}))
    tf = respx.post(settings.THREATFOX_API_URL).mock(return_value=httpx.Response(200, json={
        "query_status": "ok", "data": [
            {"ioc": "203.0.113.5:443", "ioc_type": "ip:port", "threat_type": "botnet_cc", "malware_printable": "Cobalt Strike"},
            {"ioc": "evil.example", "ioc_type": "domain", "threat_type": "payload_delivery", "malware_printable": "AMOS"},
            {"ioc": "ab" * 32, "ioc_type": "sha256_hash", "threat_type": "payload", "malware_printable": "AMOS"}]}))

    urls = await reputation.urlhaus()
    assert urls == [{"feed": "urlhaus", "indicator": "http://www.example.com/x.exe", "host": "www.example.com",
                     "threat": "malware_download"}]
    assert uh.calls[0].request.headers["Auth-Key"] == "k"

    tfx = await reputation.threatfox()
    assert [(e["host"], e["malware"]) for e in tfx] == [("203.0.113.5", "Cobalt Strike"), ("evil.example", "AMOS")]
    assert tf.calls[0].request.headers["Auth-Key"] == "k"

    tf.mock(return_value=httpx.Response(200, json={"query_status": "unknown_auth_key"}))
    try:
        await reputation.threatfox()
        raise AssertionError("bad key must fail")
    except ValueError as exc:
        assert "unknown_auth_key" in str(exc)


async def test_feeds_without_key_fail_cleanly(monkeypatch):
    monkeypatch.setattr(settings, "ABUSECH_AUTH_KEY", None)
    monkeypatch.setattr(settings, "THREATFOX_AUTH_KEY", None)
    out = await reputation.check([], [])
    assert out["_feeds"]["urlhaus"] == "error" and out["_feeds"]["threatfox"] == "error"
