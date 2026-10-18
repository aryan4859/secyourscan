from app.config import settings
from app.services import report
from tests.test_intel import Net, _scan
from tests.test_pipeline import COMBO, _ingest


async def test_domain_report_aggregates_and_scores(client, admin, other_tenant):
    await client.post("/watchlist", headers=admin, json={"type": "domain", "value": "acme.example.com", "is_vip": True})
    await _ingest(client, admin, COMBO, source="paste")
    with Net(vpn_ports=(22, 443, 3389)):
        await _scan(client, admin, "surface")
        await _scan(client, admin, "brand")

    doms = (await client.get("/report/domains", headers=admin)).json()
    assert doms == [{"domain": "example.com", "verified": False, "allowed": True}]

    r = (await client.get("/report/domain/acme.example.com", headers=admin)).json()
    assert r["domain"] == "example.com"
    assert r["leaks"]["total"] == 1 and r["leaks"]["critical_open"] == 1
    assert "Secr3tPass" not in str(r)  # titles and metadata only, never leak content
    assert any(p["port"] == 3389 and p["risk"] == "critical" for p in r["surface"]["critical_ports"])
    assert r["vulns"]["by_priority"]["critical"] == 1
    assert r["brand"]["high_risk"] == 1
    factors = {f["factor"]: f for f in r["factors"]}
    assert factors["Critical ports exposed"]["points"] == 15
    assert factors["Actively exploited CVEs (KEV)"]["points"] == 20
    assert r["score"] == min(sum(f["points"] for f in r["factors"]), 100)

    pdf = await client.get("/report/domain/example.com/pdf", headers=admin)
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
    assert (await client.get("/report/domain/example.com", headers=other_tenant)).json()["leaks"]["total"] == 0


async def test_report_requires_verified_domain_when_enforced(client, admin, monkeypatch):
    monkeypatch.setattr(settings, "REQUIRE_DOMAIN_VERIFICATION", True)
    r = await client.get("/report/domain/example.com", headers=admin)
    assert r.status_code == 403 and "not verified" in r.json()["detail"]
    assert (await client.get("/report/domain/example.com/pdf", headers=admin)).status_code == 403


def test_score_caps_each_factor():
    base = {"surface": {"critical_ports": [{}] * 9, "listed": 0, "tls": {"failing": 0}, "dns_critical": 0},
            "vulns": {"by_priority": {"critical": 0, "high": 0}}, "brand": {"high_risk": 0, "phishing_live": 0},
            "ransomware": [], "leaks": {"critical_open": 0}}
    total, level, factors = report.score(base)
    assert (total, level) == (30, "moderate") and factors[0]["cap"] == 30
