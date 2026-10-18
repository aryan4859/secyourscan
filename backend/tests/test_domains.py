from unittest.mock import patch

from app.config import settings
from tests.test_intel import Net, _scan


def _txt(records: dict):
    async def txt_values(name):
        return records.get(name, [])
    return patch("app.services.domains.txt_values", txt_values)


async def test_txt_challenge_verifies_root_domain(client, admin, other_tenant):
    r = await client.post("/domains", headers=admin, json={"domain": "portal.Example.com."})
    assert r.status_code == 201, r.text
    d = r.json()
    assert d["domain"] == "example.com" and d["verified"] is False
    assert d["record_name"] == "_secyourscan-verify.example.com"
    assert d["record_value"].startswith("secyourscan-verification=")
    assert (await client.post("/domains", headers=admin, json={"domain": "example.com"})).status_code == 409

    with _txt({}):
        v = (await client.post(f"/domains/{d['id']}/verify", headers=admin)).json()
    assert v["verified"] is False and v["last_error"] == "TXT record not found"
    with _txt({d["record_name"]: ["secyourscan-verification=wrong"]}):
        v = (await client.post(f"/domains/{d['id']}/verify", headers=admin)).json()
    assert v["verified"] is False and "does not match" in v["last_error"]
    with _txt({d["record_name"]: ["v=spf1 -all", d["record_value"]]}):
        v = (await client.post(f"/domains/{d['id']}/verify", headers=admin)).json()
    assert v["verified"] is True and v["last_error"] is None

    # Another tenant can neither see nor verify it.
    assert (await client.get("/domains", headers=other_tenant)).json()["items"] == []
    assert (await client.post(f"/domains/{d['id']}/verify", headers=other_tenant)).status_code == 404
    audit = (await client.get("/system/audit", headers=admin)).json()
    assert {"ADD_DOMAIN", "VERIFY_DOMAIN"} <= {a["action"] for a in audit}


async def test_scans_skip_unverified_domains_when_required(client, admin, monkeypatch):
    monkeypatch.setattr(settings, "REQUIRE_DOMAIN_VERIFICATION", True)
    await client.post("/watchlist", headers=admin, json={"type": "domain", "value": "example.com"})
    with Net():
        await _scan(client, admin, "surface")
    assert (await client.get("/surface/hosts", headers=admin)).json() == []

    d = (await client.post("/domains", headers=admin, json={"domain": "example.com"})).json()
    with _txt({d["record_name"]: [d["record_value"]]}):
        await client.post(f"/domains/{d['id']}/verify", headers=admin)
    with Net():
        await _scan(client, admin, "surface")
    hosts = {h["hostname"] for h in (await client.get("/surface/hosts", headers=admin)).json()}
    assert "www.example.com" in hosts
