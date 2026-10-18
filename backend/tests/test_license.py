import base64
import json
from datetime import date, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.config import settings
from app.services import license


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _issue(key, **payload) -> str:
    body = _b64(json.dumps({"customer": "Acme", "max_domains": 1, **payload}).encode())
    return f"SYS1.{body}.{_b64(key.sign(f'SYS1.{body}'.encode()))}"


def _pub(key) -> str:
    return _b64(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


async def test_licence_states_and_enforcement(client, admin, monkeypatch):
    vendor, forger = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    future = (date.today() + timedelta(days=30)).isoformat()
    past = (date.today() - timedelta(days=1)).isoformat()

    # No public key: licensing off, everything allowed.
    assert (await client.get("/system/license", headers=admin)).json()["state"] == "off"

    monkeypatch.setattr(settings, "LICENSE_PUBLIC_KEY", _pub(vendor))
    monkeypatch.setattr(settings, "LICENSE_KEY", None)
    assert license.status()["state"] == "missing"
    assert (await client.post("/intel/scan/brand", headers=admin)).status_code == 402

    monkeypatch.setattr(settings, "LICENSE_KEY", _issue(forger, expires=future))
    st = license.status()
    assert st["state"] == "invalid" and "signature" in st["reason"]

    monkeypatch.setattr(settings, "LICENSE_KEY", _issue(vendor, expires=past))
    assert license.status()["state"] == "expired"
    assert (await client.post("/intel/scan/brand", headers=admin)).status_code == 402

    monkeypatch.setattr(settings, "LICENSE_KEY", _issue(vendor, expires=future))
    lic = (await client.get("/system/license", headers=admin)).json()
    assert lic["state"] == "valid" and lic["customer"] == "Acme" and lic["domains_used"] == 0
    assert (await client.post("/intel/scan/brand", headers=admin)).status_code == 202
    # max_domains=1: the second domain is refused.
    assert (await client.post("/domains", headers=admin, json={"domain": "example.com"})).status_code == 201
    r = await client.post("/domains", headers=admin, json={"domain": "example.org"})
    assert r.status_code == 402 and "1 domain" in r.json()["detail"]
