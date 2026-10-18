"""Offline licence verification for on-prem installs.

A licence is ``SYS1.<payload>.<signature>`` (base64url): a JSON payload signed
with the vendor's Ed25519 private key. The install holds only the public key
(``LICENSE_PUBLIC_KEY``), so licences can be checked with no network access
and cannot be forged. When no public key is configured, licensing is off
(development and self-built installs).

Payload: {"customer", "issued", "expires" (YYYY-MM-DD), "max_domains", "features"}.
"""

import base64
import json
from datetime import date

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..config import settings

PREFIX = "SYS1"


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def verify(token: str, public_key_b64: str) -> dict:
    """The payload if ``token`` is genuine; raises ValueError otherwise."""
    try:
        prefix, payload_b64, sig_b64 = token.strip().split(".")
    except ValueError:
        raise ValueError("malformed licence")
    if prefix != PREFIX:
        raise ValueError("unknown licence format")
    payload = _b64d(payload_b64)
    try:
        Ed25519PublicKey.from_public_bytes(_b64d(public_key_b64)).verify(_b64d(sig_b64), f"{PREFIX}.{payload_b64}".encode())
    except (InvalidSignature, ValueError):
        raise ValueError("signature does not match this product")
    return json.loads(payload)


def status() -> dict:
    """{"state": off|missing|invalid|expired|valid, …payload, "reason"}."""
    if not settings.LICENSE_PUBLIC_KEY:
        return {"state": "off"}
    if not settings.LICENSE_KEY:
        return {"state": "missing", "reason": "No LICENSE_KEY configured"}
    try:
        lic = verify(settings.LICENSE_KEY, settings.LICENSE_PUBLIC_KEY)
    except ValueError as exc:
        return {"state": "invalid", "reason": str(exc)}
    expires = lic.get("expires")
    if expires and date.fromisoformat(expires) < date.today():
        return {"state": "expired", "reason": f"Licence expired on {expires}", **lic}
    return {"state": "valid", **lic}


def can_scan() -> tuple[bool, str | None]:
    st = status()
    return (st["state"] in ("off", "valid"), st.get("reason"))


def max_domains() -> int | None:
    st = status()
    return st.get("max_domains") if st["state"] == "valid" else None
