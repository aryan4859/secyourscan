"""Infostealer log parsing.

Infostealers (RedLine, Lumma, Vidar, StealC…) dump what they took from a
machine in two common shapes:

* blocks, one credential per block::

      URL: https://vpn.acme.example/login
      USER: j.doe@acme.example
      PASS: hunter2

* ULP lines (``url:login:password``), how logs are resold in bulk::

      https://mail.acme.example/owa:j.doe@acme.example:hunter2

plus system details (HWID, machine name, IP, country, OS) that tell infected
machines apart. ``parse`` returns the credentials with the password masked and
fingerprinted, never the password itself.
"""

import hashlib
import hmac
import re
from functools import lru_cache
from urllib.parse import urlsplit

FAMILIES = {
    "redline": "RedLine", "lumma": "Lumma", "lummac2": "Lumma", "vidar": "Vidar", "stealc": "StealC",
    "raccoon": "Raccoon", "risepro": "RisePro", "meta stealer": "META", "metastealer": "META",
    "aurora stealer": "Aurora", "titan stealer": "Titan", "mystic stealer": "Mystic", "rhadamanthys": "Rhadamanthys",
    "atomic stealer": "Atomic (AMOS)", "amos": "Atomic (AMOS)",
}
_URL_KEYS = {"url", "host", "hostname", "site", "soft url", "link", "origin"}
_LOGIN_KEYS = {"user", "username", "login", "email", "user login", "account"}
_PASS_KEYS = {"pass", "password", "pwd", "passwd", "user password"}
_MACHINE_KEYS = {
    "hwid": "hwid", "machine id": "hwid", "machineid": "hwid", "uid": "hwid",
    "computer name": "computer", "pc name": "computer", "machinename": "computer", "machine name": "computer",
    "ip": "ip", "ip address": "ip", "country": "country", "location": "country",
    "os": "os", "operation system": "os", "windows": "os",
}
_KV_RE = re.compile(r"^\s*([A-Za-z][A-Za-z ]{0,20}?)\s*[:=]\s*(.+?)\s*$")
_ULP_RE = re.compile(r"^\s*((?:https?|android)://[^\s]+?):([^\s:]{1,255}):(\S{1,128})\s*$", re.M)
_MAX_RECORDS = 2000


@lru_cache(maxsize=1)
def _fp_key() -> bytes:
    """Per-installation key for password fingerprints, derived from the JWT
    signing key, so a fingerprint means nothing outside this deployment."""
    from cryptography.hazmat.primitives import serialization

    from ..security import signing_keys

    private, _ = signing_keys()
    raw = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    return hashlib.sha256(b"secyourscan/password-fingerprint/v1" + raw).digest()


def fingerprint(password: str) -> str:
    """Keyed, truncated hash: equal passwords get equal fingerprints (so reuse
    is visible) but the password cannot be recovered or looked up elsewhere."""
    return hmac.new(_fp_key(), password.encode("utf-8", "ignore"), hashlib.sha256).hexdigest()[:16]


def mask(value: str) -> str:
    if "*" in value:  # already masked (parsing a stored snippet)
        return value
    if len(value) <= 4:
        return "*" * len(value)
    return f"{value[0]}{'*' * min(len(value) - 2, 12)}{value[-1]}"


def host_of(url: str) -> str:
    u = url if "://" in url else f"http://{url}"
    try:
        return (urlsplit(u).hostname or "").lower()
    except ValueError:
        return ""


def detect_family(text: str) -> str | None:
    low = text[:200_000].lower()
    for needle, name in FAMILIES.items():
        if needle in low:
            return name
    return None


def looks_like_stealer(text: str) -> bool:
    low = text[:200_000].lower()
    blocks = len(re.findall(r"^\s*(?:url|host|soft url)\s*:", low, re.M))
    passes = len(re.findall(r"^\s*(?:pass|password)\s*:", low, re.M))
    return bool(blocks and passes) or bool(_ULP_RE.search(text)) or "stealer" in low


def _record(url, login, password, machine, fmt, *, keep_fp=True) -> dict | None:
    if not url or not (login or password):
        return None
    login = (login or "").strip().lower()[:255]
    password = (password or "").strip()
    return {
        "url": url.strip()[:512],
        "host": host_of(url.strip()),
        "login": login,
        "password_masked": mask(password) if password else "",
        "password_length": len(password) if password and "*" not in password else None,
        "password_fp": fingerprint(password) if keep_fp and password and "*" not in password else None,
        "hwid": machine.get("hwid"),
        "computer": machine.get("computer"),
        "format": fmt,
    }


def parse(text: str) -> dict:
    """``{"records": [...], "machines": [...], "family": str | None}``."""
    records: list[dict] = []
    machines: dict[str, dict] = {}
    machine: dict = {}
    cur: dict = {}

    def flush():
        nonlocal cur
        r = _record(cur.get("url"), cur.get("login"), cur.get("password"), machine, "block")
        if r:
            records.append(r)
        cur = {}

    for line in text.splitlines():
        if len(records) >= _MAX_RECORDS:
            break
        m = _KV_RE.match(line)
        if not m:
            continue
        key, value = m.group(1).strip().lower(), m.group(2).strip()
        if key in _MACHINE_KEYS:
            field = _MACHINE_KEYS[key]
            if field == "hwid":
                flush()
                machine = {"hwid": value[:64]}
                machines.setdefault(machine["hwid"], dict(machine))
            else:
                machine[field] = value[:120]
                if machine.get("hwid"):
                    machines[machine["hwid"]][field] = value[:120]
        elif key in _URL_KEYS:
            if cur.get("url"):
                flush()
            cur["url"] = value
        elif key in _LOGIN_KEYS:
            cur["login"] = value
        elif key in _PASS_KEYS:
            cur["password"] = value
            if cur.get("url"):
                flush()
    flush()

    for url, login, password in _ULP_RE.findall(text):
        if len(records) >= _MAX_RECORDS:
            break
        r = _record(url, login, password, {}, "ulp")
        if r:
            records.append(r)

    # An unnamed machine still counts once if credentials came from it.
    if records and not machines and any(r["format"] == "block" for r in records):
        machines["unknown"] = {"hwid": None, **{k: v for k, v in machine.items() if k != "hwid"}}
    return {"records": records, "machines": list(machines.values()), "family": detect_family(text)}
