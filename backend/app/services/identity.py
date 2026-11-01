"""Identity & access intelligence.

Turns the leak table into a per-identity view: for every login that belongs to
the tenant (an address on a watched domain, a watched email, an executive, or
any account on one of the tenant's own apps) it answers how the credential was
exposed (infostealer vs combo list), on which apps, from which infected
machines, whether the same password shows up elsewhere, and how urgent it is.

Computed on read from ``Leak.entities``. Leaks stored before stealer parsing
existed are re-parsed from their (masked) snippet, so they still count, just
without password fingerprints.
"""

from collections import Counter, defaultdict
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Executive, Leak, WatchItem
from . import stealer
from .normalization import normalize_identifier

ROW_CAP = 20_000
_OPEN = ("new", "reviewing", "escalated")


def _under(host: str, domains: set[str]) -> str | None:
    for d in domains:
        if host == d or host.endswith("." + d):
            return d
    return None


async def _scope(db: AsyncSession, tenant_id: str) -> dict:
    watch = (await db.execute(select(WatchItem).where(WatchItem.tenant_id == tenant_id,
                                                      WatchItem.is_active.is_(True)))).scalars().all()
    execs = (await db.execute(select(Executive).where(Executive.tenant_id == tenant_id))).scalars().all()
    exec_by_email = {normalize_identifier(e, "email"): x.name for x in execs for e in x.emails or []}
    return {
        "domains": {w.value.lower() for w in watch if w.type == "domain"},
        "emails": {normalize_identifier(w.value, "email") for w in watch if w.type == "email"},
        "vip": {normalize_identifier(w.value, "email") for w in watch if w.type == "email" and w.is_vip} | set(exec_by_email),
        "execs": exec_by_email,
    }


def _stealer_of(leak) -> dict | None:
    ent = leak.entities or {}
    if ent.get("stealer"):
        return ent["stealer"]
    snippet = leak.snippet or ""
    if stealer.looks_like_stealer(snippet):
        parsed = stealer.parse(snippet)
        return parsed if parsed["records"] else None
    return None


def _risk(i: dict) -> int:
    s = 20
    if i["stealer"]:
        s += 35
    if i["corporate_apps"]:
        s += 15
    if i["reused"]:
        s += 10
    if i["vip"]:
        s += 15
    s += min(10, 2 * (len(i["exposures"]) - 1))
    if not i["open"]:
        s -= 25
    return max(0, min(100, s))


async def collect(db: AsyncSession, tenant_id: str) -> dict:
    scope = await _scope(db, tenant_id)
    rows = (await db.execute(
        select(Leak.id, Leak.title, Leak.source, Leak.source_url, Leak.severity, Leak.status, Leak.discovered_at,
               Leak.entities, Leak.snippet)
        .where(Leak.tenant_id == tenant_id).order_by(Leak.discovered_at.desc()).limit(ROW_CAP))).all()

    ids: dict[str, dict] = {}
    machines: dict[str, dict] = {}
    fp_logins: dict[str, set] = defaultdict(set)
    families: Counter = Counter()

    def ident(login: str) -> dict | None:
        login = login.strip().lower()
        if not login or len(login) > 255:
            return None
        email = "@" in login
        norm = normalize_identifier(login, "email") if email else login
        dom = norm.rsplit("@", 1)[1] if email else None
        if norm not in ids:
            ids[norm] = {"login": norm, "domain": dom, "watched": norm in scope["emails"],
                         "on_domain": bool(dom and _under(dom, scope["domains"])), "vip": norm in scope["vip"],
                         "executive": scope["execs"].get(norm), "exposures": [], "apps": set(), "corporate_apps": set(),
                         "machines": set(), "families": set(), "fps": set(), "masks": set(), "stealer": False,
                         "first_seen": None, "last_seen": None, "open": False, "max_severity": 0}
        return ids[norm]

    def touch(i, leak, kind, app=None, rec=None):
        at: datetime = leak.discovered_at
        i["first_seen"] = min(i["first_seen"] or at, at)
        i["last_seen"] = max(i["last_seen"] or at, at)
        i["open"] = i["open"] or leak.status in _OPEN
        i["max_severity"] = max(i["max_severity"], leak.severity)
        if not any(e["leak_id"] == leak.id and e.get("app") == app for e in i["exposures"]):
            i["exposures"].append({"leak_id": leak.id, "title": leak.title or leak.source, "source": leak.source,
                                   "kind": kind, "app": app, "severity": leak.severity, "status": leak.status,
                                   "at": at.isoformat(), "password": (rec or {}).get("password_masked")})

    for leak in rows:
        ent = leak.entities or {}
        logs = _stealer_of(leak)
        if logs:
            fam = logs.get("family")
            for rec in logs["records"]:
                if not rec.get("login"):
                    continue
                host = rec.get("host") or ""
                corp = _under(host, scope["domains"])
                i = ident(rec["login"])
                if i is None:
                    continue
                if corp and not i["on_domain"]:
                    i["on_domain"] = True  # a username on one of *our* apps is ours even without an email
                i["stealer"] = True
                if host:
                    i["apps"].add(host)
                    if corp:
                        i["corporate_apps"].add(host)
                if rec.get("hwid") or rec.get("computer"):
                    mid = rec.get("hwid") or rec.get("computer")
                    i["machines"].add(mid)
                if fam:
                    i["families"].add(fam)
                if rec.get("password_fp"):
                    i["fps"].add(rec["password_fp"])
                    fp_logins[rec["password_fp"]].add(i["login"])
                if rec.get("password_masked"):
                    i["masks"].add(rec["password_masked"])
                touch(i, leak, "stealer", host or None, rec)
            for m in logs.get("machines") or []:
                mid = m.get("hwid") or m.get("computer") or f"unknown:{leak.id[:8]}"
                mm = machines.setdefault(mid, {"id": mid, "hwid": m.get("hwid"), "computer": m.get("computer"),
                                               "ip": m.get("ip"), "country": m.get("country"), "os": m.get("os"),
                                               "family": fam, "logins": set(), "corporate_apps": set(), "leaks": set(),
                                               "first_seen": leak.discovered_at, "last_seen": leak.discovered_at})
                mm["leaks"].add(leak.id)
                mm["first_seen"] = min(mm["first_seen"], leak.discovered_at)
                mm["last_seen"] = max(mm["last_seen"], leak.discovered_at)
                for rec in logs["records"]:
                    rid = rec.get("hwid") or rec.get("computer")
                    if rid == m.get("hwid") or rid == m.get("computer") or (not rid and len(logs["machines"]) == 1):
                        if rec.get("login"):
                            mm["logins"].add(rec["login"])
                        if _under(rec.get("host") or "", scope["domains"]):
                            mm["corporate_apps"].add(rec["host"])
            if fam:
                families[fam] += 1

        for c in ent.get("credentials") or []:
            i = ident(c.get("identifier", ""))
            if i is None:
                continue
            if c.get("password_fp"):
                i["fps"].add(c["password_fp"])
                fp_logins[c["password_fp"]].add(i["login"])
            if c.get("password_masked"):
                i["masks"].add(c["password_masked"])
            touch(i, leak, "combo", None, {"password_masked": c.get("password_masked")})

    # Only identities that are ours.
    mine = {k: v for k, v in ids.items() if v["watched"] or v["on_domain"] or v["vip"]}
    for i in mine.values():
        # Reuse: one password seen in several leaks of this account, or the
        # same password on several accounts.
        same_everywhere = len(i["fps"]) == 1 and len({e["leak_id"] for e in i["exposures"]}) > 1
        i["reused"] = same_everywhere or any(len(fp_logins[fp]) > 1 for fp in i["fps"])
        i["shared_with"] = sorted({other for fp in i["fps"] for other in fp_logins[fp] if other != i["login"]})[:20]
        i["risk"] = _risk(i)
    mine_logins = set(mine)
    relevant_machines = [m for m in machines.values() if m["logins"] & mine_logins or m["corporate_apps"]]
    return {"identities": mine, "machines": relevant_machines, "families": families, "fp_logins": fp_logins}


def _out(i: dict, detail: bool = False) -> dict:
    o = {
        "login": i["login"], "domain": i["domain"], "vip": i["vip"], "executive": i["executive"],
        "watched": i["watched"], "risk": i["risk"], "stealer": i["stealer"], "reused": i["reused"],
        "exposures": len(i["exposures"]), "apps": sorted(i["apps"])[:50], "corporate_apps": sorted(i["corporate_apps"]),
        "machines": len(i["machines"]), "families": sorted(i["families"]), "open": i["open"],
        "max_severity": i["max_severity"],
        "first_seen": i["first_seen"].isoformat() if i["first_seen"] else None,
        "last_seen": i["last_seen"].isoformat() if i["last_seen"] else None,
    }
    if detail:
        o["timeline"] = sorted(i["exposures"], key=lambda e: e["at"], reverse=True)
        o["passwords"] = sorted(i["masks"])[:20]
        o["distinct_passwords"] = len(i["fps"]) or None
        o["shared_with"] = i["shared_with"]
        o["machine_ids"] = sorted(i["machines"])
        o["actions"] = actions(i)
    return o


def actions(i: dict) -> list[str]:
    out = []
    if i["stealer"]:
        out.append("Treat the user's device as compromised: isolate it, re-image, then reset every saved password.")
        out.append("Revoke active sessions and tokens (SSO, VPN, mail, SaaS): stealers take session cookies that survive a password change.")
    else:
        out.append("Force a password reset and check sign-in logs for the exposure dates.")
    if i["corporate_apps"]:
        out.append(f"Audit access to {', '.join(sorted(i['corporate_apps'])[:5])} since {i['first_seen']:%Y-%m-%d}.")
    if i["reused"]:
        out.append("The same password appears on several accounts or leaks: rotate it everywhere and enforce MFA.")
    if i["vip"]:
        out.append("VIP account: brief the person directly and watch for follow-on phishing or impersonation.")
    return out


def summary(data: dict) -> dict:
    ids = list(data["identities"].values())
    apps: Counter = Counter()
    corp: Counter = Counter()
    domains: Counter = Counter()
    for i in ids:
        apps.update(i["apps"])
        corp.update(i["corporate_apps"])
        if i["domain"]:
            domains[i["domain"]] += 1
    bands = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for i in ids:
        bands["critical" if i["risk"] >= 80 else "high" if i["risk"] >= 60 else "medium" if i["risk"] >= 30 else "low"] += 1
    shared = sorted(((len(v), sorted(v)[:10]) for v in data["fp_logins"].values()
                     if len(v & set(data["identities"])) > 1), key=lambda x: -x[0])[:10]
    return {
        "identities": len(ids),
        "stealer_infected": sum(1 for i in ids if i["stealer"]),
        "corporate_app_accounts": sum(1 for i in ids if i["corporate_apps"]),
        "vip": sum(1 for i in ids if i["vip"]),
        "reused_passwords": sum(1 for i in ids if i["reused"]),
        "open": sum(1 for i in ids if i["open"]),
        "machines": len(data["machines"]),
        "bands": bands,
        "families": [{"family": f, "logs": n} for f, n in data["families"].most_common(10)],
        "top_apps": [{"host": h, "accounts": n, "corporate": h in corp} for h, n in apps.most_common(12)],
        "domains": [{"domain": d, "accounts": n} for d, n in domains.most_common(10)],
        "shared_passwords": [{"accounts": n, "logins": logins} for n, logins in shared],
    }


def machine_out(m: dict) -> dict:
    return {"id": m["id"], "hwid": m["hwid"], "computer": m["computer"], "ip": m["ip"], "country": m["country"],
            "os": m["os"], "family": m["family"], "logins": sorted(m["logins"])[:50], "accounts": len(m["logins"]),
            "corporate_apps": sorted(m["corporate_apps"]), "logs": len(m["leaks"]),
            "first_seen": m["first_seen"].isoformat(), "last_seen": m["last_seen"].isoformat()}


def identities(data: dict, *, q: str | None = None, kind: str = "all", limit: int = 200) -> list[dict]:
    rows = list(data["identities"].values())
    if q:
        ql = q.lower()
        rows = [i for i in rows if ql in i["login"] or any(ql in a for a in i["apps"])]
    if kind == "stealer":
        rows = [i for i in rows if i["stealer"]]
    elif kind == "corporate":
        rows = [i for i in rows if i["corporate_apps"]]
    elif kind == "vip":
        rows = [i for i in rows if i["vip"]]
    elif kind == "reused":
        rows = [i for i in rows if i["reused"]]
    rows.sort(key=lambda i: (-i["risk"], -(i["last_seen"].timestamp() if i["last_seen"] else 0), i["login"]))
    return [_out(i) for i in rows[:limit]]


def identity(data: dict, login: str) -> dict | None:
    key = normalize_identifier(login.strip().lower(), "email") if "@" in login else login.strip().lower()
    i = data["identities"].get(key)
    return _out(i, detail=True) if i else None
