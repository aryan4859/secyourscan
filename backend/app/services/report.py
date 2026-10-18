"""Domain Exposure report: everything SecYourScan knows about one root
domain, with a risk score whose every point is explained.

Only data already collected is used; nothing is fetched here. Leak content is
never included — only titles (already masked), sources, severities and dates.
"""

import io
from datetime import timedelta
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import (
    IntelCache,
    Leak,
    Lookalike,
    PhishingUrl,
    RansomwareHit,
    SurfaceEvent,
    SurfaceHost,
    TlsGrade,
    VulnFinding,
    WatchItem,
    utcnow,
)
from . import asm
from .domains import root_of

LEAK_WINDOW = timedelta(days=90)
_OPEN = ("new", "reviewing", "escalated")


def _under(host: str, root: str) -> bool:
    return host == root or host.endswith("." + root)


def score(r: dict) -> tuple[int, str, list[dict]]:
    """(0–100, level, contributing factors). Each factor is capped so no single
    category can dominate; the caps are part of the explanation."""
    factors = []

    def add(label, count, each, cap):
        if count:
            factors.append({"factor": label, "count": count, "points": min(count * each, cap), "cap": cap})

    s = r["surface"]
    add("Critical ports exposed", len(s["critical_ports"]), 15, 30)
    add("Hosts listed in threat feeds", s["listed"], 25, 25)
    add("TLS endpoints graded D/F", s["tls"]["failing"], 5, 15)
    add("Critical DNS / email-security gaps", s["dns_critical"], 10, 20)
    v = r["vulns"]
    add("Actively exploited CVEs (KEV)", v["by_priority"]["critical"], 20, 30)
    add("High-likelihood CVEs (EPSS ≥ 50%)", v["by_priority"]["high"], 5, 10)
    b = r["brand"]
    add("High-risk lookalike domains", b["high_risk"], 3, 15)
    add("Live phishing URLs", b["phishing_live"], 10, 20)
    add("Ransomware leak-site mentions", len(r["ransomware"]), 40, 40)
    add("Critical leak mentions (90 days)", r["leaks"]["critical_open"], 5, 25)
    total = min(sum(f["points"] for f in factors), 100)
    level = "critical" if total >= 70 else "high" if total >= 40 else "moderate" if total >= 20 else "low"
    return total, level, sorted(factors, key=lambda f: -f["points"])


async def build(db: AsyncSession, tenant_id: str, domain: str) -> dict:
    root = root_of(domain)
    now = utcnow()
    t = tenant_id

    hosts = [h for h in (await db.execute(select(SurfaceHost).where(SurfaceHost.tenant_id == t))).scalars()
             if _under(h.hostname, root)]
    names = {h.hostname for h in hosts}
    crit_ports = [{"hostname": h.hostname, **asm.classify_port(p)} for h in hosts if h.resolves for p in (h.ports or [])
                  if asm.classify_port(p)["risk"] in ("critical", "high")]
    crit_ports.sort(key=lambda x: (asm.RISK_ORDER[x["risk"]], x["port"]))
    grades = [g for g in (await db.execute(select(TlsGrade).where(TlsGrade.tenant_id == t))).scalars() if g.hostname in names]
    dist = {}
    for g in grades:
        dist[g.grade] = dist.get(g.grade, 0) + 1
    posture_row = await db.get(IntelCache, f"posture:{t}")
    checks = ((posture_row.data if posture_row else {}).get(root) or {}).get("checks", [])
    events = [e for e in (await db.execute(select(SurfaceEvent).where(SurfaceEvent.tenant_id == t)
                                           .order_by(SurfaceEvent.at.desc()).limit(500))).scalars()
              if _under(e.subject, root)][:10]

    vulns = [f for f in (await db.execute(select(VulnFinding).where(VulnFinding.tenant_id == t, VulnFinding.status == "open"))).scalars()
             if f.host in names or any(f.ip in (h.ips or []) for h in hosts)]
    by_p = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in vulns:
        by_p[f.priority] = by_p.get(f.priority, 0) + 1
    vulns.sort(key=lambda f: ({"critical": 0, "high": 1, "medium": 2, "low": 3}[f.priority], -(f.epss or 0)))

    looks = [x for x in (await db.execute(select(Lookalike).where(Lookalike.tenant_id == t, Lookalike.target == root))).scalars()]
    looks.sort(key=lambda x: -x.risk)
    phish = [p for p in (await db.execute(select(PhishingUrl).where(PhishingUrl.tenant_id == t, PhishingUrl.target == root))).scalars()]
    rw = [h for h in (await db.execute(select(RansomwareHit).where(RansomwareHit.tenant_id == t))).scalars()
          if h.status != "false_positive" and (root in (h.matched or "") or root.split(".")[0] == h.matched
                                               or _under((h.domain or "").removeprefix("www."), root))]

    watched = {w.id for w in (await db.execute(select(WatchItem).where(WatchItem.tenant_id == t))).scalars()
               if (w.type == "domain" and _under(w.value, root)) or (w.type == "email" and w.value.endswith("@" + root))}
    leaks = [lk for lk in (await db.execute(select(Leak.id, Leak.title, Leak.source, Leak.severity, Leak.status,
                                                   Leak.discovered_at, Leak.watch_matches)
                                            .where(Leak.tenant_id == t, Leak.discovered_at >= now - LEAK_WINDOW))).all()
             if any(m.get("id") in watched for m in lk.watch_matches or [])]
    leaks.sort(key=lambda x: (-x.severity, -x.discovered_at.timestamp()))

    report = {
        "domain": root,
        "generated_at": now.isoformat(),
        "surface": {
            "hosts": len(hosts), "live": sum(1 for h in hosts if h.resolves),
            "new_7d": sum(1 for h in hosts if now - h.first_seen <= timedelta(days=7)),
            "open_ports": sum(len(h.ports or []) for h in hosts if h.resolves),
            "critical_ports": crit_ports[:25],
            "listed": sum(1 for h in hosts if h.threats),
            "listed_hosts": [{"hostname": h.hostname, "threats": h.threats} for h in hosts if h.threats][:10],
            "tls": {"graded": len(grades), "distribution": dist, "failing": sum(1 for g in grades if g.grade in ("D", "F")),
                    "failing_hosts": [{"hostname": g.hostname, "grade": g.grade, "issue": (g.issues or [{}])[0].get("text")}
                                      for g in grades if g.grade in ("D", "F")][:10]},
            "certs_expiring": sum(1 for h in hosts if h.tls_not_after and h.tls_not_after - now <= timedelta(days=30)),
            "dns_checks": checks,
            "dns_critical": sum(1 for c in checks if not c["ok"] and c["severity"] == "critical"),
            "recent_changes": [{"subject": e.subject, "kind": e.kind, "severity": e.severity, "detail": e.detail,
                                "at": e.at.isoformat()} for e in events],
        },
        "vulns": {"open": len(vulns), "by_priority": by_p,
                  "top": [{"cve": f.cve, "host": f.host, "priority": f.priority, "kev": f.kev,
                           "epss": f.epss, "name": f.kev_name} for f in vulns[:10]]},
        "brand": {"lookalikes": len(looks), "high_risk": sum(1 for x in looks if x.risk >= 70 and x.status != "benign"),
                  "top": [{"domain": x.domain, "technique": x.technique, "risk": x.risk, "status": x.status,
                           "mx": x.has_mx} for x in looks[:10]],
                  "phishing_live": sum(1 for p in phish if p.status in ("new", "reported")),
                  "phishing": [{"url": p.url, "source": p.source, "status": p.status} for p in phish[:10]]},
        "ransomware": [{"group": h.group, "victim": h.victim, "attack_date": h.attack_date.isoformat() if h.attack_date else None,
                        "status": h.status} for h in rw],
        "leaks": {"window_days": LEAK_WINDOW.days, "total": len(leaks),
                  "critical_open": sum(1 for x in leaks if x.severity >= 80 and x.status in _OPEN),
                  "by_source": _count(x.source for x in leaks),
                  "top": [{"id": x.id, "title": x.title or x.source, "source": x.source, "severity": x.severity,
                           "status": x.status, "discovered_at": x.discovered_at.isoformat()} for x in leaks[:10]]},
    }
    report["score"], report["level"], report["factors"] = score(report)
    return report


def _count(it) -> dict:
    out = {}
    for x in it:
        out[x] = out.get(x, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


# ── PDF ──────────────────────────────────────────────────────────────────────

_LEVEL_COLOR = {"critical": colors.HexColor("#c0392b"), "high": colors.HexColor("#d35400"),
                "moderate": colors.HexColor("#b7950b"), "low": colors.HexColor("#1e8449")}


def pdf(r: dict, tenant_name: str) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
                            title=f"Exposure report: {r['domain']}")
    st = getSampleStyleSheet()
    small = st["BodyText"].clone("small", fontSize=8, leading=10)
    h2 = st["Heading2"].clone("h2", spaceBefore=10, spaceAfter=4)
    grid = TableStyle([("FONT", (0, 0), (-1, -1), "Helvetica", 8), ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8),
                       ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef1f5")),
                       ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#c8cfd8")), ("VALIGN", (0, 0), (-1, -1), "TOP")])

    def table(head, rows, widths=None):
        if not rows:
            return Paragraph("None found.", small)
        data = [head] + [[Paragraph(escape(str(c)), small) for c in row] for row in rows]
        t = Table(data, colWidths=widths, repeatRows=1)
        t.setStyle(grid)
        return t

    s, v, b = r["surface"], r["vulns"], r["brand"]
    level_style = st["Heading1"].clone("lvl", textColor=_LEVEL_COLOR[r["level"]])
    story = [
        Paragraph(f"Exposure report: {escape(r['domain'])}", st["Title"]),
        Paragraph(f"{escape(tenant_name)} · generated {r['generated_at'][:16].replace('T', ' ')} UTC", small),
        Spacer(1, 6),
        Paragraph(f"Risk score {r['score']}/100 · {r['level'].upper()}", level_style),
        table(["Contributing factor", "Count", "Points (cap)"],
              [[f["factor"], f["count"], f"{f['points']} ({f['cap']})"] for f in r["factors"]], [110 * mm, 25 * mm, 35 * mm]),
        Paragraph("Summary", h2),
        table(["Area", "Finding"], [
            ["Attack surface", f"{s['hosts']} hosts, {s['live']} live, {s['new_7d']} new this week, {s['open_ports']} open ports"],
            ["Critical/high ports", str(len(s["critical_ports"]))],
            ["TLS", f"{s['tls']['graded']} graded; " + ", ".join(f"{k}: {n}" for k, n in sorted(s["tls"]["distribution"].items()))],
            ["Certificates expiring ≤ 30 days", str(s["certs_expiring"])],
            ["Threat-feed listings", str(s["listed"])],
            ["Open vulnerabilities", f"{v['open']} (KEV {v['by_priority']['critical']}, high {v['by_priority']['high']})"],
            ["Lookalike domains", f"{b['lookalikes']} registered, {b['high_risk']} high risk"],
            ["Live phishing URLs", str(b["phishing_live"])],
            ["Ransomware leak-site mentions", str(len(r["ransomware"]))],
            [f"Leak mentions ({r['leaks']['window_days']} days)", f"{r['leaks']['total']} ({r['leaks']['critical_open']} critical open)"],
        ], [60 * mm, 110 * mm]),
        Paragraph("Critical and high-risk ports", h2),
        table(["Host", "Port", "Service", "Risk", "Why"], [[p["hostname"], p["port"], p["service"], p["risk"], p["why"]]
                                                          for p in s["critical_ports"]]),
        Paragraph("Email and DNS security", h2),
        table(["Check", "Result", "Detail"], [[c["check"], "pass" if c["ok"] else f"FAIL ({c['severity']})", c["detail"]]
                                              for c in s["dns_checks"]], [45 * mm, 30 * mm, 95 * mm]),
        Paragraph("Weak TLS endpoints", h2),
        table(["Host", "Grade", "Main issue"], [[x["hostname"], x["grade"], x["issue"]] for x in s["tls"]["failing_hosts"]]),
        Paragraph("Top vulnerabilities", h2),
        table(["CVE", "Host", "Priority", "KEV", "EPSS"], [[x["cve"], x["host"], x["priority"], "yes" if x["kev"] else "no",
                                                           f"{x['epss'] * 100:.1f}%" if x["epss"] is not None else "—"] for x in v["top"]]),
        Paragraph("Lookalike domains", h2),
        table(["Domain", "Technique", "Risk", "Mail", "Status"], [[x["domain"], x["technique"], x["risk"], "yes" if x["mx"] else "no",
                                                                  x["status"]] for x in b["top"]]),
        Paragraph("Ransomware leak-site mentions", h2),
        table(["Group", "Victim", "Attack date", "Status"], [[x["group"], x["victim"], (x["attack_date"] or "—")[:10], x["status"]]
                                                            for x in r["ransomware"]]),
        Paragraph("Recent attack-surface changes", h2),
        table(["When", "Subject", "Change"], [[x["at"][:16].replace("T", " "), x["subject"], x["detail"]] for x in s["recent_changes"]],
              [30 * mm, 50 * mm, 90 * mm]),
        Spacer(1, 8),
        Paragraph("Sources: certificate transparency, passive DNS, Shodan InternetDB, CISA KEV, FIRST EPSS, abuse.ch, "
                  "OpenPhish, PhishStats, ransomware.live, RansomLook and SecYourScan's own collectors. "
                  "Findings are automated; verify before acting.", small),
    ]
    doc.build(story)
    return buf.getvalue()
