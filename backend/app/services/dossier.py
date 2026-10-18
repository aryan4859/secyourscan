"""Signed PDF dossier of a tenant's exposures.

The PDF lists each leak's source, timestamps, severity, matched watch items,
YARA rules and SHA-256 of the raw evidence — never the secrets themselves.
The SHA-256 of the finished PDF is signed with Ed25519; the signature is
returned in ``X-Dossier-Signature`` and the public key is served at
``/leaks/export/public-key`` so a recipient can verify it was not altered.
"""

import base64
import hashlib
import io
from datetime import UTC, datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from xml.sax.saxutils import escape

from ..config import settings
from ..security import _read_pem, signing_keys


def _signing_key() -> Ed25519PrivateKey:
    pem = _read_pem(settings.DOSSIER_SIGNING_KEY)
    if pem:
        key = serialization.load_pem_private_key(pem, password=None)
        if isinstance(key, Ed25519PrivateKey):
            return key
        raise ValueError("DOSSIER_SIGNING_KEY must be an Ed25519 key")
    return signing_keys()[0]


def public_key_pem() -> str:
    return _signing_key().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def build_pdf(tenant_name: str, leaks: list, generated_by: str) -> tuple[bytes, str, str]:
    """Return ``(pdf_bytes, sha256_hex, base64_signature)``."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm,
                            bottomMargin=15 * mm, title=f"Exposure dossier - {tenant_name}")
    styles = getSampleStyleSheet()
    small = styles["BodyText"].clone("small", fontSize=7.5, leading=9)
    story = [
        Paragraph(f"Exposure dossier: {escape(tenant_name)}", styles["Title"]),
        Paragraph(
            f"Generated {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')} by {escape(generated_by)}. "
            f"{len(leaks)} records. Secrets are masked; raw evidence is identified by SHA-256.",
            styles["BodyText"],
        ),
        Spacer(1, 6 * mm),
    ]
    rows = [["Discovered", "Sev", "Source", "Matched", "Rules", "Status", "SHA-256"]]
    for lk in leaks:
        rows.append([
            Paragraph(lk.discovered_at.strftime("%Y-%m-%d %H:%M"), small),
            str(lk.severity),
            Paragraph(escape(f"{lk.source} {lk.source_url or ''}")[:160], small),
            Paragraph(escape(", ".join(m["value"] for m in lk.watch_matches or []))[:120], small),
            Paragraph(escape(", ".join(m["rule"] for m in lk.yara_matches or []))[:120], small),
            lk.status,
            Paragraph(lk.sha256, small),
        ])
    table = Table(rows, repeatRows=1, colWidths=[22 * mm, 9 * mm, 38 * mm, 32 * mm, 28 * mm, 17 * mm, 34 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#9ca3af")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]),
    ]))
    story.append(table)
    doc.build(story)
    pdf = buf.getvalue()
    digest = hashlib.sha256(pdf).digest()
    signature = base64.b64encode(_signing_key().sign(digest)).decode()
    return pdf, digest.hex(), signature
