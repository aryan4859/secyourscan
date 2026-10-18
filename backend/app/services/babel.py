"""Babel extractor: entities out of breach text in any script.

Regex extraction of emails, domains, IPv4, Bitcoin and Monero wallets, phone
numbers, payment cards (Luhn-checked) and ``identifier:password`` pairs, plus a
script-detection pass (which writing systems the text uses — a cheap signal
for where a dump came from). Also produces the masked text that is stored and
displayed: passwords, card numbers and private keys never leave object
storage unmasked.
"""

import ipaddress
import re
import unicodedata
from collections import Counter

EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}(?![\w-])")
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
BTC_RE = re.compile(r"(?<![A-Za-z0-9])(?:bc1[ac-hj-np-z02-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})(?![A-Za-z0-9])")
XMR_RE = re.compile(r"(?<![A-Za-z0-9])4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}(?![A-Za-z0-9])")
CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
PHONE_RE = re.compile(r"(?<![\w+])\+\d{1,3}[\s.-]?\(?\d{1,4}\)?(?:[\s.-]?\d{2,4}){2,4}(?!\d)")
DOMAIN_RE = re.compile(r"(?<![\w@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})(?![\w-])", re.I)
ONION_RE = re.compile(r"\b[a-z2-7]{56}\.onion\b", re.I)
# identifier:password or identifier;password or identifier|password, one per line
CRED_RE = re.compile(r"^\s*([^\s:;|]{3,255})\s*[:;|]\s*(\S{4,128})\s*$", re.M)
KV_SECRET_RE = re.compile(r"(?i)\b(pass(?:word|wd)?|pwd|secret|token|api[_-]?key)\b(\s*[:=]\s*)(['\"]?)([^\s'\"]{4,})\3")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z ]+ )?PRIVATE KEY-----", re.S)

_FILE_TLDS = {"txt", "csv", "sql", "zip", "rar", "png", "jpg", "html", "php", "js", "json", "xml", "log", "exe", "py"}
_MAX_PER_TYPE = 500


def _luhn(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _uniq(items, limit=_MAX_PER_TYPE) -> list[str]:
    return list(dict.fromkeys(items))[:limit]


def _valid_ipv4(s: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(s)
    except ValueError:
        return False
    return not (ip.is_unspecified or ip.is_loopback)


def mask_secret(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return f"{value[0]}{'*' * min(len(value) - 2, 12)}{value[-1]}"


def detect_scripts(text: str, sample: int = 20000) -> dict[str, float]:
    counts: Counter = Counter()
    for ch in text[:sample]:
        if ch.isalpha():
            try:
                name = unicodedata.name(ch)
            except ValueError:
                continue
            counts[name.split(" ", 1)[0]] += 1
    total = sum(counts.values()) or 1
    return {k: round(v / total, 3) for k, v in counts.most_common(5)}


def extract(text: str) -> dict:
    emails = _uniq(e.lower() for e in EMAIL_RE.findall(text))
    email_domains = {e.split("@", 1)[1] for e in emails}

    domains = []
    for d in DOMAIN_RE.findall(text):
        d = d.lower()
        if d.rsplit(".", 1)[-1] in _FILE_TLDS or d in email_domains or IPV4_RE.fullmatch(d):
            continue
        domains.append(d)

    cards = []
    for m in CARD_RE.findall(text):
        digits = re.sub(r"\D", "", m)
        if 13 <= len(digits) <= 19 and _luhn(digits) and len(set(digits)) > 1:
            cards.append(f"{digits[:6]}{'*' * (len(digits) - 10)}{digits[-4:]}")

    credentials = []
    for ident, pwd in CRED_RE.findall(text):
        if ident.lower().startswith(("http", "https")) or pwd.startswith("//"):
            continue
        credentials.append({"identifier": ident.lower(), "password_masked": mask_secret(pwd), "password_length": len(pwd)})

    return {
        "emails": emails,
        "domains": _uniq(sorted(email_domains) + domains),
        "ips": _uniq(ip for ip in IPV4_RE.findall(text) if _valid_ipv4(ip)),
        "btc_wallets": _uniq(BTC_RE.findall(text)),
        "xmr_wallets": _uniq(XMR_RE.findall(text)),
        "onions": _uniq(o.lower() for o in ONION_RE.findall(text)),
        "phones": _uniq(PHONE_RE.findall(text)),
        "cards": _uniq(cards),
        "credentials": credentials[:_MAX_PER_TYPE],
        "credential_count": len(credentials),
        "has_private_key": bool(PRIVATE_KEY_RE.search(text)),
        "scripts": detect_scripts(text),
    }


def mask_text(text: str) -> str:
    """The display copy: secrets replaced, structure kept."""
    out = PRIVATE_KEY_RE.sub("-----BEGIN PRIVATE KEY-----\n[redacted]\n-----END PRIVATE KEY-----", text)
    out = KV_SECRET_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}{mask_secret(m.group(4))}{m.group(3)}", out)
    out = CRED_RE.sub(lambda m: m.group(0).replace(m.group(2), mask_secret(m.group(2))), out)

    def _card(m: re.Match) -> str:
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn(digits) and len(set(digits)) > 1:
            return f"{digits[:6]}{'*' * (len(digits) - 10)}{digits[-4:]}"
        return m.group(0)

    return CARD_RE.sub(_card, out)
