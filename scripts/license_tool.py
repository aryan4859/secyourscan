"""Vendor-side licence tool. Keep the private key OFF customer machines.

    python scripts/license_tool.py keygen --out vendor_license_key.pem
        → writes the private key; prints LICENSE_PUBLIC_KEY for your release builds

    python scripts/license_tool.py issue --key vendor_license_key.pem \\
        --customer "Acme Bank" --days 365 --max-domains 5
        → prints a LICENSE_KEY to give the customer

    python scripts/license_tool.py show <LICENSE_KEY> --public-key <LICENSE_PUBLIC_KEY>
        → verifies and prints a licence
"""

import argparse
import base64
import json
import sys
from datetime import date, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

PREFIX = "SYS1"


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def public_b64(key: Ed25519PrivateKey) -> str:
    return b64e(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def keygen(args) -> None:
    out = Path(args.out)
    if out.exists():
        sys.exit(f"Refusing to overwrite {out}")
    key = Ed25519PrivateKey.generate()
    out.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
    print(f"Private key written to {out} — store it in your vault, never ship it.")
    print(f"LICENSE_PUBLIC_KEY={public_b64(key)}")


def issue(token_payload: dict, key: Ed25519PrivateKey) -> str:
    payload_b64 = b64e(json.dumps(token_payload, separators=(",", ":"), sort_keys=True).encode())
    sig = key.sign(f"{PREFIX}.{payload_b64}".encode())
    return f"{PREFIX}.{payload_b64}.{b64e(sig)}"


def cmd_issue(args) -> None:
    key = serialization.load_pem_private_key(Path(args.key).read_bytes(), password=None)
    payload = {"customer": args.customer, "issued": date.today().isoformat(),
               "expires": (date.today() + timedelta(days=args.days)).isoformat(),
               "max_domains": args.max_domains, "features": args.features.split(",") if args.features else []}
    print(f"LICENSE_KEY={issue(payload, key)}")


def cmd_show(args) -> None:
    prefix, payload_b64, sig_b64 = args.token.split(".")
    Ed25519PublicKey.from_public_bytes(b64d(args.public_key)).verify(b64d(sig_b64), f"{prefix}.{payload_b64}".encode())
    print(json.dumps(json.loads(b64d(payload_b64)), indent=2))


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("--out", default="vendor_license_key.pem")
    i = sub.add_parser("issue")
    i.add_argument("--key", required=True)
    i.add_argument("--customer", required=True)
    i.add_argument("--days", type=int, default=365)
    i.add_argument("--max-domains", type=int, default=5)
    i.add_argument("--features", default="")
    s = sub.add_parser("show")
    s.add_argument("token")
    s.add_argument("--public-key", required=True)
    args = p.parse_args()
    {"keygen": keygen, "issue": cmd_issue, "show": cmd_show}[args.cmd](args)


if __name__ == "__main__":
    main()
