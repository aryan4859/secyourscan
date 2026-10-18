"""Generate .env and the JWT signing key. Refuses to overwrite either.

    python scripts/gen_secrets.py --admin-email you@yourcompany.com
"""

import argparse
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--admin-email", default="admin@secyourscan.example.com")
    args = parser.parse_args()

    env_path = ROOT / ".env"
    key_path = ROOT / "secrets" / "jwt_private_key.pem"
    if env_path.exists() or key_path.exists():
        sys.exit(f"Refusing to overwrite {env_path} / {key_path}; delete them first if you mean it.")

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key_path.parent.mkdir(exist_ok=True)
    pem = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    key_path.write_bytes(pem)

    admin_password = secrets.token_urlsafe(18)
    template = (ROOT / ".env.example").read_text(encoding="utf-8")
    values = {
        "POSTGRES_PASSWORD": secrets.token_urlsafe(24),
        "RABBITMQ_PASS": secrets.token_urlsafe(24),
        "ES_PASSWORD": secrets.token_urlsafe(24),
        "MINIO_ACCESS_KEY": "sys" + secrets.token_hex(6),
        "MINIO_SECRET_KEY": secrets.token_urlsafe(30),
        "ADMIN_EMAIL": args.admin_email,
        "ADMIN_PASSWORD": admin_password,
    }
    lines = []
    for line in template.splitlines():
        name = line.split("=", 1)[0].strip()
        lines.append(f"{name}={values[name]}" if name in values and "=" in line else line)
    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {env_path} and {key_path}")
    print(f"Admin login: {args.admin_email}  (password is ADMIN_PASSWORD in .env; change it after first sign-in)")


if __name__ == "__main__":
    main()
