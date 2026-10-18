#!/usr/bin/env sh
# SecYourScan on-prem installer.
#
#   ./scripts/install.sh --admin-email secops@customer.com [--license-key SYS1....] [--public-host scan.customer.com]
#
# Needs Docker with the compose plugin and Python 3 (for secret generation).
# Safe to re-run: existing secrets are kept, containers are updated in place.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

ADMIN_EMAIL=""
LICENSE_KEY=""
PUBLIC_HOST=""
while [ $# -gt 0 ]; do
  case "$1" in
    --admin-email) ADMIN_EMAIL="$2"; shift 2 ;;
    --license-key) LICENSE_KEY="$2"; shift 2 ;;
    --public-host) PUBLIC_HOST="$2"; shift 2 ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mError:\033[0m %s\n' "$*" >&2; exit 1; }

say "Checking prerequisites"
command -v docker >/dev/null 2>&1 || die "Docker is not installed (https://docs.docker.com/engine/install/)"
docker compose version >/dev/null 2>&1 || die "The Docker compose plugin is missing"
command -v python3 >/dev/null 2>&1 || die "python3 is required to generate secrets"
python3 -c "import cryptography" 2>/dev/null || die "python3 needs the 'cryptography' package: pip3 install cryptography"
MEM_KB=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
[ "$MEM_KB" -eq 0 ] || [ "$MEM_KB" -ge 7500000 ] || echo "Warning: less than 8 GB RAM; Elasticsearch may struggle." >&2

if [ ! -f .env ]; then
  [ -n "$ADMIN_EMAIL" ] || die "First install: pass --admin-email"
  say "Generating secrets"
  python3 scripts/gen_secrets.py --admin-email "$ADMIN_EMAIL"
else
  say "Keeping existing .env and secrets"
fi

set_env() {  # set_env NAME VALUE — replace or append a line in .env
  if grep -q "^$1=" .env; then
    python3 - "$1" "$2" <<'PY'
import sys, pathlib
name, value = sys.argv[1], sys.argv[2]
p = pathlib.Path(".env")
p.write_text("\n".join(f"{name}={value}" if l.startswith(f"{name}=") else l for l in p.read_text().splitlines()) + "\n")
PY
  else
    printf '%s=%s\n' "$1" "$2" >> .env
  fi
}
[ -z "$LICENSE_KEY" ] || { say "Installing licence"; set_env LICENSE_KEY "$LICENSE_KEY"; }
if [ -n "$PUBLIC_HOST" ]; then
  set_env CORS_ORIGINS "https://$PUBLIC_HOST"
  set_env ALLOWED_HOSTS "$PUBLIC_HOST,localhost"
  set_env COOKIE_SECURE true
fi

say "Building and starting containers (first run takes several minutes)"
docker compose up -d --build

say "Waiting for the API"
i=0
until curl -fsS http://127.0.0.1:8080/system/status 2>/dev/null | grep -q operational; do
  i=$((i + 1)); [ "$i" -lt 90 ] || die "API did not become healthy; see: docker compose logs api"
  sleep 4
done

ADMIN=$(grep '^ADMIN_EMAIL=' .env | cut -d= -f2-)
say "SecYourScan is running"
echo "  URL:    http://127.0.0.1:8080  (put your TLS reverse proxy in front for ${PUBLIC_HOST:-production})"
echo "  Login:  $ADMIN  — password is ADMIN_PASSWORD in .env; change it after first sign-in"
echo "  Next:   Domains → add and verify your root domains, then Watchlist → add your assets"
