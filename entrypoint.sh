#!/bin/sh
# init what is missing, never overwrite existing data, then start Apache
# runs as www-data; pa-automation-init service chowns data/ and jobs/ first
set -e
APP=/var/www/html
DATA=$APP/data

for d in "$DATA" "$APP/jobs"; do
    if [ ! -w "$d" ]; then
        echo "[init] ERROR: $d is not writable by $(id -un) (uid $(id -u)). Start with 'docker compose up -d'" \
             "(service pa-automation-init sets the owner) or run: chown -R 33:33 data jobs" >&2
        exit 1
    fi
done
umask 077
mkdir -p "$DATA/ssl"
# /run is tmpfs, recreate Apache runtime dirs
mkdir -p /run/lock /run/apache2

# --- env settings to data/runtime.json, mod_wsgi can't see the container env
#     validated before anything is created; empty = default, invalid = exit
python3 - <<'PYEOF'
import json, math, os, re, sys

errors = []

def env(name, default):
    value = os.environ.get(name, '').strip()
    return value if value else default

def show(value):
    return repr(value if len(value) <= 60 else value[:60] + '...')

def number(name, default, low, high=None, whole=True, example=''):
    raw = env(name, str(default))
    try:
        value = int(raw) if whole else float(raw)
        if not math.isfinite(value) or value < low or (high is not None and value > high):   # nan passes range checks
            raise ValueError
        return value
    except ValueError:
        kind = 'a whole number' if whole else 'a number'
        limits = f' between {low:g} and {high:g}' if high is not None else f' >= {low:g}'
        errors.append(f'{name}={show(raw)}: must be {kind}{limits} (e.g. {example or default})')
        return default

debug = env('APP_DEBUG', '0')
if debug not in ('0', '1'):
    errors.append(f'APP_DEBUG={show(debug)}: must be 0 or 1')

hosts = [h.strip() for h in env('APP_ALLOWED_HOSTS', '*').split(',') if h.strip()]
bad_hosts = [h for h in hosts if not re.fullmatch(r'[A-Za-z0-9.:*\[\]-]+', h)]
if bad_hosts:
    errors.append(f'APP_ALLOWED_HOSTS: invalid host name / IP {show(bad_hosts[0])} (comma separated, e.g. 10.0.0.5,pa-auto.local or *)')

cert_cn = env('APP_CERT_CN', 'pa-automation')
if not re.fullmatch(r'[A-Za-z0-9.-]{1,64}', cert_cn):
    errors.append(f'APP_CERT_CN={show(cert_cn)}: letters, digits, "." and "-" only, max 64 (e.g. pa-automation.example.com)')

ca_bundle = env('APP_PANOS_CA_BUNDLE', '')
if ca_bundle and not os.path.isfile(ca_bundle):
    errors.append(f'APP_PANOS_CA_BUNDLE={show(ca_bundle)}: file not found inside the container (mount it in volumes:, or leave empty)')

cfg = {
    'DEBUG': debug == '1',
    'ALLOWED_HOSTS': hosts or ['*'],
    'TZ_OFFSET_HOURS': number('APP_TZ_OFFSET_HOURS', 7, -12, 14, whole=False, example='7 or 5.5'),
    'LOGIN_FAILURE_LIMIT': number('APP_LOGIN_FAILURE_LIMIT', 5, 1),
    'LOGIN_COOLOFF_MINUTES': number('APP_LOGIN_COOLOFF_MINUTES', 15, 1),
    'HSTS_SECONDS': number('APP_HSTS_SECONDS', 0, 0, example='31536000'),
    'MIN_FREE_DISK_MB': number('APP_MIN_FREE_DISK_MB', 100, 0),
    'JOB_MAX_SIZE_MB': number('APP_JOB_MAX_SIZE_MB', 1024, 0),
    'PANOS_CA_BUNDLE': ca_bundle,
}
if errors:
    print('[init] ERROR: invalid settings in docker-compose.yml (environment:), container not started:', file=sys.stderr)
    for e in errors:
        print('[init]   ' + e, file=sys.stderr)
    print('[init] Fix them, then run: docker compose up -d', file=sys.stderr)
    sys.exit(1)
if not os.environ.get('APP_ALLOWED_HOSTS', '').strip():
    print("[init] WARNING: APP_ALLOWED_HOSTS is empty, using '*' (any host name). Set the host names / IPs of the tool (README).")
with open(os.environ.get('APP_RUNTIME_FILE', '/var/www/html/data/runtime.json'), 'w', encoding='utf-8') as f:
    json.dump(cfg, f)
PYEOF
CERT_CN=$(printf '%s' "${APP_CERT_CN:-}" | tr -d '[:space:]')
[ -n "$CERT_CN" ] || CERT_CN=pa-automation

# --- self-signed cert, per installation
if [ ! -s "$DATA/ssl/server.crt" ] || [ ! -s "$DATA/ssl/server.key" ]; then
    echo "[init] generate self-signed certificate"
    openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
        -keyout "$DATA/ssl/server.key" -out "$DATA/ssl/server.crt" \
        -subj "/CN=$CERT_CN" \
        -addext "subjectAltName=DNS:$CERT_CN" \
        -addext "basicConstraints=critical,CA:FALSE" \
        -addext "extendedKeyUsage=serverAuth" 2>/dev/null
fi
chmod 700 "$DATA/ssl"
chmod 600 "$DATA/ssl/server.key"

# --- Django SECRET_KEY
if [ ! -s "$DATA/secret_key" ]; then
    echo "[init] generate secret key"
    python3 -c 'import secrets; print(secrets.token_urlsafe(50))' > "$DATA/secret_key"
fi
chmod 600 "$DATA/secret_key"

# password hashes, secret key, firewall details: app user only
chmod 700 "$DATA" "$APP/jobs"
chmod 600 "$DATA/runtime.json"

# --- DB schema; admin/admin only created when no web user exists
#     deleting all users brings admin/admin back for recovery
/opt/venv/bin/python "$APP/manage.py" migrate --noinput | tail -1
chmod 600 "$DATA/db.sqlite3"
/opt/venv/bin/python "$APP/manage.py" shell -c "from django.contrib.auth.models import User; User.objects.exists() or (User.objects.create_superuser('admin', 'admin@localhost', 'admin'), print('[init] created default web user admin / admin - CHANGE IT'))"

find "$APP/jobs" -type f -exec chmod 600 {} +

exec apache2ctl -D FOREGROUND
