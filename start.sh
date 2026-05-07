#!/bin/bash
# Boot atuin-server for OpenHost.
#
# Topology:
#
#   browser/CLI → OpenHost outer Caddy (TLS termination)
#              → OpenHost router (subdomain atuin.<zone>)
#              → container :8080  (auth_proxy.py — owner-gate sidecar
#                                  for /register; pass-through for
#                                  CLI traffic)
#              → 127.0.0.1:8888   (atuin-server)
#
# Atuin clients use the same hostname as a browser would: when a
# user runs `atuin login --username ... --password ... --key ...
# --server-url https://atuin.<zone>` the client speaks HTTPS to
# the OpenHost outer Caddy and uses its own bearer-token auth
# (stored client-side after register/login).
#
# Registration is gated to the zone owner: /register is NOT in
# openhost.toml's public_paths list, so only the zone owner can
# reach it.  Once the owner has registered their own atuin
# account, they have a token they can use from any device.

set -euo pipefail

PERSIST="${OPENHOST_APP_DATA_DIR:-/data/app_data/atuin}"
DB_PATH="$PERSIST/atuin.db"
CONFIG_PATH="$PERSIST/server.toml"

mkdir -p "$PERSIST"

# Render server config on each boot so changes to openhost.toml take
# effect when the app reloads.
cat > "$CONFIG_PATH" <<EOF
host = "127.0.0.1"
port = 8888

# We keep open_registration true on the atuin-server itself so that
# registration is technically permitted; the OpenHost router gate
# in front (which only forwards /register requests when the caller
# has a verified owner JWT) is what actually keeps the server
# single-tenant.  We don't pin it to false because that would also
# block the owner.
open_registration = true

db_uri = "sqlite://$DB_PATH"
path = ""

# The default behaviour is to reject sessions older than 'max_history_length'.
# Since this server is intended to be private, we don't need to be paranoid;
# leave it at the default.
EOF

export ATUIN_CONFIG_DIR="$PERSIST"
export ATUIN_HOST="127.0.0.1"
export ATUIN_PORT="8888"
export ATUIN_DB_URI="sqlite://$DB_PATH"
export ATUIN_OPEN_REGISTRATION="true"

# -----------------------------------------------------------------
# Launch atuin-server
# -----------------------------------------------------------------
echo "[start.sh] Starting atuin-server on 127.0.0.1:8888 (db=$DB_PATH)"
/usr/local/bin/atuin-server start &
ATUIN_PID=$!

# -----------------------------------------------------------------
# Launch auth-proxy
# -----------------------------------------------------------------
echo "[start.sh] Starting auth-proxy on 0.0.0.0:8080 -> 127.0.0.1:8888"
AUTH_PROXY_LISTEN_PORT="${AUTH_PROXY_LISTEN_PORT:-8080}" \
  AUTH_PROXY_UPSTREAM_HOST="127.0.0.1" \
  AUTH_PROXY_UPSTREAM_PORT="8888" \
  python3 /opt/openhost-atuin/auth_proxy.py &
PROXY_PID=$!

# -----------------------------------------------------------------
# Supervision
# -----------------------------------------------------------------
trap 'kill -TERM "$ATUIN_PID" "$PROXY_PID" 2>/dev/null; wait' TERM INT

set +e
wait -n "$ATUIN_PID" "$PROXY_PID"
EXIT_CODE=$?
set -e

echo "[start.sh] Child exited (code=$EXIT_CODE); shutting down"
kill -TERM "$ATUIN_PID" "$PROXY_PID" 2>/dev/null || true
wait || true
exit "$EXIT_CODE"
