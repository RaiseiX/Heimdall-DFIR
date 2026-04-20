#!/bin/bash
# ─── Default users initialisation ────────────────────────────────────────────
# Reads ADMIN_DEFAULT_PASSWORD and ANALYST_DEFAULT_PASSWORD from the environment.
# If not set, generates a random password and prints it to the container logs.
# Set these variables in your .env before first launch.
set -e

ADMIN_PWD="${ADMIN_DEFAULT_PASSWORD:-}"
ANALYST_PWD="${ANALYST_DEFAULT_PASSWORD:-}"

if [ -z "$ADMIN_PWD" ]; then
  ADMIN_PWD=$(openssl rand -hex 16)
  echo "⚠  ADMIN_DEFAULT_PASSWORD not set — generated random password: $ADMIN_PWD"
  echo "   → Save this now, it will NOT be shown again."
fi

if [ -z "$ANALYST_PWD" ]; then
  ANALYST_PWD=$(openssl rand -hex 16)
  echo "⚠  ANALYST_DEFAULT_PASSWORD not set — generated random password: $ANALYST_PWD"
  echo "   → Save this now, it will NOT be shown again."
fi

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --variable="admin_pwd=$ADMIN_PWD" \
  --variable="analyst_pwd=$ANALYST_PWD" <<-EOSQL
    INSERT INTO users (username, email, password_hash, full_name, role) VALUES
    ('admin',   'admin@forensiclab.local',   crypt(:'admin_pwd',   gen_salt('bf')), 'Administrateur',      'admin'),
    ('analyst', 'analyst@forensiclab.local', crypt(:'analyst_pwd', gen_salt('bf')), 'Analyste Forensique', 'analyst')
    ON CONFLICT (username) DO NOTHING;
EOSQL

echo "✓ Default users initialized"
