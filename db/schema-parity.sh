#!/usr/bin/env bash
set -uo pipefail

cd "$(dirname "$0")/.." || exit 2
export LC_ALL=C

EXPECTED="db/schema.columns"
[ -f "$EXPECTED" ] || { echo "Référence absente : ${EXPECTED}" >&2; exit 2; }

actual="$(docker compose exec -T db psql -U forensiclab -d forensiclab -At -c "SELECT table_name || '.' || column_name FROM information_schema.columns WHERE table_schema = 'public'" 2>/dev/null)" \
    || { echo "Lecture du schéma impossible" >&2; exit 2; }
[ -n "$actual" ] || { echo "Lecture du schéma impossible" >&2; exit 2; }

missing="$(comm -23 <(grep -v '^[[:space:]]*$' "$EXPECTED" | sort -u) <(printf '%s\n' "$actual" | sed '/^[[:space:]]*$/d' | sort -u))"
if [ -n "$missing" ]; then
    printf '%s\n' "$missing"
    exit 1
fi
exit 0
