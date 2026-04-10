#!/bin/sh
# ─── Heimdall DFIR — Application des migrations SQL ─────────────────────────
# Usage : sh db/run_migrations.sh
# Prérequis : le conteneur 'yggdrasil' (PostgreSQL) doit être en cours d'exécution.
set -e

cd "$(dirname "$0")/.."

run() {
    local f="$1"
    if [ -f "$f" ]; then
        echo "▶ $(basename $f)"
        docker exec -i yggdrasil psql -U forensiclab forensiclab < "$f" 2>/dev/null || \
            echo "  ⚠ Ignorée (déjà appliquée ou non applicable)"
    else
        echo "  ⚠ Fichier introuvable : $f"
    fi
}

echo "=== Migrations v2.x ==="
run db/migrate_v2.7.sql
run db/migrate_v2.8.sql
run db/migrate_v2.9.sql
run db/migrate_v2.10.sql
run db/migrate_v2.11.sql
run db/migrate_v2.12.sql
run db/migrate_v2.13.sql
run db/migrate_v2.14.sql
run db/migrate_v2.15.sql
run db/migrate_v2.16.sql
run db/migrate_v2.17.sql
run db/migrate_v2.18.sql
run db/migrate_v2.19.sql
run db/migrate_v2.20.sql
run db/migrate_v2.21.sql
run db/migrate_v2.22.sql

echo ""
echo "=== Migrations numérotées (features) ==="
for f in db/migrations/0*.sql db/migrations/2*.sql; do
    run "$f"
done

echo ""
echo "✓ Toutes les migrations ont été appliquées."
