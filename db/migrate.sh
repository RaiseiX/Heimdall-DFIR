#!/bin/bash
# ─── Heimdall DFIR — Migration Runner ────────────────────────────────────────
# Usage standalone : bash db/migrate.sh
# Usage from start.sh : called automatically at step [5/7]
#
# How it works:
#   - Creates the schema_migrations tracking table if absent (idempotent)
#   - For each SQL file (strict order): skip if already recorded, otherwise apply
#   - On real failure: prints the error and stops (no silent migration)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

cd "$(dirname "$0")/.."

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

# ─── Load PGPASSWORD from .env if not already set ────────────────────────────
# Required on systems where pg_hba.conf uses password auth for local connections.
if [ -z "${PGPASSWORD:-}" ] && [ -f .env ]; then
    PGPASSWORD=$(grep "^DB_PASSWORD=" .env | cut -d= -f2-)
    export PGPASSWORD
fi

psql_exec() {
    docker compose exec -T db psql -U forensiclab forensiclab "$@"
}

# ─── Wait for init.sql to complete ───────────────────────────────────────────
# Phase 1: wait until PostgreSQL accepts connections (up to 40s).
echo -e "${CYAN}  Waiting for database schema (init.sql)...${NC}"
for i in $(seq 1 20); do
    if psql_exec -t -c "SELECT 1;" > /dev/null 2>&1; then break; fi
    if [ "$i" -eq 20 ]; then
        echo -e "${RED}  ❌ Cannot connect to PostgreSQL after 40s.${NC}"
        echo -e "${RED}     Check: docker compose logs db${NC}"
        exit 1
    fi
    sleep 2
done

# Phase 2: wait until the 'users' table appears (fresh install: init.sql is
# still running). Give it up to 90s; if the DB is already reachable but the
# table never appears it means init.sql failed — we fail fast after 10s.
_can_connect=1
for i in $(seq 1 45); do
    if psql_exec -t -c "SELECT 1 FROM users LIMIT 1;" > /dev/null 2>&1; then
        _can_connect=0
        break
    fi
    # After 10s of connectivity with no users table → init.sql failed, don't
    # wait the full 90s.
    if [ "$i" -ge 5 ] && psql_exec -t -c "SELECT 1;" > /dev/null 2>&1; then
        _can_connect=0
        _table_count=$(psql_exec -t -c \
            "SELECT count(*) FROM information_schema.tables WHERE table_schema='public';" \
            2>/dev/null | tr -d '[:space:]')
        if [ "${_table_count:-0}" -gt 0 ]; then
            echo -e "${RED}"
            echo "  ❌ Database is reachable but the 'users' table is missing."
            echo "     init.sql failed or was only partially applied."
            echo ""
            echo "  ── To reset and reinstall (WARNING: deletes all data) ──────"
            echo "     docker compose down -v"
            echo "     bash start.sh"
            echo ""
            echo "  ── To re-run init.sql on an existing volume ─────────────────"
            echo "     docker compose exec db psql -U forensiclab forensiclab \\"
            echo "       < db/init.sql"
            echo "     bash db/migrate.sh"
            echo -e "${NC}"
            exit 1
        fi
    fi
    if [ "$i" -eq 45 ]; then
        echo -e "${RED}  ❌ Database schema not ready after 90s.${NC}"
        echo -e "${RED}     Check: docker compose logs db${NC}"
        exit 1
    fi
    sleep 2
done

echo -e "${CYAN}  Initializing migration runner...${NC}"

psql_exec -c "
CREATE TABLE IF NOT EXISTS schema_migrations (
    filename   TEXT        PRIMARY KEY,
    applied_at TIMESTAMPTZ DEFAULT NOW()
);" > /dev/null 2>&1

run() {
    local file="$1"
    local name
    name=$(basename "$file")

    if [ ! -f "$file" ]; then
        return 0
    fi

    local count
    count=$(psql_exec -t -c "SELECT COUNT(*) FROM schema_migrations WHERE filename='${name}';" 2>/dev/null | tr -d '[:space:]')
    if [ "${count:-0}" -gt 0 ]; then
        echo -e "  ${YELLOW}⏭  ${name}${NC}"
        return 0
    fi

    echo -e "  ▶  ${name}"
    local output
    if output=$(docker compose exec -T db psql -U forensiclab forensiclab -v ON_ERROR_STOP=1 < "$file" 2>&1); then
        psql_exec -c "INSERT INTO schema_migrations(filename) VALUES('${name}');" > /dev/null 2>&1
        echo -e "  ${GREEN}✓  ${name}${NC}"
    else
        echo -e "  ${RED}❌  Failed : ${name}${NC}"
        echo -e "  ${RED}   Error details:${NC}"
        echo "$output" | sed 's/^/     /'
        echo ""
        echo -e "  ${RED}   To force-skip if already applied manually :${NC}"
        echo "     docker compose exec db psql -U forensiclab forensiclab \\"
        echo "       -c \"INSERT INTO schema_migrations(filename) VALUES('${name}') ON CONFLICT DO NOTHING;\""
        exit 1
    fi
}

echo ""
echo -e "${CYAN}  Running v2.x migrations${NC}"
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
echo -e "${CYAN}  Running feature migrations${NC}"
for f in $(find db/migrations -name "*.sql" 2>/dev/null | sort); do
    run "$f"
done

echo ""
echo -e "${GREEN}  ✓ All migrations are up to date.${NC}"
