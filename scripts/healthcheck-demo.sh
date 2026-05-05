#!/usr/bin/env bash
# healthcheck-demo.sh — Heimdall DFIR Pre-Demo Health Verification
#
# Checks all critical services are healthy before the presentation.
# Outputs ✅/❌ per check and exits with code 1 if any check fails.
#
# Usage:
#   bash scripts/healthcheck-demo.sh
#   # or from project root:
#   chmod +x scripts/healthcheck-demo.sh && ./scripts/healthcheck-demo.sh

set -euo pipefail

PASS=0
FAIL=0
ERRORS=()

# ── Color helpers ──────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
RESET='\033[0m'
BOLD='\033[1m'

ok()   { echo -e "${GREEN}  ✅ $1${RESET}"; PASS=$((PASS + 1)); }
fail() { echo -e "${RED}  ❌ $1${RESET}"; FAIL=$((FAIL + 1)); ERRORS+=("$1"); }
info() { echo -e "${YELLOW}  ℹ  $1${RESET}"; }

# ── Config (override via env if needed) ───────────────────────────────────────
BACKEND_URL="${BACKEND_URL:-http://localhost}"
FRONTEND_URL="${FRONTEND_URL:-http://localhost}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║   Heimdall DFIR — Healthcheck Pré-Démo      ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════╝${RESET}"
echo ""

# ─── 1. Docker containers ─────────────────────────────────────────────────────
echo -e "${BOLD}[1/7] Docker Containers${RESET}"

REQUIRED_SERVICES=("traefik" "frontend" "backend" "pgbouncer" "db" "redis" "elasticsearch" "worker")

for svc in "${REQUIRED_SERVICES[@]}"; do
  STATUS=$(docker compose -f "${COMPOSE_FILE}" ps --format json "${svc}" 2>/dev/null \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('State','') if isinstance(d,dict) else d[0].get('State',''))" 2>/dev/null \
    || docker compose -f "${COMPOSE_FILE}" ps "${svc}" 2>/dev/null | grep -E "Up|running" -c || echo "0")
  if echo "${STATUS}" | grep -qiE "running|up|1"; then
    ok "Container '${svc}' is running"
  else
    fail "Container '${svc}' is NOT running"
  fi
done

# ─── 2. PostgreSQL ────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}[2/7] PostgreSQL${RESET}"

if docker compose -f "${COMPOSE_FILE}" exec -T db \
     psql -U "${POSTGRES_USER:-forensiclab}" -d "${POSTGRES_DB:-forensiclab}" \
     -c "SELECT COUNT(*) FROM cases;" > /dev/null 2>&1; then
  CASE_COUNT=$(docker compose -f "${COMPOSE_FILE}" exec -T db \
    psql -U "${POSTGRES_USER:-forensiclab}" -d "${POSTGRES_DB:-forensiclab}" \
    -tAc "SELECT COUNT(*) FROM cases;" 2>/dev/null | tr -d '[:space:]')
  ok "PostgreSQL accessible — ${CASE_COUNT:-?} cas en base"
else
  fail "PostgreSQL inaccessible"
fi

# Check risk_score migration applied
if docker compose -f "${COMPOSE_FILE}" exec -T db \
     psql -U "${POSTGRES_USER:-forensiclab}" -d "${POSTGRES_DB:-forensiclab}" \
     -c "SELECT risk_level FROM cases LIMIT 1;" > /dev/null 2>&1; then
  ok "Migration risk_score OK (colonnes présentes)"
else
  fail "Migration risk_score MANQUANTE (colonne risk_level absente)"
fi

# Check demo data present
DEMO_COUNT=$(docker compose -f "${COMPOSE_FILE}" exec -T db \
  psql -U "${POSTGRES_USER:-forensiclab}" -d "${POSTGRES_DB:-forensiclab}" \
  -tAc "SELECT COUNT(*) FROM cases WHERE case_number LIKE 'DEMO-%';" 2>/dev/null \
  | tr -d '[:space:]' || echo "0")
if [ "${DEMO_COUNT}" -gt 0 ] 2>/dev/null; then
  ok "Données démo présentes (${DEMO_COUNT} cas DEMO-*)"
else
  info "Pas de données démo (exécuter: node scripts/seed-demo.js)"
fi

# ─── 3. Redis ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}[3/7] Redis${RESET}"

REDIS_PONG=$(docker compose -f "${COMPOSE_FILE}" exec -T redis \
  redis-cli -a "${REDIS_PASSWORD:-}" PING 2>/dev/null | tr -d '[:space:]' || echo "FAIL")
if [ "${REDIS_PONG}" = "PONG" ]; then
  ok "Redis PING → PONG"
else
  fail "Redis ne répond pas (réponse: ${REDIS_PONG})"
fi

# ─── 4. Elasticsearch ─────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}[4/7] Elasticsearch${RESET}"

ES_STATUS=$(docker compose -f "${COMPOSE_FILE}" exec -T elasticsearch \
  curl -s -o /dev/null -w "%{http_code}" http://localhost:9200/_cluster/health 2>/dev/null || echo "000")
if [ "${ES_STATUS}" = "200" ]; then
  ES_HEALTH=$(docker compose -f "${COMPOSE_FILE}" exec -T elasticsearch \
    curl -s http://localhost:9200/_cluster/health 2>/dev/null | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(d.get('status','?'))" 2>/dev/null || echo "?")
  if [ "${ES_HEALTH}" = "red" ]; then
    fail "Elasticsearch cluster status: RED"
  else
    ok "Elasticsearch cluster status: ${ES_HEALTH}"
  fi

  # Check threat_intel index
  TI_COUNT=$(docker compose -f "${COMPOSE_FILE}" exec -T elasticsearch \
    curl -s "http://localhost:9200/threat_intel/_count" 2>/dev/null | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(d.get('count',0))" 2>/dev/null || echo "0")
  if [ "${TI_COUNT:-0}" -gt 0 ] 2>/dev/null; then
    ok "Index threat_intel non vide (${TI_COUNT} documents)"
  else
    info "Index threat_intel vide ou absent (optionnel pour la démo)"
  fi
else
  fail "Elasticsearch inaccessible (HTTP ${ES_STATUS})"
fi

# ─── 5. Backend API ───────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}[5/7] Backend API${RESET}"

API_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${BACKEND_URL}/api/health" 2>/dev/null || echo "000")
if [ "${API_STATUS}" = "200" ]; then
  API_VER=$(curl -s "${BACKEND_URL}/api/health" 2>/dev/null | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(d.get('version','?'))" 2>/dev/null || echo "?")
  ok "Backend API GET /api/health → 200 (v${API_VER}) via Traefik"
else
  fail "Backend API inaccessible (HTTP ${API_STATUS}) — URL: ${BACKEND_URL}/api/health (via Traefik)"
fi

# ─── 6. Traefik ───────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}[6/7] Traefik (bifrost)${RESET}"

TRAEFIK_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080/ping" 2>/dev/null || echo "000")
if [ "${TRAEFIK_STATUS}" = "200" ]; then
  ok "Traefik ping → 200 (dashboard: http://localhost:8080)"
else
  fail "Traefik inaccessible (HTTP ${TRAEFIK_STATUS}) — http://localhost:8080/ping"
fi

# ─── 7. Frontend ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}[7/7] Frontend${RESET}"

FE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${FRONTEND_URL}" 2>/dev/null || echo "000")
if [ "${FE_STATUS}" = "200" ]; then
  ok "Frontend accessible (HTTP 200) — ${FRONTEND_URL}"
else
  fail "Frontend inaccessible (HTTP ${FE_STATUS}) — ${FRONTEND_URL}"
fi

# ─── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  Résultat : ${GREEN}${PASS} OK${RESET}  ${RED}${FAIL} ERREUR(S)${RESET}"

if [ ${FAIL} -gt 0 ]; then
  echo ""
  echo -e "${RED}  Problèmes détectés :${RESET}"
  for err in "${ERRORS[@]}"; do
    echo -e "${RED}    • ${err}${RESET}"
  done
  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo ""
  exit 1
fi

echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo -e "${GREEN}${BOLD}  ✅ Tous les services sont opérationnels. Bonne démo !${RESET}"
echo ""
exit 0
