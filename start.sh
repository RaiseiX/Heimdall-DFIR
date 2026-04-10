#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════════╗
# ║              Heimdall DFIR — Installation script v0.9.6             ║
# ╚══════════════════════════════════════════════════════════════════════╝

set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                                                              ║"
echo "║          H E I M D A L L   D F I R   v 0 . 9 . 6           ║"
echo "║          DFIR & Threat Hunting Workbench                     ║"
echo "║                                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ─── Prerequisites ────────────────────────────────────────────────────────────

echo -e "${CYAN}[1/7] Checking prerequisites...${NC}"

if ! command -v docker &>/dev/null; then
    echo -e "${RED}❌ Docker is not installed. See https://docs.docker.com/get-docker/${NC}"
    exit 1
fi

if ! docker compose version &>/dev/null; then
    echo -e "${RED}❌ Docker Compose v2 is not available (docker compose plugin required).${NC}"
    exit 1
fi

if ! command -v openssl &>/dev/null; then
    echo -e "${RED}❌ openssl is required to generate secrets.${NC}"
    exit 1
fi

echo -e "${GREEN}  ✓ Docker $(docker --version | awk '{print $3}' | tr -d ',')${NC}"
echo -e "${GREEN}  ✓ Docker Compose $(docker compose version --short 2>/dev/null || echo 'v2')${NC}"
echo -e "${GREEN}  ✓ openssl available${NC}"

# Check DNS resolution (required for Docker build)
if ! nslookup deb.debian.org >/dev/null 2>&1 && ! host deb.debian.org >/dev/null 2>&1; then
    echo -e "${YELLOW}  ⚠ DNS: cannot resolve deb.debian.org${NC}"
    echo -e "${YELLOW}    Docker build uses host network (network: host) to work around this.${NC}"
    echo -e "${YELLOW}    If the build still fails, configure Docker DNS permanently:${NC}"
    echo -e "${YELLOW}      echo '{\"dns\":[\"8.8.8.8\",\"1.1.1.1\"]}' | sudo tee /etc/docker/daemon.json${NC}"
    echo -e "${YELLOW}      sudo systemctl restart docker && bash start.sh${NC}"
else
    echo -e "${GREEN}  ✓ DNS resolution OK${NC}"
fi

# ─── Environment file ─────────────────────────────────────────────────────────

echo -e "\n${CYAN}[2/7] Configuring environment...${NC}"

if [ ! -f .env ]; then
    echo -e "${YELLOW}  ⚙  Creating .env from .env.example...${NC}"
    cp .env.example .env

    # Auto-generate all secrets
    JWT_SECRET=$(openssl rand -hex 64)
    DB_PASSWORD=$(openssl rand -hex 24)
    REDIS_PASSWORD=$(openssl rand -hex 24)
    VOLWEB_DJANGO_SECRET=$(openssl rand -hex 32)
    VOLWEB_PASSWORD=$(openssl rand -base64 18 | tr -d '+/=\n' | head -c 20)
    MINIO_ROOT_USER="heimdall$(openssl rand -hex 4)"
    MINIO_ROOT_PASSWORD=$(openssl rand -hex 20)

    sed -i "s|DB_PASSWORD=CHANGEME_min32chars_random|DB_PASSWORD=${DB_PASSWORD}|g" .env
    sed -i "s|REDIS_PASSWORD=CHANGEME_min32chars_random|REDIS_PASSWORD=${REDIS_PASSWORD}|g" .env
    sed -i "s|JWT_SECRET=CHANGEME_generate_with_openssl_rand_hex_64|JWT_SECRET=${JWT_SECRET}|g" .env
    sed -i "s|VOLWEB_DJANGO_SECRET=CHANGEME_min50chars_random_string|VOLWEB_DJANGO_SECRET=${VOLWEB_DJANGO_SECRET}|g" .env
    sed -i "s|VOLWEB_PASSWORD=CHANGEME_min16chars_volweb|VOLWEB_PASSWORD=${VOLWEB_PASSWORD}|g" .env
    sed -i "s|MINIO_ROOT_USER=CHANGEME_access_key_id|MINIO_ROOT_USER=${MINIO_ROOT_USER}|g" .env
    sed -i "s|MINIO_ROOT_PASSWORD=CHANGEME_min12chars_secret_key|MINIO_ROOT_PASSWORD=${MINIO_ROOT_PASSWORD}|g" .env

    echo -e "${GREEN}  ✓ Secrets generated automatically${NC}"
else
    echo -e "${GREEN}  ✓ Existing .env file kept${NC}"

    # Upgrade path: add missing variables for existing installs
    if ! grep -q "^VOLWEB_PASSWORD=" .env; then
        VOLWEB_PASSWORD=$(openssl rand -base64 18 | tr -d '+/=\n' | head -c 20)
        echo "VOLWEB_PASSWORD=${VOLWEB_PASSWORD}" >> .env
        echo -e "${GREEN}  ✓ VOLWEB_PASSWORD generated and added to .env${NC}"
    fi
    if ! grep -q "^VOLWEB_USER=" .env; then
        echo "VOLWEB_USER=admin" >> .env
    fi
    if ! grep -q "^VOLWEB_URL=" .env; then
        echo "VOLWEB_URL=http://hel-api:8000" >> .env
    fi
    if ! grep -q "^VOLWEB_PUBLIC_URL=" .env; then
        echo "VOLWEB_PUBLIC_URL=http://localhost:8888" >> .env
    fi
fi

# Read final values from .env for the summary
VOLWEB_USER_VAL=$(grep "^VOLWEB_USER=" .env | cut -d= -f2)
VOLWEB_PASSWORD_VAL=$(grep "^VOLWEB_PASSWORD=" .env | cut -d= -f2)
MINIO_ROOT_USER_VAL=$(grep "^MINIO_ROOT_USER=" .env | cut -d= -f2)
MINIO_ROOT_PASSWORD_VAL=$(grep "^MINIO_ROOT_PASSWORD=" .env | cut -d= -f2)

# Detect docker group GID for the infrastructure dashboard
DOCKER_GID_VAL=$(stat -c %g /var/run/docker.sock 2>/dev/null || echo "999")
if grep -q "DOCKER_GID=999" .env; then
    sed -i "s|DOCKER_GID=999|DOCKER_GID=${DOCKER_GID_VAL}|g" .env
fi
echo -e "${GREEN}  ✓ DOCKER_GID=${DOCKER_GID_VAL}${NC}"

# Create SSL directory (required even without certificates)
mkdir -p nginx/ssl

# Ensure SQL files are world-readable so the postgres user inside the
# container can execute them (Permission denied breaks schema init).
chmod a+r db/init.sql db/migrations/*.sql 2>/dev/null || true

# ─── Build ────────────────────────────────────────────────────────────────────

echo -e "\n${CYAN}[3/7] Building Docker images...${NC}"
echo -e "${YELLOW}  (first run may take 5-10 minutes)${NC}"
docker compose build

# ─── Start services ───────────────────────────────────────────────────────────

echo -e "\n${CYAN}[4/7] Starting services...${NC}"
docker compose up -d

echo -e "${YELLOW}  ⏳ Waiting for the database...${NC}"
for i in $(seq 1 30); do
    if docker compose exec -T db pg_isready -U forensiclab -q 2>/dev/null; then
        echo -e "${GREEN}  ✓ PostgreSQL ready${NC}"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo -e "${RED}  ❌ PostgreSQL did not respond after 60s — check: docker compose logs db${NC}"
        exit 1
    fi
    sleep 2
done

# Verify the password in .env matches the running PostgreSQL instance.
# IMPORTANT: docker compose exec uses Unix socket with 'trust' auth, which
# bypasses password verification entirely. We must connect via TCP through
# the Docker network (scram-sha-256) to actually test the credential.
#
# We retry up to 5 times with a 3s delay: pg_isready can succeed before
# PostgreSQL finishes running its init scripts (creating roles/databases),
# which would cause a false "wrong password" on a genuine fresh install.
DB_PASSWORD_VAL=$(grep "^DB_PASSWORD=" .env | cut -d= -f2)
_DB_NET=$(docker inspect yggdrasil \
    --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' \
    2>/dev/null | awk '{print $1}')

if [ -n "$_DB_NET" ]; then
    _auth_ok=false
    _auth_err=""
    for _attempt in 1 2 3 4 5; do
        _auth_err=$(docker run --rm \
            --network "$_DB_NET" \
            -e PGPASSWORD="$DB_PASSWORD_VAL" \
            postgres:16-alpine \
            psql -h yggdrasil -U forensiclab -d forensiclab -c "SELECT 1;" \
            2>&1 >/dev/null)
        if [ $? -eq 0 ]; then
            _auth_ok=true
            break
        fi
        # Only retry if the error is NOT a definitive auth failure
        if echo "$_auth_err" | grep -q "password authentication failed"; then
            break
        fi
        sleep 3
    done

    if [ "$_auth_ok" = true ]; then
        echo -e "${GREEN}  ✓ PostgreSQL password verified${NC}"
    elif echo "$_auth_err" | grep -q "password authentication failed"; then
        echo -e "${RED}"
        echo "  ❌ Cannot authenticate to PostgreSQL with the password in .env"
        echo ""
        echo "  This usually means a Docker volume from a previous install exists"
        echo "  with a different password. PostgreSQL ignores POSTGRES_PASSWORD"
        echo "  when data already exists."
        echo ""
        echo "  ── To reset and reinstall (WARNING: deletes all data) ──────────"
        echo "     docker compose down -v"
        echo "     rm .env"
        echo "     bash start.sh"
        echo ""
        echo "  ── To keep existing data (find the old password) ────────────────"
        echo "     Check your previous .env backup, then update DB_PASSWORD in .env"
        echo -e "${NC}"
        exit 1
    else
        echo -e "${YELLOW}  ⚠ Could not verify PostgreSQL password (DB may still be initializing) — continuing${NC}"
    fi
else
    echo -e "${YELLOW}  ⚠ Could not detect Docker network — skipping password verification${NC}"
fi

# ─── Migrations ───────────────────────────────────────────────────────────────

echo -e "\n${CYAN}[5/7] Applying database migrations...${NC}"
bash db/migrate.sh

# ─── VolWeb & MinIO ───────────────────────────────────────────────────────────

echo -e "\n${CYAN}[6/7] Initializing VolWeb + MinIO...${NC}"

# Wait for VolWeb (hel-api) to be ready
echo -e "${YELLOW}  ⏳ Waiting for VolWeb...${NC}"
for i in $(seq 1 30); do
    if docker exec hel-api python manage.py check --deploy 2>/dev/null | grep -q "System check" \
       || curl -sf http://localhost:8888/api/ >/dev/null 2>&1; then
        echo -e "${GREEN}  ✓ VolWeb ready${NC}"
        break
    fi
    # Fallback: check if daphne process is running
    if docker exec hel-api pgrep -x daphne >/dev/null 2>&1; then
        echo -e "${GREEN}  ✓ VolWeb ready${NC}"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo -e "${YELLOW}  ⚠ VolWeb is slow to start — continuing installation...${NC}"
        break
    fi
    sleep 3
done

# Create MinIO 'volweb' bucket via minio/mc
echo -e "${YELLOW}  ⏳ Creating MinIO 'volweb' bucket...${NC}"
MINIO_URL="http://njord:9000"
NETWORK=$(docker inspect njord --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null | awk '{print $1}')

if [ -n "$NETWORK" ]; then
    docker run --rm \
        --network "$NETWORK" \
        -e "MC_HOST_local=${MINIO_URL%% }" \
        minio/mc \
        alias set local "http://njord:9000" \
        "${MINIO_ROOT_USER_VAL}" "${MINIO_ROOT_PASSWORD_VAL}" >/dev/null 2>&1 \
    && docker run --rm \
        --network "$NETWORK" \
        -e "MC_HOST_local=http://${MINIO_ROOT_USER_VAL}:${MINIO_ROOT_PASSWORD_VAL}@njord:9000" \
        minio/mc mb local/volweb --ignore-existing >/dev/null 2>&1 \
    && echo -e "${GREEN}  ✓ MinIO 'volweb' bucket ready${NC}" \
    || echo -e "${YELLOW}  ⚠ MinIO bucket must be created manually: http://localhost:9001 → Buckets → Create 'volweb'${NC}"
else
    echo -e "${YELLOW}  ⚠ Docker network not detected — MinIO bucket must be created manually${NC}"
fi

# VolWeb superuser is created automatically by docker/volweb-init.sh on startup.
# No manual intervention required.
echo -e "${GREEN}  ✓ VolWeb superuser synced from .env (VOLWEB_USER / VOLWEB_PASSWORD)${NC}"

# ─── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ✅  Heimdall DFIR is ready!                                 ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║  🌐  Main interface   →  http://localhost                    ║${NC}"
echo -e "${GREEN}║  📡  Backend API      →  http://localhost:4000               ║${NC}"
echo -e "${GREEN}║  🧠  VolWeb (RAM)     →  http://localhost:8888               ║${NC}"
echo -e "${GREEN}║  🗄️  MinIO (S3)       →  http://localhost:9001               ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Heimdall DFIR                                               ║${NC}"
echo -e "${GREEN}║  👤  Admin   :  admin    /  Admin2026!                       ║${NC}"
echo -e "${GREEN}║  👤  Analyst :  analyst  /  Analyst2026!                     ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  VolWeb (Volatility 3)                                       ║${NC}"
printf "${GREEN}║  👤  %-54s ║${NC}\n" "User : ${VOLWEB_USER_VAL:-admin}  /  ${VOLWEB_PASSWORD_VAL}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  MinIO (S3 console)                                          ║${NC}"
printf "${GREEN}║  🔑  %-54s ║${NC}\n" "User : ${MINIO_ROOT_USER_VAL}"
printf "${GREEN}║  🔑  %-54s ║${NC}\n" "Pass : ${MINIO_ROOT_PASSWORD_VAL}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${YELLOW}║  ⚠️  Change default Heimdall passwords before going to prod! ║${NC}"
echo -e "${YELLOW}║  💾  Back up your .env file — it contains all secrets       ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ─── Post-installation ────────────────────────────────────────────────────────

echo -e "${CYAN}[7/7] Post-installation steps (optional)${NC}"
echo ""
echo -e "${BOLD}  Zimmerman Tools (Windows artifact parsers):${NC}"
echo "    → Place DLL files in the zimmerman_tools volume (/app/zimmerman-tools/)"
echo "    → Download: https://ericzimmerman.github.io/"
echo ""
echo -e "${BOLD}  Hayabusa (Sigma EVTX detections):${NC}"
echo "    docker cp hayabusa odin:/app/hayabusa/hayabusa"
echo "    docker exec odin chmod +x /app/hayabusa/hayabusa"
echo ""
echo -e "${BOLD}  Local AI (Ollama):${NC}"
echo "    → Set OLLAMA_URL=http://ollama:11434 in .env"
echo "    → Then: docker compose up -d ollama"
echo "    → Pull a model: docker exec ollama ollama pull qwen3:14b"
echo ""
echo -e "${CYAN}  Useful commands:${NC}"
echo "    docker compose logs -f backend   # API logs"
echo "    docker compose ps                # Service status"
echo "    docker compose down              # Stop all services"
echo "    docker compose restart           # Restart all services"
echo ""
