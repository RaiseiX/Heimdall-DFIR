#Requires -Version 5.1
# ╔══════════════════════════════════════════════════════════════════════╗
# ║              Heimdall DFIR — Installation script v0.9.6             ║
# ║              Windows (PowerShell 5.1+)                              ║
# ╚══════════════════════════════════════════════════════════════════════╝
#
# Usage:
#   Right-click start.ps1 -> "Run with PowerShell"
#   OR from a PowerShell terminal:
#   Set-ExecutionPolicy -Scope Process Bypass; .\start.ps1

$ErrorActionPreference = "Stop"

# ─── Helpers ──────────────────────────────────────────────────────────────────

function Write-Ok  ($msg) { Write-Host "  [OK] $msg" -ForegroundColor Green  }
function Write-Warn($msg) { Write-Host "  [!!] $msg" -ForegroundColor Yellow }
function Write-Err ($msg) { Write-Host "  [XX] $msg" -ForegroundColor Red    }
function Write-Step($msg) { Write-Host "`n$msg"      -ForegroundColor Cyan   }

function New-RandomHex([int]$bytes) {
    $buf = [byte[]]::new($bytes)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($buf)
    return ($buf | ForEach-Object { $_.ToString("x2") }) -join ""
}

function New-RandomAlpha([int]$length) {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    $buf   = [byte[]]::new($length)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($buf)
    return ($buf | ForEach-Object { $chars[$_ % $chars.Length] }) -join ""
}

function Replace-InFile([string]$file, [string]$old, [string]$new) {
    (Get-Content $file -Raw) -replace [regex]::Escape($old), $new |
        Set-Content $file -NoNewline
}

function Get-EnvValue([string]$key) {
    $line = Get-Content .env | Where-Object { $_ -match "^$key=" } | Select-Object -First 1
    if ($line) { return $line.Substring($key.Length + 1) }
    return ""
}

# ─── Banner ───────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                                                              ║" -ForegroundColor Cyan
Write-Host "║          H E I M D A L L   D F I R   v 0 . 9 . 6           ║" -ForegroundColor Cyan
Write-Host "║          DFIR & Threat Hunting Workbench                     ║" -ForegroundColor Cyan
Write-Host "║                                                              ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ─── [1/7] Prerequisites ──────────────────────────────────────────────────────

Write-Step "[1/7] Checking prerequisites..."

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Err "Docker is not installed."
    Write-Err "Download Docker Desktop: https://docs.docker.com/desktop/install/windows/"
    exit 1
}

docker compose version 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Err "Docker Compose v2 is not available. Update Docker Desktop."
    exit 1
}

docker info 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Err "Docker daemon is not running. Please start Docker Desktop."
    exit 1
}

$dockerVersion  = (docker --version) -replace "Docker version ([^\s,]+).*", '$1'
$composeVersion = docker compose version --short 2>$null

Write-Ok "Docker $dockerVersion"
Write-Ok "Docker Compose $composeVersion"

try {
    [System.Net.Dns]::GetHostAddresses("deb.debian.org") | Out-Null
    Write-Ok "DNS resolution OK"
} catch {
    Write-Warn "DNS: cannot resolve deb.debian.org"
    Write-Warn "  Docker build uses host network (network: host) to work around this."
    Write-Warn "  If the build still fails, open Docker Desktop -> Settings -> Docker Engine"
    Write-Warn '  and add: "dns": ["8.8.8.8", "1.1.1.1"]'
}

# ─── [2/7] Environment file ───────────────────────────────────────────────────

Write-Step "[2/7] Configuring environment..."

if (-not (Test-Path ".env")) {
    Write-Warn "Creating .env from .env.example..."
    Copy-Item ".env.example" ".env"

    $JWT_SECRET           = New-RandomHex 64
    $DB_PASSWORD          = New-RandomHex 24
    $REDIS_PASSWORD       = New-RandomHex 24
    $VOLWEB_DJANGO_SECRET = New-RandomHex 32
    $VOLWEB_PASSWORD      = New-RandomAlpha 20
    $MINIO_ROOT_USER      = "heimdall" + (New-RandomHex 4)
    $MINIO_ROOT_PASSWORD  = New-RandomHex 20

    Replace-InFile ".env" "DB_PASSWORD=CHANGEME_min32chars_random"               "DB_PASSWORD=$DB_PASSWORD"
    Replace-InFile ".env" "REDIS_PASSWORD=CHANGEME_min32chars_random"            "REDIS_PASSWORD=$REDIS_PASSWORD"
    Replace-InFile ".env" "JWT_SECRET=CHANGEME_generate_with_openssl_rand_hex_64" "JWT_SECRET=$JWT_SECRET"
    Replace-InFile ".env" "VOLWEB_DJANGO_SECRET=CHANGEME_min50chars_random_string" "VOLWEB_DJANGO_SECRET=$VOLWEB_DJANGO_SECRET"
    Replace-InFile ".env" "VOLWEB_PASSWORD=CHANGEME_min16chars_volweb"           "VOLWEB_PASSWORD=$VOLWEB_PASSWORD"
    Replace-InFile ".env" "MINIO_ROOT_USER=CHANGEME_access_key_id"               "MINIO_ROOT_USER=$MINIO_ROOT_USER"
    Replace-InFile ".env" "MINIO_ROOT_PASSWORD=CHANGEME_min12chars_secret_key"   "MINIO_ROOT_PASSWORD=$MINIO_ROOT_PASSWORD"

    Write-Ok "Secrets generated automatically"
} else {
    Write-Ok "Existing .env file kept"

    $envContent = Get-Content ".env" -Raw
    if ($envContent -notmatch "(?m)^VOLWEB_PASSWORD=") {
        $vp = New-RandomAlpha 20
        Add-Content ".env" "VOLWEB_PASSWORD=$vp"
        Write-Ok "VOLWEB_PASSWORD generated and added to .env"
    }
    if ($envContent -notmatch "(?m)^VOLWEB_USER=")       { Add-Content ".env" "VOLWEB_USER=admin" }
    if ($envContent -notmatch "(?m)^VOLWEB_URL=")        { Add-Content ".env" "VOLWEB_URL=http://hel-api:8000" }
    if ($envContent -notmatch "(?m)^VOLWEB_PUBLIC_URL=") { Add-Content ".env" "VOLWEB_PUBLIC_URL=http://localhost:8888" }
}

$VOLWEB_USER_VAL         = Get-EnvValue "VOLWEB_USER"
$VOLWEB_PASSWORD_VAL     = Get-EnvValue "VOLWEB_PASSWORD"
$MINIO_ROOT_USER_VAL     = Get-EnvValue "MINIO_ROOT_USER"
$MINIO_ROOT_PASSWORD_VAL = Get-EnvValue "MINIO_ROOT_PASSWORD"
$DB_PASSWORD_VAL         = Get-EnvValue "DB_PASSWORD"

# DOCKER_GID is not needed on Windows (Docker Desktop manages socket access)
Write-Ok "DOCKER_GID: not required on Windows"

New-Item -ItemType Directory -Force -Path "nginx\ssl" | Out-Null

# ─── [3/7] Build ──────────────────────────────────────────────────────────────

Write-Step "[3/7] Building Docker images..."
Write-Host "  (first run may take 5-10 minutes)" -ForegroundColor Yellow

docker compose build
if ($LASTEXITCODE -ne 0) {
    Write-Err "Docker build failed. Check the output above."
    exit 1
}

# ─── [4/7] Start services ─────────────────────────────────────────────────────

Write-Step "[4/7] Starting services..."

docker compose up -d
if ($LASTEXITCODE -ne 0) {
    Write-Err "Failed to start services."
    exit 1
}

Write-Host "  Waiting for the database..." -ForegroundColor Yellow
$dbReady = $false
for ($i = 1; $i -le 30; $i++) {
    docker compose exec -T db pg_isready -U forensiclab -q 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "PostgreSQL ready"
        $dbReady = $true
        break
    }
    Start-Sleep -Seconds 2
}
if (-not $dbReady) {
    Write-Err "PostgreSQL did not respond after 60s. Check: docker compose logs db"
    exit 1
}

# ─── [5/7] Migrations ─────────────────────────────────────────────────────────

Write-Step "[5/7] Applying database migrations..."

# Resolve db/ directory path for Docker bind mount
$dbPath = (Resolve-Path "db").Path

# Run all migration SQL files inside a disposable postgres container
# connected to the same Docker network as yggdrasil (the PostgreSQL service)
$network = docker inspect yggdrasil --format "{{range `$k,`$v := .NetworkSettings.Networks}}{{`$k}}{{end}}" 2>$null

$migrations = @(
    "migrate_v2.7.sql","migrate_v2.8.sql","migrate_v2.9.sql","migrate_v2.10.sql",
    "migrate_v2.11.sql","migrate_v2.12.sql","migrate_v2.13.sql","migrate_v2.14.sql",
    "migrate_v2.15.sql","migrate_v2.16.sql","migrate_v2.17.sql","migrate_v2.18.sql",
    "migrate_v2.19.sql","migrate_v2.20.sql","migrate_v2.21.sql","migrate_v2.22.sql"
)

$featureMigrations = Get-ChildItem "db\migrations\*.sql" -ErrorAction SilentlyContinue |
    Sort-Object Name | Select-Object -ExpandProperty Name

# Bootstrap schema_migrations table
docker run --rm `
    --network $network `
    -e "PGPASSWORD=$DB_PASSWORD_VAL" `
    postgres:16-alpine `
    psql -h yggdrasil -U forensiclab forensiclab -c `
    "CREATE TABLE IF NOT EXISTS schema_migrations (filename TEXT PRIMARY KEY, applied_at TIMESTAMPTZ DEFAULT NOW());" 2>&1 | Out-Null

foreach ($file in ($migrations + $featureMigrations)) {
    $subdir = if ($featureMigrations -contains $file) { "migrations\" } else { "" }
    $fullPath = Join-Path $dbPath ($subdir + $file)
    if (-not (Test-Path $fullPath)) { continue }

    # Check if already applied
    $count = docker run --rm `
        --network $network `
        -e "PGPASSWORD=$DB_PASSWORD_VAL" `
        postgres:16-alpine `
        psql -h yggdrasil -U forensiclab forensiclab -t -c `
        "SELECT COUNT(*) FROM schema_migrations WHERE filename='$file';" 2>$null
    $count = $count.Trim()

    if ($count -gt 0) {
        Write-Host "  skip:  $file" -ForegroundColor Yellow
        continue
    }

    Write-Host "  apply: $file"
    $sqlContent = Get-Content $fullPath -Raw

    $result = docker run --rm `
        --network $network `
        -v "${fullPath}:/migration.sql:ro" `
        -e "PGPASSWORD=$DB_PASSWORD_VAL" `
        postgres:16-alpine `
        psql -h yggdrasil -U forensiclab forensiclab -v ON_ERROR_STOP=1 -f /migration.sql 2>&1

    if ($LASTEXITCODE -eq 0) {
        docker run --rm `
            --network $network `
            -e "PGPASSWORD=$DB_PASSWORD_VAL" `
            postgres:16-alpine `
            psql -h yggdrasil -U forensiclab forensiclab -c `
            "INSERT INTO schema_migrations(filename) VALUES('$file') ON CONFLICT DO NOTHING;" 2>&1 | Out-Null
        Write-Ok $file
    } else {
        Write-Err "Migration failed: $file"
        Write-Host $result
        exit 1
    }
}

Write-Ok "All migrations applied"

# ─── [6/7] VolWeb + MinIO ─────────────────────────────────────────────────────

Write-Step "[6/7] Initializing VolWeb + MinIO..."

Write-Host "  Waiting for VolWeb..." -ForegroundColor Yellow
$volwebReady = $false
for ($i = 1; $i -le 30; $i++) {
    docker exec hel-api pgrep -x daphne 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Ok "VolWeb ready"; $volwebReady = $true; break }
    try {
        Invoke-WebRequest -Uri "http://localhost:8888/api/" -TimeoutSec 2 -UseBasicParsing -ErrorAction Stop | Out-Null
        Write-Ok "VolWeb ready"; $volwebReady = $true; break
    } catch {}
    Start-Sleep -Seconds 3
}
if (-not $volwebReady) { Write-Warn "VolWeb is slow to start — continuing..." }

Write-Host "  Creating MinIO 'volweb' bucket..." -ForegroundColor Yellow
$minioNetwork = docker inspect njord --format "{{range `$k,`$v := .NetworkSettings.Networks}}{{`$k}}{{end}}" 2>$null
if ($minioNetwork) {
    docker run --rm `
        --network $minioNetwork `
        -e "MC_HOST_local=http://${MINIO_ROOT_USER_VAL}:${MINIO_ROOT_PASSWORD_VAL}@njord:9000" `
        minio/mc mb local/volweb --ignore-existing 2>&1 | Out-Null

    if ($LASTEXITCODE -eq 0) {
        Write-Ok "MinIO 'volweb' bucket ready"
    } else {
        Write-Warn "Create bucket manually: http://localhost:9001 -> Buckets -> Create 'volweb'"
    }
} else {
    Write-Warn "Docker network not detected — create MinIO bucket manually"
}

Write-Ok "VolWeb superuser synced from .env"

# ─── Summary ──────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  Heimdall DFIR is ready!                                     ║" -ForegroundColor Green
Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Green
Write-Host "║                                                              ║" -ForegroundColor Green
Write-Host "║  Main interface   ->  http://localhost                       ║" -ForegroundColor Green
Write-Host "║  Backend API      ->  http://localhost:4000                  ║" -ForegroundColor Green
Write-Host "║  VolWeb (RAM)     ->  http://localhost:8888                  ║" -ForegroundColor Green
Write-Host "║  MinIO (S3)       ->  http://localhost:9001                  ║" -ForegroundColor Green
Write-Host "║                                                              ║" -ForegroundColor Green
Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Green
Write-Host "║  Heimdall DFIR                                               ║" -ForegroundColor Green
Write-Host "║  Admin   :  admin    /  Admin2026!                           ║" -ForegroundColor Green
Write-Host "║  Analyst :  analyst  /  Analyst2026!                        ║" -ForegroundColor Green
Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Green
Write-Host "║  VolWeb (Volatility 3)                                       ║" -ForegroundColor Green
Write-Host ("║  User : {0,-52} ║" -f "$VOLWEB_USER_VAL  /  $VOLWEB_PASSWORD_VAL") -ForegroundColor Green
Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Green
Write-Host "║  MinIO (S3 console)                                          ║" -ForegroundColor Green
Write-Host ("║  User : {0,-52} ║" -f $MINIO_ROOT_USER_VAL) -ForegroundColor Green
Write-Host ("║  Pass : {0,-52} ║" -f $MINIO_ROOT_PASSWORD_VAL) -ForegroundColor Green
Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Green
Write-Host "║                                                              ║" -ForegroundColor Green
Write-Host "║  [!] Change default Heimdall passwords before production!    ║" -ForegroundColor Yellow
Write-Host "║  [!] Back up your .env file — it contains all secrets        ║" -ForegroundColor Yellow
Write-Host "║                                                              ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""

# ─── [7/7] Post-installation ──────────────────────────────────────────────────

Write-Step "[7/7] Post-installation steps (optional)"
Write-Host ""
Write-Host "  Zimmerman Tools (Windows artifact parsers):" -ForegroundColor White
Write-Host "    -> Place DLL files in the zimmerman_tools volume (/app/zimmerman-tools/)"
Write-Host "    -> Download: https://ericzimmerman.github.io/"
Write-Host ""
Write-Host "  Hayabusa (Sigma EVTX detections):" -ForegroundColor White
Write-Host "    docker cp hayabusa odin:/app/hayabusa/hayabusa"
Write-Host "    docker exec odin chmod +x /app/hayabusa/hayabusa"
Write-Host ""
Write-Host "  Local AI (Ollama):" -ForegroundColor White
Write-Host "    -> Set OLLAMA_URL=http://ollama:11434 in .env"
Write-Host "    -> Then: docker compose up -d ollama"
Write-Host "    -> Pull a model: docker exec ollama ollama pull qwen3:14b"
Write-Host ""
Write-Host "  Useful commands:" -ForegroundColor Cyan
Write-Host "    docker compose logs -f backend   # API logs"
Write-Host "    docker compose ps                # Service status"
Write-Host "    docker compose down              # Stop all services"
Write-Host "    docker compose restart           # Restart all services"
Write-Host ""
