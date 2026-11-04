#!/bin/bash
set -uo pipefail

cd "$(dirname "$0")" || exit 1

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

DRY_RUN=0
ASSUME_YES=0
ACCEPT_AUDIT=0
REALIGN=0

usage() {
    echo "Usage : bash update.sh [--dry-run] [--yes] [--accept-audit-problems] [--realign-db-password]"
    echo ""
    echo "  --dry-run                 contrôles en lecture seule, puis affiche les étapes sans rien modifier"
    echo "  --yes                     ne pas demander de confirmation"
    echo "  --accept-audit-problems   poursuivre même si la chaîne d'audit est déjà en défaut avant la mise à jour"
    echo "  --realign-db-password     aligner le mot de passe du rôle forensiclab sur DB_PASSWORD de .env, sans toucher aux données"
    echo ""
    echo "La mise à jour ne supprime jamais de volume, de base ni de fichier de preuve."
}

for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        --yes|-y) ASSUME_YES=1 ;;
        --accept-audit-problems) ACCEPT_AUDIT=1 ;;
        --realign-db-password) REALIGN=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo -e "${RED}Option inconnue : ${arg}${NC}"; usage; exit 64 ;;
    esac
done

MIN_DOCKER_FREE_MB="${HEIMDALL_MIN_DOCKER_FREE_MB:-5120}"
BACKUP_MARGIN_MB="${HEIMDALL_BACKUP_MARGIN_MB:-512}"
HEALTH_TIMEOUT="${HEIMDALL_HEALTH_TIMEOUT:-300}"
BACKUP_ROOT="${HEIMDALL_BACKUP_DIR:-backups/updates}"
ENV_BACKUP_ROOT="${HEIMDALL_ENV_BACKUP_DIR:-$(dirname "$BACKUP_ROOT")/env}"
ENV_BACKUP=""
STAMP="$(date +%Y%m%d-%H%M%S)-$$"
BACKUP_DIR=""
DUMP_FILE=""
PHASE="preflight"
TOTAL=10

step() { echo -e "\n${CYAN}[$1/${TOTAL}] $2${NC}"; }
ok() { echo -e "${GREEN}  ✓ $*${NC}"; }
warn() { echo -e "${YELLOW}  ⚠ $*${NC}"; }
info() { echo -e "    $*"; }
done_ok() { [ "$DRY_RUN" -eq 1 ] || ok "$@"; }

explain_state() {
    echo ""
    echo -e "${BOLD}  État de la plateforme :${NC}"
    case "$PHASE" in
        preflight)
            info "Rien n'a été modifié. Les services tournent comme avant la mise à jour."
            ;;
        built)
            info "Les nouvelles images sont construites, mais les conteneurs en marche n'ont pas été touchés."
            info "La base n'a pas été modifiée."
            ;;
        stopped)
            info "Le backend et le worker sont arrêtés. La base et les volumes sont intacts."
            info "Relance des anciens conteneurs, sans recréation :"
            if docker compose start backend worker; then
                ok "backend et worker relancés sur leurs images d'avant la mise à jour"
            else
                warn "relance impossible, à faire à la main : docker compose start backend worker"
            fi
            ;;
        migrating)
            info "Une migration a échoué. Le backend et le worker restent arrêtés : ne les relance pas sur un schéma incomplet."
            info "Sauvegarde vérifiée : ${DUMP_FILE}"
            info ""
            info "Option 1, recommandée : corrige la cause affichée plus haut, puis relance « bash update.sh »."
            info "  Les migrations déjà passées sont inscrites dans schema_migrations et ne seront pas rejouées."
            info ""
            info "Option 2 : revenir à l'état d'avant la mise à jour. Le contenu actuel de la base est remplacé par la sauvegarde,"
            info "  à lancer seulement après confirmation, une fois le code ramené au commit précédent (${FROM_COMMIT}) :"
            info "  docker compose exec -T db pg_restore -U forensiclab -d forensiclab --clean --if-exists --single-transaction --no-owner < \"${DUMP_FILE}\""
            info "  docker compose build && docker compose up -d"
            ;;
        started)
            info "Les migrations sont appliquées et les services ont été relancés. La sauvegarde reste disponible : ${DUMP_FILE}"
            info "Diagnostic : docker compose ps ; docker logs odin --tail 100 ; docker logs huginn --tail 100"
            ;;
    esac
}

fail() {
    echo -e "${RED}  ❌ $*${NC}"
    explain_state
    exit 1
}

run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        echo -e "${YELLOW}  [dry-run] $*${NC}"
        return 0
    fi
    "$@"
}

env_get() {
    grep -E "^$1=" .env 2>/dev/null | tail -n 1 | cut -d= -f2-
}

json_field() {
    printf '%s' "$1" | grep -o "\"$2\":\"[^\"]*\"" | head -n 1 | cut -d'"' -f4
}

json_object() {
    printf '%s' "$1" | grep -o "\"$2\":{[^}]*}" | head -n 1 | cut -d: -f2-
}

counts_not_worse() {
    local before="$1" after="$2" pair key n prev
    for pair in $(printf '%s' "$after" | grep -o '"[a-z_]*":[0-9]*'); do
        key="${pair%%:*}"
        n="${pair##*:}"
        prev="$(printf '%s' "$before" | grep -o "${key}:[0-9]*" | head -n 1 | cut -d: -f2)"
        [ -n "$prev" ] || return 1
        [ "$n" -le "$prev" ] || return 1
    done
    return 0
}

free_mb() {
    local target="$1"
    while [ ! -d "$target" ]; do target="$(dirname "$target")"; done
    df -Pk "$target" 2>/dev/null | awk 'NR==2 {print int($4/1024)}'
}

container_health() {
    docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$1" 2>/dev/null || echo "absent"
}

backup_env() {
    [ -n "$ENV_BACKUP" ] && return 0
    ( umask 077; mkdir -p "$ENV_BACKUP_ROOT" ) || return 1
    chmod 700 "$ENV_BACKUP_ROOT" || return 1
    local target="${ENV_BACKUP_ROOT}/${STAMP}.env"
    [ -e "$target" ] && return 1
    ( umask 077; cp .env "$target" ) || return 1
    chmod 600 "$target" || return 1
    cmp -s .env "$target" || return 1
    ENV_BACKUP="$(cd "$ENV_BACKUP_ROOT" && pwd)/${STAMP}.env"
}

auth_check() {
    env_get DB_PASSWORD | docker compose exec -T db sh -c 'IFS= read -r PGPASSWORD; export PGPASSWORD; psql -h db -U forensiclab -d forensiclab -tAc "SELECT 1"' 2>&1 >/dev/null
}

realign_db_password() {
    { env_get DB_PASSWORD; printf '%s\n' '\getenv pw p' "ALTER ROLE forensiclab PASSWORD :'pw';"; } \
        | docker compose exec -T db sh -c 'IFS= read -r p; export p; exec psql -U forensiclab -d forensiclab -v ON_ERROR_STOP=1 -q' >/dev/null
}

wait_healthy() {
    local name="$1" deadline=$((SECONDS + HEALTH_TIMEOUT)) status
    while :; do
        status="$(container_health "$name")"
        case "$status" in
            healthy|running) return 0 ;;
        esac
        [ "$SECONDS" -ge "$deadline" ] && { echo "$status"; return 1; }
        sleep 2
    done
}

echo -e "${CYAN}${BOLD}Heimdall DFIR — mise à jour sans perte de données${NC}"
[ "$DRY_RUN" -eq 1 ] && echo -e "${YELLOW}Mode à blanc (dry-run) : seuls des contrôles en lecture seule sont exécutés.${NC}"

if [ "$REALIGN" -eq 1 ]; then
    [ -f .env ] || fail "Fichier .env introuvable."
    [ -n "$(env_get DB_PASSWORD)" ] || fail "DB_PASSWORD absent de .env."
    [ "$(container_health yggdrasil)" = "healthy" ] || fail "PostgreSQL (yggdrasil) n'est pas sain : docker compose up -d db, puis relance."
    if [ "$DRY_RUN" -eq 1 ]; then
        echo -e "${YELLOW}  [dry-run] ALTER ROLE forensiclab PASSWORD <DB_PASSWORD de .env>, par la connexion locale du conteneur${NC}"
        exit 0
    fi
    if [ "$ASSUME_YES" -eq 0 ]; then
        [ -t 0 ] || fail "Pas de terminal pour confirmer : relance avec --yes."
        read -r -p "  Remplacer le mot de passe du rôle forensiclab par DB_PASSWORD de .env ? Aucune donnée n'est touchée. [o/N] " answer
        [[ "$answer" =~ ^[oOyY]$ ]] || fail "Annulé."
    fi
    realign_db_password || fail "ALTER ROLE a échoué. Diagnostic : docker compose logs db"
    AUTH_ERR="$(auth_check)" || fail "Le mot de passe est réaligné mais la connexion TCP échoue encore : ${AUTH_ERR}"
    ok "Rôle forensiclab aligné sur .env ; les données n'ont pas été touchées"
    info "Suite : bash update.sh, ou docker compose up -d si tu ne mets pas à jour."
    exit 0
fi

step 1 "Prérequis"
command -v docker >/dev/null 2>&1 || fail "Docker n'est pas installé."
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 n'est pas disponible."
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum est requis pour contrôler la sauvegarde."
[ -f docker-compose.yml ] || fail "docker-compose.yml introuvable : lance le script depuis la racine du dépôt."
[ -f .env ] || fail "Fichier .env introuvable. Une mise à jour a besoin du .env de l'installation existante ; pour une première installation, utilise start.sh."
ok "Docker, Docker Compose, .env présents"

step 2 "Variables d'environnement"
REQUIRED=(DB_PASSWORD REDIS_PASSWORD JWT_SECRET VOLWEB_DJANGO_SECRET VOLWEB_PASSWORD MINIO_ROOT_USER MINIO_ROOT_PASSWORD)
BAD=()
for key in "${REQUIRED[@]}"; do
    value="$(env_get "$key")"
    if [ -z "$value" ] || [[ "$value" == CHANGEME* ]]; then BAD+=("$key"); fi
done
if [ "${#BAD[@]}" -gt 0 ]; then
    fail "Variables absentes ou laissées à CHANGEME dans .env : ${BAD[*]}
     Elles ne sont pas régénérées : la base, Redis et MinIO gardent les valeurs d'origine.
     Reprends-les depuis la sauvegarde de ton .env."
fi
JWT_VALUE="$(env_get JWT_SECRET)"
AUDIT_VALUE="$(env_get AUDIT_HMAC_KEY)"
GENERATE_AUDIT_KEY=0
if [ -z "$AUDIT_VALUE" ] || [[ "$AUDIT_VALUE" == CHANGEME* ]]; then
    GENERATE_AUDIT_KEY=1
    command -v openssl >/dev/null 2>&1 || fail "openssl est requis pour générer AUDIT_HMAC_KEY."
    warn "AUDIT_HMAC_KEY absente : elle sera générée dans .env, sans être affichée"
elif [ "$AUDIT_VALUE" = "$JWT_VALUE" ]; then
    fail "AUDIT_HMAC_KEY est identique à JWT_SECRET. Elle n'est pas remplacée automatiquement : des lignes d'audit ont pu être signées avec elle.
     Choisis la suite à donner avant de relancer la mise à jour."
elif [ "${#AUDIT_VALUE}" -lt 32 ]; then
    fail "AUDIT_HMAC_KEY fait moins de 32 caractères."
fi
unset JWT_VALUE AUDIT_VALUE value
OTHER_CHANGEME="$(grep -oE '^[A-Z0-9_]+=CHANGEME' .env | cut -d= -f1 | grep -vx 'AUDIT_HMAC_KEY' | tr '\n' ' ')"
[ -n "$OTHER_CHANGEME" ] && warn "Valeurs encore à CHANGEME, sans effet sur la mise à jour : ${OTHER_CHANGEME}"
if [ "$GENERATE_AUDIT_KEY" -eq 1 ]; then
    CONFIG_ERR="$(AUDIT_HMAC_KEY=placeholder-for-config-check docker compose config -q 2>&1)" \
        || fail "docker compose config refuse la configuration : ${CONFIG_ERR}"
else
    CONFIG_ERR="$(docker compose config -q 2>&1)" || fail "docker compose config refuse la configuration : ${CONFIG_ERR}"
fi
ok "Variables obligatoires présentes"

step 3 "Base de données et services"
DB_STATUS="$(container_health yggdrasil)"
if [ "$DB_STATUS" != "healthy" ]; then
    if [ "$DRY_RUN" -eq 1 ]; then
        warn "PostgreSQL (yggdrasil) est « ${DB_STATUS} » : la mise à jour réelle le démarrerait avec docker compose up -d db"
    else
        warn "PostgreSQL (yggdrasil) est « ${DB_STATUS} », démarrage de la base seule"
        docker compose up -d db || fail "Impossible de démarrer PostgreSQL. Diagnostic : docker compose logs db"
        wait_healthy yggdrasil >/dev/null || fail "PostgreSQL n'est pas sain après ${HEALTH_TIMEOUT}s. Diagnostic : docker compose logs db"
    fi
fi
if [ "$DB_STATUS" = "healthy" ] || [ "$DRY_RUN" -eq 0 ]; then
    AUTH_ERR="$(auth_check)"
    AUTH_RC=$?
    if [ "$AUTH_RC" -ne 0 ]; then
        if printf '%s' "$AUTH_ERR" | grep -q "password authentication failed"; then
            echo -e "${RED}  ❌ PostgreSQL refuse le mot de passe DB_PASSWORD de .env.${NC}"
            info "Le volume de la base garde le mot de passe défini à sa création ; il ne suit pas les changements de .env."
            info "Correction sans perte de données : aligner le rôle forensiclab sur .env, puis relancer la mise à jour."
            info ""
            info "  bash update.sh --realign-db-password"
            info "  bash update.sh"
            explain_state
            exit 1
        fi
        fail "Connexion à PostgreSQL impossible : ${AUTH_ERR}"
    fi
    ok "PostgreSQL accepte le mot de passe de .env"
    DB_SIZE="$(docker compose exec -T db psql -U forensiclab -d forensiclab -tAc "SELECT pg_database_size('forensiclab')" 2>/dev/null | tr -dc '0-9')"
    [ -n "$DB_SIZE" ] || fail "Impossible de mesurer la taille de la base."
else
    DB_SIZE=0
fi
for name in odin huginn; do
    info "${name} : $(container_health "$name")"
done

step 4 "Espace disque"
DB_MB=$(( (DB_SIZE + 1048575) / 1048576 ))
NEED_BACKUP_MB=$(( DB_MB + BACKUP_MARGIN_MB ))
BACKUP_FREE="$(free_mb "$BACKUP_ROOT")"
[ -n "$BACKUP_FREE" ] || fail "Impossible de mesurer l'espace disque libre pour ${BACKUP_ROOT}."
[ "$BACKUP_FREE" -ge "$NEED_BACKUP_MB" ] \
    || fail "Espace disque insuffisant pour la sauvegarde : ${BACKUP_FREE} Mo libres, ${NEED_BACKUP_MB} Mo nécessaires (base de ${DB_MB} Mo)."
ok "Sauvegarde : ${BACKUP_FREE} Mo libres, ${NEED_BACKUP_MB} Mo nécessaires"
DOCKER_ROOT="$(docker info -f '{{.DockerRootDir}}' 2>/dev/null)"
DOCKER_FREE="$( [ -n "$DOCKER_ROOT" ] && free_mb "$DOCKER_ROOT" )"
if [ -z "$DOCKER_FREE" ]; then
    warn "Espace libre de Docker non mesurable (${DOCKER_ROOT:-inconnu}), contrôle ignoré"
elif [ "$DOCKER_FREE" -lt "$MIN_DOCKER_FREE_MB" ]; then
    fail "Espace disque insuffisant pour construire les images : ${DOCKER_FREE} Mo libres dans ${DOCKER_ROOT}, ${MIN_DOCKER_FREE_MB} Mo demandés."
else
    ok "Images : ${DOCKER_FREE} Mo libres dans ${DOCKER_ROOT}"
fi

FROM_COMMIT="$(cat "${BACKUP_ROOT}/last-commit" 2>/dev/null | tr -dc '0-9a-f' | head -c 40)"
[[ "$FROM_COMMIT" =~ ^[0-9a-f]{7,40}$ ]] || FROM_COMMIT="unknown"
TO_COMMIT="$(git rev-parse --short=12 HEAD 2>/dev/null)"
[[ "$TO_COMMIT" =~ ^[0-9a-f]{7,40}$ ]] || TO_COMMIT="unknown"
DIRTY="false"
if [ "$TO_COMMIT" != "unknown" ] && [ -n "$(git status --porcelain --untracked-files=no 2>/dev/null)" ]; then DIRTY="true"; fi
[ "$DIRTY" = "true" ] && warn "L'arbre de travail contient des modifications non commitées : elles seront construites et signalées dans le journal d'audit"
OPERATOR="${SUDO_USER:-${USER:-$(id -un 2>/dev/null)}}"
[[ "$OPERATOR" =~ ^[A-Za-z_][A-Za-z0-9_.-]{0,63}$ ]] || OPERATOR="unknown"
PREVIOUS_ANCHOR="$(cat "${BACKUP_ROOT}/last-anchor" 2>/dev/null | tr -dc '0-9a-f' | head -c 64)"
[[ "$PREVIOUS_ANCHOR" =~ ^[0-9a-f]{64}$ ]] || PREVIOUS_ANCHOR=""
[ -n "$PREVIOUS_ANCHOR" ] && info "Ancre de la mise à jour précédente à retrouver dans la chaîne : ${PREVIOUS_ANCHOR}"
info "Version déployée : ${FROM_COMMIT}  →  version installée : ${TO_COMMIT}"

if [ "$DRY_RUN" -eq 0 ] && [ "$ASSUME_YES" -eq 0 ]; then
    if [ -t 0 ]; then
        echo ""
        read -r -p "  Lancer la mise à jour ? Le backend et le worker seront arrêtés pendant la sauvegarde et les migrations. [o/N] " answer
        [[ "$answer" =~ ^[oOyY]$ ]] || fail "Mise à jour annulée."
    else
        fail "Pas de terminal pour confirmer : relance avec --yes pour une mise à jour non interactive."
    fi
fi

if [ "$GENERATE_AUDIT_KEY" -eq 1 ]; then
    if [ "$DRY_RUN" -eq 1 ]; then
        echo -e "${YELLOW}  [dry-run] génération d'AUDIT_HMAC_KEY dans .env${NC}"
    else
        backup_env || fail "Impossible de sauvegarder .env avant de le modifier."
        ok "Copie de .env avant modification : ${ENV_BACKUP}"
        NEW_KEY="$(openssl rand -hex 64)"
        [[ "$NEW_KEY" =~ ^[0-9a-f]{128}$ ]] || fail "openssl n'a pas produit de clé valide."
        TMP_ENV="$(mktemp .env.update.XXXXXX)" || fail "Impossible d'écrire à côté de .env."
        chmod --reference=.env "$TMP_ENV" 2>/dev/null || chmod 600 "$TMP_ENV"
        if grep -q '^AUDIT_HMAC_KEY=' .env; then
            K="$NEW_KEY" awk '/^AUDIT_HMAC_KEY=/{print "AUDIT_HMAC_KEY=" ENVIRON["K"]; next} {print}' .env > "$TMP_ENV"
        else
            { cat .env && { [ -z "$(tail -c 1 .env)" ] || echo; } && echo "AUDIT_HMAC_KEY=${NEW_KEY}"; } > "$TMP_ENV"
        fi
        WRITE_RC=$?
        EXPECTED_LINES=$(grep -cv '^AUDIT_HMAC_KEY=' .env)
        if [ "$WRITE_RC" -ne 0 ] \
            || [ "$(grep -cv '^AUDIT_HMAC_KEY=' "$TMP_ENV")" -ne "$EXPECTED_LINES" ] \
            || [ "$(grep -c "^AUDIT_HMAC_KEY=${NEW_KEY}\$" "$TMP_ENV")" -ne 1 ]; then
            unset NEW_KEY
            shred -u "$TMP_ENV" 2>/dev/null || unlink "$TMP_ENV"
            fail "La réécriture de .env n'a pas pu être contrôlée : .env est resté intact (copie : ${ENV_BACKUP})."
        fi
        mv "$TMP_ENV" .env || fail "Impossible de mettre à jour .env (copie intacte : ${ENV_BACKUP})."
        unset NEW_KEY
        ok "AUDIT_HMAC_KEY générée dans .env"
    fi
fi

step 5 "Construction des images"
run docker compose build || fail "La construction des images a échoué."
PHASE="built"
done_ok "Images construites"

step 6 "Vérification de la chaîne d'audit avant mise à jour"
ANCHOR_BEFORE=""
AUDIT_BEFORE=""
VERIFY_ARGS=(verify)
[ -n "$PREVIOUS_ANCHOR" ] && VERIFY_ARGS+=(--anchor "$PREVIOUS_ANCHOR")
if [ "$DRY_RUN" -eq 1 ]; then
    run docker compose run --rm --no-deps -T --user node --entrypoint node backend scripts/auditChain.js "${VERIFY_ARGS[@]}"
else
    AUDIT_BEFORE="$(docker compose run --rm --no-deps -T --user node --entrypoint node backend scripts/auditChain.js "${VERIFY_ARGS[@]}" 2>/dev/null | tail -n 1)"
    AUDIT_RC=$?
    case "$AUDIT_RC" in
        0)
            ANCHOR_BEFORE="$(json_field "$AUDIT_BEFORE" last_hmac)"
            ok "Chaîne intègre, ancre : ${ANCHOR_BEFORE}"
            ;;
        2)
            echo -e "${RED}  Chaîne d'audit en défaut avant la mise à jour : $(json_object "$AUDIT_BEFORE" problem_counts)${NC}"
            if [ "$ACCEPT_AUDIT" -eq 0 ]; then
                fail "Mise à jour arrêtée : examine l'intégrité dans Réglages → Audit, ou relance avec --accept-audit-problems pour poursuivre en connaissance de cause."
            fi
            ANCHOR_BEFORE="$(json_field "$AUDIT_BEFORE" last_hmac)"
            warn "Défaut accepté explicitement (--accept-audit-problems)"
            ;;
        3)
            warn "Le schéma actuel ne permet pas encore de vérifier la chaîne : la mise à jour continue sans ancre préalable"
            ;;
        *)
            fail "Vérification de la chaîne impossible : ${AUDIT_BEFORE:-aucune réponse}"
            ;;
    esac
fi

step 7 "Arrêt du backend et du worker (base et volumes conservés)"
run docker compose stop backend worker || fail "Impossible d'arrêter le backend et le worker."
PHASE="stopped"
done_ok "backend et worker arrêtés"

step 8 "Sauvegarde vérifiée de la base"
if [ "$DRY_RUN" -eq 1 ]; then
    echo -e "${YELLOW}  [dry-run] pg_dump vers ${BACKUP_ROOT}/${STAMP}/heimdall-${STAMP}.dump, puis pg_restore --list et sha256sum${NC}"
else
    umask 077
    mkdir -p "${BACKUP_ROOT}" && mkdir "${BACKUP_ROOT}/${STAMP}" || fail "Impossible de créer un nouveau dossier de sauvegarde ${BACKUP_ROOT}/${STAMP}."
    chmod 700 "${BACKUP_ROOT}/${STAMP}"
    BACKUP_DIR="$(cd "${BACKUP_ROOT}/${STAMP}" && pwd)"
    DUMP_NAME="heimdall-${STAMP}.dump"
    DUMP_FILE="${BACKUP_DIR}/${DUMP_NAME}"
    docker compose exec -T db pg_dump -U forensiclab -d forensiclab -Fc > "$DUMP_FILE" \
        || fail "pg_dump a échoué : pas de sauvegarde, pas de mise à jour."
    [ -s "$DUMP_FILE" ] || fail "La sauvegarde est vide : pas de mise à jour."
    docker compose exec -T db pg_restore --list < "$DUMP_FILE" > "${BACKUP_DIR}/dump-contents.txt" 2>&1 \
        || fail "La sauvegarde ne se relit pas avec pg_restore --list : pas de mise à jour."
    DUMP_SHA="$(sha256sum "$DUMP_FILE" | awk '{print $1}')"
    printf '%s  %s\n' "$DUMP_SHA" "$DUMP_NAME" > "${BACKUP_DIR}/${DUMP_NAME}.sha256"
    backup_env || fail "Impossible de sauvegarder .env : pas de mise à jour."
    [ -n "$AUDIT_BEFORE" ] && printf '%s\n' "$AUDIT_BEFORE" > "${BACKUP_DIR}/audit-before.json"
    printf 'from=%s\nto=%s\ndump=%s\nsha256=%s\n' "$FROM_COMMIT" "$TO_COMMIT" "$DUMP_NAME" "$DUMP_SHA" > "${BACKUP_DIR}/update.txt"
    ok "Sauvegarde : ${DUMP_FILE} ($(du -h "$DUMP_FILE" | cut -f1), sha256 ${DUMP_SHA})"
fi

step 9 "Migrations"
PHASE="migrating"
run bash db/migrate.sh || fail "Les migrations ont échoué."
done_ok "Schéma à jour"

step 10 "Redémarrage, santé et inscription au journal d'audit"
run docker compose up -d || { PHASE="started"; fail "docker compose up -d a échoué."; }
PHASE="started"
if [ "$DRY_RUN" -eq 1 ]; then
    run docker compose exec -T backend node scripts/auditChain.js record --from "$FROM_COMMIT" --to "$TO_COMMIT"
    run docker compose exec -T backend node scripts/auditChain.js verify
    echo -e "\n${GREEN}Mode à blanc terminé : rien n'a été modifié.${NC}"
    exit 0
fi
for name in odin huginn; do
    status="$(wait_healthy "$name")" || fail "${name} n'est pas sain après ${HEALTH_TIMEOUT}s (état : ${status})."
    ok "${name} sain"
done
docker compose exec -T backend node scripts/seedDfiq.js >/dev/null 2>&1 \
    || warn "Chargement du catalogue DFIQ en échec, à relancer : docker exec odin node scripts/seedDfiq.js"
RECORD_ARGS=(--from "$FROM_COMMIT" --to "$TO_COMMIT" --backup "$DUMP_NAME" --backup-sha256 "$DUMP_SHA" --operator "$OPERATOR" --dirty "$DIRTY")
[ -n "$ANCHOR_BEFORE" ] && RECORD_ARGS+=(--anchor-before "$ANCHOR_BEFORE")
RECORD_OUT="$(docker compose exec -T backend node scripts/auditChain.js record "${RECORD_ARGS[@]}" 2>/dev/null | tail -n 1)" \
    || fail "La mise à jour n'a pas pu être inscrite au journal d'audit : ${RECORD_OUT:-aucune réponse}"
ANCHOR_AFTER="$(json_field "$RECORD_OUT" hmac)"
[[ "$ANCHOR_AFTER" =~ ^[0-9a-f]{64}$ ]] || fail "Réponse d'inscription illisible : ${RECORD_OUT}"
printf '%s\n' "$TO_COMMIT" > "${BACKUP_ROOT}/last-commit"
printf '%s\n' "$ANCHOR_AFTER" > "${BACKUP_ROOT}/last-anchor"
printf 'anchor_after=%s\n' "$ANCHOR_AFTER" >> "${BACKUP_DIR}/update.txt"
ok "Mise à jour inscrite au journal d'audit"
AUDIT_AFTER="$(docker compose exec -T backend node scripts/auditChain.js verify --anchor "$ANCHOR_AFTER" 2>/dev/null | tail -n 1)"
AUDIT_RC=$?
printf '%s\n' "$AUDIT_AFTER" > "${BACKUP_DIR}/audit-after.json"
BEFORE_COUNTS="$(json_object "$AUDIT_BEFORE" problem_counts)"
AFTER_COUNTS="$(json_object "$AUDIT_AFTER" problem_counts)"
if [ "$AUDIT_RC" -eq 2 ] && [ "$ACCEPT_AUDIT" -eq 1 ] && [ -n "$AFTER_COUNTS" ] && [ -n "$BEFORE_COUNTS" ] && counts_not_worse "$BEFORE_COUNTS" "$AFTER_COUNTS"; then
    warn "Chaîne toujours en défaut, sans problème nouveau ni aggravé depuis avant la mise à jour : ${AFTER_COUNTS} (avant : ${BEFORE_COUNTS})"
    AUDIT_RC=0
fi
if [ "$AUDIT_RC" -ne 0 ]; then
    fail "Chaîne d'audit en défaut après la mise à jour : $(json_object "$AUDIT_AFTER" problem_counts)
     Ne modifie rien dans audit_log ; examine Réglages → Audit et conserve ${BACKUP_DIR}."
fi

echo ""
echo -e "${GREEN}${BOLD}  ✅ Mise à jour terminée${NC}"
info "Sauvegarde et contrôles : ${BACKUP_DIR}"
info "Copie de .env (secrets, à garder à part du dump) : ${ENV_BACKUP}"
info "Ancre d'audit de cette mise à jour (hmac de la ligne platform_update) : ${ANCHOR_AFTER}"
info "Note cette ancre hors de la plateforme. La prochaine mise à jour vérifie qu'elle figure toujours dans la chaîne."
