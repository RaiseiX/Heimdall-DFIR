#!/bin/bash
set -uo pipefail

cd "$(dirname "$0")" || exit 1

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

IMAGE="restic/restic:0.19.1@sha256:136600b6ff6843d61d355f7f71f460a166429f35de6fd11b568fece3c9a4d510"
DEFAULT_VOLUMES="uploads_data collections_data volweb_media minio_data evidence_data"
CONFIG_KEYS=(RESTIC_REPOSITORY RESTIC_PASSWORD_FILE BACKUP_VOLUMES BACKUP_INCLUDE_ENV KEEP_DAILY KEEP_WEEKLY KEEP_MONTHLY SSH_KEY_FILE SSH_KNOWN_HOSTS RESTIC_ENV_FILE COMPOSE_PROJECT_NAME)

usage() {
    echo "Usage : bash backup.sh <commande> [options]"
    echo ""
    echo "  init                                   initialise le dépôt restic ; refusé s'il existe déjà"
    echo "  run [--dry-run] [--yes]                sauvegarde la base PostgreSQL, les volumes et .env, puis applique la rétention"
    echo "  check [--read-data-subset=N%]          vérifie l'intégrité du dépôt"
    echo "  snapshots                              liste les snapshots"
    echo "  restore <snapshot> <dossier_cible>     restaure dans un dossier hôte vide ou inexistant"
    echo "  --help                                 affiche cette aide"
    echo ""
    echo "Options de run :"
    echo "  --dry-run   contrôles en lecture seule, puis affiche les étapes sans rien écrire dans le dépôt"
    echo "  --yes       ne pas demander de confirmation ; obligatoire hors terminal"
    echo ""
    echo "Configuration : fichier backup.env à la racine (jamais versionné), ou celui de HEIMDALL_BACKUP_CONFIG."
    echo "Modèle : backup.env.example. Format KEY=valeur, une variable par ligne. Une variable déjà présente dans l'environnement garde sa valeur."
    echo ""
    echo "  RESTIC_REPOSITORY      obligatoire : chemin absolu local, sftp:user@hote:/chemin, s3:https://hote/bucket, etc."
    echo "                         Un dépôt local est monté sur /repo avec le réseau coupé ; un dépôt distant utilise le réseau de l'hôte."
    echo "  RESTIC_PASSWORD_FILE   obligatoire : fichier contenant le mot de passe du dépôt, en mode 600 ou 400."
    echo "                         Il est monté en lecture seule dans le conteneur et n'est jamais passé en argument."
    echo "  BACKUP_VOLUMES         noms courts séparés par des espaces (défaut : ${DEFAULT_VOLUMES})"
    echo "  BACKUP_INCLUDE_ENV     1 par défaut : inclut .env dans la sauvegarde (il contient des secrets : protège le dépôt en conséquence)"
    echo "  KEEP_DAILY, KEEP_WEEKLY, KEEP_MONTHLY"
    echo "                         rétention : sans aucune de ces variables, rien n'est jamais supprimé du dépôt"
    echo "  SSH_KEY_FILE           clé privée pour sftp, montée en lecture seule"
    echo "  SSH_KNOWN_HOSTS        fichier known_hosts pour sftp, obligatoire avec sftp ; la clé de l'hôte est vérifiée strictement"
    echo "  RESTIC_ENV_FILE        fichier de variables (S3, etc.) en mode 600 ou 400, passé au conteneur par --env-file"
    echo "  COMPOSE_PROJECT_NAME   préfixe des volumes ; par défaut, le nom de projet donné par docker compose config"
    echo ""
    echo "Étapes de run : contrôles, dump PostgreSQL (pg_dump -Fc) envoyé directement à restic, volumes montés en lecture seule,"
    echo "rétention si définie, résumé JSON dans backups/backup-runs/."
    echo ""
    echo "restore ne touche jamais aux volumes Docker : la cible doit être un dossier hôte vide ou inexistant, hors de /var/lib/docker."
    echo "Un essai de restauration régulier est le seul vrai test d'une sauvegarde."
}

for arg in "$@"; do
    case "$arg" in
        -h|--help) usage; exit 0 ;;
    esac
done

STAMP="$(date +%Y%m%d-%H%M%S)-$$"
RUNS_DIR="backups/backup-runs"
SUMMARY_FILE=""
RUN_ACTIVE=0
DRY_RUN=0
ASSUME_YES=0
CURRENT_STEP="contrôles"
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
DB_STATUS="skipped"; DB_SNAP=""; DB_ADDED=""; DB_SECS=""
VOL_STATUS="skipped"; VOL_SNAP=""; VOL_ADDED=""; VOL_SECS=""
RET_STATUS="skipped"
PROJECT=""
NETWORK="none"
REPO_LOCAL=0
REPO_ABS=""
PASSWORD_ABS=""
COMMON=()
RESTIC_OPTS=()

step() { echo -e "\n${CYAN}[$1] $2${NC}"; }
ok() { echo -e "${GREEN}  ✓ $*${NC}"; }
warn() { echo -e "${YELLOW}  ⚠ $*${NC}"; }
info() { echo -e "    $*"; }

jstr() { if [ -n "$1" ]; then printf '"%s"' "$1"; else printf 'null'; fi; }
jnum() { if [[ "$1" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then printf '%s' "$1"; else printf 'null'; fi; }

write_summary() {
    [ "$RUN_ACTIVE" -eq 1 ] && [ "$DRY_RUN" -eq 0 ] || return 0
    local status="$1" volumes_json="" v
    for v in ${BACKUP_VOLUMES:-$DEFAULT_VOLUMES}; do volumes_json+="${volumes_json:+,}\"${v}\""; done
    ( umask 077; mkdir -p "$RUNS_DIR" ) || return 0
    chmod 700 "$RUNS_DIR" 2>/dev/null
    SUMMARY_FILE="${RUNS_DIR}/${STAMP}.json"
    (
        umask 077
        printf '{"stamp":"%s","started_at":"%s","finished_at":"%s","status":"%s","failed_step":%s,' \
            "$STAMP" "$STARTED_AT" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$status" "$([ "$status" = ok ] && echo null || jstr "$CURRENT_STEP")"
        printf '"database":{"status":"%s","snapshot_id":%s,"data_added":%s,"duration_seconds":%s},' \
            "$DB_STATUS" "$(jstr "$DB_SNAP")" "$(jnum "$DB_ADDED")" "$(jnum "$DB_SECS")"
        printf '"volumes":{"status":"%s","snapshot_id":%s,"data_added":%s,"duration_seconds":%s,"names":[%s],"env_included":%s},' \
            "$VOL_STATUS" "$(jstr "$VOL_SNAP")" "$(jnum "$VOL_ADDED")" "$(jnum "$VOL_SECS")" "$volumes_json" "$([ "${BACKUP_INCLUDE_ENV:-1}" = 1 ] && echo true || echo false)"
        printf '"retention":{"status":"%s"}}\n' "$RET_STATUS"
    ) > "$SUMMARY_FILE" || return 0
    chmod 600 "$SUMMARY_FILE" 2>/dev/null
}

fail() {
    echo -e "${RED}  ❌ $*${NC}"
    write_summary failed
    [ -n "$SUMMARY_FILE" ] && info "Résumé de l'exécution : ${SUMMARY_FILE}"
    exit 1
}

run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        echo -e "${YELLOW}  [dry-run] $*${NC}"
        return 0
    fi
    "$@"
}

json_str() { printf '%s\n' "$1" | grep -o "\"$2\":\"[^\"]*\"" | head -n 1 | cut -d'"' -f4; }
json_num() { printf '%s\n' "$1" | grep -o "\"$2\":[0-9.]*" | head -n 1 | cut -d: -f2; }
summary_line() { printf '%s\n' "$1" | grep '"message_type":"summary"' | tail -n 1; }

tail_output() { printf '%s\n' "$1" | tail -n 5 | sed 's/^/    /'; }

mode_private() {
    local m
    m="$(stat -c %a "$1" 2>/dev/null)" || return 1
    [[ "$m" =~ ^[0-7]+$ ]] || return 1
    [ $(( 8#$m & 077 )) -eq 0 ]
}

path_within() {
    case "$1/" in
        "$2"/*) return 0 ;;
    esac
    return 1
}

container_health() {
    docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$1" 2>/dev/null || echo "absent"
}

load_config() {
    local file="${HEIMDALL_BACKUP_CONFIG:-backup.env}" line key value k
    [ -f "$file" ] || fail "Configuration introuvable : ${file}. Copie backup.env.example vers backup.env et renseigne-le (voir --help)."
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        [[ "$line" =~ ^[[:space:]]*([A-Z_]+)=(.*)$ ]] || continue
        key="${BASH_REMATCH[1]}"
        value="${BASH_REMATCH[2]}"
        if [[ "$value" =~ ^\"(.*)\"$ ]] || [[ "$value" =~ ^\'(.*)\'$ ]]; then value="${BASH_REMATCH[1]}"; fi
        for k in "${CONFIG_KEYS[@]}"; do
            if [ "$k" = "$key" ] && [ -z "${!k+x}" ]; then printf -v "$k" '%s' "$value"; fi
        done
    done < "$file"
}

validate_config() {
    local v n
    [ -n "${RESTIC_REPOSITORY:-}" ] || fail "RESTIC_REPOSITORY est obligatoire dans la configuration."
    [ -n "${RESTIC_PASSWORD_FILE:-}" ] || fail "RESTIC_PASSWORD_FILE est obligatoire dans la configuration."
    if [[ "$RESTIC_REPOSITORY" =~ ://[^/@]*:[^/@]*@ ]]; then
        fail "RESTIC_REPOSITORY contient un mot de passe dans l'URL : retire-le et fournis les identifiants par RESTIC_ENV_FILE."
    fi
    [ -f "$RESTIC_PASSWORD_FILE" ] || fail "Fichier de mot de passe introuvable : ${RESTIC_PASSWORD_FILE}"
    [ -s "$RESTIC_PASSWORD_FILE" ] || fail "Fichier de mot de passe vide : ${RESTIC_PASSWORD_FILE}"
    mode_private "$RESTIC_PASSWORD_FILE" || fail "Le fichier de mot de passe est lisible par le groupe ou les autres : chmod 600 ${RESTIC_PASSWORD_FILE}"
    PASSWORD_ABS="$(realpath -m -- "$RESTIC_PASSWORD_FILE")"
    if [ -n "${RESTIC_ENV_FILE:-}" ]; then
        [ -f "$RESTIC_ENV_FILE" ] || fail "RESTIC_ENV_FILE introuvable : ${RESTIC_ENV_FILE}"
        mode_private "$RESTIC_ENV_FILE" || fail "RESTIC_ENV_FILE est lisible par le groupe ou les autres : chmod 600 ${RESTIC_ENV_FILE}"
    fi
    BACKUP_VOLUMES="${BACKUP_VOLUMES:-$DEFAULT_VOLUMES}"
    [ -n "${BACKUP_VOLUMES// /}" ] || BACKUP_VOLUMES="$DEFAULT_VOLUMES"
    for v in $BACKUP_VOLUMES; do
        [[ "$v" =~ ^[a-z0-9][a-z0-9_]*$ ]] || fail "Nom de volume invalide dans BACKUP_VOLUMES : ${v}"
    done
    BACKUP_INCLUDE_ENV="${BACKUP_INCLUDE_ENV:-1}"
    [[ "$BACKUP_INCLUDE_ENV" =~ ^[01]$ ]] || fail "BACKUP_INCLUDE_ENV doit valoir 0 ou 1."
    for n in KEEP_DAILY KEEP_WEEKLY KEEP_MONTHLY; do
        [[ "${!n:-0}" =~ ^[0-9]+$ ]] || fail "${n} doit être un entier."
    done
    if [[ "$RESTIC_REPOSITORY" == /* ]]; then
        REPO_LOCAL=1
        REPO_ABS="$(realpath -m -- "$RESTIC_REPOSITORY")"
        NETWORK="none"
    elif [[ "$RESTIC_REPOSITORY" == *:* ]]; then
        NETWORK="host"
    else
        fail "RESTIC_REPOSITORY doit être un chemin absolu local ou une URL restic (sftp:, s3:, ...)."
    fi
    if [[ "$RESTIC_REPOSITORY" == sftp:* ]]; then
        [ -n "${SSH_KNOWN_HOSTS:-}" ] || fail "SSH_KNOWN_HOSTS est obligatoire avec un dépôt sftp : la clé de l'hôte est vérifiée strictement."
        [ -f "$SSH_KNOWN_HOSTS" ] || fail "SSH_KNOWN_HOSTS introuvable : ${SSH_KNOWN_HOSTS}"
        if [ -n "${SSH_KEY_FILE:-}" ]; then
            [ -f "$SSH_KEY_FILE" ] || fail "SSH_KEY_FILE introuvable : ${SSH_KEY_FILE}"
            mode_private "$SSH_KEY_FILE" || fail "SSH_KEY_FILE est lisible par le groupe ou les autres : chmod 600 ${SSH_KEY_FILE}"
        fi
    fi
}

build_common() {
    local repo_in="$RESTIC_REPOSITORY" ssh_args
    if [ "$REPO_LOCAL" -eq 1 ]; then repo_in="/repo"; fi
    COMMON=(--network "$NETWORK" --security-opt no-new-privileges
        -v "${PASSWORD_ABS}:/run/secrets/restic_password:ro"
        -e RESTIC_PASSWORD_FILE=/run/secrets/restic_password
        -e "RESTIC_REPOSITORY=${repo_in}"
        -e RESTIC_PROGRESS_FPS=0.0166)
    [ "$REPO_LOCAL" -eq 1 ] && COMMON+=(-v "${REPO_ABS}:/repo")
    [ -n "${RESTIC_ENV_FILE:-}" ] && COMMON+=(--env-file "$RESTIC_ENV_FILE")
    if [[ "$RESTIC_REPOSITORY" == sftp:* ]]; then
        ssh_args="-o StrictHostKeyChecking=yes -o UserKnownHostsFile=/run/secrets/known_hosts -o BatchMode=yes"
        COMMON+=(-v "$(realpath -m -- "$SSH_KNOWN_HOSTS"):/run/secrets/known_hosts:ro")
        if [ -n "${SSH_KEY_FILE:-}" ]; then
            COMMON+=(-v "$(realpath -m -- "$SSH_KEY_FILE"):/run/secrets/ssh_key:ro")
            ssh_args="${ssh_args} -o IdentitiesOnly=yes -i /run/secrets/ssh_key"
        fi
        RESTIC_OPTS=(-o "sftp.args=${ssh_args}")
    fi
}

run_restic() {
    local extra=()
    while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do extra+=("$1"); shift; done
    shift
    docker run --rm "${COMMON[@]}" ${extra[@]+"${extra[@]}"} "$IMAGE" ${RESTIC_OPTS[@]+"${RESTIC_OPTS[@]}"} "$@"
}

repo_reachable() {
    run_restic -- cat config >/dev/null 2>&1
}

resolve_project() {
    local out
    if [ -n "${COMPOSE_PROJECT_NAME:-}" ]; then
        PROJECT="$COMPOSE_PROJECT_NAME"
    else
        out="$(docker compose config --format json 2>/dev/null)"
        PROJECT="$(printf '%s\n' "$out" | grep -m1 -oE '"name": *"[^"]*"' | head -n 1 | cut -d'"' -f4)"
        if [ -z "$PROJECT" ]; then
            PROJECT="$(basename "$PWD" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9_-')"
            warn "Nom de projet compose non lisible : préfixe déduit du dossier (${PROJECT}). Fixe COMPOSE_PROJECT_NAME si les volumes sont introuvables."
        fi
    fi
    [[ "$PROJECT" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || fail "Nom de projet compose invalide : ${PROJECT}"
}

prepare() {
    command -v docker >/dev/null 2>&1 || fail "Docker n'est pas installé."
    command -v realpath >/dev/null 2>&1 || fail "realpath est requis."
    load_config
    validate_config
    build_common
}

require_repo_dir() {
    [ "$REPO_LOCAL" -eq 0 ] || [ -d "$REPO_ABS" ] || fail "Le dossier du dépôt local n'existe pas : ${REPO_ABS}. Crée-le, puis lance « bash backup.sh init »."
}

cmd_init() {
    prepare
    if [ "$REPO_LOCAL" -eq 1 ] && [ ! -d "$REPO_ABS" ]; then
        ( umask 077; mkdir -p "$REPO_ABS" ) || fail "Impossible de créer ${REPO_ABS}."
    fi
    repo_reachable && fail "Le dépôt existe déjà : initialisation refusée."
    run_restic -- init || fail "restic init a échoué."
    ok "Dépôt initialisé"
    info "Garde le fichier de mot de passe hors de cette machine : sans lui, le dépôt est illisible."
}

cmd_check() {
    local subset=""
    for arg in "$@"; do
        case "$arg" in
            --read-data-subset=*)
                subset="$arg"
                [[ "${arg#--read-data-subset=}" =~ ^([0-9]+(\.[0-9]+)?%|[0-9]+/[0-9]+)$ ]] || { echo -e "${RED}Sous-ensemble invalide : ${arg}${NC}"; exit 64; }
                ;;
            *) echo -e "${RED}Option inconnue : ${arg}${NC}"; usage; exit 64 ;;
        esac
    done
    prepare
    require_repo_dir
    if [ -n "$subset" ]; then
        run_restic -- check "$subset" || fail "restic check a échoué."
    else
        run_restic -- check || fail "restic check a échoué."
    fi
    ok "Dépôt vérifié"
}

cmd_snapshots() {
    prepare
    require_repo_dir
    run_restic -- snapshots || fail "restic snapshots a échoué."
}

cmd_restore() {
    [ "$#" -eq 2 ] || { echo -e "${RED}Usage : bash backup.sh restore <snapshot> <dossier_cible>${NC}"; exit 64; }
    local snapshot="$1" target abs mount_point v docker_root
    [[ "$snapshot" =~ ^([0-9a-f]{6,64}|latest)$ ]] || { echo -e "${RED}Identifiant de snapshot invalide : ${snapshot}${NC}"; exit 64; }
    prepare
    require_repo_dir
    resolve_project
    abs="$(realpath -m -- "$2")"
    [ "$abs" != "/" ] || fail "Cible refusée : /"
    docker_root="$(docker info -f '{{.DockerRootDir}}' 2>/dev/null)"
    for target in /var/lib/docker ${docker_root:+"$docker_root"}; do
        if path_within "$abs" "$target" || path_within "$target" "$abs"; then
            fail "Cible refusée : ${abs} recouvre le stockage de Docker (${target}). La restauration ne touche jamais aux volumes de production."
        fi
    done
    for v in $BACKUP_VOLUMES; do
        mount_point="$(docker volume inspect -f '{{.Mountpoint}}' "${PROJECT}_${v}" 2>/dev/null)"
        [ -n "$mount_point" ] || continue
        if path_within "$abs" "$mount_point" || path_within "$mount_point" "$abs"; then
            fail "Cible refusée : ${abs} recouvre le volume Docker ${PROJECT}_${v}. La restauration ne touche jamais aux volumes de production."
        fi
    done
    if [ -e "$abs" ]; then
        [ -d "$abs" ] || fail "La cible existe et n'est pas un dossier : ${abs}"
        [ -z "$(ls -A -- "$abs" 2>/dev/null)" ] || fail "Le dossier cible n'est pas vide : ${abs}"
    else
        ( umask 077; mkdir -p "$abs" ) || fail "Impossible de créer ${abs}."
    fi
    run_restic -v "${abs}:/restore" -- restore "$snapshot" --target /restore --verify || fail "restic restore a échoué."
    ok "Snapshot ${snapshot} restauré dans ${abs}"
    info "Les fichiers appartiennent à root : contrôle-les, puis recopie-les toi-même vers leur destination."
}

cmd_run() {
    local arg
    for arg in "$@"; do
        case "$arg" in
            --dry-run) DRY_RUN=1 ;;
            --yes|-y) ASSUME_YES=1 ;;
            *) echo -e "${RED}Option inconnue : ${arg}${NC}"; usage; exit 64 ;;
        esac
    done
    if [ "$DRY_RUN" -eq 0 ] && [ "$ASSUME_YES" -eq 0 ] && [ ! -t 0 ]; then
        fail "Pas de terminal pour confirmer : relance avec --yes."
    fi

    echo -e "${CYAN}${BOLD}Heimdall DFIR — sauvegarde restic${NC}"
    [ "$DRY_RUN" -eq 1 ] && echo -e "${YELLOW}Mode à blanc (dry-run) : rien n'est écrit dans le dépôt.${NC}"

    step "1/5" "Contrôles"
    prepare
    RUN_ACTIVE=1
    docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 n'est pas disponible."
    [ -f docker-compose.yml ] || fail "docker-compose.yml introuvable : lance le script depuis la racine du dépôt."
    if [ "$BACKUP_INCLUDE_ENV" = 1 ]; then
        [ -f .env ] || fail "Fichier .env introuvable (BACKUP_INCLUDE_ENV=1)."
    fi
    require_repo_dir
    [ "$(container_health yggdrasil)" = "healthy" ] || fail "PostgreSQL (yggdrasil) n'est pas sain : docker compose up -d db, puis relance."
    resolve_project
    local v
    for v in $BACKUP_VOLUMES; do
        docker volume inspect "${PROJECT}_${v}" >/dev/null 2>&1 || fail "Volume introuvable : ${PROJECT}_${v}. Fixe COMPOSE_PROJECT_NAME ou BACKUP_VOLUMES."
    done
    repo_reachable || fail "Dépôt inaccessible : initialise-le avec « bash backup.sh init » ou vérifie RESTIC_REPOSITORY, le mot de passe et le réseau."
    ok "Docker, configuration, mot de passe, PostgreSQL, volumes (${BACKUP_VOLUMES}), dépôt"

    if [ "$DRY_RUN" -eq 0 ] && [ "$ASSUME_YES" -eq 0 ]; then
        echo ""
        read -r -p "  Lancer la sauvegarde ? [o/N] " answer
        [[ "$answer" =~ ^[oOyY]$ ]] || fail "Sauvegarde annulée."
    fi

    local out line rc started
    CURRENT_STEP="base de données"
    step "2/5" "Base de données PostgreSQL"
    if [ "$DRY_RUN" -eq 1 ]; then
        echo -e "${YELLOW}  [dry-run] docker compose exec -T db pg_dump -U forensiclab -d forensiclab -Fc | restic backup --stdin --stdin-filename postgres/forensiclab.dump --tag heimdall --tag db${NC}"
    else
        started=$SECONDS
        out="$(docker compose exec -T db pg_dump -U forensiclab -d forensiclab -Fc | run_restic -i -- backup --stdin --stdin-filename postgres/forensiclab.dump --tag heimdall --tag db --json 2>&1)"
        rc=$?
        DB_SECS=$((SECONDS - started))
        line="$(summary_line "$out")"
        DB_SNAP="$(json_str "$line" snapshot_id)"
        DB_ADDED="$(json_num "$line" data_added)"
        if [ "$rc" -ne 0 ]; then
            DB_STATUS="failed"
            tail_output "$out"
            if [ -n "$DB_SNAP" ]; then
                if run_restic -- tag --add incomplete --remove db "$DB_SNAP" >/dev/null 2>&1; then
                    warn "Le snapshot ${DB_SNAP} est incomplet : il porte désormais le tag « incomplete » et plus le tag « db ». Ne le restaure pas ; supprime-le quand tu veux avec restic forget ${DB_SNAP}."
                else
                    warn "Un snapshot incomplet (${DB_SNAP}) a été créé et n'a pas pu être marqué : ne le restaure pas ; supprime-le avec restic forget ${DB_SNAP}."
                fi
            fi
            fail "pg_dump ou restic a échoué : la sauvegarde de la base n'est pas valide."
        fi
        [ -n "$DB_SNAP" ] || { DB_STATUS="failed"; fail "restic n'a pas renvoyé d'identifiant de snapshot pour la base."; }
        DB_STATUS="ok"
        ok "Base sauvegardée : snapshot ${DB_SNAP}, ${DB_ADDED:-0} octets ajoutés"
    fi

    CURRENT_STEP="volumes"
    step "3/5" "Volumes"
    local vol_args=()
    for v in $BACKUP_VOLUMES; do vol_args+=(-v "${PROJECT}_${v}:/data/${v}:ro"); done
    [ "$BACKUP_INCLUDE_ENV" = 1 ] && vol_args+=(-v "${PWD}/.env:/data/env/.env:ro")
    if [ "$DRY_RUN" -eq 1 ]; then
        echo -e "${YELLOW}  [dry-run] restic backup /data --tag heimdall --tag volumes, avec ${BACKUP_VOLUMES}$([ "$BACKUP_INCLUDE_ENV" = 1 ] && echo ' et .env') montés en lecture seule${NC}"
    else
        started=$SECONDS
        out="$(run_restic "${vol_args[@]}" -- backup /data --tag heimdall --tag volumes --json 2>&1)"
        rc=$?
        VOL_SECS=$((SECONDS - started))
        line="$(summary_line "$out")"
        VOL_SNAP="$(json_str "$line" snapshot_id)"
        VOL_ADDED="$(json_num "$line" data_added)"
        if [ "$rc" -ne 0 ]; then
            VOL_STATUS="failed"
            tail_output "$out"
            fail "La sauvegarde des volumes a échoué."
        fi
        [ -n "$VOL_SNAP" ] || { VOL_STATUS="failed"; fail "restic n'a pas renvoyé d'identifiant de snapshot pour les volumes."; }
        VOL_STATUS="ok"
        ok "Volumes sauvegardés : snapshot ${VOL_SNAP}, ${VOL_ADDED:-0} octets ajoutés"
    fi

    CURRENT_STEP="rétention"
    step "4/5" "Rétention"
    local forget_args=()
    [ -n "${KEEP_DAILY:-}" ] && forget_args+=(--keep-daily "$KEEP_DAILY")
    [ -n "${KEEP_WEEKLY:-}" ] && forget_args+=(--keep-weekly "$KEEP_WEEKLY")
    [ -n "${KEEP_MONTHLY:-}" ] && forget_args+=(--keep-monthly "$KEEP_MONTHLY")
    if [ "${#forget_args[@]}" -eq 0 ]; then
        info "Aucune variable KEEP_* : rien n'est supprimé du dépôt."
    else
        if [ "$DRY_RUN" -eq 1 ]; then
            echo -e "${YELLOW}  [dry-run] restic forget --tag heimdall --group-by tags ${forget_args[*]} --prune${NC}"
        else
            out="$(run_restic -- forget --tag heimdall --group-by tags "${forget_args[@]}" --prune 2>&1)" || { RET_STATUS="failed"; tail_output "$out"; fail "La rétention a échoué : les sauvegardes sont faites, rien n'est perdu."; }
            RET_STATUS="ok"
            ok "Rétention appliquée"
        fi
    fi

    CURRENT_STEP="résumé"
    step "5/5" "Résumé"
    if [ "$DRY_RUN" -eq 1 ]; then
        echo -e "\n${GREEN}Mode à blanc terminé : rien n'a été écrit.${NC}"
        exit 0
    fi
    write_summary ok
    echo ""
    echo -e "${GREEN}${BOLD}  ✅ Sauvegarde terminée${NC}"
    info "Base : ${DB_SNAP} ; volumes : ${VOL_SNAP}"
    info "Résumé : ${SUMMARY_FILE}"
    info "Vérifie régulièrement avec « bash backup.sh check » et essaie une restauration."
}

COMMAND="${1:-}"
[ -n "$COMMAND" ] || { usage; exit 64; }
shift

case "$COMMAND" in
    init) cmd_init "$@" ;;
    run) cmd_run "$@" ;;
    check) cmd_check "$@" ;;
    snapshots) cmd_snapshots "$@" ;;
    restore) cmd_restore "$@" ;;
    *) echo -e "${RED}Commande inconnue : ${COMMAND}${NC}"; usage; exit 64 ;;
esac
