#!/bin/bash
set -uo pipefail

IMAGE="${1:-/opt/zimmerman-tools}"
VOLUME="${2:-/app/zimmerman-tools}"
LOCK="${3:-/app/zimmerman-tools.lock}"
MARKER="$VOLUME/.tools.lock.sha256"

log() { echo "[zimmerman-sync] $*"; }

if [ ! -d "$IMAGE" ] || [ -z "$(ls -A "$IMAGE" 2>/dev/null)" ]; then
    log "aucun jeu d'outils dans l'image ($IMAGE) : volume inchange"
    exit 0
fi
if [ ! -f "$LOCK" ]; then
    log "verrou introuvable ($LOCK) : volume inchange"
    exit 0
fi

WANT="$(sha256sum "$LOCK" | cut -d' ' -f1)"
mkdir -p "$VOLUME" || exit 1
HAVE="$(cat "$MARKER" 2>/dev/null || true)"
if [ "$WANT" = "$HAVE" ]; then
    log "outils a jour (verrou ${WANT:0:12})"
    exit 0
fi

if ls "$VOLUME"/*.dll >/dev/null 2>&1; then
    rm -rf "$VOLUME/.previous.incoming"
    mkdir -p "$VOLUME/.previous.incoming" || exit 1
    for entry in "$VOLUME"/*; do
        cp -a "$entry" "$VOLUME/.previous.incoming/" || { log "sauvegarde du jeu actuel impossible : rien n'est modifie"; exit 1; }
    done
    rm -rf "$VOLUME/.previous"
    mv "$VOLUME/.previous.incoming" "$VOLUME/.previous" || exit 1
    [ -f "$MARKER" ] && mv "$MARKER" "$VOLUME/.previous/.tools.lock.sha256"
    log "jeu precedent sauvegarde dans $VOLUME/.previous"
fi

if ! cp -a "$IMAGE"/. "$VOLUME"/; then
    log "copie des outils de l'image echouee : marqueur non ecrit, nouvel essai au prochain demarrage"
    exit 1
fi

printf '%s\n' "$WANT" > "$MARKER.incoming" && mv "$MARKER.incoming" "$MARKER" || exit 1
log "outils synchronises depuis l'image (verrou ${WANT:0:12})"
