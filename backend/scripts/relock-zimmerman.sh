#!/usr/bin/env bash
# Adopter une nouvelle version amont des outils Eric Zimmerman.
#
# download.ericzimmermanstools.com ne publie que « latest » : aucune URL
# versionnee n'existe. Le verrou est donc un jeu d'empreintes, et le build
# echoue des qu'une archive amont bouge. Ce script est la porte de sortie
# volontaire : il retelecharge tout et reecrit zimmerman-tools.lock.
#
# A executer QUAND ON DECIDE de monter de version, jamais en reaction a un build
# rouge. Un parseur forensique qui change modifie ce qui sort des scelles.
#
# Apres execution :
#   1. git diff backend/zimmerman-tools.lock   -> quelles archives ont bouge
#   2. reconstruire, puis comparer la sortie sur un cas connu avant/apres
#   3. verifier qu'aucune map n'a disparu (voir zimmerman-maps-retained/README)
set -euo pipefail

BASE="https://download.ericzimmermanstools.com/net9"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="$HERE/zimmerman-tools.lock"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

[ -f "$LOCK" ] || { echo "verrou introuvable: $LOCK" >&2; exit 1; }

# La liste des outils vient du verrou lui-meme : ajouter un outil se fait en
# ajoutant sa ligne, pas en modifiant ce script.
mapfile -t TOOLS < <(awk '!/^#/ && NF==2 {print $2}' "$LOCK")
[ "${#TOOLS[@]}" -gt 0 ] || { echo "aucun outil dans $LOCK" >&2; exit 1; }

echo "Retelechargement de ${#TOOLS[@]} archives..."
for z in "${TOOLS[@]}"; do
  printf '  %-26s ' "$z"
  if curl -fsSL --retry 3 --connect-timeout 30 -o "$TMP/$z" "$BASE/$z"; then
    echo "ok"
  else
    echo "ECHEC — $BASE/$z"
    echo "Si l'outil a disparu amont, retirer sa ligne du verrou en connaissance de cause." >&2
    exit 1
  fi
done

{
  # L'en-tete du verrou est conserve tel quel : il porte le raisonnement, pas
  # des donnees, et se perdrait a chaque regeneration.
  awk '/^[0-9a-f]{64}  / {exit} {print}' "$LOCK"
  for z in "${TOOLS[@]}"; do
    name="${z%.zip}"
    lm=$(curl -sI --max-time 20 "$BASE/$z" | awk 'tolower($1)=="last-modified:"{sub(/^[^:]*: */,""); print; exit}' | tr -d '\r')
    sha=$(sha256sum "$TMP/$z" | cut -d" " -f1)
    printf '# %s — amont Last-Modified: %s\n%s  %s\n' "$name" "${lm:-inconnue}" "$sha" "$z"
  done
} > "$LOCK.new"

mv "$LOCK.new" "$LOCK"
echo
echo "Verrou reecrit. Relire le diff AVANT de reconstruire :"
echo "  git diff -- backend/zimmerman-tools.lock"
