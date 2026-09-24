#!/bin/bash
# ╔══════════════════════════════════════════════════════════════╗
# ║   Heimdall DFIR — Repeuplement des outils Zimmerman          ║
# ║                                                              ║
# ║   Appele par entrypoint.sh quand des DLL critiques manquent   ║
# ║   du volume zimmerman_tools — typiquement a sa creation.      ║
# ╚══════════════════════════════════════════════════════════════╝
#
# La liste ET les empreintes viennent de /app/zimmerman-tools.lock, le meme
# fichier que le build. Deux listes divergent toujours : celle-ci portait encore
# BitsParser, dont l'URL rend 404 depuis toujours.
#
# Une archive dont l'empreinte ne correspond pas est REFUSEE, pas installee.
# Sans cela, ce chemin rouvrirait au demarrage la porte que le build ferme.
set -euo pipefail

DEST="${ZIMMERMAN_TOOLS_DIR:-/app/zimmerman-tools}"
LOCK="${ZIMMERMAN_LOCK:-/app/zimmerman-tools.lock}"
BASE_URL="https://download.ericzimmermanstools.com/net9"
TEMP="$(mktemp -d)"
trap 'rm -rf "$TEMP"' EXIT
mkdir -p "$DEST" "$TEMP/extracted"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Outils Zimmerman — verrou: $LOCK"
echo "  Destination: $DEST"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ ! -f "$LOCK" ]; then
  echo "  ✗ Verrou introuvable — aucun telechargement non verifie ne sera fait." >&2
  exit 1
fi

TOOLS=$(awk '!/^#/ && NF==2 {print $2}' "$LOCK")
[ -n "$TOOLS" ] || { echo "  ✗ Verrou vide." >&2; exit 1; }

cd "$TEMP"
failed=0
for z in $TOOLS; do
  printf '  %-26s ' "${z%.zip}"
  if curl -fsSL --connect-timeout 30 --retry 3 -o "$z" "$BASE_URL/$z"; then
    echo "telecharge"
  else
    echo "INACCESSIBLE ($BASE_URL/$z)"
    failed=1
  fi
done

# Verification globale : une seule empreinte fausse condamne le lot, parce qu'on
# ne sait alors plus ce qu'on est en train d'installer.
if ! sha256sum -c "$LOCK"; then
  echo "  ✗ Empreinte(s) non conformes — rien n'est installe." >&2
  echo "    Si l'amont a publie une nouvelle version, c'est une decision :" >&2
  echo "    bash backend/scripts/relock-zimmerman.sh, puis reconstruire." >&2
  exit 1
fi

for z in $TOOLS; do
  unzip -o -q "$z" -d "$TEMP/extracted/"
done

find "$TEMP/extracted" -name "*.dll" -exec cp -n {} "$DEST/" \; 2>/dev/null || true
find "$TEMP/extracted" -name "*.runtimeconfig.json" -exec cp -n {} "$DEST/" \; 2>/dev/null || true

mkdir -p "$DEST/Maps" "$DEST/SQLMaps" "$DEST/BatchExamples"
unzip -o -q EvtxECmd.zip -d "$DEST/Maps/"
unzip -o -q SQLECmd.zip  -d "$DEST/SQLMaps/"
unzip -o -q RECmd.zip    -d "$DEST/BatchExamples/"

# Les maps retirees par l'amont voyagent dans l'image ; les reposer ici evite que
# ce chemin rende un volume moins couvert que l'image elle-meme.
RETAINED="/app/zimmerman-maps-retained"
if [ -d "$RETAINED" ]; then
  mkdir -p "$DEST/Maps/EvtxeCmd/Maps"
  cp -f "$RETAINED"/*.map "$DEST/Maps/EvtxeCmd/Maps/" 2>/dev/null || true
fi

echo "  ✓ $(ls "$DEST"/*.dll 2>/dev/null | wc -l) DLL, $(find "$DEST/Maps" -name '*.map' 2>/dev/null | wc -l) maps"
[ "$failed" -eq 0 ] || { echo "  ✗ Au moins un telechargement a echoue." >&2; exit 1; }
