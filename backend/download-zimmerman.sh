#!/bin/bash
# ╔══════════════════════════════════════════════════════════════╗
# ║   ForensicLab — Téléchargement des outils Zimmerman         ║
# ║                                                              ║
# ║   Utilisation :                                              ║
# ║     docker exec forensiclab-api bash /app/download-zimmerman.sh ║
# ║   Ou depuis l'entrypoint au premier démarrage.              ║
# ╚══════════════════════════════════════════════════════════════╝

set -e

DEST="${ZIMMERMAN_TOOLS_DIR:-/app/zimmerman-tools}"
TEMP="/tmp/zimmerman-download"
mkdir -p "$DEST" "$TEMP/extracted"

BASE_URL="https://download.ericzimmermanstools.com/net9"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Téléchargement des outils Zimmerman"
echo "  Destination: $DEST"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

TOOLS=(
  "MFTECmd.zip"
  "PECmd.zip"
  "LECmd.zip"
  "SBECmd.zip"
  "AmcacheParser.zip"
  "AppCompatCacheParser.zip"
  "EvtxECmd.zip"
  "RECmd.zip"
  "JLECmd.zip"
  "SrumECmd.zip"
  "WxTCmd.zip"
  "SumECmd.zip"
  "RBCmd.zip"
  "BitsParser.zip"
  "SQLECmd.zip"
)

for tool in "${TOOLS[@]}"; do
  name="${tool%.zip}"
  echo "  Downloading $name..."
  if curl -fsSL --connect-timeout 30 -o "$TEMP/$tool" "$BASE_URL/$tool" 2>/dev/null; then
    unzip -o -q "$TEMP/$tool" -d "$TEMP/extracted/" 2>/dev/null || true
    echo "  ✓ $name extrait"
  else
    echo "  ✗ $name inaccessible (URL: $BASE_URL/$tool)"
  fi
done

# Flatten: copier DLLs + runtimeconfig.json à la racine de DEST
# (runtimeconfig.json requis pour dotnet framework-dependent execution)
echo ""
echo "  Mise en place des DLLs dans $DEST..."
find "$TEMP/extracted" -name "*.dll" -exec cp -n {} "$DEST/" \; 2>/dev/null || true
find "$TEMP/extracted" -name "*.runtimeconfig.json" -exec cp -n {} "$DEST/" \; 2>/dev/null || true

DLL_COUNT=$(ls "$DEST"/*.dll 2>/dev/null | wc -l)
echo "  ✓ $DLL_COUNT DLLs disponibles"

# ─── Maps pour EvtxECmd ───────────────────────────────────────
# EvtxECmd cherche ses .map dans {ZIMMERMAN_DIR}/Maps/
echo ""
echo "  Downloading EvtxECmd Maps..."
if curl -fsSL --connect-timeout 30 -o "$TEMP/EvtxECmdMaps.zip" \
    "https://download.ericzimmermanstools.com/net9/EvtxECmd.zip" 2>/dev/null; then
  mkdir -p "$DEST/Maps"
  unzip -o -q "$TEMP/EvtxECmdMaps.zip" -d "$DEST/Maps/" 2>/dev/null || true
  MAP_COUNT=$(ls "$DEST/Maps"/*.map 2>/dev/null | wc -l)
  echo "  ✓ EvtxECmd Maps: $MAP_COUNT fichiers"
else
  echo "  ✗ Maps EvtxECmd inaccessibles"
fi

# ─── Maps pour SQLECmd ───────────────────────────────────────
# SQLECmd cherche ses maps dans {ZIMMERMAN_DIR}/SQLMaps/
echo "  Downloading SQLECmd Maps..."
if curl -fsSL --connect-timeout 30 -o "$TEMP/SQLECmdMaps.zip" \
    "https://download.ericzimmermanstools.com/net9/SQLECmd.zip" 2>/dev/null; then
  mkdir -p "$DEST/SQLMaps"
  unzip -o -q "$TEMP/SQLECmdMaps.zip" -d "$DEST/SQLMaps/" 2>/dev/null || true
  SQL_MAP_COUNT=$(ls "$DEST/SQLMaps"/*.smap 2>/dev/null | wc -l)
  echo "  ✓ SQLECmd Maps: $SQL_MAP_COUNT fichiers"
else
  echo "  ✗ Maps SQLECmd inaccessibles"
fi

# ─── BatchExamples pour RECmd ─────────────────────────────────
echo "  Downloading RECmd BatchExamples..."
if curl -fsSL --connect-timeout 30 -o "$TEMP/RECmdBatch.zip" \
    "https://download.ericzimmermanstools.com/net9/RECmd.zip" 2>/dev/null; then
  mkdir -p "$DEST/BatchExamples"
  unzip -o -q "$TEMP/RECmdBatch.zip" -d "$DEST/BatchExamples/" 2>/dev/null || true
  echo "  ✓ RECmd BatchExamples installés"
else
  echo "  ✗ RECmd BatchExamples inaccessibles"
fi

# ─── Nettoyage ────────────────────────────────────────────────
rm -rf "$TEMP"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Installation terminée"
echo "  Outils disponibles dans: $DEST"
echo ""
echo "  DLLs installés:"
ls -1 "$DEST"/*.dll 2>/dev/null | while IFS= read -r f; do
  echo "    ✓ $(basename "$f")"
done || echo "    (aucun DLL trouvé)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
