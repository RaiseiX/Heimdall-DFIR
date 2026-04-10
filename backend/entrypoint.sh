#!/bin/sh
# ╔══════════════════════════════════════════════════════════════╗
# ║   ForensicLab — Entrypoint de vérification des outils       ║
# ║                                                              ║
# ║   Exécuté au démarrage du conteneur (en root).               ║
# ║   1. Corrige les permissions des volumes Docker             ║
# ║   2. Vérifie les DLLs Zimmerman dans le volume monté        ║
# ║   3. Télécharge les outils manquants si nécessaire          ║
# ║   4. S'assure que le binaire Hayabusa est accessible        ║
# ║   5. Lance le serveur Node.js via gosu (user node)          ║
# ╚══════════════════════════════════════════════════════════════╝
set -e

# ─── 0. Création et permissions des volumes Docker ─────────────
# Les volumes nommés Docker sont créés vides : les sous-répertoires doivent
# être créés explicitement avant d'en corriger les droits, sinon multer/fs
# obtient ENOENT et le backend renvoie 500 pendant l'upload (→ "Bloquée").
mkdir -p \
  /app/uploads \
  /app/uploads/collections \
  /app/collections \
  /app/temp \
  /app/evidence \
  /app/zimmerman-tools \
  /app/hayabusa
# Chown uniquement les répertoires écrits par le serveur (uploads, temp, evidence).
# Les répertoires en lecture seule (zimmerman-tools, hayabusa avec des milliers de fichiers)
# sont exclus du chown récursif pour éviter un délai de démarrage de plusieurs minutes.
chown -R node:node /app/uploads /app/collections /app/temp /app/evidence 2>/dev/null || true
# Pour hayabusa et zimmerman-tools : seulement le répertoire racine (pas -R).
chown node:node /app/zimmerman-tools /app/hayabusa 2>/dev/null || true
# Ensure all directories under /app/collections are traversable (some tar archives
# extract directories with mode 0o600, lacking the execute bit needed by the node user)
chmod -R u+rX /app/collections 2>/dev/null || true

ZIMMERMAN_DIR="${ZIMMERMAN_TOOLS_DIR:-/app/zimmerman-tools}"
HAYABUSA_DIR="${HAYABUSA_DIR:-/app/hayabusa}"
HAYABUSA_BIN="${HAYABUSA_BIN:-/app/hayabusa/hayabusa}"

echo "╔══════════════════════════════════════════════╗"
echo "║   ForensicLab — Vérification des outils      ║"
echo "╚══════════════════════════════════════════════╝"

# ─── 1. Outils Eric Zimmerman ──────────────────────────────────
# Outils critiques sans lesquels le parsing est impossible
CRITICAL_DLLS="MFTECmd.dll EvtxECmd.dll PECmd.dll AmcacheParser.dll AppCompatCacheParser.dll"
MISSING=0

echo "→ Vérification des outils Zimmerman dans: $ZIMMERMAN_DIR"
for dll in $CRITICAL_DLLS; do
  if [ ! -f "$ZIMMERMAN_DIR/$dll" ]; then
    echo "  ✗ Manquant: $dll"
    MISSING=1
  else
    echo "  ✓ $dll"
  fi
done

# Outils non-critiques (signalement seulement)
OPTIONAL_DLLS="LECmd.dll RECmd.dll SBECmd.dll JLECmd.dll SrumECmd.dll WxTCmd.dll RBCmd.dll SumECmd.dll BitsParser.dll"
for dll in $OPTIONAL_DLLS; do
  if [ ! -f "$ZIMMERMAN_DIR/$dll" ]; then
    echo "  ⚠ Optionnel manquant: $dll"
  else
    echo "  ✓ $dll"
  fi
done

# Si des outils critiques manquent, on tente le téléchargement
if [ "$MISSING" = "1" ]; then
  echo ""
  echo "→ Outils critiques manquants — lancement du téléchargement..."
  if [ -x /app/download-zimmerman.sh ]; then
    /app/download-zimmerman.sh || echo "AVERTISSEMENT: Téléchargement partiel — certains parsers seront indisponibles"
  else
    echo "ERREUR: /app/download-zimmerman.sh introuvable"
  fi
fi

# Vérifier Maps pour EvtxECmd
if [ ! -d "$ZIMMERMAN_DIR/Maps" ] || [ -z "$(ls "$ZIMMERMAN_DIR/Maps"/*.map 2>/dev/null)" ]; then
  echo "  ⚠ Maps EvtxECmd manquantes: $ZIMMERMAN_DIR/Maps/ (EvtxECmd fonctionnera sans mapping enrichi)"
else
  MAP_COUNT=$(ls "$ZIMMERMAN_DIR/Maps"/*.map 2>/dev/null | wc -l)
  echo "  ✓ Maps EvtxECmd: $MAP_COUNT fichiers"
fi

# Vérifier BatchExamples pour RECmd
if [ ! -f "$ZIMMERMAN_DIR/BatchExamples/RECmd_Batch_MC.reb" ]; then
  echo "  ⚠ RECmd_Batch_MC.reb manquant (RECmd fonctionnera en mode basique)"
else
  echo "  ✓ RECmd BatchExamples"
fi

echo ""

# ─── 2. Hayabusa ───────────────────────────────────────────────
echo "→ Vérification de Hayabusa dans: $HAYABUSA_DIR"

# Si le binaire canonique n'existe pas, chercher une version nommée et créer un lien
if [ ! -x "$HAYABUSA_BIN" ]; then
  HAYABIN=$(ls "$HAYABUSA_DIR/hayabusa-"* 2>/dev/null | head -1)
  if [ -n "$HAYABIN" ]; then
    echo "  → Binaire versionnné trouvé: $(basename $HAYABIN)"
    chmod +x "$HAYABIN"
    ln -sf "$HAYABIN" "$HAYABUSA_BIN"
    echo "  ✓ Lien créé: hayabusa → $(basename $HAYABIN)"
  else
    echo "  ✗ Hayabusa non disponible — le mode fallback (règles Sigma intégrées) sera utilisé"
  fi
fi

if [ -x "$HAYABUSA_BIN" ]; then
  HAYABUSA_VER=$("$HAYABUSA_BIN" --version 2>/dev/null | head -1 || echo "version inconnue")
  echo "  ✓ Hayabusa: $HAYABUSA_VER"

  # Vérifier la présence des règles
  RULES_DIR="$HAYABUSA_DIR/rules"
  if [ -d "$RULES_DIR" ]; then
    RULE_COUNT=$(find "$RULES_DIR" -name "*.yml" 2>/dev/null | wc -l)
    echo "  ✓ Règles Hayabusa: $RULE_COUNT fichiers .yml"
  else
    echo "  ⚠ Dossier rules absent — Hayabusa peut fonctionner avec règles intégrées"
  fi
else
  echo "  ✗ Hayabusa: non installé (fallback Sigma activé)"
fi

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   Démarrage ForensicLab API v2.7.0           ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# ─── 3. Docker socket group — matérialise le GID dans /etc/group ──────────
# Docker group_add injecte le GID au niveau kernel pour le processus init,
# mais gosu appelle initgroups() qui relit /etc/group — si le GID n'y figure
# pas, il est perdu lors du setuid(node). On crée donc le groupe dans
# /etc/group et on y ajoute node avant de céder les droits via gosu.
if [ -n "${DOCKER_GID}" ] && [ "${DOCKER_GID}" != "0" ]; then
  if ! getent group "${DOCKER_GID}" > /dev/null 2>&1; then
    groupadd --gid "${DOCKER_GID}" dockerhost 2>/dev/null || true
    echo "  ✓ Groupe dockerhost (GID ${DOCKER_GID}) créé dans /etc/group"
  fi
  DOCKER_GROUP=$(getent group "${DOCKER_GID}" | cut -d: -f1)
  if [ -n "$DOCKER_GROUP" ]; then
    usermod -aG "${DOCKER_GROUP}" node 2>/dev/null || true
    echo "  ✓ Utilisateur node ajouté au groupe ${DOCKER_GROUP} (GID ${DOCKER_GID})"
  fi
fi

# ─── 4. Démarrage du serveur Node.js (en tant que node via gosu) ───
exec gosu node node src/server.js
