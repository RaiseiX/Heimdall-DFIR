#!/usr/bin/env bash
set -uo pipefail

cd "$(dirname "$0")" || exit 2

SEMVER='^[0-9]+\.[0-9]+\.[0-9]+$'
PACKAGES=(backend/package.json frontend/package.json)
LOCKS=(backend/package-lock.json frontend/package-lock.json)

usage() {
    echo "Usage : bash version.sh check | set X.Y.Z" >&2
    exit 2
}

package_version() {
    sed -n 's/^  "version": "\([^"]*\)".*/\1/p' "$1" | head -n 1
}

check() {
    local problems=() version file found tag
    if [ ! -f VERSION ]; then
        echo "VERSION : fichier absent"
        return 1
    fi
    version="$(tr -d '[:space:]' < VERSION)"
    if ! [[ "$version" =~ $SEMVER ]]; then
        echo "VERSION : « ${version} » n'est pas de la forme X.Y.Z"
        return 1
    fi
    for file in "${PACKAGES[@]}"; do
        found="$(package_version "$file" 2>/dev/null)"
        [ "$found" = "$version" ] || problems+=("${file} : ${found:-absente} au lieu de ${version}")
    done
    grep -qF "Version ${version} · [Changelog](CHANGELOG.md)" README.md 2>/dev/null \
        || problems+=("README.md : la ligne « Version ${version} » manque")
    grep -qF "Version ${version} · [Historique des changements](CHANGELOG.md)" README.fr.md 2>/dev/null \
        || problems+=("README.fr.md : la ligne « Version ${version} » manque")
    grep -qF "## [${version}]" CHANGELOG.md 2>/dev/null \
        || problems+=("CHANGELOG.md : aucune entrée « ## [${version}] »")
    if command -v git >/dev/null 2>&1 && git rev-parse --git-dir >/dev/null 2>&1; then
        while IFS= read -r tag; do
            [ -n "$tag" ] || continue
            [ "$tag" = "v${version}" ] || problems+=("tag Git ${tag} sur ce commit, alors que VERSION vaut ${version}")
        done < <(git tag --points-at HEAD 2>/dev/null | grep '^v[0-9]')
    fi
    if [ "${#problems[@]}" -gt 0 ]; then
        printf '%s\n' "${problems[@]}"
        return 1
    fi
    return 0
}

set_version() {
    local version="$1" file
    [[ "$version" =~ $SEMVER ]] || { echo "Version invalide : ${version} (attendu X.Y.Z)" >&2; exit 2; }
    command -v node >/dev/null 2>&1 || { echo "node est requis pour réécrire les package.json" >&2; exit 2; }
    printf '%s\n' "$version" > VERSION
    for file in "${PACKAGES[@]}" "${LOCKS[@]}"; do
        [ -f "$file" ] || continue
        node -e '
            const fs = require("fs");
            const [file, version] = process.argv.slice(1);
            const data = JSON.parse(fs.readFileSync(file, "utf8"));
            data.version = version;
            if (data.packages && data.packages[""]) data.packages[""].version = version;
            fs.writeFileSync(file, `${JSON.stringify(data, null, 2)}\n`);
        ' "$file" "$version" || exit 1
    done
    sed -i -E "s/^Version [0-9]+\.[0-9]+\.[0-9]+ · /Version ${version} · /" README.md README.fr.md
    echo "Version ${version} reportée. Ajouter l'entrée « ## [${version}] » au CHANGELOG avant de lancer : bash version.sh check"
}

case "${1:-}" in
    check) check ;;
    set) [ "$#" -eq 2 ] || usage; set_version "$2" ;;
    *) usage ;;
esac
