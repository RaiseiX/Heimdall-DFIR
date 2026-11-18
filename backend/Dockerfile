# ════════════════════════════════════════════════════════════════════════════
# Stage 1 — tool-fetcher
# Downloads .NET 9, Zimmerman tools, and Hayabusa.
# This stage is Docker-layer-cached independently from the application code.
# It only re-runs when tool URLs or versions change — not on every code edit.
# ════════════════════════════════════════════════════════════════════════════
ARG DOTNET_VERSION=10.0.15
ARG DOTNET_SHA512=a90177d75bc891f71aa814dde3bcf76a356f5a506824669f1891754457954a3d13b72f3ca04c98fa0fe588514a5a781f8a87b17930ee802105c14f9edb28318a
ARG HAYABUSA_VERSION=3.10.0
ARG HAYABUSA_SHA256=9f2f2415c74e4dd8ddb0f0fd1fc240921cc0a91a5c07e66a4a75fe652a592861
ARG HAYABUSA_RULES=4961
ARG BMC_TOOLS_COMMIT=5a4cad32be78b3b874aeec910cb478e04ba3501e
ARG BMC_TOOLS_SHA256=4f2453a968e0d0dc66dc0afdb2e79c1af36bfdbae5a06e3c8c89a616ad82ca92

FROM node:24.22.2-trixie-slim@sha256:0820eaa85e07d0490446dd01d14707e17e6108a36988cf374899cd057eb3812d AS tool-fetcher
ARG DOTNET_VERSION
ARG DOTNET_SHA512
ARG HAYABUSA_VERSION
ARG HAYABUSA_SHA256
ARG HAYABUSA_RULES

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ─── .NET 9 Runtime (required by all Zimmerman tools) ───
RUN set -e; \
    curl -fsSL --retry 3 --connect-timeout 30 -o /tmp/dotnet.tar.gz \
        "https://builds.dotnet.microsoft.com/dotnet/Runtime/${DOTNET_VERSION}/dotnet-runtime-${DOTNET_VERSION}-linux-x64.tar.gz"; \
    echo "${DOTNET_SHA512}  /tmp/dotnet.tar.gz" | sha512sum -c -; \
    mkdir -p /usr/share/dotnet; \
    tar -xzf /tmp/dotnet.tar.gz -C /usr/share/dotnet; \
    rm /tmp/dotnet.tar.gz; \
    ln -s /usr/share/dotnet/dotnet /usr/local/bin/dotnet; \
    dotnet --list-runtimes | grep -q "Microsoft.NETCore.App ${DOTNET_VERSION} "

# ─── Outils Eric Zimmerman (.NET 9), verrouilles par empreinte ───
# La liste vient de zimmerman-tools.lock et de nulle part ailleurs : deux listes
# finissent toujours par diverger. Chaque archive est verifiee et le build
# S'ARRETE des qu'une empreinte ne correspond plus.
#
# Avant ceci, quinze `curl` etaient suivis d'un `|| echo "Failed: $tool"`. Une
# image dont les quinze telechargements avaient echoue sortait verte — c'est par
# ce chemin qu'un outil absent atteint la production sans que personne le voie.
# BitsParser en est la preuve : son URL rend 404 depuis toujours, et le produit
# declare pourtant un parseur `bits`.
#
# `set -e` porte la garantie : toute etape qui echoue arrete l'image.
COPY zimmerman-tools.lock /tmp/zimmerman-tools.lock
RUN set -e; \
    mkdir -p /app/zimmerman-tools /tmp/ztools/extracted; \
    cd /tmp/ztools; \
    BASE="https://download.ericzimmermanstools.com/net"; \
    awk '!/^#/ && NF==2 {print $2}' /tmp/zimmerman-tools.lock > /tmp/tools.txt; \
    test -s /tmp/tools.txt; \
    while read -r z; do \
      echo "-> $z"; \
      curl -fsSL --retry 3 --connect-timeout 30 -o "$z" "$BASE/$z"; \
    done < /tmp/tools.txt; \
    sha256sum -c /tmp/zimmerman-tools.lock; \
    while read -r z; do unzip -o -q "$z" -d /tmp/ztools/extracted/; done < /tmp/tools.txt; \
    find /tmp/ztools/extracted -name "*.dll" -exec cp -n {} /app/zimmerman-tools/ \; ; \
    find /tmp/ztools/extracted -name "*.runtimeconfig.json" -exec cp -n {} /app/zimmerman-tools/ \; ; \
    find /tmp/ztools/extracted -maxdepth 1 -name "libe_sqlite3.so" -exec cp -n {} /app/zimmerman-tools/ \; ; \
    mkdir -p /app/zimmerman-tools/Maps /app/zimmerman-tools/SQLMaps /app/zimmerman-tools/BatchExamples; \
    unzip -o -q EvtxECmd.zip -d /app/zimmerman-tools/Maps/; \
    unzip -o -q SQLECmd.zip  -d /app/zimmerman-tools/SQLMaps/; \
    unzip -o -q RECmd.zip    -d /app/zimmerman-tools/BatchExamples/; \
    cd /; rm -rf /tmp/ztools; \
    echo "=== $(ls /app/zimmerman-tools/*.dll | wc -l) DLL, $(find /app/zimmerman-tools/Maps -name '*.map' | wc -l) maps amont ==="

# Maps qu'Eric Zimmerman a retirees de la distribution mais qui decrivent des
# sources encore presentes sur les parcs analyses : MSSQLSERVER 18456 (echec de
# connexion, donc du brute-force contre une base), ESENT, F-Secure, McAfee
# Endpoint Security, Citrix MetaFrame.
#
# Relevees le 2026-09-18 en comparant le volume de production (453 maps, accumule
# depuis avril) a l'archive amont du jour (383) : 73 manquaient a l'amont, 69 ont
# pu etre recuperees. Sans elles, adopter les outils 2026.5.0 ferait perdre les
# champs nommes de ces sources — une regression silencieuse offerte par une
# montee de version.
#
# Une map absente ne supprime pas l'evenement : elle lui retire ses champs
# nommes. C'est la lisibilite qui part, pas la ligne.
COPY zimmerman-maps-retained/ /app/zimmerman-tools/Maps/EvtxeCmd/Maps/

# ─── Hayabusa (Linux x64) ───
RUN set -e; \
    mkdir -p /app/hayabusa /tmp/hayabusa; \
    curl -fsSL --retry 3 --connect-timeout 30 -o /tmp/hayabusa/hayabusa.zip \
        "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/hayabusa-${HAYABUSA_VERSION}-lin-x64-musl.zip"; \
    echo "${HAYABUSA_SHA256}  /tmp/hayabusa/hayabusa.zip" | sha256sum -c -; \
    unzip -o -q /tmp/hayabusa/hayabusa.zip -d /app/hayabusa/; \
    rm -rf /tmp/hayabusa; \
    chmod +x "/app/hayabusa/hayabusa-${HAYABUSA_VERSION}-lin-x64-musl"; \
    ln -sf "/app/hayabusa/hayabusa-${HAYABUSA_VERSION}-lin-x64-musl" /app/hayabusa/hayabusa; \
    test "$(find /app/hayabusa/rules -name '*.yml' | wc -l)" -eq "${HAYABUSA_RULES}"


# ════════════════════════════════════════════════════════════════════════════
# Stage 2 — runtime
# Installs system deps and the Node app. Rebuilds fast on code changes because
# the heavy tool-fetcher stage above is pulled from cache.
# ════════════════════════════════════════════════════════════════════════════
FROM node:24.22.2-trixie-slim@sha256:0820eaa85e07d0490446dd01d14707e17e6108a36988cf374899cd057eb3812d
ARG DOTNET_VERSION
ARG HAYABUSA_RULES
ARG BMC_TOOLS_COMMIT
ARG BMC_TOOLS_SHA256

WORKDIR /app

# ─── System runtime dependencies ───
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    curl \
    wget \
    file \
    libmagic1 \
    unzip \
    p7zip-full \
    tar \
    gzip \
    ca-certificates \
    gnupg \
    libicu76 \
    python3-libscca \
    yara \
    tshark \
    gosu \
    systemd \
    && rm -rf /var/lib/apt/lists/*

# ─── Python forensic libraries ───
COPY python-build.lock python-tools.lock /tmp/
RUN set -e; \
    pip3 install --no-cache-dir --break-system-packages --require-hashes -r /tmp/python-build.lock; \
    pip3 install --no-cache-dir --break-system-packages --require-hashes --no-build-isolation --use-pep517 --only-binary=:all: --no-binary=fusepy -r /tmp/python-tools.lock; \
    pip3 uninstall -y --break-system-packages setuptools; \
    rm /tmp/python-build.lock /tmp/python-tools.lock

# ─── RDP Bitmap Cache reconstructor (ANSSI bmc-tools) — reconstructs RDP session tiles ───
RUN set -e; \
    mkdir -p /app/tools; \
    curl -fsSL --retry 3 --connect-timeout 30 -o /app/tools/bmc-tools.py \
        "https://raw.githubusercontent.com/ANSSI-FR/bmc-tools/${BMC_TOOLS_COMMIT}/bmc-tools.py"; \
    echo "${BMC_TOOLS_SHA256}  /app/tools/bmc-tools.py" | sha256sum -c -

# ─── Copy forensic tools from tool-fetcher (no re-download) ───
COPY --from=tool-fetcher /usr/share/dotnet /usr/share/dotnet
COPY --from=tool-fetcher /app/zimmerman-tools /app/zimmerman-tools
COPY --from=tool-fetcher /app/zimmerman-tools /opt/zimmerman-tools
COPY --from=tool-fetcher /app/hayabusa /app/hayabusa

RUN ln -sf /usr/share/dotnet/dotnet /usr/local/bin/dotnet

ENV DOTNET_ROOT=/usr/share/dotnet
ENV PATH="${PATH}:/usr/share/dotnet"
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
ENV HAYABUSA_DIR=/app/hayabusa
ENV HAYABUSA_BIN=/app/hayabusa/hayabusa
ENV ZIMMERMAN_TOOLS_DIR=/app/zimmerman-tools

# ─── Node.js application (production deps only) ───
COPY --chown=node:node package*.json ./
RUN npm install --omit=dev --no-audit --no-fund \
    && chown -R node:node /app/node_modules \
    && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx

COPY --chown=node:node . .

# ─── Python parser scripts ───
RUN mkdir -p /app/parsers && chmod +x /app/parsers/*.py 2>/dev/null || true \
    && chown -R node:node /app/parsers

# ─── Runtime directories ───
RUN mkdir -p /app/uploads /app/evidence /app/temp /app/collections /app/logs \
    && chown -R node:node /app/uploads /app/evidence /app/temp /app/collections /app/logs

# Le verrou voyage aussi dans l'image finale : download-zimmerman.sh est le
# chemin qui repeuple un volume zimmerman_tools vide au premier demarrage, et
# un telechargement non verifie la rouvrirait la porte que le build vient de
# fermer.
COPY --chown=node:node zimmerman-tools.lock /app/zimmerman-tools.lock
COPY --chown=node:node zimmerman-maps-retained/ /app/zimmerman-maps-retained/
COPY --chown=node:node download-zimmerman.sh /app/download-zimmerman.sh
RUN chmod +x /app/download-zimmerman.sh

COPY --chown=node:node entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Own tool directories (copied as root above, hand to node)
RUN chown -R node:node /app/zimmerman-tools /app/hayabusa

RUN set -e; \
    /app/hayabusa/hayabusa help > /dev/null; \
    test "$(find /app/hayabusa/rules -name '*.yml' | wc -l)" -eq "${HAYABUSA_RULES}"; \
    dotnet --list-runtimes | grep -q "Microsoft.NETCore.App ${DOTNET_VERSION} "; \
    python3 -c "import dissect.regf, dissect.esedb, dissect.cim, dissect.target, flow.record, psutil, Crypto, PIL"; \
    test -s /app/tools/bmc-tools.py; \
    tshark --version > /dev/null; \
    test ! -e /usr/local/bin/npm

# entrypoint.sh runs as root briefly to fix volume permissions, then drops to
# the unprivileged `node` user via gosu. This is required because Docker named
# volumes are owned by root on first creation.
EXPOSE 4000

ENTRYPOINT ["/bin/sh", "/app/entrypoint.sh"]
