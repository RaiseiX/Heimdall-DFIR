FROM node:20-bookworm-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
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
    libicu72 \
    python3-libscca \
    yara \
    tshark \
    gosu \
    && rm -rf /var/lib/apt/lists/*

# ═══ Install .NET 9 Runtime (required for Zimmerman tools net9) ═══
RUN wget -q https://dot.net/v1/dotnet-install.sh -O /tmp/dotnet-install.sh \
    && chmod +x /tmp/dotnet-install.sh \
    && /tmp/dotnet-install.sh --channel 9.0 --runtime dotnet --install-dir /usr/share/dotnet \
    && ln -s /usr/share/dotnet/dotnet /usr/local/bin/dotnet \
    && rm /tmp/dotnet-install.sh \
    && dotnet --info || echo "dotnet installed"

ENV DOTNET_ROOT=/usr/share/dotnet
ENV PATH="${PATH}:/usr/share/dotnet"
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1

# ═══ Install Python forensic parsing libraries ═══
# dissect       — Fox-IT forensic framework (Prefetch v17/v23/v30/v31 incl. Win10 MAM, SRUM, etc.)
# dissect.esedb — ESE database reader (SrumECmd replacement on Linux)
# python3-libscca (apt, above) — fallback prefetch reader for older formats
RUN pip3 install --no-cache-dir --break-system-packages \
    dissect \
    dissect.esedb \
    && echo "=== dissect + dissect.esedb installed ===" \
    || echo "WARNING: dissect install failed — prefetch/srum parsers may be unavailable"

# ═══ Download Zimmerman Tools (.NET 9 versions) ═══
RUN mkdir -p /app/zimmerman-tools /tmp/ztools/extracted \
    && cd /tmp/ztools \
    && BASE="https://download.ericzimmermanstools.com/net9" \
    && for tool in \
        MFTECmd.zip \
        PECmd.zip \
        LECmd.zip \
        EvtxECmd.zip \
        RECmd.zip \
        AmcacheParser.zip \
        AppCompatCacheParser.zip \
        SBECmd.zip \
        JLECmd.zip \
        SrumECmd.zip \
        WxTCmd.zip \
        RBCmd.zip \
        SumECmd.zip \
        BitsParser.zip \
        SQLECmd.zip \
    ; do \
        echo "Downloading $tool..." \
        && curl -fsSL -o "$tool" "$BASE/$tool" 2>/dev/null \
        && unzip -o -q "$tool" -d /tmp/ztools/extracted/ 2>/dev/null \
        || echo "Failed: $tool (will retry via entrypoint)"; \
    done \
    # Flatten DLLs + runtimeconfig.json to /app/zimmerman-tools/ root
    && find /tmp/ztools/extracted -name "*.dll" -exec cp -n {} /app/zimmerman-tools/ \; 2>/dev/null || true \
    && find /tmp/ztools/extracted -name "*.runtimeconfig.json" -exec cp -n {} /app/zimmerman-tools/ \; 2>/dev/null || true \
    # Download Maps for EvtxECmd (place at {ZIMMERMAN_DIR}/Maps/*.map)
    && echo "Downloading EvtxECmd Maps..." \
    && curl -fsSL -o Maps.zip "https://download.ericzimmermanstools.com/net9/EvtxECmd.zip" 2>/dev/null \
    && mkdir -p /app/zimmerman-tools/Maps \
    && unzip -o -q Maps.zip -d /app/zimmerman-tools/Maps/ 2>/dev/null || true \
    # Download Maps for SQLECmd (place at {ZIMMERMAN_DIR}/SQLMaps/)
    && echo "Downloading SQLECmd Maps..." \
    && curl -fsSL -o SQLMaps.zip "https://download.ericzimmermanstools.com/net9/SQLECmd.zip" 2>/dev/null \
    && mkdir -p /app/zimmerman-tools/SQLMaps \
    && unzip -o -q SQLMaps.zip -d /app/zimmerman-tools/SQLMaps/ 2>/dev/null || true \
    # Download RECmd Batch files
    && echo "Downloading RECmd BatchExamples..." \
    && curl -fsSL -o Batch.zip "https://download.ericzimmermanstools.com/net9/RECmd.zip" 2>/dev/null \
    && mkdir -p /app/zimmerman-tools/BatchExamples \
    && unzip -o -q Batch.zip -d /app/zimmerman-tools/BatchExamples/ 2>/dev/null || true \
    && rm -rf /tmp/ztools \
    && echo "=== Zimmerman tools installed ===" \
    && ls /app/zimmerman-tools/*.dll 2>/dev/null | head -20 || true

# ═══ Download Hayabusa (latest Linux release) ═══
RUN mkdir -p /app/hayabusa /tmp/hayabusa \
    && cd /tmp/hayabusa \
    && echo "Downloading Hayabusa (latest)..." \
    && curl -fsSL -L -o hayabusa.zip \
        "https://github.com/Yamato-Security/hayabusa/releases/download/v3.8.1/hayabusa-3.8.1-lin-x64-gnu.zip" \
    && unzip -o -q hayabusa.zip -d /app/hayabusa/ \
    && chmod +x /app/hayabusa/hayabusa* 2>/dev/null || true \
    && echo "=== Hayabusa installed ===" \
    && ls -la /app/hayabusa/ \
    && rm -rf /tmp/hayabusa

# Normalise Hayabusa binary: always expose as /app/hayabusa/hayabusa
# The zip may contain a versioned binary (hayabusa-2.x.x-linux-gnu-x64).
RUN HAYABIN=$(ls /app/hayabusa/hayabusa-* 2>/dev/null | head -1) \
    && if [ -n "$HAYABIN" ]; then \
        chmod +x "$HAYABIN" \
        && ln -sf "$HAYABIN" /app/hayabusa/hayabusa \
        && echo "Hayabusa symlink: $(basename $HAYABIN) -> hayabusa"; \
    elif [ -f /app/hayabusa/hayabusa ]; then \
        chmod +x /app/hayabusa/hayabusa \
        && echo "Hayabusa binary found directly"; \
    else \
        echo "WARNING: Hayabusa binary not found — fallback Sigma rules will be used"; \
    fi

# Download/update Hayabusa rules
RUN if [ -x /app/hayabusa/hayabusa ]; then \
        cd /app/hayabusa \
        && /app/hayabusa/hayabusa update-rules --no-wizard 2>/dev/null \
        || echo "Rules update skipped (offline build — will update at runtime)"; \
    fi

ENV HAYABUSA_DIR=/app/hayabusa
ENV HAYABUSA_BIN=/app/hayabusa/hayabusa
ENV ZIMMERMAN_TOOLS_DIR=/app/zimmerman-tools

# ═══ Node.js app ═══
COPY --chown=node:node package*.json ./
RUN npm install --omit=dev --no-audit --no-fund \
    && chown -R node:node /app/node_modules

COPY --chown=node:node . .

# ═══ Python forensic parser scripts ═══
RUN mkdir -p /app/parsers && chmod +x /app/parsers/*.py 2>/dev/null || true \
    && chown -R node:node /app/parsers

RUN mkdir -p /app/uploads /app/evidence /app/temp /app/collections \
    && chown -R node:node /app/uploads /app/evidence /app/temp /app/collections

# Keep download script for manual re-download if needed
COPY --chown=node:node download-zimmerman.sh /app/download-zimmerman.sh
RUN chmod +x /app/download-zimmerman.sh

# Startup entrypoint: verifies tools, downloads missing ones, then starts API
COPY --chown=node:node entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Own tool directories downloaded as root
RUN chown -R node:node /app/zimmerman-tools /app/hayabusa

# entrypoint.sh runs as root to fix volume permissions, then drops to node via gosu.
# This is necessary because Docker named volumes are owned by root on first creation.
EXPOSE 4000

ENTRYPOINT ["/bin/sh", "/app/entrypoint.sh"]
