# ════════════════════════════════════════════════════════════════════════════
# Stage 1 — tool-fetcher
# Downloads .NET 9, Zimmerman tools, and Hayabusa.
# This stage is Docker-layer-cached independently from the application code.
# It only re-runs when tool URLs or versions change — not on every code edit.
# ════════════════════════════════════════════════════════════════════════════
FROM node:20-bookworm-slim AS tool-fetcher

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    unzip \
    ca-certificates \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# ─── .NET 9 Runtime (required by all Zimmerman tools) ───
RUN wget -q https://dot.net/v1/dotnet-install.sh -O /tmp/dotnet-install.sh \
    && chmod +x /tmp/dotnet-install.sh \
    && /tmp/dotnet-install.sh --channel 9.0 --runtime dotnet --install-dir /usr/share/dotnet \
    && ln -s /usr/share/dotnet/dotnet /usr/local/bin/dotnet \
    && rm /tmp/dotnet-install.sh \
    && dotnet --info || echo "dotnet installed"

# ─── Zimmerman Tools (.NET 9) ───
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
    && find /tmp/ztools/extracted -name "*.dll" -exec cp -n {} /app/zimmerman-tools/ \; 2>/dev/null || true \
    && find /tmp/ztools/extracted -name "*.runtimeconfig.json" -exec cp -n {} /app/zimmerman-tools/ \; 2>/dev/null || true \
    # EvtxECmd Maps
    && echo "Downloading EvtxECmd Maps..." \
    && curl -fsSL -o Maps.zip "$BASE/EvtxECmd.zip" 2>/dev/null \
    && mkdir -p /app/zimmerman-tools/Maps \
    && unzip -o -q Maps.zip -d /app/zimmerman-tools/Maps/ 2>/dev/null || true \
    # SQLECmd Maps
    && echo "Downloading SQLECmd Maps..." \
    && curl -fsSL -o SQLMaps.zip "$BASE/SQLECmd.zip" 2>/dev/null \
    && mkdir -p /app/zimmerman-tools/SQLMaps \
    && unzip -o -q SQLMaps.zip -d /app/zimmerman-tools/SQLMaps/ 2>/dev/null || true \
    # RECmd BatchExamples
    && echo "Downloading RECmd BatchExamples..." \
    && curl -fsSL -o Batch.zip "$BASE/RECmd.zip" 2>/dev/null \
    && mkdir -p /app/zimmerman-tools/BatchExamples \
    && unzip -o -q Batch.zip -d /app/zimmerman-tools/BatchExamples/ 2>/dev/null || true \
    && rm -rf /tmp/ztools \
    && echo "=== Zimmerman tools installed ===" \
    && ls /app/zimmerman-tools/*.dll 2>/dev/null | head -20 || true

# ─── Hayabusa (Linux x64) ───
RUN mkdir -p /app/hayabusa /tmp/hayabusa \
    && cd /tmp/hayabusa \
    && echo "Downloading Hayabusa..." \
    && curl -fsSL -L -o hayabusa.zip \
        "https://github.com/Yamato-Security/hayabusa/releases/download/v3.8.1/hayabusa-3.8.1-lin-x64-gnu.zip" \
    && unzip -o -q hayabusa.zip -d /app/hayabusa/ \
    && chmod +x /app/hayabusa/hayabusa* 2>/dev/null || true \
    && echo "=== Hayabusa installed ===" \
    && ls -la /app/hayabusa/ \
    && rm -rf /tmp/hayabusa

# Normalise Hayabusa binary name → always /app/hayabusa/hayabusa
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

# Pre-download Hayabusa rules while in the tool-fetcher stage
RUN if [ -x /app/hayabusa/hayabusa ]; then \
        cd /app/hayabusa \
        && /app/hayabusa/hayabusa update-rules --no-wizard 2>/dev/null \
        || echo "Rules update skipped (offline build — will update at runtime)"; \
    fi


# ════════════════════════════════════════════════════════════════════════════
# Stage 2 — runtime
# Installs system deps and the Node app. Rebuilds fast on code changes because
# the heavy tool-fetcher stage above is pulled from cache.
# ════════════════════════════════════════════════════════════════════════════
FROM node:20-bookworm-slim

WORKDIR /app

# ─── System runtime dependencies ───
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

# ─── Python forensic libraries ───
RUN pip3 install --no-cache-dir --break-system-packages \
    dissect \
    dissect.esedb \
    && echo "=== dissect + dissect.esedb installed ===" \
    || echo "WARNING: dissect install failed — prefetch/srum parsers may be unavailable"

# ─── Copy forensic tools from tool-fetcher (no re-download) ───
COPY --from=tool-fetcher /usr/share/dotnet /usr/share/dotnet
COPY --from=tool-fetcher /app/zimmerman-tools /app/zimmerman-tools
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
    && chown -R node:node /app/node_modules

COPY --chown=node:node . .

# ─── Python parser scripts ───
RUN mkdir -p /app/parsers && chmod +x /app/parsers/*.py 2>/dev/null || true \
    && chown -R node:node /app/parsers

# ─── Runtime directories ───
RUN mkdir -p /app/uploads /app/evidence /app/temp /app/collections \
    && chown -R node:node /app/uploads /app/evidence /app/temp /app/collections

COPY --chown=node:node download-zimmerman.sh /app/download-zimmerman.sh
RUN chmod +x /app/download-zimmerman.sh

COPY --chown=node:node entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Own tool directories (copied as root above, hand to node)
RUN chown -R node:node /app/zimmerman-tools /app/hayabusa

# entrypoint.sh runs as root briefly to fix volume permissions, then drops to
# the unprivileged `node` user via gosu. This is required because Docker named
# volumes are owned by root on first creation.
EXPOSE 4000

ENTRYPOINT ["/bin/sh", "/app/entrypoint.sh"]
