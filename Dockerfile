# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: Builder — compile liboqs + oqs-provider against system OpenSSL 3
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

# Install build deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    wget \
    ca-certificates \
    git \
    cmake \
    ninja-build \
    pkg-config \
    libssl-dev \
    libtool \
    autoconf \
    automake \
    libcurl4-openssl-dev \
    && rm -rf /var/lib/apt/lists/*

# ── 1. Build liboqs ──────────────────────────────────────────────────────────
WORKDIR /tmp/liboqs
RUN git clone --branch main --depth 1 \
        https://github.com/open-quantum-safe/liboqs.git . && \
    cmake -GNinja -B build \
        -DCMAKE_INSTALL_PREFIX=/opt/oqs \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_DIST_BUILD=ON && \
    ninja -C build && ninja -C build install

# ── 2. Build oqs-provider (links against system OpenSSL 3) ───────────────────
WORKDIR /tmp/oqs-provider
RUN git clone --branch main --depth 1 \
        https://github.com/open-quantum-safe/oqs-provider.git . && \
    cmake -GNinja -B build \
        -Dliboqs_DIR=/opt/oqs/lib/cmake/liboqs \
        -DCMAKE_INSTALL_PREFIX=/opt/oqs-provider && \
    ninja -C build && ninja -C build install

# ── 3. Install Python deps (in builder so final image stays clean) ───────────
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: Runtime — lean final image
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

# Install only runtime OpenSSL (3.x ships with Debian bookworm/slim)
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled artifacts from builder
COPY --from=builder /opt/oqs          /opt/oqs
COPY --from=builder /opt/oqs-provider /opt/oqs-provider
COPY --from=builder /install          /usr/local

# ── Wire oqs-provider into the system OpenSSL config ─────────────────────────
# Find the real providers dir and drop the .so there
RUN PROV_DIR=$(openssl version -d | awk '{print $2}' | tr -d '"') && \
    PROV_DIR="${PROV_DIR}/lib/x86_64-linux-gnu/ossl-modules" && \
    mkdir -p "$PROV_DIR" && \
    # try both possible output locations from cmake install
    SO=$(find /opt/oqs-provider -name "oqsprovider.so" | head -1) && \
    cp "$SO" "$PROV_DIR/oqsprovider.so"

# Patch openssl.cnf properly so oqs-provider is loaded at startup
RUN CONF=$(openssl version -d | awk '{print $2}' | tr -d '"')/openssl.cnf && \
    # Inject provider activation before the closing bracket of [provider_sect]
    # If [provider_sect] doesn't exist yet, append a complete stanza
    if grep -q '\[provider_sect\]' "$CONF"; then \
        sed -i '/^\[provider_sect\]/a oqsprovider = oqsprovider_sect' "$CONF"; \
        printf '\n[oqsprovider_sect]\nmodule = oqsprovider\nactivate = 1\n' >> "$CONF"; \
    else \
        printf '\n[openssl_init]\nproviders = provider_sect\n\n[provider_sect]\ndefault = default_sect\noqsprovider = oqsprovider_sect\n\n[default_sect]\nactivate = 1\n\n[oqsprovider_sect]\nmodule = oqsprovider\nactivate = 1\n' >> "$CONF"; \
    fi

# Runtime library path so liboqs.so is found by the provider
ENV LD_LIBRARY_PATH="/opt/oqs/lib:/opt/oqs/lib64:${LD_LIBRARY_PATH}"

# ── App setup ────────────────────────────────────────────────────────────────
WORKDIR /app
COPY . .

RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Health-check so Railway/Render know when the container is ready
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]