FROM python:3.11-slim

# Install build tools, OpenSSL, and dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl \
    libssl3 \
    ca-certificates \
    build-essential \
    libssl-dev \
    python3-dev \
    git \
    perl \
    cmake \
    ninja-build \
    pkg-config \
    libcairo2-dev \
    libpng-dev \
    libjpeg-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Build and install OpenSSL 3.x
RUN git clone --depth 1 --branch openssl-3.3.0 https://github.com/openssl/openssl.git /opt/openssl-src \
    && cd /opt/openssl-src \
    && ./Configure --prefix=/opt/openssl3 linux-x86_64 shared \
    && make -j"$(nproc)" \
    && make install_sw \
    && rm -rf /opt/openssl-src

# Build and install liboqs (required by oqs-provider)
RUN git clone --depth 1 --branch 0.9.2 https://github.com/open-quantum-safe/liboqs.git /opt/liboqs-src \
     && cmake -S /opt/liboqs-src -B /opt/liboqs-build -GNinja \
         -DBUILD_SHARED_LIBS=ON \
         -DOQS_BUILD_ONLY_LIB=ON \
         -DOQS_USE_OPENSSL=OFF \
         -DCMAKE_BUILD_TYPE=Release \
    && cmake --build /opt/liboqs-build \
    && cmake --install /opt/liboqs-build \
    && rm -rf /opt/liboqs-src /opt/liboqs-build

# Build and install oqs-provider
RUN git clone --depth 1 --branch 0.5.3 https://github.com/open-quantum-safe/oqs-provider.git /opt/oqs-provider-src \
    && cmake -S /opt/oqs-provider-src -B /opt/oqs-provider-build -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DOPENSSL_ROOT_DIR=/opt/openssl3 \
        -DCMAKE_PREFIX_PATH=/opt/openssl3 \
    && cmake --build /opt/oqs-provider-build \
    && cmake --install /opt/oqs-provider-build --prefix /opt/oqs-provider \
    && rm -rf /opt/oqs-provider-src /opt/oqs-provider-build

ENV LD_LIBRARY_PATH=/opt/openssl3/lib:/usr/local/lib
ENV OPENSSL_PQC_BIN=/opt/openssl3/bin/openssl
ENV OPENSSL_PQC_ARGS="-provider oqsprovider -provider default -provider-path /opt/oqs-provider/lib"

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')" || exit 1

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]