git checkout main
FROM python:3.11-slim

# Install build dependencies for OpenSSL + oqs-provider
RUN apt-get update && apt-get install -y \
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

# Build liboqs (Open Quantum Safe library)
WORKDIR /tmp
RUN git clone --branch main --depth 1 https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && mkdir build && cd build && \
    cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local/oqs .. && \
    ninja && ninja install

# Download and compile OQS-OpenSSL (OQS fork for PQC support)
WORKDIR /tmp
RUN git clone https://github.com/open-quantum-safe/openssl.git oqs-openssl && \
    cd oqs-openssl && \
    git checkout OQS-OpenSSL_3_6_1 && \
    ./config --prefix=/usr/local/openssl --with-oqs-dir=/usr/local/oqs && \
    make -j"$(nproc)" && \
    make install && \
    # Symlink openssl binary globally for all environments
    ln -sf /usr/local/openssl/bin/openssl /usr/bin/openssl3 && \
    ln -sf /usr/local/openssl/bin/openssl /usr/bin/openssl && \
    ln -sf /usr/local/openssl/bin/openssl /usr/local/bin/openssl

# Build oqs-provider (after OpenSSL is installed)
WORKDIR /tmp
RUN git clone --branch main --depth 1 https://github.com/open-quantum-safe/oqs-provider.git && \
    cd oqs-provider && mkdir build && cd build && \
    cmake -GNinja -DOPENSSL_ROOT_DIR=/usr/local/openssl -DCMAKE_INSTALL_PREFIX=/usr/local/oqs-provider .. && \
    ninja && ninja install

# Copy oqs-provider module to OpenSSL providers directory
RUN cp /usr/local/oqs-provider/lib/oqsprovider.so /usr/local/openssl/lib64/ossl-modules/ || true

# Set OpenSSL to PATH and load oqs-provider by default
ENV PATH="/usr/local/openssl/bin:/usr/local/bin:$PATH"
ENV LD_LIBRARY_PATH="/usr/local/openssl/lib:/usr/local/oqs/lib:$LD_LIBRARY_PATH"
ENV OQS_PROVIDER="/usr/local/openssl/lib64/ossl-modules/oqsprovider.so"
ENV OPENSSL_CONF="/usr/local/openssl/openssl.cnf"

# Patch openssl.cnf to load oqs-provider by default
RUN echo "\n[oqs_provider]\nactivate = 1\n" >> /usr/local/openssl/openssl.cnf && \
    echo "\n[provider_oqs]\nmodule = /usr/local/openssl/lib64/ossl-modules/oqsprovider.so\n" >> /usr/local/openssl/openssl.cnf

# Permissions for OpenSSL and OQS
RUN chmod -R 755 /usr/local/openssl /usr/local/oqs

# Clean up build dependencies to reduce image size
RUN apt-get purge -y build-essential git cmake ninja-build pkg-config libssl-dev libtool autoconf automake libcurl4-openssl-dev && \
    apt-get autoremove -y && apt-get clean

# Set up app
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create non-root user for security
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8000

# Run FastAPI
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
