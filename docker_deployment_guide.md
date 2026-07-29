# QShield Deployment Guide for Punjab National Bank (PNB)

This guide provides bank-grade deployment instructions for setting up and running **QShield** in secure enterprise environments.

---

## 📋 Table of Contents
1. [System Requirements](#-system-requirements)
2. [Deployment Option A: SQLite (Default, Persistent, Zero-Configuration)](#-deployment-option-a-sqlite-default-persistent-zero-configuration)
3. [Deployment Option B: PostgreSQL (Recommended for Production)](#-deployment-option-b-postgresql-recommended-for-production)
4. [Air-Gapped / Offline Build Guide (No Internet Access)](#-air-gapped--offline-build-guide-no-internet-access)
5. [Verification & Health Checks](#-verification--health-checks)
6. [Security & Access Control](#-security--access-control)

---

## 🖥️ System Requirements
* **Docker Engine** version 20.10.0+
* **Docker Compose** version 2.0.0+
* **System Resources**: Min 2 vCPUs, 4GB RAM (during source compilation)

---

## 🚀 Deployment Option A: SQLite (Default, Persistent, Zero-Configuration)
Best for staging, user acceptance testing (UAT), or sandboxed evaluations.

1. **Navigate to the project root directory**:
   ```bash
   cd QShield-main
   ```
2. **Start the application**:
   ```bash
   docker-compose up -d --build
   ```
3. **What this does**:
   * Compiles the custom, PQC-enabled OpenSSL build inside the container.
   * Starts QShield on port `8000`.
   * Mounts a local volume named `qshield-data` mapped to `/data/` inside the container.
   * Auto-initializes the database `qshield.db` inside `/data/` which **persists** database records securely across container restarts or upgrades.

---

## 🗄️ Deployment Option B: PostgreSQL (Recommended for Production)
Best for production environments requiring central high-availability databases.

1. **Edit the `docker-compose.yml` file**:
   * Comment out Option 1 (**qshield** service).
   * Uncomment Option 2 (**db** and **qshield-pg** services) and the volume/port definitions.
2. **Configure Database Credentials**:
   Modify the PostgreSQL environment variables in `docker-compose.yml` to set a secure password:
   ```yaml
   POSTGRES_USER: qshield_user
   POSTGRES_PASSWORD: <your-secure-bank-password>
   POSTGRES_DB: qshield
   ```
3. **Start the multi-container stack**:
   ```bash
   docker-compose up -d --build
   ```
4. **Data Persistence**:
   * PostgreSQL data is mounted to the persistent volume `pg-data`.
   * Web reports are persisted to the `qshield-reports` volume.

---

## 🔒 Air-Gapped / Offline Build Guide (No Internet Access)
Since banking production servers typically lack outbound access to GitHub, the standard compilation steps in the `Dockerfile` will fail because they attempt to run `git clone`. Follow these steps to build the image offline:

### Step 1: Pre-download Dependencies
On a machine with internet access, download the source tarballs:
1. **OpenSSL 3.3.0**: [openssl-3.3.0.tar.gz](https://github.com/openssl/openssl/archive/refs/tags/openssl-3.3.0.tar.gz)
2. **liboqs 0.9.2**: [liboqs-0.9.2.tar.gz](https://github.com/open-quantum-safe/liboqs/archive/refs/tags/0.9.2.tar.gz)
3. **oqs-provider 0.5.3**: [oqs-provider-0.5.3.tar.gz](https://github.com/open-quantum-safe/oqs-provider/archive/refs/tags/0.5.3.tar.gz)

### Step 2: Transfer and Modify Dockerfile
1. Transfer the three tarballs to the same directory on the target server.
2. Edit the compile stages in the `Dockerfile` to use the local files instead of cloning them:

```dockerfile
# 1. OpenSSL 3.3.0
COPY openssl-3.3.0.tar.gz /opt/
RUN tar -xzf /opt/openssl-3.3.0.tar.gz -C /opt/ \
    && mv /opt/openssl-openssl-3.3.0 /opt/openssl-src \
    && cd /opt/openssl-src \
    && ./Configure --prefix=/opt/openssl3 linux-x86_64 shared \
    && make -j"$(nproc)" \
    && make install_sw \
    && rm -rf /opt/openssl-src /opt/openssl-3.3.0.tar.gz

# 2. liboqs 0.9.2
COPY liboqs-0.9.2.tar.gz /opt/
RUN tar -xzf /opt/liboqs-0.9.2.tar.gz -C /opt/ \
    && mv /opt/liboqs-0.9.2 /opt/liboqs-src \
    && cmake -S /opt/liboqs-src -B /opt/liboqs-build -GNinja \
         -DBUILD_SHARED_LIBS=ON \
         -DOQS_BUILD_ONLY_LIB=ON \
         -DOQS_USE_OPENSSL=OFF \
         -DCMAKE_BUILD_TYPE=Release \
    && cmake --build /opt/liboqs-build \
    && cmake --install /opt/liboqs-build \
    && rm -rf /opt/liboqs-src /opt/liboqs-build /opt/liboqs-0.9.2.tar.gz

# 3. oqs-provider 0.5.3
COPY oqs-provider-0.5.3.tar.gz /opt/
RUN tar -xzf /opt/oqs-provider-0.5.3.tar.gz -C /opt/ \
    && mv /opt/oqs-provider-0.5.3 /opt/oqs-provider-src \
    && cmake -S /opt/oqs-provider-src -B /opt/oqs-provider-build -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DOPENSSL_ROOT_DIR=/opt/openssl3 \
        -DCMAKE_PREFIX_PATH=/opt/openssl3 \
    && cmake --build /opt/oqs-provider-build \
    && cmake --install /opt/oqs-provider-build --prefix /opt/oqs-provider \
    && rm -rf /opt/oqs-provider-src /opt/oqs-provider-build /opt/oqs-provider-0.5.3.tar.gz
```

### Step 3: Run the local Build
Run the standard command, which will now build successfully using local tarballs:
```bash
docker-compose up -d --build
```

---

## 🔍 Verification & Health Checks

### Check Container Status
Verify that the containers are healthy and running:
```bash
docker ps
```
*(Look for status `Up (healthy)` in the QShield container list)*

### Verify PQC Probing Capability
To verify that the custom OpenSSL compilation succeeded and the container is PQC-ready:
1. Exec into the running container:
   ```bash
   docker exec -it qshield-app bash
   ```
2. Test the OpenSSL binary directly with the `oqsprovider`:
   ```bash
   $OPENSSL_PQC_BIN list -providers -provider-path /opt/oqs-provider/lib -provider oqsprovider
   ```
   *(Should list `oqsprovider` and its hybrid key exchanges e.g. `X25519+ML-KEM-768`)*

---

## 🔑 Security & Access Control

### Default Admin Credentials
* **Username**: `admin`
* **Password**: `admin123`

### Security Recommendations for PNB:
* **Proxy Configuration**: If scanning targets through the Bank's proxy, export `HTTP_PROXY` and `HTTPS_PROXY` in the environment variables block.
* **HTTPS**: Behind a bank-wide reverse proxy (e.g. F5 BIG-IP or Nginx), make sure TLS termination is handled correctly.
* **Database Secrets**: Ensure credentials in `docker-compose.yml` are restricted and stored securely.
