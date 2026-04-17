# Q-Shield Scanning Architecture Analysis

## Executive Summary

Q-Shield is a **TLS/cryptographic inventory and compliance scanner** that specializes in detecting post-quantum cryptography (PQC) readiness and quantum-related risks. It performs multi-layered scanning of TLS endpoints with focus on cryptographic asset discovery and quantum vulnerability assessment.

---

## 1. TARGET TYPES SUPPORTED

### 1.1 Target Input Formats
The scanner accepts multiple target formats via input parsing (`_parse_target()` in tls_scanner.py):

- **Hostnames**: `example.com`, `api.example.com`, `rru.ac.in`
- **Domain with port**: `example.com:8443`, `api.example.com:9000`
- **IPv4 addresses**: `192.168.1.1`, `192.168.1.1:443`
- **IPv6 addresses (bracketed)**: `[::1]`, `[fe80::1]:8443`
- **Full URLs**: `https://example.com`, `https://example.com:8443`

### 1.2 Port Discovery & Probing
**Port probing function**: `_probe_common_ports()` in scanner.py
- Tests common TLS/HTTPS ports on single targets
- Ports tested: **443, 8443, 8080, 9443, 3000, 5000, 8000**
- Default port if unspecified: **443 (HTTPS)**
- Configurable timeout (default: 3 seconds per port)

### 1.3 Subdomain Scanning
Via `/api/scan/subdomains` endpoint (app.py):
- Accepts parent domain + list of subdomain targets
- Scans each subdomain independently
- Can include/exclude parent domain in combined CBOM
- Useful for multi-environment reconnaissance (prod, staging, dev, etc.)

### 1.4 Multi-Target Scanning
Via `/api/scan/multi` and `scan_multiple_targets()`:
- Parallel scanning with configurable worker pool (default: 5 workers)
- Batch scanning of multiple domains
- Can target via CLI: `python scanner.py target1.com target2.com target3.com`
- Or via file: `python scanner.py -f targets.txt`

### 1.5 Third-Party Vendor Scanning
Via `VendorScanRequest` (app.py):
- Managed list of third-party vendors stored in database
- Each vendor has domain, criticality level (low/medium/high/critical)
- Scheduled or on-demand scanning
- Integrated audit logging

---

## 2. SECURITY ASPECTS EVALUATED

### 2.1 TLS/SSL Protocol Analysis

#### **A. Protocol Version Support Detection**
**Function**: `_get_tls_versions_supported()` in tls_scanner.py
- **TLS 1.0**: Detected and flagged as `WEAK` strength
- **TLS 1.1**: Detected and flagged as `WEAK` strength
- **TLS 1.2**: Detected and classified as `ACCEPTABLE` strength
- **TLS 1.3**: Detected and classified as `STRONG` strength
- Method: Active probing of each version (not hardcoded)

#### **B. Cipher Suite Analysis**
**Function**: `_collect_cipher_suites()` in tls_scanner.py

**Analyzed Properties**:
- TLS version per cipher
- Cipher suite name (IANA format: `TLS_*_WITH_*`)
- Key exchange algorithm
- Authentication algorithm
- Encryption algorithm
- Hash algorithm used

**Strength Classification**:
```
BROKEN:     NULL, EXPORT, RC2, RC4, DES, MD5
WEAK:       3DES, SHA-1, RSA<2048, ECDSA<256
ACCEPTABLE: AES-128, TLSv1.2
STRONG:     AES-256, ChaCha20, TLSv1.3
```

#### **C. Key Exchange Analysis**
**Function**: `_get_key_exchange_details()` in tls_scanner.py

**Classical KE Algorithms Detected**:
- DHE (Diffie-Hellman Ephemeral) → Ephemeral forward secrecy
- ECDHE (Elliptic Curve DHE) → Modern with forward secrecy
- RSA key exchange → No forward secrecy
- Static ECDH/DH → No forward secrecy
- Extracts curve names: P-256, P-384, P-521, X25519, X448

**Forward Secrecy Detection**: 
- Marked `true` if using ephemeral KEX (DHE, ECDHE)
- Marked `false` for static RSA/ECDH

#### **D. Certificate Analysis**
**Function**: `_get_certificate_metadata()` in tls_scanner.py

**Extracted Fields**:
- **Subject**: DN format (RFC 4514)
- **Issuer**: CA identification
- **Validity Period**: `valid_from`, `valid_to` (ISO 8601)
- **Serial Number**: Hex format
- **Signature Algorithm**: e.g., "SHA256withRSA", "SHA384withECDSA"
- **Public Key Algorithm**: RSA, ECDSA, DSA, Ed25519, Ed448
- **Public Key Size**: Bit length (e.g., 2048 for RSA, 256 for ECDSA)
- **Subject Alternative Names (SANs)**: DNS names, IP addresses
- **Certificate Chain Length**: Number of certs in chain
- **AIA Extensions**: OCSP responder URL, issuer CA URL

**Certificate Strength Classification**:
```
Key Type          BROKEN           WEAK              ACCEPTABLE      STRONG
RSA               <1024            1024-2047         2048+            4096+
ECDSA             <160             160-223           224-255          256+
DSA               <1024            1024-2047         2048+            -
Ed25519/Ed448     -                -                 -                All
```

#### **E. OCSP Status Checking**
**Function**: `_check_ocsp_status()` in tls_scanner.py

**OCSP Features**:
- Retrieves OCSP responder URL from cert extension
- Fetches issuer certificate (if needed)
- Validates certificate revocation status
- Caches responses (LRU cache, max 500 entries, 5-min TTL) for performance
- Status values: `good`, `revoked`, `unknown`
- Graceful fallback when OCSP unavailable

---

### 2.2 Post-Quantum Cryptography (PQC) Detection

#### **A. Multi-Engine PQC Detection Framework**
Q-Shield uses a **universal token-based algorithm analysis** (via `detect_algorithm_category()` in universal_pqc_detection.py) that automatically detects:
- **Pure PQC algorithms** (e.g., MLKEM768, Dilithium3)
- **Hybrid algorithms** (e.g., X25519+MLKEM768, P256+MLKEM768)
- **Future algorithms** (auto-scales without hardcoding specific combos)

#### **B. Detection Engines (Ordered by Priority)**

**1. Primary: ctypes to libssl**
- `_get_tls13_group_via_ctypes()` in tls_scanner.py
- Extracts negotiated TLS 1.3 group using Python's internal OpenSSL
- Calls `SSL_get_negotiated_group()` and `OBJ_nid2sn()`
- **Advantage**: Works without external OpenSSL CLI
- **Detects**: Hybrid algorithms like X25519MLKEM768 directly

**2. Secondary: PQC-Enabled OpenSSL Binary**
- `_probe_pqc_via_openssl_pqc_binary()` in tls_scanner.py
- Uses oqs-openssl or openssl-pqc if available
- Probes with `openssl s_client -groups X25519MLKEM768:X25519KYBER768:...`
- Auto-detects PQC binary at startup via `_find_pqc_openssl()`
- **Confirms**: Server's actual PQC negotiation capability

**3. Tertiary: Standard OpenSSL CLI**
- Fallback method if no PQC binary available
- Parses negotiated group from OpenSSL output

**4. Quaternary: curl**
- `_probe_pqc_via_curl()` in tls_scanner.py
- Uses `curl --curves X25519MLKEM768:...`
- Works on modern curl versions (macOS Sonoma+, Ubuntu 24.04+)

**5. Quinary: gnutls-cli**
- `_probe_pqc_via_gnutls()` in tls_scanner.py
- Uses gnutls with PQC priority string

#### **C. PQC Algorithm Registry**
**Supported PQC Algorithms**:

**Key Encapsulation Mechanisms (KEMs)**:
- ML-KEM: 512, 768, 1024
- Kyber: 512, 768, 1024
- MLKEM/Kyber hybrids with classical curves: X25519, P-256, P-384, secp256r1, secp384r1

**Digital Signatures**:
- ML-DSA: 44, 65, 87 (NIST FIPS round 3)
- Dilithium: 2, 3, 5
- SLH-DSA: 128, 192, 256 (SPHINCS+)

**Hybrid Combinations Recognized**:
- X25519+MLKEM768, X25519+MLKEM1024
- X25519+KYBER512, X25519+KYBER768, X25519+KYBER1024
- P-256+MLKEM768, P-256+KYBER512/768/1024
- P-384+MLKEM1024, P-384+KYBER1024
- secp256r1/secp384r1 variants
- P-521+MLKEM1024, SECP521R1+MLKEM1024

#### **D. PQC Results Structure**
```python
{
  "pqc_status": {
    "mode": "classical|pqc_hybrid|pqc_pure|pqc_supported",
    "supported": bool,
    "active": bool,  # Currently negotiated
    "negotiated_group": str,
    "pqc_groups_supported": [list of groups server supports]
  },
  "universal_analysis": {
    "is_hybrid": bool,
    "is_pqc": bool,
    "is_classical": bool,
    "classical_tokens": [list],
    "pqc_tokens": [list],
    "reason": str,
    "confidence": float
  }
}
```

#### **E. PQC Readiness Classification**
Endpoints classified as PQC-ready if:
- ✅ TLS 1.3 with hybrid KEM negotiated (e.g., X25519MLKEM768)
- ✅ Server confirms PQC group selection
- ✅ Hybrid mode active (providing quantum resistance)

---

### 2.3 HTTP Security Headers Analysis

**Function**: `_extract_headers_crypto_info()` in scanner.py

**Headers Checked**:
- **HSTS** (Strict-Transport-Security): Policy duration and subdomains
- **CSP** (Content-Security-Policy): Full policy string
- **X-Content-Type-Options**: `nosniff` enforcement
- **X-Frame-Options**: Clickjacking protection
- **Server**: Exposes server software version (security concern)

**Result Format**:
```python
{
  "strict_transport_security": "max-age=...; includeSubDomains",
  "content_security_policy": "...",
  "x_content_type_options": "nosniff",
  "x_frame_options": "DENY",
  "server": "nginx/..."
  "security_headers_present": ["HSTS", "CSP", "X-Content-Type-Options"]
}
```

---

## 3. API ENDPOINT SECURITY CHECKS

### 3.1 API Endpoint Discovery

**Function**: `_detect_api_endpoints()` in scanner.py

**Probed API Paths**:
```
/api              /api/v1           /api/v2
/v1               /v2               /graphql
/rest             /.well-known/openid-configuration
/swagger.json     /openapi.json     /health
/status
```

**Detection Method**:
- HTTP `HEAD` requests to each path
- Response status < 400 = endpoint exists
- Extracts Content-Type header
- Identifies endpoints as APIs if: `"json"` in Content-Type OR `"api"` in path

**API Metadata Collected**:
```python
{
  "path": "/api/v1",
  "url": "https://example.com/api/v1",
  "status": 200,
  "content_type": "application/json",
  "is_api": True
}
```

### 3.2 API Endpoint-Specific TLS Scans
All API endpoints discovered are:
1. Rescanned for TLS cipher suites specific to their port
2. Checked for PQC support at the API endpoint
3. Certificate chains validated
4. Included in CBOM as separate assets if on different ports

---

## 4. ENTRY POINTS & TARGET DISCOVERY

### 4.1 CLI Entry Point
**File**: `scanner.py` main()

```bash
python scanner.py example.com                          # Single target
python scanner.py example.com api.example.com         # Multiple targets
python scanner.py -f targets.txt                       # File input
python scanner.py --format cbom|json|summary           # Output format
python scanner.py --timeout 15 --no-api-probe          # Options
```

### 4.2 Web API Entry Points

#### **Public Scan Endpoint** (no auth):
- **POST** `/api/scan/public`
- Request: `{ "target": "...", "timeout": 10 }`
- Used for public/unauthenticated scanning

#### **Authenticated Single Scan**:
- **POST** `/api/scan`
- Request: `{ "target": "...", "timeout": 10 }`
- Saves scan in database, logged to audit trail

#### **Stream Scan** (real-time progress):
- **GET** `/api/scan/stream?target=...&timeout=...`
- Server-Sent Events (SSE) stream
- Sends `[PHASE]` progress markers as scan progresses

#### **Multi-Target Scan**:
- **POST** `/api/scan/multi`
- Request: `{ "targets": ["...", "..."], "timeout": 10 }`
- Parallel scanning of multiple targets

#### **Subdomain Scan**:
- **POST** `/api/scan/subdomains`
- Request: `{ "parent_target": "example.com", "subdomains": ["api", "dashboard", "..."], ... }`
- Scans subdomains + generates combined CBOM

#### **Vendor Scan**:
- **POST** `/api/vendor/scan`
- Scans pre-registered third-party vendors

### 4.3 Scanning Flow

```
Input (CLI/API)
    ↓
Target Validation & Parsing (_validate_scan_target_or_raise)
    ├─ Hostname validation (RFC-compliant)
    ├─ IP address validation (IPv4/IPv6)
    ├─ Domain name validation
    └─ Port range validation (1-65535)
    ↓
TLS Scan (scan_tls)
    ├─ Protocol version detection (TLS 1.0-1.3)
    ├─ Cipher suite enumeration
    ├─ Certificate retrieval & analysis
    ├─ Key exchange details extraction
    ├─ PQC support detection (multi-engine)
    └─ OCSP revocation checking
    ↓
HTTP Layer Analysis (scanner.py)
    ├─ API endpoint discovery
    └─ Security header extraction
    ↓
CBOM Generation (cbom_generator.py)
    ├─ Asset classification
    ├─ Strength assessment
    ├─ Quantum vulnerability mapping
    └─ Risk scoring
    ↓
Results Storage & Reporting
    ├─ Database persistence
    ├─ Audit logging
    └─ PDF/JSON export
```

### 4.4 Progress Reporting
Stream endpoint sends phase markers:
```
[PROBE_PORTS]      - Testing common ports
[TLS_HANDSHAKE]    - Performing TLS 1.2/1.3 handshake
[CERT_ANALYSIS]    - Extracting certificate details
[PQC_DETECTION]    - Probing PQC capabilities
[API_DISCOVERY]    - Scanning for API endpoints
[OCSP_CHECK]       - Checking certificate revocation
[COMPLETE]         - Scan finished
```

---

## 5. COVERAGE GAPS & MISSING ENDPOINT SECURITY CHECKS

### 5.1 Missing HTTP-Level Security Checks

#### **A. Missing HTTP Response Header Analysis**
Currently checked:
- ✅ HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Server

**NOT checked** (gaps):
- ❌ X-XSS-Protection (legacy but still useful)
- ❌ Referrer-Policy
- ❌ Feature-Policy / Permissions-Policy
- ❌ Cross-Origin-Opener-Policy (COOP)
- ❌ Cross-Origin-Embedder-Policy (COEP)
- ❌ Expect-CT (Certificate Transparency enforcement)
- ❌ Public-Key-Pins (HPKP) - deprecated but indicates maturity
- ❌ X-Permitted-Cross-Domain-Policies
- ❌ X-UA-Compatible
- ❌ Cache-Control / Pragma (sensitive data leakage)

**Impact**: Limited visibility into XSS, clickjacking, and supply chain protections.

#### **B. Missing HTTP Method Analysis**
**NOT checked**:
- ❌ Allowed HTTP methods (OPTIONS requests)
- ❌ WebDAV methods enabled (PROPFIND, MOVE, DELETE, PUT)
- ❌ TRACE method enabled (HTTP response splitting vector)
- ❌ HEAD method support
- ❌ CONNECT method (HTTPS tunnel)

**Impact**: Can't detect overly permissive HTTP configurations or WebDAV exposure.

#### **C. Missing Security Redirect Analysis**
**NOT checked**:
- ❌ HTTP → HTTPS redirect chain (insecure intermediates)
- ❌ Redirect loops or open redirects
- ❌ Redirect to different domain (domain squatting risk)
- ❌ HTTPS downgrade detection

**Impact**: Can't identify insecure redirect chains vulnerable to MITM.

---

### 5.2 Missing API-Specific Security Checks

#### **A. Missing API Authentication Verification**
**NOT checked**:
- ❌ OAuth2 endpoint validation
- ❌ API key requirements (authentication bypass risk)
- ❌ JWT/bearer token support
- ❌ CORS policy analysis
- ❌ Rate limiting headers (X-RateLimit-*)
- ❌ API versioning practices

**Current**: Merely detects API path existence, doesn't validate auth model.

**Impact**: Can't assess whether APIs require authentication or are exposed.

#### **B. Missing CORS Analysis**
**NOT checked**:
- ❌ Access-Control-Allow-Origin values
- ❌ Access-Control-Allow-Methods
- ❌ Access-Control-Allow-Credentials
- ❌ Access-Control-Max-Age
- ❌ Insecure CORS patterns (wildcard `*`)

**Impact**: Can't detect browser-based attack vectors via permissive CORS.

#### **C. Missing GraphQL Specific Checks**
When `/graphql` endpoint detected:
- ❌ Introspection query testing (should be disabled in production)
- ❌ Query complexity limits
- ❌ Field scope validation
- ❌ Batch query limits
- ❌ GraphQL schema enumeration risk

**Impact**: GraphQL endpoints scanned for existence but not for configuration issues.

---

### 5.3 Missing Cryptographic Protocol Checks

#### **A. Missing Implementation Details**
- ❌ Session resumption mechanism (tickets vs. session IDs)
- ❌ Serialized key transport (TLS session IDs, session tickets)
- ❌ Renegotiation safety (secure renegotiation flag)
- ❌ 0-RTT handling (TLS 1.3 early data vulnerabilities)
- ❌ Server-side session cache configuration

**Impact**: Can't identify session resumption security issues.

#### **B. Missing Downgrade Attack Detection**
- ❌ SSLV2 fallback (SSLv2 protocol check)
- ❌ Version downgrade via crafted ClientHello
- ❌ SignatureAlgorithms offer (fallback weakness)
- ❌ POODLE-like vulnerability detection

**Impact**: Can't detect forced protocol downgrade attacks.

#### **C. Missing Elliptic Curve Analysis**
- ❌ Weak curves (e.g., Brainpool P-160)
- ❌ Suite-B curves enforcement
- ❌ Curve preferences/prioritization
- ❌ Custom/proprietary curve usage

**Impact**: Limited visibility into ECC strength variations.

---

### 5.4 Certificate-Specific Gaps

#### **A. Missing Extended Validation (EV) Certificate Detection**
- ❌ EV certificate identification
- ❌ OID parsing for EV indicators
- ❌ CA authorization level assessment

**Impact**: Can't distinguish between standard and EV certificates.

#### **B. Missing Certificate Transparency (CT) Validation**
- ❌ SCT (Signed Certificate Timestamp) extraction
- ❌ CT log server validation
- ❌ CT compliance checking (RFC 6962)
- ❌ Missing CT logs (Chrome Chromium enforcement)

**Impact**: Can't verify CT compliance or log validity.

#### **C. Missing CAA (Certification Authority Authorization) Analysis**
- ❌ DNS CAA record checking
- ❌ Authorized CA verification
- ❌ CAA issue/issuewild directives

**Impact**: Can't detect if CA can issue certificates for the domain.

#### **D. Missing Certificate Pinning Detection**
- ❌ HPKP (HTTP Public Key Pinning) analysis
- ❌ Certificate/public key pinning in code (binary scanning)
- ❌ Pin expiration validation

**Impact**: No visibility into pinning strategies already in place.

---

### 5.5 Missing Vulnerability-Specific Checks

#### **A. Missing TLS Vulnerability Scanners**
- ❌ Heartbleed (CVE-2014-0160)
- ❌ CCS Injection (CVE-2014-0224)
- ❌ CRIME (compression-based attack)
- ❌ BREACH (gzip+TLS attack)
- ❌ Lucky Thirteen (padding oracle)
- ❌ DROWN (cross-protocol attack)
- ❌ FREAK (export-grade key exchange)

**Current**: Flags broken/weak algorithms but doesn't test for specific CVEs.

**Impact**: Can't identify endpoints vulnerable to known protocol attacks.

#### **B. Missing Cryptographic Agility Checks**
- ❌ Fallback cipher suite depths (how many weaker options available)
- ❌ Mandatory algorithm enforcement verification
- ❌ Legacy algorithm deprecation timeline
- ❌ Compliance with internal crypto policies

**Impact**: Can't assess organization's ability to quickly deprecate weak algorithms.

---

### 5.6 Missing Business Logic & Configuration Checks

#### **A. Missing DNS & Domain Analysis**
- ❌ SPF record validation (email spoofing risk)
- ❌ DKIM/DMARC configuration
- ❌ DNSSEC validation
- ❌ DNS rebinding vulnerabilities
- ❌ Subdomain enumeration (only accepts input subdomains)
- ❌ Zone transfer attempts (AXFR vulnerability)

**Impact**: No DNS-layer security assessment.

#### **B. Missing Certificate Lifecycle Management**
- ❌ Certificate expiration warning (approaching renewal)
- ❌ Upcoming expiration (predict outages)
- ❌ Certificate issuance frequency (monitoring for rogue certs)
- ❌ Key rotation frequency analysis

**Impact**: Can't proactively identify certificates nearing expiration.

#### **C. Missing Organization Audit Features**
- ❌ Certificate ownership tracking
- ❌ Certificate cost analysis (license count)
- ❌ Unused certificate detection
- ❌ Wildcard certificate inventory
- ❌ Self-signed certificate tracking

**Impact**: No visibility into certificate sprawl or cost optimization.

---

### 5.7 Missing Advanced PQC Analysis

#### **A. Missing PQC Deployment Roadmap Validation**
- ❌ Hybrid-first transition progress tracking
- ❌ Key sizes vs. security level recommendations
- ❌ ML-KEM vs. KYBER maturity (NIST standard vs. pre-standard)
- ❌ PQC signature algorithm deployment (ML-DSA preference)
- ❌ Legacy PQC algorithm (pre-FIPS) detection with warnings

**Current**: Detects PQC present/absent; doesn't assess transition phase.

**Impact**: Can't advise on hybrid migration best practices.

#### **B. Missing Quantum Vulnerability Context**
- ❌ Harvesting threat assessment (harvest-now-decrypt-later timeline)
- ❌ Data sensitivity mapping (which endpoints protect sensitive data)
- ❌ Industry-specific quantum risk profiles
- ❌ Regulatory quantum readiness requirements (NIST, Post-Quantum Cryptography)

**Impact**: Generic quantum risk without business context.

---

## 6. RECOMMENDED PRIORITY ADDITIONS

### **High Priority (Security Impact)**
1. **HTTP Security Header Audit** - Cost: Medium
   - Add checks for all OWASP-recommended headers
   - Severity scoring for missing headers

2. **CORS Policy Analysis** - Cost: Medium
   - Parse and validate CORS headers
   - Detection of insecure patterns (wildcard origins)

3. **Certificate Expiration Tracking** - Cost: Low
   - Alert on expiration dates
   - Proactive renewal warnings (30/14/7 days)

4. **API Authentication Verification** - Cost: High
   - Probe for auth requirements
   - Detect exposed/unauthenticated endpoints

5. **CAA Record Validation** - Cost: Low
   - Query DNS CAA records
   - Verify CA authorization

### **Medium Priority (Operational Impact)**
6. **Certificate Transparency Validation** - Cost: Medium
   - Extract and validate SCTs
   - Verify CT log inclusion

7. **TLS Vulnerability Testing** - Cost: High
   - POODLE, FREAK, INSECURE patterns
   - Downgrade attack detection

8. **DNS Security Analysis** - Cost: High
   - SPF/DKIM/DMARC validation
   - DNSSEC checks

### **Lower Priority (Strategic Planning)**
9. **PQC Roadmap Tracker** - Cost: Medium
   - Hybrid deployment phases
   - Migration timeline recommendations

10. **Cryptographic Agility Scoring** - Cost: Medium
    - How quickly algorithms can be deprecated
    - Organization crypto policy compliance

---

## 7. CURRENT COVERAGE SUMMARY

### ✅ Well-Covered Areas
- TLS protocol version enumeration (1.0-1.3)
- Cipher suite discovery and strength classification
- Certificate metadata extraction (standard fields)
- Public key algorithm and size analysis
- OCSP revocation checking
- **PQC detection** (excellent multi-engine approach)
- Hybrid algorithm identification (X25519+MLKEM, etc.)
- Forward secrecy detection
- API endpoint discovery (basic)
- HTTP security header extraction (basic)

### ⚠️ Partially Covered Areas
- Certificate validation (only checks expiration, not full chain)
- API endpoints (existence detection only, no auth/security config)
- HTTP security (only 4 headers checked)
- TLS version downgrade (not tested)

### ❌ Not Covered Areas
- Web application-level security (WAF, authentication methods)
- DNS security (SPF, DKIM, DMARC, CAA)
- Zero-RTT/early data vulnerabilities
- Specific TLS CVE testing
- Certificate pinning strategies
- Certificate Transparency compliance
- CORS security policies
- Cryptographic agility assessment
- Business-context quantum risk

---

## 8. ARCHITECTURE STRENGTHS

1. **Multi-Engine PQC Detection**: Uses ctypes, native OpenSSL, and fallback methods—robust approach
2. **Universal Algorithm Analysis**: Token-based detection scales to future algorithms
3. **Parallel Scanning**: Thread pool for multi-target efficiency
4. **Database Persistence**: Scan history, audit logs, scheduled reports
5. **Flexibility**: Works with self-signed certs, multiple input formats
6. **Extensibility**: Modular functions for certificate, cipher, PQC analysis
7. **PQC-Focused**: Deep expertise in quantum-safe cryptography

---

## 9. RECOMMENDATIONS FOR NEXT PHASE

Focus on **API endpoint security** (highest operational impact) and **certificate lifecycle management** (lowest effort, high compliance value). PQC analysis is already excellent; recommend enhancing it with business context rather than technical expansion.

