# Q-Shield: Post-Quantum Cryptographic Inventory & Readiness Scanner

[![Hackathon Submission](https://img.shields.io/badge/Hackathon-Submission-blue.svg)](#)
[![PQC Ready](https://img.shields.io/badge/PQC-Ready-success.svg)](#)
[![Security Posture](https://img.shields.io/badge/Security-Visibility-brightgreen.svg)](#)

> **Executive Summary for SOC Analysts, IT Leads & Hackathon Judges**
> Q-Shield is a comprehensive cryptographic inventory scanner designed for the impending Post-Quantum Cryptography (PQC) transition. It provides full visibility into the cryptographic posture of public-facing assets (web servers, APIs, TLS endpoints). It generates a structured **Cryptographic Bill of Materials (CBOM)**, enabling SOC teams, compliance auditors, and IT leadership to identify legacy encryption, track PQC migration, and ensure compliance with frameworks like PCI-DSS and NIST.

---

## 🌟 The Problem We Solve
Modern organizations lack comprehensive visibility into their cryptographic assets across dynamic, distributed environments. This leaves them:
- **Vulnerable to "Harvest Now, Decrypt Later"** quantum attacks.
- Blind to deprecated, legacy encryption algorithms (e.g., TLS 1.0, 3DES, SHA-1).
- Struggling to maintain compliance and cryptographic agility.

**The Solution:** Q-Shield automates the discovery, classification, and continuous monitoring of these assets without requiring agent installations.

## 🎯 Key Use Cases
- **SOC Analysts & Incident Responders:** Rapidly triage endpoints to ensure they meet security baselines. Automatically flag endpoints with broken/weak cipher suites.
- **Compliance & Audit Teams:** Instantly generate a Cryptographic Bill of Materials (CBOM) for reporting (e.g., PCI-DSS requirements for strong cryptography).
- **IT & Security Architects:** Plan and track the organization's migration to Post-Quantum Cryptography (PQC) by identifying which endpoints currently support quantum-safe hybrid algorithms (e.g., ML-KEM).

## ✨ Features

- **Advanced PQC Detection**: Multi-engine detection of pure and hybrid Post-Quantum Cryptography algorithms.
- **TLS Protocol Discovery**: Detects supported TLS versions (1.0, 1.1, 1.2, 1.3).
- **Cipher Suite Inventory**: Enumerates all supported cipher suites with parsed components.
- **Certificate Analysis**: Extracts full X.509 certificate metadata including SANs and checks OCSP revocation.
- **Key Exchange Detection**: Identifies key exchange algorithms, parameters, and Forward Secrecy support.
- **API Endpoint Probing**: Discovers common API paths and types automatically.
- **HTTP Security Headers**: Extracts HSTS, CSP, and other critical security headers.
- **CBOM Generation**: Produces standardized cryptographic inventory reports.
- **Multi-Target Scanning**: Parallel scanning of multiple endpoints or subdomains.

---

## 🚀 Quick Start

### Installation

```bash
pip install -r requirements.txt
```

### CLI Usage

**Single Target Scan:**
```bash
python scanner.py example.com
```

**Multiple Targets:**
```bash
python scanner.py example.com api.example.com secure.example.com
```

**From File:**
```bash
python scanner.py -f targets.txt
```

**Output Formats (CBOM, JSON, Summary):**
```bash
python scanner.py example.com --format cbom -o report.json
python scanner.py example.com --format summary
```

---

## 🛡️ Web Interface, RBAC, and Database

The solution includes a full-featured web application tailored for enterprise teams:

- **Session-based login** (`/login`)
- **Role-Based Access Control (RBAC)**:
  - `admin` / `cyber_lead` / `it_lead` / `security_head`: Org-wide access to view all employees' scan history, reports, and platform audit logs. Can clear scan history.
  - `analyst`: Employee-level access to run scans and view/download their own scan results.
  - `viewer`: Read-only limited role for dashboards.
- **Persistent Storage**: Scan history is saved using an SQL database (default: SQLite, `scan_records`, `users`, `audit_logs`).
- **Audit Logging**: Comprehensive tracking of user actions (login/logout/scan).

### Subdomain Reconnaissance Workflow
Integrated with Certificate Transparency (CT) intelligence:
1. Scan a primary domain.
2. The system detects associated subdomains.
3. Users can select specific subdomains to scan, generating a combined CBOM across the entire scope.

### Scheduled Reporting
- Configure domain/subdomain scope, frequency (`weekly` or `monthly`), and delivery email.
- Background workers automatically execute due schedules, store results, and email executive summaries.

---

## 📦 Output Structure (CBOM Format)

Q-Shield generates a standardized Cryptographic Bill of Materials (CBOM):

```json
{
  "cbom_version": "1.0.0",
  "generated_at": "2026-02-13T10:30:00+00:00",
  "generator": "Q-Shield TLS Scanner",
  "endpoints": [
    {
      "endpoint": "example.com:443",
      "ip_address": "93.184.216.34",
      "tls_versions": ["TLSv1.2", "TLSv1.3"],
      "forward_secrecy": true,
      "weak_crypto_detected": false,
      "assets": [
        {
          "asset_id": "a1b2c3d4e5f6g7h8",
          "asset_type": "certificate",
          "name": "CN=example.com",
          "strength": "strong",
          "quantum_vulnerable": true,
          "properties": { ... }
        }
      ]
    }
  ],
  "summary": {
    "total_endpoints": 1,
    "total_assets": 15,
    "quantum_vulnerable_assets": 12,
    "endpoints_with_weak_crypto": 0
  }
}
```

### Strength Classifications
Every asset is evaluated and scored to provide instant context for SOC teams:
| Strength | Description | Action Required |
|----------|-------------|-----------------|
| `strong` | Recommended (AES-256, RSA-2048+, ECDSA-256+, TLSv1.3) | None |
| `acceptable` | Currently acceptable (AES-128, TLSv1.2) | Monitor for future deprecation |
| `weak` | Deprecated (3DES, RSA-1024, TLSv1.0/1.1) | Plan for upgrade immediately |
| `broken` | Known broken (MD5, DES, RC4, SSLv3) | **CRITICAL: Remediate immediately** |

---

## 🛠️ Module Usage for Developers

Integrate Q-Shield directly into your Python security pipelines.

**Low-Level TLS Scanner:**
```python
from tls_scanner import scan_tls
result = scan_tls("example.com")
print(result["tls_versions_supported"])
```

**CBOM Generator:**
```python
from tls_scanner import scan_tls
from cbom_generator import generate_cbom

results = [scan_tls("example.com"), scan_tls("api.example.com")]
cbom = generate_cbom(results)
print(cbom.to_json())
```

---

## ☁️ Deployment

This repository is configured for serverless deployment on Vercel using `vercel.json`.

1. Push this project to GitHub.
2. In Vercel dashboard, click **Add New → Project**.
3. Import your GitHub repo (Vercel will detect Python via `app.py` + `vercel.json`).
4. Click **Deploy**.

*(Note: SQLite is used by default. For production deployments on serverless platforms, configure a remote PostgreSQL/MySQL via the `DATABASE_URL` environment variable).*

---

## 🏗️ Architecture Summary
- `scanner.py`: Main orchestrator, handles multi-target concurrency.
- `tls_scanner.py`: Low-level protocol analysis, socket interactions, and PQC multi-engine detection.
- `cbom_generator.py`: Risk classification, asset structuring, and JSON generation.
- `app.py`: Flask web application, API routes, RBAC middleware, and background scheduler.

---

### Tests
```bash
python -m unittest
```
