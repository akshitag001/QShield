# Q-Shield Cryptographic Inventory Scanner

A comprehensive tool for discovering and inventorying cryptographic controls in public-facing applications (web servers, APIs, TLS endpoints). Generates a structured **Cryptographic Bill of Materials (CBOM)** suitable for compliance reporting, risk assessment, and post-quantum readiness planning.

## Features

- **TLS Protocol Discovery**: Detects supported TLS versions (1.0, 1.1, 1.2, 1.3)
- **Cipher Suite Inventory**: Enumerates all supported cipher suites with parsed components
- **Certificate Analysis**: Extracts full X.509 certificate metadata including SANs
- **Key Exchange Detection**: Identifies key exchange algorithms and parameters
- **API Endpoint Probing**: Discovers common API paths and types
- **HTTP Security Headers**: Extracts HSTS, CSP, and other security headers
- **CBOM Generation**: Produces standardized cryptographic inventory reports
- **Quantum Vulnerability Flagging**: Identifies assets vulnerable to quantum attacks
- **Multi-Target Scanning**: Parallel scanning of multiple endpoints

## Installation

```bash
pip install -r requirements.txt
```

## Authentication, RBAC, and Database

The web app now includes:

- Session-based login (`/login`)
- Role-based access control (RBAC)
  - `admin` / `cyber_lead` / `it_lead` / `security_head`: org-wide access
    - View all employees' scan history and reports
    - View platform audit logs (`/api/admin/logs`)
    - Clear full scan history
  - `analyst`: employee-level access
    - Can scan targets
    - Can view/download only their own scan results and reports
  - `viewer`: read-only limited role in UI (no scanning)
- Persistent scan history using SQL database (default: SQLite)
- Audit logging of user actions (login/logout/scan/history-clear)
- Subdomain workflow from CT intelligence:
  - After primary domain scan, detected subdomains are listed.
  - User can scan selected subdomains or all detected subdomains.
  - Combined CBOM is generated across selected scope (parent + selected subdomains).
- Scheduled reporting workflow:
  - Page: `/scheduled-reporting`
  - Configure domain + codomain scope, frequency (`weekly` or `monthly`), date/time, and delivery email.
  - Enable/disable schedules from the same page.
  - Background worker executes due schedules, runs a scan, stores results, and emails summary.

### Default Login (first run)

- Username: `admin`
- Password: `textmebroforpass`

Set these environment variables in production:

- `SESSION_SECRET_KEY`
- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`
- `DATABASE_URL` (example: `sqlite:///./qshield.db`)

Set these for scheduled email delivery:

- `SMTP_HOST`
- `SMTP_PORT` (default: `587`)
- `SMTP_USERNAME`
- `SMTP_PASSWORD`
- `SMTP_FROM_EMAIL` (or fallback to `SMTP_USERNAME`)
- `SMTP_USE_TLS` (`1` by default)

Optional scheduler controls:

- `SCHEDULE_REPORT_POLL_SECONDS` (default: `60`, minimum `30`)
- `DISABLE_SCHEDULE_WORKER` (`1` to disable)

### Database Behavior

- Scan results are stored in `scan_records` table.
- Users are stored in `users` table.
- Audit events are stored in `audit_logs` table.
- On first startup, an admin user is auto-created if no users exist.

### Subdomain Scan API

- `POST /api/scan/subdomains`
  - Input: `parent_target`, `subdomains[]`, `include_parent`, `timeout`
  - Output: per-target scan results + combined CBOM + vulnerabilities summary

## Quick Start

### Single Target Scan

```bash
python scanner.py example.com
```

### Multiple Targets

```bash
python scanner.py example.com api.example.com secure.example.com
```

### From File

```bash
python scanner.py -f targets.txt
```

### Output Formats

```bash
# Full CBOM (default)
python scanner.py example.com --format cbom

# Raw JSON scan results
python scanner.py example.com --format json

# Human-readable summary
python scanner.py example.com --format summary
```

### Save to File

```bash
python scanner.py example.com -o report.json
```

## Module Usage

### Low-Level TLS Scanner

```python
from tls_scanner import scan_tls

result = scan_tls("example.com")
print(result["tls_versions_supported"])
print(result["cipher_suites"])
print(result["certificate"])
```

### CBOM Generator

```python
from tls_scanner import scan_tls
from cbom_generator import generate_cbom

# Scan multiple targets
results = [scan_tls("example.com"), scan_tls("api.example.com")]

# Generate CBOM
cbom = generate_cbom(results)
print(cbom.to_json())
```

### Multi-Target Scanner

```python
from scanner import scan_multiple_targets, generate_inventory_report

targets = ["example.com", "api.example.com"]
report = generate_inventory_report(targets, output_format="cbom")
print(report)
```

## Output Structure

### CBOM Format

```json
{
  "cbom_version": "1.0.0",
  "generated_at": "2026-02-13T10:30:00+00:00",
  "generator": "Q-Shield TLS Scanner",
  "endpoints": [
    {
      "endpoint": "example.com:443",
      "ip_address": "93.184.216.34",
      "port": 443,
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

### Asset Types

| Type | Description |
|------|-------------|
| `certificate` | X.509 certificates |
| `cipher_suite` | Complete cipher suite configurations |
| `key_exchange` | Key exchange algorithms (RSA, DHE, ECDHE) |
| `hash_algorithm` | Hash/MAC algorithms (SHA-256, SHA-384) |
| `symmetric_cipher` | Symmetric encryption (AES-256-GCM) |
| `public_key` | Public key parameters |
| `protocol` | TLS protocol versions |

### Strength Classifications

| Strength | Description |
|----------|-------------|
| `strong` | Recommended (AES-256, RSA-2048+, ECDSA-256+) |
| `acceptable` | Currently acceptable (AES-128, TLSv1.2) |
| `weak` | Deprecated (3DES, RSA-1024, TLSv1.0/1.1) |
| `broken` | Known broken (MD5, DES, RC4, SSLv3) |

## CLI Options

```
usage: scanner.py [-h] [-f FILE] [--timeout TIMEOUT]
                  [--format {cbom,json,summary}]
                  [--no-api-probe] [--no-headers] [-o OUTPUT]
                  [targets ...]

Options:
  targets              Target URLs, hostnames, or IP:PORT
  -f, --file           File containing targets (one per line)
  --timeout            Connection timeout in seconds (default: 5)
  --format             Output format: cbom, json, summary
  --no-api-probe       Skip API endpoint detection
  --no-headers         Skip HTTP security header extraction
  -o, --output         Output file (default: stdout)
```

## CLI Error Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 2 | Invalid target |
| 3 | DNS failure |
| 4 | Connection failed |
| 5 | Timeout |
| 6 | TLS handshake failed |
| 10 | Unexpected error |

## Tests

```bash
python -m unittest
```

## Deploying on Vercel

This repository is configured for Vercel using `vercel.json`.

### Deploy from Dashboard

1. Push this project to GitHub.
2. In Vercel dashboard, click **Add New → Project**.
3. Import your GitHub repo.
4. Keep defaults (Vercel will detect Python via `app.py` + `vercel.json`).
5. Click **Deploy**.

Optional CLI deploy:

```bash
npm i -g vercel
vercel login
vercel --prod
```

### Notes

- Required Python dependencies for cloud deployment are listed in `requirements.txt`.
- The app stores scan history in memory, so history resets whenever the serverless instance is recycled.

## Limitations

- Cipher enumeration depends on local Python/OpenSSL capabilities
- TLS 1.0/1.1 may be disabled in modern runtimes
- API endpoint detection uses HEAD requests on common paths
- Certificate chain analysis requires OpenSSL CLI or `cryptography` library
- Only reports what is observable on the wire (passive scanning)

## Architecture

```
scanner.py          - Main orchestrator, multi-target scanning
tls_scanner.py      - Low-level TLS protocol scanner
cbom_generator.py   - CBOM generation and asset classification
```

## Future Enhancements (Planned)

- Post-Quantum Cryptography (PQC) detection
- Risk scoring engine
- Compliance mapping (NIST, PCI-DSS)
- Dashboard UI
- Scheduled scanning and change detection
- No dashboards or recommendations
