#!/usr/bin/env python3
from tls_scanner import _get_key_exchange_details, _get_tls_versions_supported

host = 'sc.com'
port = 443
timeout = 10

print("Testing key exchange detection on sc.com...\n")

# Get supported TLS versions first
versions = _get_tls_versions_supported(host, port, timeout)
print(f"Supported TLS versions: {versions}\n")

# Get key exchange details
kx = _get_key_exchange_details(host, port, versions, timeout)

print("KEY EXCHANGE DETAILS:")
print("=" * 70)
print(f"Algorithm (Raw): {kx.get('algorithm')}")
print(f"Normalized (NIST Standard): {kx.get('normalized_algorithm')}")
print(f"Detection Engine: {kx.get('detection_engine')}")

if kx.get('pqc'):
    pqc = kx['pqc']
    print(f"\nPQC Hybrid Details:")
    print(f"  - Detected: {pqc.get('detected')}")
    print(f"  - Raw Algorithm: {pqc.get('algorithm')}")
    print(f"  - Normalized: {pqc.get('normalized_algorithm')}")
    print(f"  - Is PQC: {pqc.get('is_pqc')}")
    print(f"  - Classical: {pqc.get('classical_component')}")
    print(f"  - NIST Level: {pqc.get('nist_security_level')}")

print("\n" + "=" * 70)
if kx.get('normalized_algorithm'):
    print(f"✓ SUCCESS: normalized_algorithm is now populated!")
    print(f"  Raw: {kx.get('algorithm')} → Normalized: {kx.get('normalized_algorithm')}")
else:
    print(f"✗ Issue: normalized_algorithm is still not populated")
