#!/usr/bin/env python
from tls_scanner import scan_tls
import json

print("=" * 60)
print("Scanning sc.com for key exchange and PQC detection")
print("=" * 60)

result = scan_tls('sc.com', 443, 15)

# Display cipher suites
cipher_suites = result.get('cipher_suites', [])
print(f"\nCipher Suites ({len(cipher_suites)} total):")
for i, cs in enumerate(cipher_suites[:10]):
    print(f"  [{i+1}] TLS {cs.get('tls_version')} | KEX: {cs.get('key_exchange')} | {cs.get('cipher_suite')}")

# Display security features
sf = result.get('security_features', {})
print(f"\nSecurity Features:")
print(f"  Forward Secrecy: {sf.get('forward_secrecy')}")
print(f"  Strong Ciphers Only: {sf.get('strong_ciphers_only')}")
print(f"  PQC Support - Supported: {sf.get('pqc_support', {}).get('supported')}")
print(f"  PQC Support - Detection Method: {sf.get('pqc_support', {}).get('detection_method')}")

pqc_algs = sf.get('pqc_support', {}).get('algorithms_detected', [])
if pqc_algs:
    print(f"  PQC Algorithms Detected ({len(pqc_algs)}):")
    for alg in pqc_algs:
        print(f"    - {alg.get('algorithm')} (hybrid: {alg.get('is_hybrid')})")
else:
    print(f"  PQC Algorithms Detected: None")

# Display key exchange details
kx_details = result.get('key_exchange_details', {})
print(f"\nKey Exchange Details:")
print(f"  Algorithm: {kx_details.get('algorithm')}")
print(f"  PQC Detected: {kx_details.get('pqc', {}).get('detected')}")
if kx_details.get('pqc', {}).get('detected'):
    print(f"  PQC Algorithm: {kx_details.get('pqc', {}).get('algorithm')}")
    print(f"  Is Hybrid: {kx_details.get('pqc', {}).get('is_hybrid')}")

print("\n" + "=" * 60)
