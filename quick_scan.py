#!/usr/bin/env python3
from tls_scanner import scan_tls

print("Scanning sc.com...\n")
result = scan_tls('sc.com', timeout=10)

if result and result.get('key_exchange_details'):
    kx = result['key_exchange_details']
    print("=== SC.COM KEY EXCHANGE ===\n")
    print(f"Algorithm: {kx.get('algorithm', 'N/A')}")
    print(f"Normalized (NIST Standard): {kx.get('normalized_algorithm', 'N/A')}")
    print(f"Type: {kx.get('type', 'N/A')}")
    print(f"Is Hybrid: {kx.get('is_hybrid', False)}")
    
    if kx.get('pqc'):
        print(f"\nPQC Detection:")
        print(f"  - Detected: {kx['pqc'].get('detected', False)}")
        print(f"  - Algorithm: {kx['pqc'].get('algorithm', 'N/A')}")
        print(f"  - Is Post-Quantum Safe: {kx['pqc'].get('is_pqc', False)}")
        print(f"  - Type: {kx['pqc'].get('type', 'N/A')}")
    
    print(f"\nTLS Version: {result.get('protocol_version', 'N/A')}")
    print(f"Cipher Suite: {result.get('cipher_suite', 'N/A')}")
else:
    print("Could not retrieve key exchange details")
