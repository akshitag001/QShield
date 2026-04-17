#!/usr/bin/env python3
import sys
sys.path.insert(0, '.')

from tls_scanner import scan_tls
import json

try:
    result = scan_tls('sc.com', timeout=10)
    if result:
        kx = result.get('key_exchange_details', {})
        print("SCAN RESULTS FOR SC.COM:")
        print("=" * 50)
        print(f"Algorithm: {kx.get('algorithm')}")
        print(f"Normalized: {kx.get('normalized_algorithm')}")
        print(f"Type: {kx.get('type')}")
        print(f"Is Hybrid: {kx.get('is_hybrid')}")
        pqc = kx.get('pqc', {})
        if pqc:
            print(f"PQC Detected: {pqc.get('detected')}")
            print(f"PQC Algorithm: {pqc.get('algorithm')}")
        print(f"Protocol: {result.get('protocol_version')}")
        print(f"Cipher: {result.get('cipher_suite')}")
    else:
        print("No result from scan")
except Exception as e:
    import traceback
    print(f"Error: {e}")
    traceback.print_exc()
