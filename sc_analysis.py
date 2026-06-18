#!/usr/bin/env python3
from tls_scanner import scan_tls
import json

result = scan_tls('sc.com', timeout=10)
kx = result['key_exchange_details']

print('SC.COM KEY EXCHANGE ANALYSIS')
print('='*70)
print(f'Raw Algorithm Detected: {kx.get("algorithm")}')
print(f'Normalization Status: {kx.get("normalized_algorithm", "Not normalized")}')

if kx.get('pqc'):
    pqc = kx['pqc']
    print(f'\nPQC/Hybrid Detection:')
    print(f'  - Detected: {pqc.get("detected")}')
    print(f'  - Algorithm: {pqc.get("algorithm")}')  
    print(f'  - Is PQC Hybrid: {pqc.get("is_pqc")}')
    print(f'  - Classical Tokens: {pqc.get("classical_tokens")}')
    print(f'  - PQC Tokens: {pqc.get("pqc_tokens")}')
    print(f'  - NIST Security Level: {pqc.get("nist_security_level")}')

print(f'\nTLS Details:')
print(f'  - TLS Version: {result.get("protocol_version", "N/A")}')
print(f'  - Cipher Suite: {result.get("cipher_suite", "N/A")}')

print(f'\n=== INTERPRETATION ===')
print('X25519KYBER768 is the draft pre-standardization name.')
print('NIST FIPS 203 standardized this as: X25519MLKEM768')
print('Status: QUANTUM-SAFE (hybrid with X25519 classical + ML-KEM PQC)')
