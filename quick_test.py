from tls_scanner import scan_tls

try:
    result = scan_tls('sc.com', 443, 15)
    
    # Get first cipher suite to see key exchange
    cs = result.get('cipher_suites', [{}])[0]
    kex = cs.get('key_exchange')
    print(f"First KEX: {kex}")
    
    # Check PQC support
    pqc = result.get('security_features', {}).get('pqc_support', {})
    print(f"PQC Supported: {pqc.get('supported')}")
    print(f"PQC Algs: {pqc.get('algorithms_detected')}")
    
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
