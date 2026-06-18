import json
import hmac
import hashlib
from datetime import datetime, timezone, timedelta

SECRET_KEY = b"QSHIELD_MOCK_SECRET_2026_DO_NOT_DEPLOY"

def issue_certificate(endpoint: str, pqc_ready: bool, weak_crypto: bool, algorithms: list = None) -> dict:
    # Map compliance status labels based on the problem statement
    if weak_crypto:
        status = "Quantum-Vulnerable"
    elif pqc_ready:
        # Check if it implements NIST-standardized Post-Quantum Algorithms (ML-KEM/Kyber, ML-DSA/Dilithium)
        nist_pqc = ["KYBER", "ML-KEM", "MLKEM", "DILITHIUM", "ML-DSA", "MLDSA"]
        has_nist = False
        if algorithms:
            for alg in algorithms:
                alg_upper = alg.upper()
                if any(nist in alg_upper for nist in nist_pqc):
                    has_nist = True
                    break
        
        if has_nist:
            status = "Post Quantum Cryptography (PQC) Ready"
        else:
            status = "Quantum-Safe"
    else:
        status = "Quantum-Vulnerable"
        
    cert = {
        "endpoint": endpoint,
        "status": status,
        "certified_at": datetime.now(timezone.utc).isoformat(),
        "issuer": "QShield Certificate Authority",
        "valid_until": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        "slogan": "Quantum-Ready Cybersecurity for Future-Safe Banking",
        "algorithms": algorithms or []
    }
    
    cert_str = json.dumps(cert, sort_keys=True)
    signature = hmac.new(SECRET_KEY, cert_str.encode(), hashlib.sha256).hexdigest()
    
    return {
        "certificate": cert,
        "signature": signature
    }

