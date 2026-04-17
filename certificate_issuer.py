"""
QShield Certificate Issuer
Generates HMAC-signed PQC readiness certificates.
"""
import json
import hmac
import hashlib
from datetime import datetime, timezone

SECRET_KEY = b"QSHIELD_MOCK_SECRET_2026_DO_NOT_DEPLOY"

def issue_certificate(endpoint: str, pqc_ready: bool, weak_crypto: bool) -> dict:
    if weak_crypto:
        status = "QUANTUM_VULNERABLE"
    elif pqc_ready:
        status = "PQC_READY" 
    else:
        status = "QUANTUM_VULNERABLE"
        
    cert = {
        "endpoint": endpoint,
        "status": status,
        "certified_at": datetime.now(timezone.utc).isoformat(),
        "issuer": "QShield Certificate Authority",
        "valid_until": "2027-01-01T00:00:00Z"
    }
    
    cert_str = json.dumps(cert, sort_keys=True)
    signature = hmac.new(SECRET_KEY, cert_str.encode(), hashlib.sha256).hexdigest()
    
    return {
        "certificate": cert,
        "signature": signature
    }
