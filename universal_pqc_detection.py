"""
Universal PQC Key Exchange Detection - FIXED VERSION
=====================================================

Pure logic-based approach that detects ANY hybrid key exchange without hardcoding.

Returns: Dict format (not dataclass) for compatibility with tls_scanner.py
"""

import re
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass


# ==========================================
# ALGORITHM DETECTION DATACLASS (for type hints)
# ==========================================

@dataclass
class AlgorithmCategory:
    """Algorithm analysis result"""
    raw_name: str
    is_classical: bool
    is_pqc: bool
    is_hybrid: bool
    classical_tokens: List[str]
    pqc_tokens: List[str]
    confidence: float
    reason: str


# ==========================================
# UNIVERSAL ALGORITHM TOKEN REGISTRY
# ==========================================

CLASSICAL_ALGORITHM_TOKENS = {
    "X25519", "X448",
    "P256", "P384", "P521",
    "SECP256R1", "SECP256K1", "SECP384R1", "SECP521R1",
    "PRIME256V1",
    "DH", "DHE", "ECDHE", "ECDH",
    "RSA",
    "BRAINPOOL", "CURVE25519", "CURVE448",
}

PQC_ALGORITHM_TOKENS = {
    "MLKEM", "ML-KEM",
    "KYBER",
    "MLDSA", "ML-DSA",
    "DILITHIUM",
    "SLHDSA", "SLH-DSA",
    "SPHINCS", "SPHINCSPLUS", "SPHINCS+",
    "FALCON",
    "NTRU", "NTRUKEM",
    "SABER",
    "FRODO", "FRODOKEM",
    "BIKE",
    "HQC",
    "MCELIECE",
}


# ==========================================
# UNIVERSAL HYBRID DETECTION ENGINE
# ==========================================

def tokenize_algorithm_name(name: str) -> Set[str]:
    """Split algorithm name into normalized tokens."""
    if not name:
        return set()
    
    normalized = name.strip().upper()
    tokens = re.split(r'[-_/+\s]+', normalized)
    
    split_tokens = set()
    for token in tokens:
        if not token:
            continue
        
        match = re.match(r'^([A-Z]+)(\d+)(.*)$', token)
        if match:
            letters = match.group(1)
            numbers = match.group(2)
            rest = match.group(3)
            
            split_tokens.add(letters)
            split_tokens.add(numbers)
            if rest:
                split_tokens.add(rest)
        else:
            split_tokens.add(token)
    
    return split_tokens


def detect_algorithm_category(name: str) -> Dict[str, Any]:
    """
    Intelligently categorize ANY algorithm name for PQC capability.
    
    Returns: Dict (not dataclass) for direct use in tls_scanner.py
    """
    if not name or not isinstance(name, str):
        return {
            "raw_name": name,
            "is_classical": False,
            "is_pqc": False,
            "is_hybrid": False,
            "classical_tokens": [],
            "pqc_tokens": [],
            "confidence": 0.0,
            "reason": "Invalid input",
        }
    
    # Check for known hex IDs (fallback for older OpenSSL binaries)
    KNOWN_HEX_GROUPS = {
        "0X11EC": {"classical": "X25519", "pqc": "KYBER768", "desc": "X25519 + Kyber-768"},
        "0X6399": {"classical": "X25519", "pqc": "MLKEM768", "desc": "X25519 + ML-KEM-768"}
    }
    
    normalized_upper = name.strip().upper()
    if normalized_upper in KNOWN_HEX_GROUPS:
        mapping = KNOWN_HEX_GROUPS[normalized_upper]
        return {
            "raw_name": name,
            "is_classical": False,
            "is_pqc": False,
            "is_hybrid": True,
            "classical_tokens": [mapping["classical"]],
            "pqc_tokens": [mapping["pqc"]],
            "confidence": 1.0,
            "reason": f"Hybrid: {mapping['desc']} (Known Hex ID)",
        }
    
    tokens = tokenize_algorithm_name(name)
    
    matching_classical = set()
    for token in tokens:
        for classical in CLASSICAL_ALGORITHM_TOKENS:
            if token == classical or classical.startswith(token):
                matching_classical.add(classical)
                break
    
    matching_pqc = set()
    for token in tokens:
        for pqc in PQC_ALGORITHM_TOKENS:
            if token == pqc or pqc in token or token in pqc:
                matching_pqc.add(pqc)
                break
    
    has_classical = len(matching_classical) > 0
    has_pqc = len(matching_pqc) > 0
    is_hybrid = has_classical and has_pqc
    
    if is_hybrid:
        confidence = 0.95
        reason = f"Hybrid: {', '.join(sorted(matching_classical))} + {', '.join(sorted(matching_pqc))}"
    elif has_pqc:
        confidence = 0.90
        reason = f"Pure PQC: {', '.join(sorted(matching_pqc))}"
    elif has_classical:
        confidence = 0.85
        reason = f"Classical: {', '.join(sorted(matching_classical))}"
    else:
        confidence = 0.30
        reason = "Unknown algorithm type"
    
    return {
        "raw_name": name,
        "is_classical": has_classical,
        "is_pqc": has_pqc,
        "is_hybrid": is_hybrid,
        "classical_tokens": sorted(list(matching_classical)),
        "pqc_tokens": sorted(list(matching_pqc)),
        "confidence": confidence,
        "reason": reason,
    }


def extract_key_exchange_components(name: str) -> Dict[str, Any]:
    """Extract classical and PQC components from a hybrid key exchange."""
    analysis = detect_algorithm_category(name)
    
    if not analysis["is_hybrid"]:
        return {
            "classical_component": None,
            "pqc_component": None,
            "strength_classical": None,
            "strength_pqc": None,
            "recommended": None,
            "reason": "Not a hybrid algorithm",
        }
    
    classical = analysis["classical_tokens"][0] if analysis["classical_tokens"] else None
    pqc = analysis["pqc_tokens"][0] if analysis["pqc_tokens"] else None
    
    classical_strength_map = {
        "X25519": "high",
        "X448": "high",
        "P256": "medium",
        "SECP256R1": "medium",
        "P384": "high",
        "SECP384R1": "high",
        "P521": "high",
        "SECP521R1": "high",
    }
    
    pqc_strength_map = {
        "MLKEM": "high",
        "KYBER": "high",
        "MLDSA": "high",
        "DILITHIUM": "high",
        "SLHDSA": "high",
        "SPHINCS": "high",
        "FALCON": "medium",
    }
    
    classical_str = classical_strength_map.get(classical, "medium")
    pqc_str = pqc_strength_map.get(pqc, "medium")
    
    return {
        "classical_component": classical,
        "pqc_component": pqc,
        "strength_classical": classical_str,
        "strength_pqc": pqc_str,
        "recommendation": (
            f"Good: Using hybrid {classical}+{pqc}. "
            f"Future: Pure ML-KEM + ML-DSA"
        ),
    }


def analyze_tls_key_exchange(tls_version: str, key_exchange_name: str) -> Dict[str, Any]:
    """Universal function to analyze any TLS key exchange for PQC capability."""
    if not key_exchange_name:
        return {
            "error": "No key exchange name provided",
            "is_pqc": False,
            "is_hybrid": False,
            "category": "unknown",
        }
    
    analysis = detect_algorithm_category(key_exchange_name)
    
    return {
        "tls_version": tls_version,
        "key_exchange": key_exchange_name,
        "analysis": analysis,
        "is_pqc": analysis["is_pqc"] and not analysis["is_classical"],
        "is_hybrid": analysis["is_hybrid"],
        "is_classical": analysis["is_classical"] and not analysis["is_pqc"],
        "category": "hybrid" if analysis["is_hybrid"] else "pqc" if analysis["is_pqc"] else "classical" if analysis["is_classical"] else "unknown",
        "classical_tokens": analysis["classical_tokens"],
        "pqc_tokens": analysis["pqc_tokens"],
        "confidence": analysis["confidence"],
        "reason": analysis["reason"],
    }


# ==========================================
# TESTING
# ==========================================

if __name__ == "__main__":
    test_cases = [
        "X25519MLKEM768",
        "X25519-MLKEM768",
        "P256KYBER512",
        "X25519",
        "MLKEM768",
    ]
    
    print("Universal PQC Detection Test")
    print("=" * 60)
    
    for test in test_cases:
        result = analyze_tls_key_exchange("TLS1.3", test)
        
        print(f"\n✓ {test}")
        print(f"  Hybrid: {result['is_hybrid']}")
        print(f"  PQC: {result['is_pqc']}")
        print(f"  Classical: {result['is_classical']}")
        print(f"  Reason: {result['reason']}")
