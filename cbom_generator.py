"""
Cryptographic Bill of Materials (CBOM) Generator

This module transforms TLS scan results into a structured CBOM format
suitable for compliance reporting, risk assessment, and crypto-agility planning.
"""

import json
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field, asdict
from enum import Enum


class CryptoAssetType(str, Enum):
    CERTIFICATE = "certificate"
    CIPHER_SUITE = "cipher_suite"
    KEY_EXCHANGE = "key_exchange"
    PROTOCOL = "protocol"
    HASH_ALGORITHM = "hash_algorithm"
    SYMMETRIC_CIPHER = "symmetric_cipher"
    PUBLIC_KEY = "public_key"
    PQC_KEM = "pqc_kem"  # Post-Quantum Key Encapsulation
    PQC_SIGNATURE = "pqc_signature"  # Post-Quantum Digital Signature
    HYBRID_KEY_EXCHANGE = "hybrid_key_exchange"  # Classical + PQC hybrid


class CryptoStrength(str, Enum):
    """Security strength classification based on NIST guidelines."""
    BROKEN = "broken"           # Known broken (MD5, SHA1 for signatures, DES)
    WEAK = "weak"               # Deprecated or weak (3DES, RSA-1024)
    ACCEPTABLE = "acceptable"   # Currently acceptable but aging
    STRONG = "strong"           # Recommended (AES-256, RSA-2048+, ECDSA-256+)
    UNKNOWN = "unknown"


@dataclass
class CryptoAsset:
    """Represents a single cryptographic asset discovered during scanning."""
    asset_id: str
    asset_type: CryptoAssetType
    name: str
    properties: Dict[str, Any] = field(default_factory=dict)
    strength: CryptoStrength = CryptoStrength.UNKNOWN
    quantum_vulnerable: bool = True  # Most classical crypto is quantum-vulnerable
    source_endpoint: str = ""
    notes: List[str] = field(default_factory=list)


@dataclass
class EndpointInventory:
    """Cryptographic inventory for a single endpoint."""
    endpoint: str
    ip_address: str
    port: int
    scan_timestamp: str
    assets: List[CryptoAsset] = field(default_factory=list)
    tls_versions: List[str] = field(default_factory=list)
    forward_secrecy: bool = False
    weak_crypto_detected: bool = False
    pqc_ready: bool = False  # Whether endpoint supports PQC


@dataclass
class CBOM:
    """Complete Cryptographic Bill of Materials."""
    cbom_version: str = "1.0.0"
    generated_at: str = ""
    generator: str = "Q-Shield TLS Scanner"
    endpoints: List[EndpointInventory] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True, default=str)


def _generate_asset_id(asset_type: str, name: str, endpoint: str) -> str:
    """Generate a deterministic unique ID for an asset."""
    data = f"{asset_type}:{name}:{endpoint}"
    return hashlib.sha256(data.encode()).hexdigest()[:16]


def _classify_hash_strength(hash_alg: Optional[str]) -> CryptoStrength:
    """Classify hash algorithm strength."""
    if not hash_alg:
        return CryptoStrength.UNKNOWN
    
    hash_upper = hash_alg.upper()
    
    if "MD5" in hash_upper or "MD4" in hash_upper:
        return CryptoStrength.BROKEN
    if "SHA1" in hash_upper or "SHA-1" in hash_upper:
        return CryptoStrength.WEAK
    if "SHA256" in hash_upper or "SHA-256" in hash_upper:
        return CryptoStrength.STRONG
    if "SHA384" in hash_upper or "SHA-384" in hash_upper:
        return CryptoStrength.STRONG
    if "SHA512" in hash_upper or "SHA-512" in hash_upper:
        return CryptoStrength.STRONG
    
    return CryptoStrength.UNKNOWN


def _classify_cipher_strength(cipher: str) -> CryptoStrength:
    """Classify symmetric cipher strength."""
    cipher_upper = cipher.upper()
    
    # Broken ciphers
    if any(x in cipher_upper for x in ["NULL", "EXPORT", "DES-CBC", "RC2", "RC4"]):
        return CryptoStrength.BROKEN
    
    # Weak ciphers
    if "3DES" in cipher_upper or "TRIPLE-DES" in cipher_upper:
        return CryptoStrength.WEAK
    
    # Strong ciphers
    if "AES" in cipher_upper:
        if "256" in cipher_upper:
            return CryptoStrength.STRONG
        if "128" in cipher_upper:
            return CryptoStrength.ACCEPTABLE
    
    if "CHACHA20" in cipher_upper:
        return CryptoStrength.STRONG
    
    return CryptoStrength.UNKNOWN


def _classify_key_size_strength(algorithm: str, key_size: Optional[int]) -> CryptoStrength:
    """Classify public key strength based on algorithm and size."""
    if not key_size:
        return CryptoStrength.UNKNOWN
    
    alg_upper = algorithm.upper()
    
    if "RSA" in alg_upper or "DSA" in alg_upper:
        if key_size < 1024:
            return CryptoStrength.BROKEN
        if key_size < 2048:
            return CryptoStrength.WEAK
        if key_size >= 2048:
            return CryptoStrength.STRONG
    
    if "EC" in alg_upper or "ECDSA" in alg_upper:
        if key_size < 224:
            return CryptoStrength.WEAK
        if key_size >= 256:
            return CryptoStrength.STRONG
    
    if "ED25519" in alg_upper or "ED448" in alg_upper:
        return CryptoStrength.STRONG
    
    return CryptoStrength.UNKNOWN


def _classify_tls_version_strength(version: str) -> CryptoStrength:
    """Classify TLS protocol version strength."""
    if version in {"SSLv2", "SSLv3"}:
        return CryptoStrength.BROKEN
    if version in {"TLSv1.0", "TLSv1.1"}:
        return CryptoStrength.WEAK
    if version == "TLSv1.2":
        return CryptoStrength.ACCEPTABLE
    if version == "TLSv1.3":
        return CryptoStrength.STRONG
    return CryptoStrength.UNKNOWN


def _is_hybrid_key_exchange(name: str) -> bool:
    """Detect if a key exchange algorithm is a hybrid classical+PQC mode."""
    if not name:
        return False
    name_upper = name.upper()
    
    # Look for both classical and PQC indicators
    classical_indicators = ["X25519", "X448", "P256", "P384", "P521", "SECP256R1", "SECP384R1", "SECP521R1"]
    pqc_indicators = ["MLKEM", "ML-KEM", "KYBER", "DILITHIUM", "MLDSA", "ML-DSA", 
                      "SPHINCS", "SLHDSA", "SLH-DSA", "FALCON", "BIKE", "HQC", "NTRU"]
    
    has_classical = any(ind in name_upper for ind in classical_indicators)
    has_pqc = any(ind in name_upper for ind in pqc_indicators)
    
    return has_classical and has_pqc


def _detect_key_exchange_type(name: str) -> str:
    """
    Classify the key exchange type and return appropriate asset type.
    Returns: 'hybrid_pqc', 'pqc', 'classical', or 'unknown'
    """
    if not name:
        return 'unknown'
    
    name_upper = name.upper()
    pqc_indicators = ["MLKEM", "ML-KEM", "KYBER", "DILITHIUM", "MLDSA", "ML-DSA", 
                      "SPHINCS", "SLHDSA", "SLH-DSA", "FALCON", "BIKE", "HQC", "NTRU"]
    classical_indicators = ["X25519", "X448", "P256", "P384", "P521", "SECP256R1", "SECP384R1", "SECP521R1"]
    
    has_pqc = any(ind in name_upper for ind in pqc_indicators)
    has_classical = any(ind in name_upper for ind in classical_indicators)
    
    if has_classical and has_pqc:
        return 'hybrid_pqc'
    elif has_pqc:
        return 'pqc'
    elif has_classical or name_upper in {"DHE", "ECDHE", "ECDH", "DH", "RSA"}:
        return 'classical'
    else:
        return 'unknown'


def _is_quantum_safe(asset_type: CryptoAssetType, name: str) -> bool:
    """
    Determine if a crypto asset is quantum-safe.
    PQC algorithms are quantum-safe by design.
    Symmetric ciphers and hashes with adequate sizes are quantum-resistant.
    Classical public key crypto (RSA, ECDSA, DH, ECDH) is quantum-vulnerable.
    X25519/X448 alone is vulnerable but often used in hybrid modes.
    """
    # PQC algorithms are quantum-safe
    if asset_type in {CryptoAssetType.PQC_KEM, CryptoAssetType.PQC_SIGNATURE}:
        return True
    
    # Hybrid is quantum-safe (provides quantum resistance)
    if asset_type == CryptoAssetType.HYBRID_KEY_EXCHANGE:
        return True
    
    if asset_type == CryptoAssetType.KEY_EXCHANGE:
        name_upper = name.upper()
        # Check for PQC indicators - these make the KEX quantum safe
        pqc_indicators = ["MLKEM", "ML-KEM", "KYBER", "DILITHIUM", "MLDSA", "ML-DSA", 
                          "SPHINCS", "SLHDSA", "SLH-DSA", "FALCON", "BIKE", "HQC", "NTRU"]
        if any(ind in name_upper for ind in pqc_indicators):
            return True
        # X25519 alone is vulnerable, but with PQC it's hybrid and safe
        if "X25519" in name_upper and any(ind in name_upper for ind in pqc_indicators):
            return True
    
    if asset_type == CryptoAssetType.SYMMETRIC_CIPHER:
        # Symmetric ciphers with adequate key size are quantum-resistant
        # (Grover's algorithm halves effective key length)
        if "AES-256" in name.upper() or "CHACHA20" in name.upper():
            return True
    
    if asset_type == CryptoAssetType.HASH_ALGORITHM:
        # SHA-256+ provides adequate quantum resistance
        if any(x in name.upper() for x in ["SHA-256", "SHA256", "SHA-384", "SHA384", "SHA-512", "SHA512"]):
            return True
    
    # Check name for PQC indicators
    name_upper = name.upper()
    pqc_indicators = ["KYBER", "MLKEM", "ML-KEM", "DILITHIUM", "MLDSA", "ML-DSA", 
                      "SPHINCS", "SLHDSA", "SLH-DSA", "FALCON", "BIKE", "HQC", "NTRU"]
    if any(ind in name_upper for ind in pqc_indicators):
        return True
    
    # All current public key crypto (RSA, ECDSA, DH, ECDH) is quantum-vulnerable
    return False


def scan_result_to_cbom(scan_result: Dict[str, Any], endpoint_label: Optional[str] = None) -> EndpointInventory:
    """Convert a single TLS scan result to an EndpointInventory."""
    
    endpoint = endpoint_label or f"{scan_result.get('host', 'unknown')}:{scan_result.get('port', 443)}"
    
    inventory = EndpointInventory(
        endpoint=endpoint,
        ip_address=scan_result.get("ip_address", ""),
        port=scan_result.get("port", 443),
        scan_timestamp=datetime.now(timezone.utc).isoformat(),
        tls_versions=scan_result.get("tls_versions_supported", []),
        forward_secrecy=scan_result.get("security_features", {}).get("forward_secrecy", False),
        weak_crypto_detected=scan_result.get("security_features", {}).get("weak_ciphers_detected", False),
    )
    
    # Add TLS protocol version assets
    for version in inventory.tls_versions:
        strength = _classify_tls_version_strength(version)
        asset = CryptoAsset(
            asset_id=_generate_asset_id("protocol", version, endpoint),
            asset_type=CryptoAssetType.PROTOCOL,
            name=version,
            properties={"version": version},
            strength=strength,
            quantum_vulnerable=False,  # Protocol versions themselves aren't quantum-vulnerable
            source_endpoint=endpoint,
        )
        if strength in {CryptoStrength.BROKEN, CryptoStrength.WEAK}:
            asset.notes.append(f"Deprecated protocol version: {version}")
            inventory.weak_crypto_detected = True
        inventory.assets.append(asset)
    
    # Check cipher suites for hybrid PQC support
    has_hybrid_pqc = False
    for cs in scan_result.get("cipher_suites", []):
        kx = cs.get("key_exchange", "")
        if _is_hybrid_key_exchange(kx):
            has_hybrid_pqc = True
            inventory.pqc_ready = True
            break
    
    # Add cipher suite assets
    for cs in scan_result.get("cipher_suites", []):
        cipher_name = cs.get("cipher_suite", "")
        
        # Main cipher suite asset
        cipher_strength = _classify_cipher_strength(cs.get("encryption", cipher_name))
        asset = CryptoAsset(
            asset_id=_generate_asset_id("cipher_suite", cipher_name, endpoint),
            asset_type=CryptoAssetType.CIPHER_SUITE,
            name=cipher_name,
            properties={
                "tls_version": cs.get("tls_version"),
                "key_exchange": cs.get("key_exchange"),
                "authentication": cs.get("authentication"),
                "encryption": cs.get("encryption"),
                "hash": cs.get("hash"),
            },
            strength=cipher_strength,
            quantum_vulnerable=True,  # Cipher suites with key exchange are quantum-vulnerable
            source_endpoint=endpoint,
        )
        
        if cipher_strength in {CryptoStrength.BROKEN, CryptoStrength.WEAK}:
            asset.notes.append("Weak or deprecated cipher suite")
            inventory.weak_crypto_detected = True
        
        inventory.assets.append(asset)
        
        # Add key exchange as separate asset
        kx = cs.get("key_exchange")
        if kx:
            # Detect if this is a hybrid PQC key exchange
            kx_type = _detect_key_exchange_type(kx)
            is_hybrid = _is_hybrid_key_exchange(kx)
            is_pqc = _is_quantum_safe(CryptoAssetType.KEY_EXCHANGE, kx)
            
            if is_hybrid:
                asset_type = CryptoAssetType.HYBRID_KEY_EXCHANGE
                strength = CryptoStrength.STRONG
                notes = [f"Hybrid key exchange: {kx}"]
            elif kx_type == 'pqc':
                asset_type = CryptoAssetType.PQC_KEM
                strength = CryptoStrength.STRONG
                notes = [f"Post-Quantum CryptoGraphic key exchange: {kx}"]
            else:
                asset_type = CryptoAssetType.KEY_EXCHANGE
                strength = CryptoStrength.STRONG if kx in {"ECDHE", "DHE", "X25519"} else CryptoStrength.ACCEPTABLE
                notes = []
            
            kx_asset = CryptoAsset(
                asset_id=_generate_asset_id("key_exchange", kx, endpoint),
                asset_type=asset_type,
                name=kx,
                properties={"algorithm": kx, "type": kx_type, "is_hybrid": is_hybrid},
                strength=strength,
                quantum_vulnerable=not is_pqc,
                source_endpoint=endpoint,
                notes=notes,
            )
            inventory.assets.append(kx_asset)
        
        # Add hash algorithm as separate asset
        hash_alg = cs.get("hash")
        if hash_alg:
            hash_strength = _classify_hash_strength(hash_alg)
            hash_asset = CryptoAsset(
                asset_id=_generate_asset_id("hash", hash_alg, endpoint),
                asset_type=CryptoAssetType.HASH_ALGORITHM,
                name=hash_alg,
                properties={"algorithm": hash_alg},
                strength=hash_strength,
                quantum_vulnerable=not _is_quantum_safe(CryptoAssetType.HASH_ALGORITHM, hash_alg),
                source_endpoint=endpoint,
            )
            inventory.assets.append(hash_asset)
    
    # Add certificate asset
    cert = scan_result.get("certificate", {})
    if cert.get("subject"):
        pub_key_alg = cert.get("public_key_algorithm", "")
        pub_key_size = cert.get("public_key_size")
        sig_alg = cert.get("signature_algorithm", "")
        
        cert_strength = _classify_key_size_strength(pub_key_alg, pub_key_size)
        
        cert_asset = CryptoAsset(
            asset_id=_generate_asset_id("certificate", cert.get("subject", ""), endpoint),
            asset_type=CryptoAssetType.CERTIFICATE,
            name=cert.get("subject", ""),
            properties={
                "subject": cert.get("subject"),
                "issuer": cert.get("issuer"),
                "valid_from": cert.get("valid_from"),
                "valid_to": cert.get("valid_to"),
                "signature_algorithm": sig_alg,
                "public_key_algorithm": pub_key_alg,
                "public_key_size": pub_key_size,
                "chain_length": cert.get("chain_length"),
                "san": cert.get("san", []),
                "serial_number": cert.get("serial_number"),
            },
            strength=cert_strength,
            quantum_vulnerable=True,  # All current certificate crypto is quantum-vulnerable
            source_endpoint=endpoint,
        )
        
        if cert_strength in {CryptoStrength.BROKEN, CryptoStrength.WEAK}:
            cert_asset.notes.append("Weak certificate key size")
            inventory.weak_crypto_detected = True
        
        inventory.assets.append(cert_asset)
        
        # Add public key as separate asset
        if pub_key_alg:
            pk_asset = CryptoAsset(
                asset_id=_generate_asset_id("public_key", f"{pub_key_alg}-{pub_key_size}", endpoint),
                asset_type=CryptoAssetType.PUBLIC_KEY,
                name=f"{pub_key_alg} {pub_key_size}-bit",
                properties={
                    "algorithm": pub_key_alg,
                    "key_size": pub_key_size,
                },
                strength=cert_strength,
                quantum_vulnerable=True,
                source_endpoint=endpoint,
            )
            inventory.assets.append(pk_asset)
    
    # Add PQC assets from security_features.pqc_support
    pqc_support = scan_result.get("security_features", {}).get("pqc_support", {})
    if pqc_support.get("supported"):
        inventory.pqc_ready = True
        
        for pqc_alg in pqc_support.get("algorithms_detected", []):
            alg_name = pqc_alg.get("algorithm", "Unknown PQC")
            alg_type = pqc_alg.get("type", "unknown")
            is_hybrid = pqc_alg.get("is_hybrid", False)
            
            # Determine asset type
            if is_hybrid:
                asset_type = CryptoAssetType.HYBRID_KEY_EXCHANGE
            elif alg_type == "kem" or "kem" in alg_type:
                asset_type = CryptoAssetType.PQC_KEM
            elif alg_type == "signature":
                asset_type = CryptoAssetType.PQC_SIGNATURE
            else:
                asset_type = CryptoAssetType.PQC_KEM
            
            pqc_asset = CryptoAsset(
                asset_id=_generate_asset_id("pqc", alg_name, endpoint),
                asset_type=asset_type,
                name=alg_name,
                properties={
                    "algorithm": alg_name,
                    "raw_name": pqc_alg.get("raw_name"),
                    "type": alg_type,
                    "nist_security_level": pqc_alg.get("nist_security_level"),
                    "is_hybrid": is_hybrid,
                    "classical_component": pqc_alg.get("classical_component"),
                },
                strength=CryptoStrength.STRONG,
                quantum_vulnerable=False,  # PQC is quantum-safe!
                source_endpoint=endpoint,
            )
            pqc_asset.notes.append("Post-Quantum Cryptography - Quantum Safe")
            if is_hybrid:
                pqc_asset.notes.append(f"Hybrid mode with classical {pqc_alg.get('classical_component', 'component')}")
            
            inventory.assets.append(pqc_asset)
    
    # Also check key_exchange_details for PQC
    kx_details = scan_result.get("key_exchange_details", {})
    kx_pqc = kx_details.get("pqc")
    if kx_pqc and kx_pqc.get("detected"):
        inventory.pqc_ready = True
        
        alg_name = kx_pqc.get("algorithm", "Unknown PQC")
        is_hybrid = kx_pqc.get("is_hybrid", False)
        alg_type = kx_pqc.get("type", "kem")
        
        if is_hybrid:
            asset_type = CryptoAssetType.HYBRID_KEY_EXCHANGE
        elif "signature" in alg_type:
            asset_type = CryptoAssetType.PQC_SIGNATURE
        else:
            asset_type = CryptoAssetType.PQC_KEM
        
        pqc_kx_asset = CryptoAsset(
            asset_id=_generate_asset_id("pqc_kx", alg_name, endpoint),
            asset_type=asset_type,
            name=alg_name,
            properties={
                "algorithm": alg_name,
                "raw_name": kx_pqc.get("raw_name"),
                "nist_security_level": kx_pqc.get("nist_security_level"),
                "is_hybrid": is_hybrid,
                "classical_component": kx_pqc.get("classical_component"),
            },
            strength=CryptoStrength.STRONG,
            quantum_vulnerable=False,
            source_endpoint=endpoint,
        )
        pqc_kx_asset.notes.append("Negotiated PQC key exchange")
        inventory.assets.append(pqc_kx_asset)
    
    # Deduplicate assets by asset_id
    seen_ids = set()
    unique_assets = []
    for asset in inventory.assets:
        if asset.asset_id not in seen_ids:
            seen_ids.add(asset.asset_id)
            unique_assets.append(asset)
    inventory.assets = unique_assets
    
    return inventory


def generate_cbom(scan_results: List[Dict[str, Any]]) -> CBOM:
    """Generate a complete CBOM from multiple scan results."""
    
    cbom = CBOM(
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
    
    # Process each scan result
    for result in scan_results:
        inventory = scan_result_to_cbom(result)
        cbom.endpoints.append(inventory)
    
    # Generate summary statistics
    all_assets = []
    for endpoint in cbom.endpoints:
        all_assets.extend(endpoint.assets)
    
    # Count by type
    type_counts = {}
    for asset in all_assets:
        type_name = asset.asset_type.value if isinstance(asset.asset_type, CryptoAssetType) else asset.asset_type
        type_counts[type_name] = type_counts.get(type_name, 0) + 1
    
    # Count by strength
    strength_counts = {}
    for asset in all_assets:
        strength_name = asset.strength.value if isinstance(asset.strength, CryptoStrength) else asset.strength
        strength_counts[strength_name] = strength_counts.get(strength_name, 0) + 1
    
    # Count quantum-vulnerable assets
    quantum_vulnerable_count = sum(1 for a in all_assets if a.quantum_vulnerable)
    quantum_safe_count = sum(1 for a in all_assets if not a.quantum_vulnerable)
    
    # Count PQC assets
    pqc_asset_types = {CryptoAssetType.PQC_KEM, CryptoAssetType.PQC_SIGNATURE, CryptoAssetType.HYBRID_KEY_EXCHANGE}
    pqc_assets_count = sum(1 for a in all_assets if a.asset_type in pqc_asset_types)
    
    cbom.summary = {
        "total_endpoints": len(cbom.endpoints),
        "total_assets": len(all_assets),
        "assets_by_type": type_counts,
        "assets_by_strength": strength_counts,
        "quantum_vulnerable_assets": quantum_vulnerable_count,
        "quantum_safe_assets": quantum_safe_count,
        "pqc_assets": pqc_assets_count,
        "endpoints_with_weak_crypto": sum(1 for e in cbom.endpoints if e.weak_crypto_detected),
        "endpoints_with_forward_secrecy": sum(1 for e in cbom.endpoints if e.forward_secrecy),
        "endpoints_pqc_ready": sum(1 for e in cbom.endpoints if e.pqc_ready),
    }
    
    return cbom


if __name__ == "__main__":
    # Example usage with a mock scan result
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python cbom_generator.py <scan_result.json>")
        print("Or pipe scan results: python tls_scanner.py example.com | python cbom_generator.py -")
        sys.exit(1)
    
    if sys.argv[1] == "-":
        # Read from stdin
        data = json.load(sys.stdin)
    else:
        # Read from file
        with open(sys.argv[1]) as f:
            data = json.load(f)
    
    # Handle single result or list of results
    if isinstance(data, list):
        scan_results = data
    else:
        scan_results = [data]
    
    cbom = generate_cbom(scan_results)
    print(cbom.to_json())
