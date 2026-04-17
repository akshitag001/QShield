import re
import logging

# --- PQC/Hybrid Detection Strict Matching (copied from tls_scanner.py) ---
PQC_ALGORITHM_INDICATORS = {
    "KYBER", "ML-KEM", "MLKEM",
    "DILITHIUM", "ML-DSA", "MLDSA",
    "FALCON", "SPHINCS", "SPHINCSPLUS",
    "NTRU", "SABER", "FRODO", "FRODOKEM",
    "BIKE", "HQC", "CLASSIC-MCELIECE", "MCELIECE"
}
HYBRID_FULL_NAMES = {
    "X25519MLKEM768", "X25519KYBER768",
    "P256MLKEM768", "P384MLKEM1024",
    "SECP256R1MLKEM768", "P256KYBER512", "P384KYBER768",
}
# Keep HYBRID_INDICATORS as alias for backward compat
HYBRID_INDICATORS = HYBRID_FULL_NAMES
logger = logging.getLogger("qshield.cbom.pqc")
logger.setLevel(logging.DEBUG)

def normalize_name(name: str) -> str:
    return name.strip().replace("'", "").replace('"', "").replace("(", "").replace(")", "")

def is_pqc_algorithm(name: str, pqc_indicators: set) -> bool:
    name_upper = normalize_name(name).upper()
    tokens = re.split(r'[-_\s/]+', name_upper)
    return any(token in pqc_indicators for token in tokens)

def is_hybrid_algorithm(name: str) -> bool:
    """Detect hybrid algorithms with various format variations (x25519-mlkem, X25519MLKEM, etc.)."""
    if not name:
        return False
    
    name_upper = normalize_name(name).upper()
    
    # Try exact match first (without dashes)
    if name_upper in HYBRID_FULL_NAMES:
        return True
    
    # Normalize dashes/underscores and try again
    name_no_separators = re.sub(r'[-_\s/]+', '', name_upper)
    if name_no_separators in HYBRID_FULL_NAMES:
        return True
    
    # Also check if it contains both classical and PQC tokens
    classical_tokens = {"X25519", "X448", "P256", "P384", "P521", "SECP256R1", "SECP384R1", "SECP521R1", "DHE", "ECDHE", "ECDH", "DH"}
    pqc_tokens = {"MLKEM", "ML-KEM", "KYBER", "ML-DSA", "MLDSA", "DILITHIUM", "FALCON", "SPHINCS"}
    
    tokens = set(re.split(r'[-_\s/]+', name_upper))
    has_classical = any(token in classical_tokens for token in tokens)
    has_pqc = any(token in pqc_tokens for token in tokens)
    
    return has_classical and has_pqc
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
from scoring_engine import calculate_qars
from certificate_issuer import issue_certificate


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
    qars_data: Dict[str, Any] = field(default_factory=dict)
    pqc_certificate: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CBOM:
    """Complete Cryptographic Bill of Materials."""
    cbom_version: str = "1.0.0"
    generated_at: str = ""
    generator: str = "Q-Shield TLS Scanner"
    endpoints: List[EndpointInventory] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        # Convert enums to strings
        for endpoint in result.get("endpoints", []):
            for asset in endpoint.get("assets", []):
                if isinstance(asset.get("asset_type"), dict) and "value" in asset["asset_type"]:
                    asset["asset_type"] = asset["asset_type"]["value"]
                elif not isinstance(asset.get("asset_type"), str):
                    asset["asset_type"] = str(asset.get("asset_type", "unknown"))
                if isinstance(asset.get("strength"), dict) and "value" in asset["strength"]:
                    asset["strength"] = asset["strength"]["value"]
                elif not isinstance(asset.get("strength"), str):
                    asset["strength"] = str(asset.get("strength", "unknown"))
        return result

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
    if not name:
        return False
    return is_hybrid_algorithm(name)


def _detect_key_exchange_type(name: str) -> str:
    """
    Classify the key exchange type and return appropriate asset type.
    Returns: 'hybrid_pqc', 'pqc', 'classical', or 'unknown'
    """
    if not name:
        return 'unknown'
    name_upper = normalize_name(name).upper()
    tokens = re.split(r'[-_\s/]+', name_upper)
    has_pqc = any(token in PQC_ALGORITHM_INDICATORS for token in tokens)
    has_hybrid = name_upper in HYBRID_FULL_NAMES
    classical_tokens = {"X25519", "X448", "P256", "P384", "P521", "SECP256R1", "SECP384R1", "SECP521R1", "DHE", "ECDHE", "ECDH", "DH", "RSA"}
    has_classical = any(token in classical_tokens for token in tokens)
    
    # DEBUG logging
    logger.debug(f"Key Exchange Detection: name={name}, normalized={name_upper}, has_hybrid={has_hybrid}, has_pqc={has_pqc}, has_classical={has_classical}")
    
    if has_hybrid:
        logger.debug(f"  -> Result: hybrid_pqc")
        return 'hybrid_pqc'
    elif has_pqc:
        logger.debug(f"  -> Result: pqc")
        return 'pqc'
    elif has_classical:
        logger.debug(f"  -> Result: classical")
        return 'classical'
    else:
        logger.debug(f"  -> Result: unknown")
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
        if is_pqc_algorithm(name, PQC_ALGORITHM_INDICATORS) or is_hybrid_algorithm(name):
            return True
    if asset_type == CryptoAssetType.SYMMETRIC_CIPHER:
        if "AES-256" in name.upper() or "CHACHA20" in name.upper():
            return True
    if asset_type == CryptoAssetType.HASH_ALGORITHM:
        if any(x in name.upper() for x in ["SHA-256", "SHA256", "SHA-384", "SHA384", "SHA-512", "SHA512"]):
            return True
    if is_pqc_algorithm(name, PQC_ALGORITHM_INDICATORS):
        return True
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
    
    # Check cipher suites for hybrid PQC support (strict)
    has_hybrid_pqc = False
    for cs in scan_result.get("cipher_suites", []):
        kx = cs.get("key_exchange", "")
        if is_hybrid_algorithm(kx):
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
    pqc_algorithms = pqc_support.get("algorithms_detected", [])
    if pqc_algorithms:
        inventory.pqc_ready = True
        for pqc_alg in pqc_algorithms:
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
                "normalized_algorithm": kx_pqc.get("normalized_algorithm"),  # NIST FIPS 203 standard name
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
    
    # VPN and SSH assets
    vpn = scan_result.get("vpn_gateway")
    if vpn and vpn.get("detected"):
        vpn_asset = CryptoAsset(
            asset_id=_generate_asset_id("vpn", vpn.get("vpn_type"), endpoint),
            asset_type=CryptoAssetType.PROTOCOL,
            name=f"VPN: {vpn.get('vpn_type')}",
            properties={"endpoint": vpn.get("endpoint")},
            strength=CryptoStrength.UNKNOWN,
            quantum_vulnerable=True,
            source_endpoint=endpoint,
            notes=["Exposed VPN Gateway Detected"]
        )
        inventory.assets.append(vpn_asset)
        
    ssh = scan_result.get("ssh_endpoint")
    if ssh and ssh.get("detected"):
        ssh_kex = ssh.get("kex_algorithms", [])
        ssh_asset = CryptoAsset(
            asset_id=_generate_asset_id("ssh", "SSH Daemon", endpoint),
            asset_type=CryptoAssetType.PROTOCOL,
            name=f"SSH: {ssh.get('banner')}",
            properties={
                "kex_algorithms": ssh_kex,
                "ciphers": ssh.get("ciphers", [])
            },
            strength=CryptoStrength.STRONG if any(x in ssh_kex for x in ["curve25519", "sntrup761x25519-sha512@openssh.com"]) else CryptoStrength.ACCEPTABLE,
            quantum_vulnerable=not any("sntrup" in x for x in ssh_kex),
            source_endpoint=endpoint,
            notes=["Exposed SSH Service Detected"]
        )
        inventory.assets.append(ssh_asset)

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
    
    # Calculate Organization QARS
    cbom.summary["qars_data"] = calculate_qars(cbom.summary)
    
    # Issue certificates per endpoint
    for endpoint in cbom.endpoints:
        endpoint.qars_data = calculate_qars({
            "quantum_vulnerable_assets": sum(1 for a in endpoint.assets if a.quantum_vulnerable),
            "total_assets": len(endpoint.assets),
            "endpoints_with_weak_crypto": 1 if endpoint.weak_crypto_detected else 0
        })
        endpoint.pqc_certificate = issue_certificate(endpoint.endpoint, endpoint.pqc_ready, endpoint.weak_crypto_detected)
    
    return cbom



# === CBOM ENHANCEMENTS FOR IBM/CYCLONEDX ===
def cbom_to_cyclonedx_json(cbom: CBOM) -> Dict[str, Any]:
    """
    Convert internal CBOM to CycloneDX/IBM CBOM-compliant JSON structure.
    This includes 'components', 'dependencies', and all required cryptoProperties fields.
    """
    components = []
    dependencies = []
    for endpoint in cbom.endpoints:
        for asset in endpoint.assets:
            comp = {
                "type": "crypto-asset",
                "name": asset.name,
                "cbom:assetType": asset.asset_type.value if hasattr(asset.asset_type, 'value') else str(asset.asset_type),
                "cbom:strength": asset.strength.value if hasattr(asset.strength, 'value') else str(asset.strength),
                "cbom:quantumVulnerable": asset.quantum_vulnerable,
                "cbom:sourceEndpoint": asset.source_endpoint,
                "cbom:notes": asset.notes,
                "cbom:cryptoProperties": asset.properties,
            }
            components.append(comp)
            # Example dependency: (extend as needed)
            dependencies.append({
                "ref": asset.asset_id,
                "dependencyType": "uses" if asset.quantum_vulnerable else "implements"
            })
    cyclonedx_cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "cbomVersion": cbom.cbom_version,
        "generated": cbom.generated_at,
        "generator": cbom.generator,
        "components": components,
        "dependencies": dependencies,
        "summary": cbom.summary,
    }
    return cyclonedx_cbom

def export_cbom_pdf(cbom: CBOM, pdf_path: str):
    """
    Generate a professional, bank-style PDF report for the CBOM.
    Uses ReportLab (pip install reportlab).
    """
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet
    import os

    print(f"[DEBUG] Attempting to write PDF to: {pdf_path}")
    try:
        doc = SimpleDocTemplate(pdf_path, pagesize=A4)
        styles = getSampleStyleSheet()
        elements = []

        # Title page
        elements.append(Paragraph("Cryptography Bill of Materials (CBOM) Report", styles['Title']))
        elements.append(Spacer(1, 24))
        elements.append(Paragraph(f"Organization: <b>Q-Shield</b>", styles['Normal']))
        elements.append(Paragraph(f"Generated: {cbom.generated_at}", styles['Normal']))
        elements.append(Paragraph(f"Report Version: {cbom.cbom_version}", styles['Normal']))
        elements.append(Spacer(1, 24))
        elements.append(Paragraph("<b>Executive Summary</b>", styles['Heading2']))
        for k, v in cbom.summary.items():
            elements.append(Paragraph(f"{k.replace('_', ' ').capitalize()}: <b>{v}</b>", styles['Normal']))
        elements.append(PageBreak())

        # Detailed crypto assets table
        elements.append(Paragraph("<b>Cryptographic Assets Inventory</b>", styles['Heading2']))
        for endpoint in cbom.endpoints:
            elements.append(Paragraph(f"Endpoint: <b>{endpoint.endpoint}</b>", styles['Heading3']))
            data = [["Asset Type", "Name", "Strength", "Quantum Vulnerable", "Notes"]]
            for asset in endpoint.assets:
                data.append([
                    asset.asset_type.value if hasattr(asset.asset_type, 'value') else str(asset.asset_type),
                    asset.name,
                    asset.strength.value if hasattr(asset.strength, 'value') else str(asset.strength),
                    "Yes" if asset.quantum_vulnerable else "No",
                    ", ".join(asset.notes) if asset.notes else "-"
                ])
            t = Table(data, repeatRows=1)
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.lightgray),
                ('TEXTCOLOR', (0,0), (-1,0), colors.black),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0,0), (-1,0), 8),
                ('GRID', (0,0), (-1,-1), 0.5, colors.gray),
            ]))
            elements.append(t)
            elements.append(Spacer(1, 12))
        # Add more sections as needed (dependencies, detection context, etc.)
        doc.build(elements)
        print(f"[DEBUG] PDF successfully written to: {pdf_path}")
    except Exception as e:
        print(f"[ERROR] PDF generation failed: {e}")

# === END ENHANCEMENTS ===

if __name__ == "__main__":
    import sys
    print("[DEBUG] Entered __main__ block of cbom_generator.py")
    if len(sys.argv) < 2:
        print("[DEBUG] Not enough arguments provided to script.")
        print("Usage: python cbom_generator.py <scan_result.json> [--pdf <output.pdf>] [--cyclonedx-json <output.json>]")
        sys.exit(1)
    if sys.argv[1] == "-":
        print("[DEBUG] Reading scan data from stdin.")
        data = json.load(sys.stdin)
    else:
        print(f"[DEBUG] Reading scan data from file: {sys.argv[1]}")
        with open(sys.argv[1]) as f:
            data = json.load(f)
    scan_results = data if isinstance(data, list) else [data]
    print("[DEBUG] Generating CBOM from scan results.")
    cbom = generate_cbom(scan_results)
    # Default: print legacy JSON
    print("[DEBUG] Printing legacy JSON output.")
    print(cbom.to_json())
    # Optionally export CycloneDX/IBM CBOM JSON
    if "--cyclonedx-json" in sys.argv:
        idx = sys.argv.index("--cyclonedx-json")
        out_path = sys.argv[idx+1] if idx+1 < len(sys.argv) else "cbom_cyclonedx.json"
        print(f"[DEBUG] Writing CycloneDX CBOM JSON to: {out_path}")
        with open(out_path, "w") as f:
            json.dump(cbom_to_cyclonedx_json(cbom), f, indent=2)
        print(f"CycloneDX CBOM JSON written to {out_path}")
    # Optionally export PDF
    if "--pdf" in sys.argv:
        idx = sys.argv.index("--pdf")
        out_path = sys.argv[idx+1] if idx+1 < len(sys.argv) else "cbom_report.pdf"
        print(f"[DEBUG] About to call export_cbom_pdf with path: {out_path}")
        export_cbom_pdf(cbom, out_path)
        print(f"[DEBUG] export_cbom_pdf call finished for: {out_path}")
        print(f"CBOM PDF report written to {out_path}")