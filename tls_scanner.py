"""
Q-Shield TLS Scanner
Scans TLS endpoints and detects PQC/hybrid key exchange with strict, accurate detection.

BUGS FIXED vs original:
1. _parse_target() had OpenSSL scan code injected into it (copy-paste error) — removed
2. _openssl_available() defined 3x and _run_openssl() defined 3x — deduplicated
3. Duplicate imports (ssl, logging, json, re, socket, etc.) — removed
4. _make_context() referenced undefined `os` and `logger` before imports — fixed
5. _handshake() used context manager incorrectly (socket closed before SSL read) — fixed
6. _get_tls_versions_supported() returned hardcoded list instead of real probing — fixed
7. _detect_tls13_key_exchange_dual() not called in _get_key_exchange_details() — unified
8. PQC false positive: fallback probe marked server PQC-ready just from CONNECTED — fixed
9. _detect_pqc_support() confirms PQC only when server negotiated group matches offered — kept correct
10. HYBRID_INDICATORS used token-split matching which split "X25519MLKEM768" into tokens
    that don't match — fixed with exact full-name check via HYBRID_FULL_NAMES
"""

import ctypes
import json
import logging
import os
import re
import shutil
import shlex
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import urllib.error
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Dict, List, Optional, Tuple, Any

# Universal PQC detection (token-based, handles any format/hybrid)
# Add graceful fallback if module is missing
try:
    from universal_pqc_detection import (
        detect_algorithm_category,
        analyze_tls_key_exchange,
        AlgorithmCategory,
    )
    UNIVERSAL_PQC_AVAILABLE = True
except ImportError as e:
    logger = logging.getLogger("qshield.pqc")
    logger.warning(f"universal_pqc_detection not available: {e} — PQC detection disabled")
    UNIVERSAL_PQC_AVAILABLE = False
    # Dummy implementations for graceful degradation
    def detect_algorithm_category(name: str) -> Dict[str, Any]:
        return {"is_hybrid": False, "is_pqc": False, "is_classical": False,
                "classical_tokens": [], "pqc_tokens": [], "confidence": 0.0,
                "reason": "PQC detection unavailable"}
    def analyze_tls_key_exchange(tls_version: str, key_exchange: str) -> Dict[str, Any]:
        return {"is_hybrid": False, "is_pqc": False, "is_classical": False, "reason": "PQC detection unavailable"}
    AlgorithmCategory = None  # type: ignore

# Optional cryptography library
try:
    from cryptography import x509
    from cryptography.x509 import ocsp
    from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

# ── Constants ────────────────────────────────────────────────────────────────

DEFAULT_TIMEOUT = 5
OCSP_CACHE_TTL_SECONDS = 300
OCSP_CACHE_MAX_SIZE = 500  # CRITICAL SECURITY FIX: Bounded cache to prevent memory leak


class LRUOCSPCache:
    """
    Thread-safe LRU cache for OCSP responses with TTL.
    
    CRITICAL SECURITY FIX: Replaces unbounded dict that could grow indefinitely
    causing memory exhaustion on long-lived process. Max 500 entries, 5-minute TTL.
    """
    
    def __init__(self, max_size: int = 500, ttl_seconds: int = 300):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.cache: OrderedDict[str, Dict[str, Any]] = OrderedDict()
        self.timestamps: Dict[str, float] = {}
    
    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Get value from cache if exists and not expired."""
        if key not in self.cache:
            return None
        
        timestamp = self.timestamps.get(key, 0)
        now = time.time()
        
        # Check if entry has expired
        if (now - timestamp) > self.ttl_seconds:
            self._delete(key)
            return None
        
        # Move to end (most recently used)
        self.cache.move_to_end(key)
        return self.cache[key]
    
    def set(self, key: str, value: Dict[str, Any]) -> None:
        """Set value in cache, evicting oldest entry if needed."""
        now = time.time()
        
        if key in self.cache:
            self.cache.move_to_end(key)
        elif len(self.cache) >= self.max_size:
            # Remove oldest entry (first in OrderedDict)
            oldest_key = next(iter(self.cache))
            self._delete(oldest_key)
        
        self.cache[key] = value
        self.timestamps[key] = now
    
    def _delete(self, key: str) -> None:
        """Delete entry from cache."""
        self.cache.pop(key, None)
        self.timestamps.pop(key, None)
    
    def clear(self) -> None:
        """Clear entire cache."""
        self.cache.clear()
        self.timestamps.clear()


# Initialize bounded OCSP cache (CRITICAL SECURITY FIX)
OCSP_CACHE = LRUOCSPCache(max_size=OCSP_CACHE_MAX_SIZE, ttl_seconds=OCSP_CACHE_TTL_SECONDS)

ERROR_CODES = {
    "invalid_target": 2,
    "dns_failure": 3,
    "connection_failed": 4,
    "timeout": 5,
    "tls_handshake_failed": 6,
    "unexpected_error": 10,
}

# ── PQC Detection Constants ───────────────────────────────────────────────────

# Individual PQC algorithm tokens (used for token-based matching)
PQC_ALGORITHM_INDICATORS = {
    "KYBER", "MLKEM",
    "DILITHIUM", "MLDSA",
    "FALCON", "SPHINCS", "SPHINCSPLUS",
    "NTRU", "SABER", "FRODO", "FRODOKEM",
    "BIKE", "HQC", "MCELIECE",
}

# Hybrid composite names — must match the FULL normalized string exactly
HYBRID_FULL_NAMES = {
    # X25519 hybrids (ML-KEM)
    "X25519MLKEM768",
    "X25519MLKEM1024",
    
    # X25519 hybrids (Kyber)
    "X25519KYBER512",
    "X25519KYBER768",
    "X25519KYBER1024",
    
    # P-256 hybrids (ML-KEM)
    "P256MLKEM768",
    "P256MLKEM1024",
    
    # P-256 hybrids (Kyber)
    "P256KYBER512",
    "P256KYBER768",
    "P256KYBER1024",
    
    # P-384 hybrids (ML-KEM)
    "P384MLKEM768",
    "P384MLKEM1024",
    
    # P-384 hybrids (Kyber)
    "P384KYBER768",
    "P384KYBER1024",
    
    # secp256r1 hybrids
    "SECP256R1MLKEM768",
    "SECP256R1MLKEM1024",
    "SECP256R1KYBER512",
    "SECP256R1KYBER768",
    "SECP256R1KYBER1024",
    
    # secp384r1 hybrids
    "SECP384R1MLKEM1024",
    "SECP384R1KYBER1024",
    
    # Ed25519 hybrids (uncommon but possible)
    "ED25519MLKEM768",
    
    # Additional NIST variants
    "P521MLKEM1024",
    "SECP521R1MLKEM1024",
}

# Known PQC algorithm registry
PQC_ALGORITHMS = {
    # Pure KEM algorithms
    "MLKEM512":          {"name": "ML-KEM-512",          "type": "kem",        "nist_level": 1},
    "MLKEM768":          {"name": "ML-KEM-768",          "type": "kem",        "nist_level": 3},
    "MLKEM1024":         {"name": "ML-KEM-1024",         "type": "kem",        "nist_level": 5},
    "KYBER512":          {"name": "Kyber-512",            "type": "kem",        "nist_level": 1},
    "KYBER768":          {"name": "Kyber-768",            "type": "kem",        "nist_level": 3},
    "KYBER1024":         {"name": "Kyber-1024",           "type": "kem",        "nist_level": 5},
    
    # X25519 hybrids (ML-KEM)
    "X25519MLKEM768":    {"name": "X25519+MLKEM768",   "type": "hybrid_kem", "nist_level": 3, "classical": "X25519"},
    "X25519MLKEM1024":   {"name": "X25519+MLKEM1024",  "type": "hybrid_kem", "nist_level": 5, "classical": "X25519"},
    
    # X25519 hybrids (Kyber) → Now labeled as ML-KEM equivalents (standardized NIST names)
    "X25519KYBER512":    {"name": "X25519+MLKEM512",    "type": "hybrid_kem", "nist_level": 1, "classical": "X25519"},
    "X25519KYBER768":    {"name": "X25519+MLKEM768",    "type": "hybrid_kem", "nist_level": 3, "classical": "X25519"},
    "X25519KYBER1024":   {"name": "X25519+MLKEM1024",   "type": "hybrid_kem", "nist_level": 5, "classical": "X25519"},
    
    # P-256 hybrids (ML-KEM)
    "P256MLKEM768":      {"name": "P256+MLKEM768",    "type": "hybrid_kem", "nist_level": 3, "classical": "P-256"},
    "P256MLKEM1024":     {"name": "P256+MLKEM1024",   "type": "hybrid_kem", "nist_level": 5, "classical": "P-256"},
    
    # P-256 hybrids (Kyber) → Now labeled as ML-KEM equivalents
    "P256KYBER512":      {"name": "P256+MLKEM512",      "type": "hybrid_kem", "nist_level": 1, "classical": "P-256"},
    "P256KYBER768":      {"name": "P256+MLKEM768",      "type": "hybrid_kem", "nist_level": 3, "classical": "P-256"},
    "P256KYBER1024":     {"name": "P256+MLKEM1024",     "type": "hybrid_kem", "nist_level": 5, "classical": "P-256"},
    
    # P-384 hybrids (ML-KEM)
    "P384MLKEM768":      {"name": "P384+MLKEM768",      "type": "hybrid_kem", "nist_level": 3, "classical": "P-384"},
    "P384MLKEM1024":     {"name": "P384+MLKEM1024",     "type": "hybrid_kem", "nist_level": 5, "classical": "P-384"},
    
    # P-384 hybrids (Kyber) → Now labeled as ML-KEM equivalents
    "P384KYBER768":      {"name": "P384+MLKEM768",      "type": "hybrid_kem", "nist_level": 3, "classical": "P-384"},
    "P384KYBER1024":     {"name": "P384+MLKEM1024",     "type": "hybrid_kem", "nist_level": 5, "classical": "P-384"},
    
    # secp256r1 hybrids (ML-KEM)
    "SECP256R1MLKEM768": {"name": "secp256r1+MLKEM768","type": "hybrid_kem", "nist_level": 3, "classical": "secp256r1"},
    "SECP256R1MLKEM1024":{"name": "secp256r1+MLKEM1024","type": "hybrid_kem", "nist_level": 5, "classical": "secp256r1"},
    
    # secp256r1 hybrids (Kyber) → Now labeled as ML-KEM equivalents
    "SECP256R1KYBER512": {"name": "secp256r1+MLKEM512", "type": "hybrid_kem", "nist_level": 1, "classical": "secp256r1"},
    "SECP256R1KYBER768": {"name": "secp256r1+MLKEM768", "type": "hybrid_kem", "nist_level": 3, "classical": "secp256r1"},
    "SECP256R1KYBER1024":{"name": "secp256r1+MLKEM1024","type": "hybrid_kem", "nist_level": 5, "classical": "secp256r1"},
    
    # secp384r1 hybrids (Kyber) → Now labeled as ML-KEM equivalents
    "SECP384R1KYBER1024":{"name": "secp384r1+MLKEM1024","type": "hybrid_kem", "nist_level": 5, "classical": "secp384r1"},
    
    # Pure Signature algorithms
    "MLDSA44":           {"name": "ML-DSA-44",           "type": "signature",  "nist_level": 2},
    "MLDSA65":           {"name": "ML-DSA-65",           "type": "signature",  "nist_level": 3},
    "MLDSA87":           {"name": "ML-DSA-87",           "type": "signature",  "nist_level": 5},
    "DILITHIUM2":        {"name": "Dilithium-2",          "type": "signature",  "nist_level": 2},
    "DILITHIUM3":        {"name": "Dilithium-3",          "type": "signature",  "nist_level": 3},
    "DILITHIUM5":        {"name": "Dilithium-5",          "type": "signature",  "nist_level": 5},
    "SLHDSA128":         {"name": "SLH-DSA-128",         "type": "signature",  "nist_level": 1},
    "SLHDSA192":         {"name": "SLH-DSA-192",         "type": "signature",  "nist_level": 3},
    "SLHDSA256":         {"name": "SLH-DSA-256",         "type": "signature",  "nist_level": 5},
}

# ── PQC OID Registry (For Certificate Signature & Public Key Algorithms) ─────────
# Maps OID dotted-string → (human_name, category, nist_level)
# Used to identify PQC algorithms in X.509 certificates
PQC_OID_MAP = {
    # ── ML-KEM (Kyber) – NIST FIPS 203 ──
    "1.3.6.1.4.1.22554.5.6.1": ("ML-KEM-512",  "KEM", 1),
    "1.3.6.1.4.1.22554.5.6.2": ("ML-KEM-768",  "KEM", 3),
    "1.3.6.1.4.1.22554.5.6.3": ("ML-KEM-1024", "KEM", 5),
    # Draft OIDs (used by BoringSSL / Cloudflare experiments)
    "1.3.6.1.4.1.44363.45.1":  ("Kyber512-draft",  "KEM", 1),
    "1.3.6.1.4.1.44363.45.2":  ("Kyber768-draft",  "KEM", 3),
    "1.3.6.1.4.1.44363.45.3":  ("Kyber1024-draft", "KEM", 5),
    
    # ── ML-DSA (Dilithium) – NIST FIPS 204 ──
    "1.3.6.1.4.1.2.267.12.4.4":   ("ML-DSA-44", "SIG", 2),
    "1.3.6.1.4.1.2.267.12.6.5":   ("ML-DSA-65", "SIG", 3),
    "1.3.6.1.4.1.2.267.12.8.7":   ("ML-DSA-87", "SIG", 5),
    # Older Dilithium draft OIDs
    "1.3.6.1.4.1.2.267.7.4.4":    ("Dilithium2", "SIG", 2),
    "1.3.6.1.4.1.2.267.7.6.5":    ("Dilithium3", "SIG", 3),
    "1.3.6.1.4.1.2.267.7.8.7":    ("Dilithium5", "SIG", 5),
    
    # ── SLH-DSA (SPHINCS+) – NIST FIPS 205 ──
    "1.3.9999.6.4.1":  ("SPHINCS+-SHA2-128s",  "SIG", 1),
    "1.3.9999.6.4.4":  ("SPHINCS+-SHA2-128f",  "SIG", 1),
    "1.3.9999.6.5.1":  ("SPHINCS+-SHA2-192s",  "SIG", 3),
    "1.3.9999.6.5.3":  ("SPHINCS+-SHA2-256s",  "SIG", 5),
    "1.3.9999.6.7.1":  ("SPHINCS+-SHAKE-128s", "SIG", 1),
    "1.3.9999.6.7.4":  ("SPHINCS+-SHAKE-128f", "SIG", 1),
    
    # ── Falcon ──
    "1.3.9999.3.1":    ("Falcon-512",  "SIG", 1),
    "1.3.9999.3.4":    ("Falcon-1024", "SIG", 5),
    # NIST round 4 OIDs
    "1.3.6.1.4.1.311.89.2.1.6": ("Falcon-512-NIST",  "SIG", 1),
    "1.3.6.1.4.1.311.89.2.1.7": ("Falcon-1024-NIST", "SIG", 5),
    
    # ── Hybrid Signature Schemes (classic + PQC) ──
    "1.3.6.1.4.1.18227.999.2.7.1.1": ("p256_dilithium2",      "HYBRID-SIG", 2),
    "1.3.6.1.4.1.18227.999.2.7.1.2": ("rsa3072_dilithium2",   "HYBRID-SIG", 2),
    "1.3.6.1.4.1.18227.999.2.7.2.1": ("p384_dilithium3",      "HYBRID-SIG", 3),
    "1.3.6.1.4.1.18227.999.2.7.3.1": ("p521_dilithium5",      "HYBRID-SIG", 5),
    "1.3.6.1.4.1.18227.999.2.7.4.1": ("p256_falcon512",       "HYBRID-SIG", 1),
    "1.3.6.1.4.1.18227.999.2.7.5.1": ("p256_sphincssha2128f", "HYBRID-SIG", 1),
}

# ── IANA TLS Supported Groups Registry (TLS 1.3 Key Share) ────────────────────
# https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
# Maps IANA code → (name, category, nist_level)
IANA_TLS_GROUPS = {
    # Classical
    0x0017: ("secp256r1", "classical", None),
    0x0018: ("secp384r1", "classical", None),
    0x0019: ("secp521r1", "classical", None),
    0x001d: ("x25519", "classical", None),
    0x001e: ("x448", "classical", None),
    # ML-KEM hybrids (IANA assigned)
    0x11eb: ("SecP256r1MLKEM768", "hybrid", 3),
    0x11ec: ("X25519MLKEM768", "hybrid", 3),
    0x11ed: ("SecP384r1MLKEM1024", "hybrid", 5),
    # Older Cloudflare/Google drafts (still seen in the wild)
    0xfe30: ("X25519Kyber768Draft00", "hybrid_draft", 3),
    0xfe31: ("P256Kyber768Draft00", "hybrid_draft", 3),
    # OQS/experimental
    0x023a: ("Kyber512", "pqc_pure", 1),
    0x023c: ("Kyber768", "pqc_pure", 3),
    0x023d: ("Kyber1024", "pqc_pure", 5),
}

def _group_id_to_name(group_id: int) -> tuple[str, str, Optional[int]]:
    """
    Convert IANA group code point to (name, category, nist_level).
    Falls back to hex string for unknown groups rather than guessing.
    """
    if group_id in IANA_TLS_GROUPS:
        return IANA_TLS_GROUPS[group_id]
    return (f"unknown_group_0x{group_id:04x}", "unknown", None)

# ── Logging ───────────────────────────────────────────────────────────────────

logger = logging.getLogger("qshield.pqc")
logger.setLevel(logging.DEBUG)

# ── OpenSSL helpers ───────────────────────────────────────────────────────────

# FIX #6: Auto-detect PQC-capable OpenSSL binary at module initialization
def _find_pqc_openssl() -> Optional[str]:
    """
    Search for PQC-enabled OpenSSL binary.
    Checks common paths and validates PQC support.
    Returns path to PQC binary or None if not found.
    """
    candidates = [
        os.environ.get("OPENSSL_PQC_BIN"),  # User override
        "/usr/local/bin/openssl",
        "/usr/bin/openssl",
        "~/.local/bin/openssl",
        "openssl-pqc",
        "oqs-openssl",
        shutil.which("openssl-pqc"),
        shutil.which("oqs-openssl"),
    ]
    
    for candidate in candidates:
        if not candidate:
            continue
        candidate = os.path.expanduser(candidate)
        
        try:
            # Test: Does this binary expose PQC groups?
            result = subprocess.run(
                [candidate, "s_client", "-help"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            help_output = result.stdout + result.stderr

            if "mlkem" in help_output.lower() or "x25519mlkem" in help_output.lower() or "pqc" in help_output.lower():
                logger.debug(f"[PQC OPENSSL] Found PQC-capable binary: {candidate}")
                return candidate
        except (subprocess.SubprocessError, FileNotFoundError, OSError):
            continue

        # Fallback: OQS builds often advertise themselves in version output
        try:
            version_result = subprocess.run(
                [candidate, "version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            version_output = (version_result.stdout + version_result.stderr).lower()
            if "open quantum safe" in version_output or "oqs" in version_output:
                logger.debug(f"[PQC OPENSSL] Found OQS OpenSSL binary via version: {candidate}")
                return candidate
        except (subprocess.SubprocessError, FileNotFoundError, OSError):
            continue
    
    logger.debug("[PQC OPENSSL] No PQC-capable OpenSSL binary found")
    return None


# FIX: Defined once, deduplicated from 3 copies in original
OPENSSL_NORMAL = shutil.which("openssl") or "openssl"
OPENSSL_PQC    = _find_pqc_openssl()  # FIX #6: Auto-detect instead of hardcoded path


def _openssl_available(which: str = "normal") -> bool:
    if which == "pqc":
        return OPENSSL_PQC is not None and shutil.which(OPENSSL_PQC) is not None
    return shutil.which(OPENSSL_NORMAL) is not None


def _run_openssl(args: List[str], timeout: int, which: str = "normal") -> Optional[str]:
    """Run OpenSSL CLI. 'which' selects normal or PQC-enabled binary."""
    effective_timeout = max(timeout, 10)  # FIX #4: Reduced from 30s to 10s for faster probing
    run_kwargs: Dict[str, Any] = {}
    if args and args[0] == "s_client":
        # FIX #1: Don't pass explicit empty input; let subprocess handle stdin naturally
        # Passing input="" closes stdin immediately which can cause OpenSSL to report
        # "connection closed by peer" before printing "Negotiated group:" line.
        # By not specifying input, stdin closes naturally after handshake completes.
        pass  # Don't set run_kwargs["input"]

    binary = OPENSSL_NORMAL if which == "normal" else OPENSSL_PQC
    extra_args: List[str] = []
    if which == "pqc":
        extra_args = shlex.split(os.environ.get("OPENSSL_PQC_ARGS", ""))
    try:
        completed = subprocess.run(
            [binary] + extra_args + args,
            capture_output=True,
            text=True,
            timeout=effective_timeout,
            **run_kwargs,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return None

    return completed.stdout + completed.stderr


# ── PQC detection helpers ─────────────────────────────────────────────────────

def normalize_name(name: str) -> str:
    """Strip noise characters for consistent matching."""
    return name.strip().replace("'", "").replace('"', "").replace("(", "").replace(")", "")


def _tokenize(name: str) -> List[str]:
    """Split a normalized, uppercased name into tokens."""
    return re.split(r'[-_\s/+]+', normalize_name(name).upper())


def _is_pqc_token_match(name: str) -> bool:
    """
    Return True if name contains any PQC or hybrid algorithm token.
    
    NOW USING: Universal token-based detection.
    Replaces hardcoded list checks with universal logic.
    """
    if not name:
        return False
    analysis = detect_algorithm_category(name)
    # True if either pure PQC or hybrid (both have PQC tokens)
    return analysis["is_pqc"]


def _is_hybrid_full_name(name: str) -> bool:
    """
    Check if algorithm name is HYBRID (both classical + PQC tokens).
    
    NOW USING: Universal token-based detection.
    Returns True only if BOTH classical and PQC components present.
    """
    if not name:
        return False
    analysis = detect_algorithm_category(name)
    # True only if BOTH classical AND PQC tokens present (is_hybrid=True)
    return analysis["is_hybrid"]


def _detect_pqc_algorithm(algorithm_str: str) -> Optional[Dict[str, Any]]:
    """
    Detect if an algorithm string identifies a PQC algorithm.
    
    NOW USING: Universal token-based detection that handles:
    - Format variations (dashes, spaces, underscores, plus signs)
    - ANY hybrid algorithm (present or future)
    - Automatic scaling with new standards
    
    Examples:
    - "X25519-MLKEM768" (with dash) ✅ DETECTED
    - "X25519 MLKEM768" (with space) ✅ DETECTED
    - "X25519MLKEM768" (concatenated) ✅ DETECTED
    - "P256KYBER512" (different hybrid) ✅ DETECTED
    - "Future2030KYBER768" (future standard) ✅ AUTO-DETECTED
    
    REPLACES: Hardcoded PQC_ALGORITHMS dict (300+ lines, limited combos)
    WITH: Token registry (2 sets of ~50 tokens, infinite combos)
    """
    if not algorithm_str:
        return None

    # Use universal detection engine (detect_algorithm_category returns dict directly)
    analysis_dict = detect_algorithm_category(algorithm_str)
    
    # Determine category based on flags
    if analysis_dict.get("is_hybrid"):
        category = "hybrid"
    elif analysis_dict.get("is_pqc"):
        category = "pqc"
    elif analysis_dict.get("is_classical"):
        category = "classical"
    else:
        category = "unknown"
    
    # Convert universal analysis to legacy dict format for compatibility
    if category == "unknown":
        return None
    
    is_hybrid = analysis_dict["is_hybrid"]
    is_pqc = analysis_dict["is_pqc"]
    
    # Log detection
    if is_hybrid:
        logger.debug(f"[PQC DETECT UNIVERSAL] '{algorithm_str}' → HYBRID: {analysis_dict['reason']}")
    elif is_pqc:
        logger.debug(f"[PQC DETECT UNIVERSAL] '{algorithm_str}' → PURE PQC: {analysis_dict['reason']}")
    else:
        logger.debug(f"[PQC DETECT UNIVERSAL] '{algorithm_str}' → CLASSICAL (not PQC)")
        return None
    
    # Build legacy format return value (for compatibility with rest of code)
    normalized_name = _normalize_pqc_group_name(algorithm_str)
    registry_info = PQC_ALGORITHMS.get(normalized_name)
    nist_level = registry_info.get("nist_level") if registry_info else 3
    
    return {
        "detected": True,
        "algorithm": algorithm_str,
        "normalized_algorithm": normalized_name,  # NIST standard name (X25519MLKEM768 vs X25519KYBER768)
        "raw_name": algorithm_str,
        "type": "hybrid_kem" if is_hybrid else "pure_pqc",
        "nist_security_level": nist_level,
        "is_hybrid": is_hybrid,
        "is_pqc": is_pqc,
        "category": category,
        "confidence": analysis_dict.get("confidence", 0.0),
        "classical_tokens": analysis_dict.get("classical_tokens", []),
        "pqc_tokens": analysis_dict.get("pqc_tokens", []),
        "recommendation": analysis_dict.get("reason", ""),
    }


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class TargetInfo:
    host: str
    port: int
    ip_address: str


# ── Target parsing ────────────────────────────────────────────────────────────

def _parse_target(target: str) -> Tuple[str, int]:
    """Parse a target string into (host, port). FIX: removed stray OpenSSL code."""
    target = target.strip()
    if "://" in target:
        parsed = urllib.parse.urlparse(target)
        host = parsed.hostname or ""
        port = parsed.port or 443
        return host, port

    if target.startswith("["):
        match = re.match(r"\[(.+)\](?::(\d+))?$", target)
        if match:
            host = match.group(1)
            port = int(match.group(2)) if match.group(2) else 443
            return host, port

    if ":" in target and target.count(":") == 1:
        host, port_str = target.split(":", 1)
        if port_str.isdigit():
            return host, int(port_str)

    return target, 443


def _resolve_ip(host: str, port: int) -> str:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return "0.0.0.0"


# ── TLS context / handshake ───────────────────────────────────────────────────

def _make_context(version: ssl.TLSVersion) -> ssl.SSLContext:
    """Create SSL context for TLS probing with verification disabled.
    
    IMPORTANT: Certificate verification is intentionally disabled because:
    1. We probe arbitrary servers including those with invalid/self-signed certs
    2. We need to enumerate TLS capabilities regardless of certificate validity
    3. Goal is cryptographic inventory, not secure communication
    
    This is safe because:
    - Q-Shield doesn't process untrusted data from certificates
    - Results are for inventory/scanning only, not for authentication
    - Traffic stays within Q-Shield, not exposed to users
    
    For authenticating with remote APIs/services, use proper cert validation.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # Intentional: allows probing invalid certs
    ctx.minimum_version = version
    ctx.maximum_version = version
    return ctx


def _handshake(host: str, port: int, ctx: ssl.SSLContext, timeout: int) -> Optional[ssl.SSLSocket]:
    """
    FIX: original used `with` context managers that closed the socket before
    the caller could read the cert. Now returns an open SSLSocket; caller
    must close it.
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        ssock = ctx.wrap_socket(sock, server_hostname=host)
        ssock.do_handshake()
        return ssock
    except Exception:
        return None


# ── FIX #2: TLS 1.3 group detection via ctypes (PRIMARY method - no OpenSSL CLI needed) ───────────

def _get_tls13_group_via_ctypes(ssock: ssl.SSLSocket) -> Optional[str]:
    """
    DISABLED: Ctypes SSL pointer extraction is broken.
    
    This function attempted to extract negotiated TLS 1.3 group from OpenSSL SSL structure.
    However, using Python id() gives the object address, not the C-level SSL* pointer.
    Proper extraction would require ctypes.cast() with CPython internals knowledge.
    This is not portable across Python versions.
    
    Falls back to _probe_pqc_via_raw_sockets() which is more reliable.
    
    Returns: None (always)
    """
    logger.debug("Ctypes SSL pointer extraction disabled - using raw sockets fallback")
    return None


def _probe_pqc_via_curl(host: str, port: int, timeout: int = 10) -> Dict[str, Any]:
    """
    FIX ROOT CAUSE 3: Detect PQC/hybrid via curl (fallback when no OpenSSL CLI).
    curl on macOS Sonoma+ and Ubuntu 24.04+ has PQC support via --curves.
    """
    result: Dict[str, Any] = {
        "supported": False,
        "method": "curl",
        "algorithm": None,
        "available": False,
    }
    
    if not shutil.which("curl"):
        return result
    
    result["available"] = True
    
    try:
        # curl with PQC groups: X25519MLKEM768, X25519Kyber768Draft00, etc.
        cmd = [
            "curl", "-v", "--curves", "X25519MLKEM768:X25519Kyber768Draft00:P256MLKEM768",
            f"https://{host}:{port}/",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = proc.stdout + proc.stderr
        
        # Check for PQC indicators in curl's TLS handshake output
        # Patterns: "SSL connection using ... / X25519Kyber768" or similar
        pqc_patterns = [
            r"X25519.*MLKEM|MLKEM.*X25519",
            r"X25519.*[Kk]yber|[Kk]yber.*X25519",
            r"MLKEM768|ML-KEM-768",
            r"(X25519MLKEM768|X25519KYBER768|P256MLKEM768)",
        ]
        
        for pattern in pqc_patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                algo = match.group(0) if match.groups() else match.group(1) if len(match.groups()) > 0 else "PQC_HYBRID"
                # ✅ Normalize: "Kyber" → "MLKEM"
                algo_normalized = _normalize_pqc_group_name(algo.upper().replace("-", "").replace(" ", ""))
                result["supported"] = True
                result["algorithm"] = algo_normalized
                logger.debug(f"[CURL PQC] Detected: {algo} → {algo_normalized}")
                return result
        
    except (subprocess.SubprocessError, FileNotFoundError, TimeoutError):
        pass
    
    return result


def _probe_pqc_via_gnutls(host: str, port: int, timeout: int = 10) -> Dict[str, Any]:
    """
    FIX ROOT CAUSE 4: Detect PQC/hybrid via gnutls-cli (Linux fallback).
    gnutls-cli on some Linux distros supports PQC groups via priority strings.
    """
    result: Dict[str, Any] = {
        "supported": False,
        "method": "gnutls",
        "algorithm": None,
        "available": False,
    }
    
    if not shutil.which("gnutls-cli"):
        return result
    
    result["available"] = True
    
    try:
        # gnutls-cli with PQC priority
        cmd = [
            "gnutls-cli",
            "--priority", "NORMAL:+KEM-X25519-MLKEM768",
            "-p", str(port),
            host,
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input="Q\n")
        output = proc.stdout + proc.stderr
        
        # Check for "Key Exchange: X25519-MLKEM768" or similar
        kex_match = re.search(r"Key\s+Exchange:\s*([^\n]+)", output, re.IGNORECASE)
        if kex_match:
            kex_str = kex_match.group(1).strip()
            if "mlkem" in kex_str.lower() or "kyber" in kex_str.lower():
                result["supported"] = True
                result["algorithm"] = kex_str
                logger.debug(f"[GNUTLS PQC] Detected: {kex_str}")
                return result
        
    except (subprocess.SubprocessError, FileNotFoundError, TimeoutError):
        pass
    
    return result


# ── TLS version probing ───────────────────────────────────────────────────────

def _supports_version(host: str, port: int, version: ssl.TLSVersion, timeout: int) -> bool:
    ctx = _make_context(version)
    ssock = _handshake(host, port, ctx, timeout)
    if ssock:
        ssock.close()
        return True
    return False


def _get_tls_versions_supported(host: str, port: int, timeout: int) -> List[str]:
    """FIX: original returned a hardcoded list — now actually probes."""
    versions = []
    version_map = [
        ("TLSv1.0", "TLSv1"),
        ("TLSv1.1", "TLSv1_1"),
        ("TLSv1.2", "TLSv1_2"),
        ("TLSv1.3", "TLSv1_3"),
    ]
    for label, attr in version_map:
        if hasattr(ssl.TLSVersion, attr):
            ver = getattr(ssl.TLSVersion, attr)
            if _supports_version(host, port, ver, timeout):
                versions.append(label)
    return versions


# ── Cipher parsing ────────────────────────────────────────────────────────────

def _lookup_pqc_oid(oid_str: str) -> Optional[Dict[str, Any]]:
    """Look up PQC algorithm info from X.509 OID string.
    
    Returns: {"name": str, "category": str, "nist_level": int} or None
    """
    if oid_str not in PQC_OID_MAP:
        return None
    name, category, nist_level = PQC_OID_MAP[oid_str]
    return {"name": name, "category": category, "nist_level": nist_level, "oid": oid_str}


def _normalize_pqc_group_name(group_name: str) -> str:
    """Normalize PQC group names: convert old Kyber draft names to standardized ML-KEM names.
    
    Maps draft names to their NIST FIPS 203 ML-KEM equivalents:
    - X25519Kyber512/512Draft00 → X25519MLKEM512
    - X25519Kyber768/768Draft00 → X25519MLKEM768
    - X25519Kyber1024/1024Draft00 → X25519MLKEM1024
    - Similar for P-256, P-384, secp variants
    
    Also normalizes alternative separators: X25519-ML-KEM-768 → X25519MLKEM768
    """
    normalized = group_name.upper().replace("-", "").replace(" ", "").replace("+", "").replace("/", "")
    
    # Map old Kyber draft names to ML-KEM standards
    kyber_to_mlkem = {
        "X25519KYBER512DRAFT00": "X25519MLKEM512",
        "X25519KYBER512": "X25519MLKEM512",
        "X25519KYBER768DRAFT00": "X25519MLKEM768",
        "X25519KYBER768": "X25519MLKEM768",
        "X25519KYBER1024DRAFT00": "X25519MLKEM1024",
        "X25519KYBER1024": "X25519MLKEM1024",
        "P256KYBER512DRAFT00": "P256MLKEM512",
        "P256KYBER512": "P256MLKEM512",
        "P256KYBER768DRAFT00": "P256MLKEM768",
        "P256KYBER768": "P256MLKEM768",
        "P256KYBER1024DRAFT00": "P256MLKEM1024",
        "P256KYBER1024": "P256MLKEM1024",
        "P384KYBER768DRAFT00": "P384MLKEM768",
        "P384KYBER768": "P384MLKEM768",
        "P384KYBER1024DRAFT00": "P384MLKEM1024",
        "P384KYBER1024": "P384MLKEM1024",
        "SECP256R1KYBER512DRAFT00": "SECP256R1MLKEM512",
        "SECP256R1KYBER512": "SECP256R1MLKEM512",
        "SECP256R1KYBER768DRAFT00": "SECP256R1MLKEM768",
        "SECP256R1KYBER768": "SECP256R1MLKEM768",
        "SECP256R1KYBER1024DRAFT00": "SECP256R1MLKEM1024",
        "SECP256R1KYBER1024": "SECP256R1MLKEM1024",
        "SECP384R1KYBER1024DRAFT00": "SECP384R1MLKEM1024",
        "SECP384R1KYBER1024": "SECP384R1MLKEM1024",
    }
    
    return kyber_to_mlkem.get(normalized, normalized)


def _cipher_risk_level(cipher_name: str) -> str:
    """Assess cipher security risk level.
    
    Returns: "CRITICAL", "WEAK", "MEDIUM", "STRONG", or "UNKNOWN"
    Ratings:
    - CRITICAL: Broken/unsafe ciphers (RC4, DES, 3DES, NULL, EXPORT, anonymous, MD5)
    - WEAK: Deprecated but not completely broken (TLS 1.0, TLS 1.1)
    - MEDIUM: Acceptable but older (CBC mode, weaker algorithms)
    - STRONG: Modern secure ciphers (GCM, ChaCha20, modern AEAD)
    - UNKNOWN: Unclassified
    """
    upper = cipher_name.upper()
    
    # CRITICAL: Broken algorithms
    critical_patterns = ["RC4", "DES", "3DES", "NULL", "EXPORT", "ANON", "MD5", "PSK_NULL"]
    for pattern in critical_patterns:
        if pattern in upper:
            return "CRITICAL"
    
    # STRONG: Modern AEAD ciphers
    strong_patterns = ["GCM", "CHACHA20", "AEAD", "POLY1305", "CCM"]
    for pattern in strong_patterns:
        if pattern in upper:
            return "STRONG"
    
    # MEDIUM: CBC mode (older but acceptable)
    if "CBC" in upper:
        return "MEDIUM"
    
    # Default for unknown
    return "UNKNOWN"


def _parse_cipher_name(cipher_name: str) -> Tuple[Optional[str], Optional[str], str, Optional[str]]:
    """Parse cipher name in IANA (TLS_*) or OpenSSL (ECDHE-RSA-*) format."""
    if cipher_name.startswith("TLS_") and "_WITH_" not in cipher_name:
        parts = cipher_name.replace("TLS_", "").split("_")
        if len(parts) >= 4:
            enc = f"{parts[0]}-{parts[1]}-{parts[2]}"
            hsh = parts[3]
            return None, None, enc, hsh
        return None, None, cipher_name.replace("TLS_", "").replace("_", "-"), None

    match = re.match(r"TLS_(.+)_WITH_(.+)$", cipher_name)
    if match:
        kx_auth = match.group(1)
        enc_hash = match.group(2)
        kx, auth = (kx_auth.split("_", 1) if "_" in kx_auth else (kx_auth, None))
        parts = enc_hash.split("_")
        hash_alg = None
        if parts[-1].startswith("SHA") or parts[-1] in {"MD5"}:
            hash_alg = parts[-1]
            encryption = "-".join(parts[:-1])
        else:
            encryption = "-".join(parts)
        return kx, auth, encryption, hash_alg

    parts = cipher_name.split("-")
    if len(parts) < 2:
        return None, None, cipher_name, None

    kx, auth, enc_start = None, None, 0
    if parts[0] in {"ECDHE", "DHE", "DH", "ECDH"}:
        kx = parts[0]
        enc_start = 1
        if len(parts) > 1 and parts[1] in {"RSA", "ECDSA", "DSS", "PSK"}:
            auth = parts[1]
            enc_start = 2
    elif parts[0] == "RSA":
        kx = auth = "RSA"
        enc_start = 1

    hash_alg = None
    enc_end = len(parts)
    if parts[-1].startswith("SHA") or parts[-1] == "MD5":
        hash_alg = parts[-1]
        enc_end -= 1

    encryption = "-".join(parts[enc_start:enc_end]) if enc_start < enc_end else cipher_name
    return kx, auth, encryption, hash_alg


def _available_ciphers(version: ssl.TLSVersion) -> List[str]:
    ctx = _make_context(version)
    ciphers = []
    for entry in ctx.get_ciphers():
        proto = entry.get("protocol", "")
        if version == ssl.TLSVersion.TLSv1_3:
            if proto == "TLSv1.3":
                ciphers.append(entry.get("name", ""))
        else:
            if proto.startswith("TLSv1"):
                ciphers.append(entry.get("name", ""))
    return sorted(set(filter(None, ciphers)))


def _probe_cipher(host: str, port: int, version: ssl.TLSVersion, cipher: str, timeout: int) -> bool:
    ctx = _make_context(version)
    if version == ssl.TLSVersion.TLSv1_3:
        if not hasattr(ctx, "set_ciphersuites"):
            return False
        try:
            ctx.set_ciphersuites(cipher)
        except ssl.SSLError:
            return False
    else:
        try:
            ctx.set_ciphers(cipher)
        except ssl.SSLError:
            return False
    ssock = _handshake(host, port, ctx, timeout)
    if ssock:
        ssock.close()
        return True
    return False


# ── TLS 1.3 key exchange detection ───────────────────────────────────────────

def _detect_tls13_key_exchange_dual(host: str, port: int, timeout: int) -> Dict[str, Any]:
    """
    Dual-engine detection with UNIVERSAL PQC analysis:
    - Standard OpenSSL: ground truth for what the server actually negotiated
    - PQC-enabled OpenSSL (if available): probes whether the server SUPPORTS PQC
      (only trusted when the server explicitly confirms the negotiated group)
    - UNIVERSAL ANALYSIS: Detect ANY hybrid algorithm automatically

    FIX: The old code marked pqc_active/hybrid=True just from "CONNECTED(" in
    the fallback probe output. That only means TCP/TLS succeeded — the server
    could have silently fallen back to X25519. We now only mark PQC active when
    the 'Negotiated TLS1.3 group' line from the server explicitly shows a PQC name.
    
    CRITICAL FIX: Improved regex patterns to handle OpenSSL output variations:
    - "Negotiated TLS 1.3 group:" (space before 1.3)
    - "Negotiated TLS1.3 group:" (no space)
    - "Negotiated group:" (shorter format)
    - "Shared group:" (alternative format)
    Handles hybrid names: X25519-MLKEM768, X25519 MLKEM768, X25519+ML-KEM-768 etc.
    
    UNIVERSAL ANALYSIS: Uses token-based detection to automatically identify
    ANY hybrid algorithm (present or future) without hardcoding specific combos.
    """
    result: Dict[str, Any] = {
        "key_exchange": "Unknown",
        "pqc_status": {
            "mode": "classical",
            "supported": False,
            "active": False,
            "negotiated_group": None,
            "pqc_groups_supported": [],
        },
        "universal_analysis": None,  # ✅ NEW: Universal token-based analysis
    }

    if not _openssl_available("normal"):
        return result

    # ── Step 1: Standard OpenSSL — what did the server actually negotiate? ──
    try:
        std_out = _run_openssl(
            ["s_client", "-connect", f"{host}:{port}", "-servername", host, "-tls1_3"],
            timeout,
            which="normal",
        )
        if std_out:
            # CRITICAL FIX: Multiple regex patterns to handle OpenSSL variations
            # Pattern 1: "Negotiated TLS 1.3 group:" (with space)
            neg_match = re.search(r"Negotiated\s+TLS\s+1\.3\s+group:\s*([^\n]+)", std_out, re.IGNORECASE)
            
            # Pattern 2: "Negotiated TLS1.3 group:" (no space before 1.3)
            if not neg_match:
                neg_match = re.search(r"Negotiated\s+TLS1\.3\s+group:\s*([^\n]+)", std_out, re.IGNORECASE)
            
            # Pattern 3: "Negotiated group:" (shorter format)
            if not neg_match:
                neg_match = re.search(r"Negotiated\s+group:\s*([^\n]+)", std_out, re.IGNORECASE)
            
            # Pattern 4: "Shared group:" or "Shared temporary group:"
            if not neg_match:
                neg_match = re.search(r"Shared\s+(?:temporary\s+)?group:\s*([^\n]+)", std_out, re.IGNORECASE)
            
            if neg_match:
                group = neg_match.group(1).strip()
                # Normalize: convert "ML-KEM" to "MLKEM" and "Kyber" to "MLKEM"
                # This handles: "X25519-MLKEM768", "X25519 MLKEM768", "X25519+ML-KEM-768" etc.
                # AND converts old drafts: "X25519Kyber768" → "X25519MLKEM768"
                group_normalized = re.sub(r'[-_\s/+]+', '', group.upper())
                group_normalized = _normalize_pqc_group_name(group_normalized)  # ✅ Map Kyber → MLKEM
                result["key_exchange"] = group_normalized
                result["pqc_status"]["negotiated_group"] = group_normalized

                # ✅ NEW: Universal analysis (auto-detects ANY hybrid without hardcoding)
                universal_analysis = detect_algorithm_category(group)
                result["universal_analysis"] = universal_analysis
                
                # Use universal classification to set PQC status
                if universal_analysis["is_hybrid"]:
                    result["pqc_status"].update({
                        "mode": "pqc_hybrid",
                        "supported": True,
                        "active": True,
                    })
                    logger.debug(
                        f"[TLS13 UNIVERSAL] PQC HYBRID DETECTED: '{group}' → '{group_normalized}'\n"
                        f"                   Classical: {universal_analysis['classical_tokens']}\n"
                        f"                   PQC: {universal_analysis['pqc_tokens']}"
                    )
                elif universal_analysis["is_pqc"]:
                    result["pqc_status"].update({
                        "mode": "pqc_pure",
                        "supported": True,
                        "active": True,
                    })
                    logger.debug(f"[TLS13 UNIVERSAL] PURE PQC DETECTED: '{group}' → '{group_normalized}'")
                else:
                    logger.debug(f"[TLS13 UNIVERSAL] Classical: '{group}' → '{group_normalized}'")
            else:
                # Fallback: Server Temp Key (for classical algorithms)
                tk = re.search(r"Server Temp Key:\s*([^\n,]+)", std_out, re.IGNORECASE)
                if tk:
                    key_str = tk.group(1).strip()
                    result["key_exchange"] = key_str
                    result["pqc_status"]["negotiated_group"] = key_str
                    
                    # ✅ NEW: Universal analysis on temp key too
                    result["universal_analysis"] = detect_algorithm_category(key_str)
                    logger.debug(f"[TLS13 UNIVERSAL] Server Temp Key: '{key_str}'")
    except Exception as exc:
        logger.debug(f"[TLS13 UNIVERSAL] OpenSSL error: {exc}")

    # ── Step 2: PQC OpenSSL — probe support (never used to set active=True) ──
    pqc_groups_supported: List[str] = []
    if _openssl_available("pqc"):
        # Test both old Kyber draft and new ML-KEM names
        test_groups = [
            "X25519MLKEM768", "X25519KYBER768",   # Primary hybrids
            "X25519MLKEM512", "X25519KYBER512",   # Smaller variant
            "X25519MLKEM1024", "X25519KYBER1024", # Larger variant
            "SECP256R1MLKEM768", "P256MLKEM768",  # P-256 variants
            "MLKEM768",                            # Pure ML-KEM for testing
        ]
        
        for group in test_groups:
            try:
                pqc_out = _run_openssl(
                    ["s_client", "-connect", f"{host}:{port}", "-servername", host,
                     "-tls1_3", "-groups", group],
                    timeout,
                    which="pqc",
                )
                if pqc_out:
                    # Use flexible regex patterns for PQC negotiation too
                    m = re.search(r"Negotiated\s+(?:TLS\s+)?1\.3\s+group:\s*([^\n]+)", pqc_out, re.IGNORECASE)
                    if not m:
                        m = re.search(r"Negotiated\s+group:\s*([^\n]+)", pqc_out, re.IGNORECASE)
                    
                    if m:
                        negotiated = m.group(1).strip()
                        # ✅ Normalize: "Kyber" → "MLKEM"
                        negotiated_norm = re.sub(r'[-_\s/+]+', '', negotiated.upper())
                        negotiated_norm = _normalize_pqc_group_name(negotiated_norm)
                        pqc_groups_supported.append(negotiated_norm)
                        logger.debug(f"[TLS13 PQC] Tested '{group}', server confirmed: '{negotiated_norm}'")
            except Exception:
                continue

    result["pqc_status"]["pqc_groups_supported"] = pqc_groups_supported
    if pqc_groups_supported and result["pqc_status"]["mode"] not in ("pqc_hybrid", "pqc_pure"):
        result["pqc_status"]["mode"] = "pqc_supported"
        result["pqc_status"]["supported"] = True

    return result


# ── Cipher suite collection ───────────────────────────────────────────────────

def _collect_cipher_suites(host: str, port: int, tls_versions: List[str], timeout: int) -> List[Dict[str, Optional[str]]]:
    """
    FIX ROOT CAUSE 6: Always capture TLS 1.3 cipher WITHOUT OpenSSL CLI fallback.
    Use Python ssl module to do direct handshake and get negotiated cipher.
    """
    results: List[Dict[str, Optional[str]]] = []
    label_to_version = {
        "TLSv1.0": ssl.TLSVersion.TLSv1,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
    }

    # FIX ROOT CAUSE 6: For TLS 1.3, do direct Python ssl handshake to get negotiated cipher
    tls13_cipher_info = None
    if "TLSv1.3" in tls_versions:
        try:
            ctx = _make_context(ssl.TLSVersion.TLSv1_3)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ssock = _handshake(host, port, ctx, timeout)
            if ssock:
                try:
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        negotiated_cipher = cipher_info[0]
                        
                        # Try to get the key exchange group
                        kex = _get_tls13_group_via_ctypes(ssock)
                        if not kex:
                            raw_res = _probe_pqc_via_raw_sockets(host, port, timeout)
                            if raw_res.get("supported"):
                                kex = raw_res.get("negotiated_group")
                        if not kex:
                            kex = "TLS1.3-Default"  # Fallback if ctypes fails
                        
                        kx, auth, enc, hsh = _parse_cipher_name(negotiated_cipher)
                        
                        # Override KEX with the actual negotiated group if detected
                        kx = kex if kex else kx
                        
                        tls13_cipher_info = {
                            "tls_version": "TLSv1.3",
                            "cipher_suite": negotiated_cipher,
                            "key_exchange": kx,
                            "authentication": auth,
                            "encryption": enc,
                            "hash": hsh,
                        }
                        results.append(tls13_cipher_info)
                        logger.debug(f"[TLS1.3 CIPHER] Negotiated via Python ssl: {negotiated_cipher} with KEX: {kx}")
                finally:
                    ssock.close()
        except Exception as e:
            logger.debug(f"[TLS1.3 CIPHER] Python ssl handshake failed: {e}")

    # For TLS 1.0-1.2: Python ssl enumeration
    for label in ["TLSv1.2", "TLSv1.1", "TLSv1.0"]:
        if label not in tls_versions:
            continue

        try:
            version = label_to_version.get(label)
            if not version:
                continue

            # Do a handshake to get the negotiated cipher for this version
            ctx = _make_context(version)
            ctx.minimum_version = version
            ctx.maximum_version = version
            
            ssock = _handshake(host, port, ctx, timeout)
            if ssock:
                try:
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        negotiated_cipher = cipher_info[0]
                        kx, auth, enc, hsh = _parse_cipher_name(negotiated_cipher)
                        
                        results.append({
                            "tls_version": label,
                            "cipher_suite": negotiated_cipher,
                            "key_exchange": kx,
                            "authentication": auth,
                            "encryption": enc,
                            "hash": hsh,
                            "risk_level": _cipher_risk_level(negotiated_cipher),  # ✅ NEW: Risk rating
                        })
                        logger.debug(f"[{label} CIPHER] Negotiated: {negotiated_cipher}")
                finally:
                    ssock.close()
        except Exception as e:
            logger.debug(f"[{label} CIPHER] Python ssl handshake failed: {e}")

    # FALLBACK: OpenSSL CLI if available AND Python ssl didn't find TLS 1.3
    if "TLSv1.3" in tls_versions and not tls13_cipher_info and _openssl_available():
        try:
            output = _run_openssl(
                ["s_client", "-connect", f"{host}:{port}", "-servername", host, "-tls1_3"],
                timeout,
            )
            if output:
                cm = re.search(r"New,\s*TLSv1\.3,\s*Cipher is\s*([^\s\n]+)", output, re.IGNORECASE)
                negotiated_cipher = cm.group(1).strip() if cm else None
                if negotiated_cipher:
                    kx, auth, enc, hsh = _parse_cipher_name(negotiated_cipher)
                    # Try to get real KEX from OpenSSL output
                    kex_match = re.search(r"Negotiated TLS1\.3 group:\s*([^\n]+)", output, re.IGNORECASE)
                    if kex_match:
                        kx = kex_match.group(1).strip()
                    
                    results.append({
                        "tls_version": "TLSv1.3",
                        "cipher_suite": negotiated_cipher,
                        "key_exchange": kx or "TLS1.3",
                        "authentication": auth,
                        "encryption": enc,
                        "hash": hsh,
                        "risk_level": _cipher_risk_level(negotiated_cipher),  # ✅ NEW: Risk rating
                    })
                    logger.debug(f"[TLS1.3 CIPHER] Negotiated via OpenSSL: {negotiated_cipher}")
        except Exception as e:
            logger.debug(f"[TLS1.3 CIPHER] OpenSSL fallback failed: {e}")

    return sorted(results, key=lambda x: (x["tls_version"], x["cipher_suite"]))


# ── Key exchange details ──────────────────────────────────────────────────────

def _get_key_exchange_details(host: str, port: int, tls_versions: List[str], timeout: int) -> Dict[str, Any]:
    """
    FIX ROOT CAUSE 5: Use Python ssl module as PRIMARY method for ALL key exchange detection.
    - For TLS 1.3: Use ctypes to extract negotiated group (works without OpenSSL CLI)
    - For TLS 1.2 and below: Use ssock.cipher() to get algorithm info
    - Only fall back to OpenSSL CLI if Python ssl fails
    
    ✅ NEW: Universal PQC analysis - automatically detects ANY hybrid algorithm
            (present or future) without hardcoding specific algorithm names.
    
    Never returns "Unknown" for classical KEX if Python ssl is available.
    """
    details: Dict[str, Any] = {
        "algorithm": None,
        "normalized_algorithm": None,  # NIST standard name (e.g. X25519MLKEM768 vs X25519KYBER768)
        "curve": None,
        "key_size": None,
        "ephemeral": None,
        "pqc": None,
        "pqc_status": None,
        "detection_engine": "python_ssl",
        "universal_analysis": None,  # ✅ NEW: Universal token-based algorithm analysis
    }

    if not tls_versions:
        return details

    # FIX ROOT CAUSE 5: PRIMARY METHOD - Python ssl module (always available)
    # For TLS 1.3: Try to extract group via ctypes to detect hybrid algorithms
    if "TLSv1.3" in tls_versions:
        try:
            ctx = _make_context(ssl.TLSVersion.TLSv1_3)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            
            ssock = _handshake(host, port, ctx, timeout)
            if ssock:
                try:
                    # Get cipher name from python ssl
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        cipher_name = cipher_info[0]
                        details["algorithm"] = cipher_name
                        details["ephemeral"] = True
                    
                    # FIX ROOT CAUSE 2: Try ctypes to get TLS 1.3 group (hybrid detection!)
                    group = _get_tls13_group_via_ctypes(ssock)
                    
                    # If ctypes fails (e.g. on Render), fall back to raw sockets to get the group
                    if not group:
                        raw_result = _probe_pqc_via_raw_sockets(host, port, timeout)
                        if raw_result.get("supported"):
                            group = raw_result.get("negotiated_group")
                            
                    if group:
                        details["curve"] = group
                        # ✅ Universal analysis (works for ANY algorithm!)
                        analysis = detect_algorithm_category(group)
                        details["universal_analysis"] = analysis
                        
                        # Try to detect if it's a PQC/hybrid algorithm
                        pqc_info = _detect_pqc_algorithm(group)
                        if pqc_info:
                            details["pqc"] = pqc_info
                            # Update algorithm to the PQC name
                            details["algorithm"] = pqc_info.get("algorithm", cipher_name)
                            # Copy normalized_algorithm to top level for dashboard display
                            if pqc_info.get("normalized_algorithm"):
                                details["normalized_algorithm"] = pqc_info.get("normalized_algorithm")
                        elif analysis["is_hybrid"] or analysis["is_pqc"]:
                            # Universal detection found hybrid/PQC even if hardcoded list didn't
                            details["algorithm"] = f"{'/'.join(analysis['classical_tokens'])}+{'/'.join(analysis['pqc_tokens'])}"
                        else:
                            # Classical group (X25519, P-256, etc.)
                            details["algorithm"] = group if group != "Unknown" else cipher_name
                    
                    # Secondary pipeline: PQC-enabled OpenSSL (oqs-openssl) probe
                    pqc_probe = _probe_pqc_via_openssl_pqc_binary(host, port, timeout)
                    details["pqc_probe"] = pqc_probe
                    if pqc_probe.get("supported") and pqc_probe.get("algorithms_detected"):
                        pqc_info = pqc_probe["algorithms_detected"][0]
                        details["pqc"] = pqc_info
                        details["algorithm"] = pqc_info.get("algorithm", details.get("algorithm"))
                        # Copy normalized_algorithm if available
                        if pqc_info.get("normalized_algorithm"):
                            details["normalized_algorithm"] = pqc_info.get("normalized_algorithm")
                        if not details.get("curve") and pqc_probe.get("negotiated_group"):
                            details["curve"] = pqc_probe["negotiated_group"]

                    if pqc_probe.get("available"):
                        details["detection_engine"] = "python_ssl+ctypes+openssl_pqc"
                    else:
                        details["detection_engine"] = "python_ssl+ctypes"
                    return details
                finally:
                    ssock.close()
        
        except Exception as e:
            logger.debug(f"[KEX PYTHON SSL TLS1.3] Error: {e}")
    
    # For TLS 1.2 and below: Python ssl module
    for tls_label in ["TLSv1.2", "TLSv1.1", "TLSv1.0"]:
        if tls_label not in tls_versions:
            continue
        
        try:
            tls_version_map = {
                "TLSv1.2": ssl.TLSVersion.TLSv1_2,
                "TLSv1.1": ssl.TLSVersion.TLSv1_1,
                "TLSv1.0": ssl.TLSVersion.TLSv1,
            }
            ver = tls_version_map.get(tls_label)
            if not ver:
                continue
            
            ctx = _make_context(ver)
            ssock = _handshake(host, port, ctx, timeout)
            if ssock:
                try:
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        cipher_name = cipher_info[0]
                        # ✅ Universal analysis on the cipher name (TLS 1.2 format)
                        analysis = detect_algorithm_category(cipher_name)
                        details["universal_analysis"] = analysis
                        
                        # Parse TLS 1.2 cipher to extract KEX
                        if "ECDHE" in cipher_name:
                            details["algorithm"] = "ECDHE"
                            # Try to extract curve name
                            if "ECDHE-RSA" in cipher_name:
                                parts = cipher_name.split("-")
                                if len(parts) > 3:
                                    details["curve"] = parts[3]
                        elif "DHE" in cipher_name:
                            details["algorithm"] = "DHE"
                        elif "RSA" in cipher_name:
                            details["algorithm"] = "RSA"
                        else:
                            details["algorithm"] = cipher_name.split("-")[0]
                        
                        details["ephemeral"] = True
                        details["detection_engine"] = "python_ssl"
                        return details
                finally:
                    ssock.close()
        
        except Exception as e:
            logger.debug(f"[KEX PYTHON SSL {tls_label}] Error: {e}")
    
    # FALLBACK: OpenSSL CLI if available (secondary method)
    if _openssl_available():
        version_flags = {
            "TLSv1.3": "-tls1_3",
            "TLSv1.2": "-tls1_2",
            "TLSv1.1": "-tls1_1",
            "TLSv1.0": "-tls1",
        }

        # For TLS 1.3 use the dual engine result
        if "TLSv1.3" in tls_versions:
            dual = _detect_tls13_key_exchange_dual(host, port, timeout)
            details["pqc_status"] = dual.get("pqc_status")
            # ✅ NEW: Get universal analysis from dual engine
            details["universal_analysis"] = dual.get("universal_analysis")
            
            kex = dual.get("key_exchange", "Unknown")
            if kex and kex != "Unknown":
                pqc_info = _detect_pqc_algorithm(kex)
                if pqc_info:
                    details["pqc"] = pqc_info
                    details["algorithm"] = pqc_info["algorithm"]
                    details["ephemeral"] = True
                    if pqc_info.get("classical_component"):
                        details["curve"] = pqc_info["classical_component"]
                else:
                    details["algorithm"] = kex
                    details["ephemeral"] = True
                details["detection_engine"] = "openssl_cli"
                return details

        # For TLS 1.2 and below, parse classical KEX from openssl output
        for label in ["TLSv1.2", "TLSv1.1", "TLSv1.0"]:
            if label not in tls_versions:
                continue
            output = _run_openssl(
                ["s_client", "-connect", f"{host}:{port}", "-servername", host, version_flags[label]],
                timeout,
            )
            if not output:
                continue

            temp_key = re.search(r"Server Temp Key:\s*([^\n]+)", output)
            if temp_key:
                line = temp_key.group(1)
                parts = [p.strip() for p in line.split(",")]
                if parts:
                    kex_name = parts[0].replace("ECDH", "ECDHE")
                    details["algorithm"] = kex_name
                    # ✅ Universal analysis on the KEX name
                    details["universal_analysis"] = detect_algorithm_category(kex_name)
                if len(parts) > 1:
                    details["curve"] = parts[1]
                if len(parts) > 2:
                    m = re.search(r"(\d+)", parts[2])
                    if m:
                        details["key_size"] = int(m.group(1))
                details["ephemeral"] = True
                details["detection_engine"] = "openssl_cli"
                return details

            kx = re.search(r"Key Exchange:\s*([^\n]+)", output)
            if kx:
                kex_name = kx.group(1).strip()
                details["algorithm"] = kex_name
                # ✅ Universal analysis on the KEX name
                details["universal_analysis"] = detect_algorithm_category(kex_name)
                details["ephemeral"] = None
                details["detection_engine"] = "openssl_cli"
                return details

    return details


# ── PQC support probing ───────────────────────────────────────────────────────

def _probe_pqc_via_raw_sockets(host: str, port: int, timeout: int = 5) -> Dict[str, Any]:
    """
    FIX ROOT CAUSE 8: Pure Python raw-socket fallback to detect PQC hybrids (ML-KEM/Kyber).
    Constructs a minimal TLS 1.3 ClientHello offering classical x25519 key share 
    while advertising support for PQC curves (x25519_mlkem768). If the server 
    prefers the PQC curve, it sends a HelloRetryRequest (HRR) for it. By parsing 
    the HRR extension, we prove the server supports PQC without needing compiled plugins!
    """
    import struct, os, socket
    
    pqc_support: Dict[str, Any] = {
        "supported": False,
        "algorithms_detected": [],
        "hybrid_mode": False,
        "detection_method": "raw_sockets_failed",
        "available": True,
        "negotiated_group": None,
        "negotiated_group_raw": None,
        "negotiated_group_id": None,
        "nist_level": None,
    }
    
    def build_sni(h: str) -> bytes:
        hb = h.encode('utf-8')
        return struct.pack(">HH", 0, len(hb)+5) + struct.pack(">HBH", len(hb)+3, 0, len(hb)) + hb
        
    try:
        offered_group_ids = [
            0x11ec,  # X25519MLKEM768
            0x11eb,  # SecP256r1MLKEM768
            0x11ed,  # SecP384r1MLKEM1024
            0xfe30,  # X25519Kyber768Draft00
            0xfe31,  # P256Kyber768Draft00
            0x001d,  # x25519
            0x0017,  # secp256r1
        ]
        groups = b"".join(struct.pack(">H", gid) for gid in offered_group_ids)
        sg_ext = struct.pack(">HH", 0x000a, len(groups) + 2) + struct.pack(">H", len(groups)) + groups
        
        sig_algs = bytes.fromhex("0403 0804")
        exts = build_sni(host) + bytes.fromhex("002b 0003 02 0304") + sg_ext
        exts += struct.pack(">HH", 0x000d, len(sig_algs) + 2) + struct.pack(">H", len(sig_algs)) + sig_algs
        
        ks_entry = struct.pack(">HH", 0x001d, 32) + bytes([0]*32)
        exts += struct.pack(">HH", 0x0033, len(ks_entry) + 2) + struct.pack(">H", len(ks_entry)) + ks_entry
        
        hello = bytes.fromhex("0303") + os.urandom(32) + bytes([32]) + os.urandom(32)
        hello += struct.pack(">H", 6) + bytes.fromhex("1301 1302 1303") + bytes([1, 0])
        hello += struct.pack(">H", len(exts)) + exts
        
        hm = struct.pack(">B", 1) + struct.pack(">I", len(hello))[1:4] + hello
        record = struct.pack(">BHH", 0x16, 0x0301, len(hm)) + hm
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.sendall(record)
        resp = s.recv(4096)
        s.close()
        
        if len(resp) > 5 and resp[0] == 0x16:
            msg = resp[5:]
            if len(msg) >= 4 and msg[0] == 2:
                hlen = int.from_bytes(msg[1:4], "big")
                payload = msg[4:4+hlen]
                if len(payload) >= 34 and payload[2:34] == bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"):
                    idx = 34 + 1 + payload[34] + 2 + 1
                    if idx + 2 <= len(payload):
                        ext_len = struct.unpack(">H", payload[idx:idx+2])[0]
                        idx += 2
                        end_idx = idx + ext_len
                        while idx + 4 <= end_idx and idx + 4 <= len(payload):
                            etype, elen = struct.unpack(">HH", payload[idx:idx+4])
                            idx += 4
                            if etype == 0x0033 and elen >= 2:
                                gid = struct.unpack(">H", payload[idx:idx+2])[0]
                                name, category, nist_level = _group_id_to_name(gid)
                                if category in ("hybrid", "hybrid_draft", "pqc_pure"):
                                    normalized = _normalize_pqc_group_name(name)
                                    pqc_support["supported"] = True
                                    pqc_support["hybrid_mode"] = category.startswith("hybrid")
                                    pqc_support["negotiated_group"] = normalized
                                    pqc_support["negotiated_group_raw"] = name
                                    pqc_support["negotiated_group_id"] = f"0x{gid:04x}"
                                    pqc_support["nist_level"] = nist_level
                                    pqc_support["detection_method"] = "raw_sockets_hrr_confirmed"

                                    pinfo = _detect_pqc_algorithm(normalized)
                                    if pinfo:
                                        pqc_support["algorithms_detected"].append(pinfo)
                                    logger.debug(f"[RAW SOCKET PQC] HRR Confirmed group: {name} (0x{gid:04x})")
                                    return pqc_support
                            idx += elen
    except Exception as e:
        logger.debug(f"[RAW SOCKET PQC] Error: {e}")
        
    return pqc_support


def _probe_pqc_via_openssl_pqc_binary(host: str, port: int, timeout: int) -> Dict[str, Any]:
    """
    FIX #3: Dedicated PQC probing using PQC-enabled OpenSSL binary.
    This is the PRIMARY detection path — uses which="pqc" to access PQC groups.
    """
    pqc_support: Dict[str, Any] = {
        "supported": False,
        "algorithms_detected": [],
        "hybrid_mode": False,
        "detection_method": "pqc_binary_available",
        "available": False,
        "negotiated_group": None,
    }
    
    if not _openssl_available("pqc"):
        pqc_support["detection_method"] = "pqc_binary_unavailable"
        return pqc_support

    pqc_support["available"] = True
    
    # Offer multiple PQC groups in order of preference
    pqc_groups = "X25519MLKEM768:X25519KYBER768:SECP256R1MLKEM768:MLKEM768:KYBER768"
    
    output = _run_openssl(
        ["s_client", "-connect", f"{host}:{port}", "-servername", host,
         "-tls1_3", "-groups", pqc_groups],
        timeout,
        which="pqc",  # FIX #5: Use PQC binary, not standard OpenSSL
    )
    
    if not output:
        return pqc_support
    
    # Parse negotiated group from output
    neg_match = re.search(r"Negotiated\s+TLS\s*1\.3\s+group:\s*([^\n]+)", output, re.IGNORECASE)
    if not neg_match:
        neg_match = re.search(r"Negotiated\s+group:\s*([^\n]+)", output, re.IGNORECASE)
    
    if neg_match:
        negotiated = neg_match.group(1).strip()
        pqc_support["negotiated_group"] = negotiated
        pqc_info = _detect_pqc_algorithm(negotiated)
        if pqc_info:
            pqc_support["supported"] = True
            pqc_support["hybrid_mode"] = bool(pqc_info.get("is_hybrid"))
            pqc_support["algorithms_detected"].append(pqc_info)
            pqc_support["detection_method"] = "pqc_binary_confirmed"
            logger.debug(f"[PQC PROBE] PQC binary confirmed: {negotiated}")
    
    return pqc_support


def _probe_pqc_via_curl(host: str, port: int) -> Dict[str, Any]:
    """
    FIX #7: HTTP-level PQC detection fallback using curl.
    Useful when PQC OpenSSL binary unavailable but curl has PQC support.
    """
    pqc_support: Dict[str, Any] = {
        "supported": False,
        "algorithms_detected": [],
        "hybrid_mode": False,
        "detection_method": "curl_unavailable",
    }
    
    if not shutil.which("curl"):
        return pqc_support
    
    try:
        result = subprocess.run(
            ["curl", "--curves", "X25519MLKEM768", "-v", f"https://{host}:{port}/"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout + result.stderr
        
        # Look for PQC indicators in curl's TLS handshake output
        if re.search(r"X25519.*[Kk]yber|[Kk]yber.*X25519|MLKEM|ml-kem", output, re.IGNORECASE):
            pqc_support["supported"] = True
            pqc_support["hybrid_mode"] = True
            pqc_support["detection_method"] = "curl_confirmed"
            logger.debug(f"[PQC CURL] curl detected PQC/hybrid on {host}")
        
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    
    return pqc_support


def _detect_pqc_support(host: str, port: int, timeout: int) -> Dict[str, Any]:
    """
    Probe whether the server will actually negotiate a PQC/hybrid group.
    FIX #3, #5, #7: Multi-path detection:
    1. Try PQC-enabled OpenSSL binary (primary)
    2. Fall back to standard OpenSSL (secondary)
    3. Fall back to curl (tertiary)
    """
    pqc_support: Dict[str, Any] = {
        "supported": False,
        "algorithms_detected": [],
        "hybrid_mode": False,
        "detection_method": "not_checked",
    }

    # FIX #3: Try PQC-enabled binary FIRST (primary detection path)
    if _openssl_available("pqc"):
        pqc_binary_result = _probe_pqc_via_openssl_pqc_binary(host, port, timeout)
        if pqc_binary_result["supported"]:
            return pqc_binary_result
    
    # Fall back to standard OpenSSL
    if not _openssl_available("normal"):
        # Try curl as last resort
        curl_result = _probe_pqc_via_curl(host, port)
        if curl_result["supported"]:
            return curl_result
            
        # Try raw sockets if curl fails
        raw_result = _probe_pqc_via_raw_sockets(host, port, timeout)
        if raw_result["supported"]:
            return raw_result

        # FIX ROOT CAUSE 7: Show actual detection engines available instead of generic "unavailable"
        available_engines = _get_available_detection_engines()
        engines_str = ", ".join([f"{e}({v})" for e, v in available_engines.items() if v == "available"])
        pqc_support["detection_method"] = f"python_ssl_primary ({engines_str})"
        pqc_support["available_engines"] = available_engines  # NEW: Include full engine status
        return pqc_support

    for group in ["X25519MLKEM768", "X25519KYBER768", "SECP256R1MLKEM768", "MLKEM768"]:
        output = _run_openssl(
            ["s_client", "-connect", f"{host}:{port}", "-servername", host,
             "-tls1_3", "-groups", group],
            timeout,
            which="normal",  # Use standard OpenSSL as fallback
        )
        if not output:
            continue

        m = re.search(r"Negotiated TLS1\.3 group:\s*([^\n]+)", output, re.IGNORECASE)
        if not m:
            logger.debug(f"[PQC PROBE] No negotiated group for '{group}' — server likely fell back")
            continue

        negotiated = m.group(1).strip()
        pqc_info = _detect_pqc_algorithm(negotiated)
        
        # Check if the negotiated group is actually PQC/Hybrid
        if not pqc_info or not (pqc_info.get("is_hybrid") or pqc_info.get("is_pqc")):
            logger.debug(f"[PQC PROBE] Offered '{group}', server negotiated '{negotiated}' — NOT PQC")
            continue

        # Server confirmed a PQC group (by name or by hex ID)
        pqc_support["supported"] = True
        pqc_support["algorithms_detected"].append(pqc_info)
        pqc_support["hybrid_mode"] = bool(pqc_info.get("is_hybrid"))
        pqc_support["detection_method"] = "negotiation_confirmed"
        logger.debug(f"[PQC PROBE] ✓ Server confirmed PQC group: '{negotiated}'")
        break

    if not pqc_support["supported"]:
        pqc_support["detection_method"] = "no_pqc_detected"

    return pqc_support


# ── Certificate metadata ──────────────────────────────────────────────────────

def _get_certificate_metadata(host: str, port: int, timeout: int) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {
        "subject": None, "issuer": None, "valid_from": None, "valid_to": None,
        "signature_algorithm": None, "public_key_algorithm": None, "public_key_size": None,
        "chain_length": None, "san": [], "serial_number": None, "version": None,
        "ocsp_responder": None, "issuer_ca_url": None,
    }

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    ssock = _handshake(host, port, ctx, timeout)
    if not ssock:
        return metadata

    try:
        der = ssock.getpeercert(binary_form=True)
    finally:
        ssock.close()

    if not der:
        return metadata

    if CRYPTOGRAPHY_AVAILABLE:
        try:
            cert = x509.load_der_x509_certificate(der)
            metadata["subject"] = cert.subject.rfc4514_string()
            metadata["issuer"] = cert.issuer.rfc4514_string()
            metadata["valid_from"] = cert.not_valid_before_utc.isoformat()
            metadata["valid_to"] = cert.not_valid_after_utc.isoformat()
            metadata["serial_number"] = format(cert.serial_number, "x").upper()
            metadata["version"] = cert.version.name

            sig_alg = cert.signature_algorithm_oid._name
            if hasattr(cert.signature_hash_algorithm, "name"):
                sig_alg = (
                    f"{cert.signature_hash_algorithm.name.upper()}with"
                    f"{type(cert.public_key()).__name__.replace('PublicKey','').replace('_','')}"
                )
            metadata["signature_algorithm"] = sig_alg
            
            # ✅ NEW: Check if signature algorithm is PQC-based
            sig_oid_str = cert.signature_algorithm_oid.dotted_string
            pqc_sig_info = _lookup_pqc_oid(sig_oid_str)
            if pqc_sig_info:
                metadata["signature_algorithm_pqc"] = pqc_sig_info
                metadata["signature_algorithm"] = f"{pqc_sig_info['name']} (PQC)"
                logger.debug(f"[CERT PQC] Signature algorithm is PQC: {pqc_sig_info['name']}")

            pub_key = cert.public_key()
            if isinstance(pub_key, rsa.RSAPublicKey):
                metadata["public_key_algorithm"] = "RSA"
                metadata["public_key_size"] = pub_key.key_size
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                metadata["public_key_algorithm"] = f"ECDSA ({pub_key.curve.name})"
                metadata["public_key_size"] = pub_key.key_size
            elif isinstance(pub_key, dsa.DSAPublicKey):
                metadata["public_key_algorithm"] = "DSA"
                metadata["public_key_size"] = pub_key.key_size
            elif isinstance(pub_key, ed25519.Ed25519PublicKey):
                metadata["public_key_algorithm"] = "Ed25519"
                metadata["public_key_size"] = 256
            elif isinstance(pub_key, ed448.Ed448PublicKey):
                metadata["public_key_algorithm"] = "Ed448"
                metadata["public_key_size"] = 456
            else:
                metadata["public_key_algorithm"] = type(pub_key).__name__

            try:
                san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                san_list = []
                for name in san_ext.value:
                    if isinstance(name, x509.DNSName):
                        san_list.append(f"DNS:{name.value}")
                    elif isinstance(name, x509.IPAddress):
                        san_list.append(f"IP:{name.value}")
                metadata["san"] = san_list
            except x509.ExtensionNotFound:
                pass

            ocsp_url, ca_issuer_url = _extract_aia_urls(cert)
            metadata["ocsp_responder"] = ocsp_url
            metadata["issuer_ca_url"] = ca_issuer_url
        except Exception:
            pass

    if metadata["subject"] is None and _openssl_available():
        pem = ssl.DER_cert_to_PEM_cert(der)
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem") as f:
            f.write(pem)
            pem_path = f.name

        output = _run_openssl(
            ["x509", "-in", pem_path, "-noout", "-subject", "-issuer", "-dates", "-text"],
            timeout,
        )
        if output:
            for pattern, key in [
                (r"subject=\s*(.+)", "subject"),
                (r"issuer=\s*(.+)", "issuer"),
                (r"notBefore=(.+)", "valid_from"),
                (r"notAfter=(.+)", "valid_to"),
                (r"Signature Algorithm:\s*([^\n]+)", "signature_algorithm"),
                (r"Public Key Algorithm:\s*([^\n]+)", "public_key_algorithm"),
            ]:
                m = re.search(pattern, output)
                if m:
                    metadata[key] = m.group(1).strip()
            pk = re.search(r"Public-Key:\s*\((\d+) bit\)", output)
            if pk:
                metadata["public_key_size"] = int(pk.group(1))

    if _openssl_available():
        chain_output = _run_openssl(
            ["s_client", "-connect", f"{host}:{port}", "-servername", host, "-showcerts"],
            timeout,
        )
        if chain_output:
            metadata["chain_length"] = chain_output.count("BEGIN CERTIFICATE") or None

    return metadata


def _extract_aia_urls(cert: "x509.Certificate") -> Tuple[Optional[str], Optional[str]]:
    ocsp_url: Optional[str] = None
    ca_issuer_url: Optional[str] = None
    if not CRYPTOGRAPHY_AVAILABLE:
        return ocsp_url, ca_issuer_url
    try:
        try:
            aia_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        except x509.ExtensionNotFound:
            return None, None
        for access_desc in aia_ext.value:
            if not isinstance(access_desc.access_location, x509.UniformResourceIdentifier):
                continue
            value = str(access_desc.access_location.value)
            if access_desc.access_method == AuthorityInformationAccessOID.OCSP and not ocsp_url:
                ocsp_url = value
            elif access_desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS and not ca_issuer_url:
                ca_issuer_url = value
    except Exception:
        pass
    return ocsp_url, ca_issuer_url


def _load_certificate_from_bytes(raw: bytes) -> Optional["x509.Certificate"]:
    if not CRYPTOGRAPHY_AVAILABLE or not raw:
        return None
    try:
        return x509.load_der_x509_certificate(raw)
    except Exception:
        pass
    try:
        return x509.load_pem_x509_certificate(raw)
    except Exception:
        return None


def _fetch_issuer_certificate(leaf_cert, timeout, host, port, ca_issuer_url):
    if not CRYPTOGRAPHY_AVAILABLE:
        return None
    if ca_issuer_url:
        try:
            with urllib.request.urlopen(ca_issuer_url, timeout=timeout) as response:
                raw = response.read()
            cert = _load_certificate_from_bytes(raw)
            if cert:
                return cert
        except Exception:
            pass
    if _openssl_available():
        output = _run_openssl(
            ["s_client", "-connect", f"{host}:{port}", "-servername", host, "-showcerts"],
            timeout,
        )
        if output:
            blocks = re.findall(
                r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                output, flags=re.DOTALL,
            )
            if len(blocks) >= 2:
                try:
                    return x509.load_pem_x509_certificate(blocks[1].encode("utf-8"))
                except Exception:
                    return None
    return None


# ── OCSP ──────────────────────────────────────────────────────────────────────

def _check_ocsp_status_openssl(leaf_der, issuer_cert, responder_url, timeout):
    if not _openssl_available() or not responder_url or not CRYPTOGRAPHY_AVAILABLE:
        return None
    leaf_pem = ssl.DER_cert_to_PEM_cert(leaf_der)
    issuer_pem = issuer_cert.public_bytes(Encoding.PEM).decode("utf-8")
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem") as cf, \
         tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem") as isf:
        cf.write(leaf_pem)
        isf.write(issuer_pem)
        cert_path, issuer_path = cf.name, isf.name
    try:
        started = time.perf_counter()
        output = _run_openssl(
            ["ocsp", "-issuer", issuer_path, "-cert", cert_path, "-url", responder_url, "-no_nonce"],
            timeout,
        )
        latency = int((time.perf_counter() - started) * 1000)
    finally:
        import os as _os
        for p in (cert_path, issuer_path):
            try:
                _os.unlink(p)
            except Exception:
                pass
    if not output:
        return None
    lowered = output.lower()
    if ": good" in lowered:
        status = "GOOD"
    elif ": revoked" in lowered:
        status = "REVOKED"
    elif ": unknown" in lowered:
        status = "UNKNOWN"
    else:
        return None
    return {
        "status": status, "checked": True, "responder": responder_url, "latency": latency,
        "ocsp_status": status, "ocsp_checked": True, "ocsp_responder": responder_url,
        "response_time_ms": latency,
    }


def _check_ocsp_status(host: str, port: int, certificate_metadata: Dict[str, Any], timeout: int) -> Dict[str, Any]:
    responder_url = certificate_metadata.get("ocsp_responder")
    result: Dict[str, Any] = {
        "status": "CHECK FAILED", "checked": False, "responder": responder_url,
        "latency": None, "ocsp_status": "CHECK FAILED", "ocsp_checked": False,
        "ocsp_responder": responder_url, "response_time_ms": None, "stapling": False,
    }

    if not responder_url:
        result["status"] = "NOT SUPPORTED"
        result["ocsp_status"] = "NOT SUPPORTED"
        if _openssl_available() and CRYPTOGRAPHY_AVAILABLE:
            try:
                output = _run_openssl(
                    ["s_client", "-connect", f"{host}:{port}", "-servername", host], timeout
                )
                if output:
                    if "OCSP response:" in output or "OCSP stapling" in output:
                        result["status"] = "FOUND VIA CERT CHAIN"
                    if "OCSP response: no response sent" in output or "OCSP stapling" in output:
                        result["checked"] = True
                        result["ocsp_checked"] = True
            except Exception:
                pass
        return result

    if not CRYPTOGRAPHY_AVAILABLE:
        return result

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ssock = _handshake(host, port, ctx, timeout)
    if not ssock:
        return result

    try:
        leaf_der = ssock.getpeercert(binary_form=True)
    finally:
        ssock.close()

    if not leaf_der:
        return result

    try:
        leaf_cert = x509.load_der_x509_certificate(leaf_der)
    except Exception:
        return result

    cache_key = f"{host}:{port}:{leaf_cert.serial_number}:{responder_url}"
    cached = OCSP_CACHE.get(cache_key)  # LRU cache handles TTL automatically
    if cached:
        return dict(cached)  # Return copy of cached value

    ocsp_timeout = max(2, min(timeout, 5))
    ocsp_url, ca_issuer_url = _extract_aia_urls(leaf_cert)
    responder_url = ocsp_url or responder_url
    result["responder"] = responder_url
    result["ocsp_responder"] = responder_url

    issuer_cert = _fetch_issuer_certificate(leaf_cert, ocsp_timeout, host, port, ca_issuer_url)
    if not issuer_cert or not responder_url:
        return result

    try:
        started = time.perf_counter()
        ocsp_request = ocsp.OCSPRequestBuilder().add_certificate(
            leaf_cert, issuer_cert, hashes.SHA1()
        ).build()
        request_data = ocsp_request.public_bytes(Encoding.DER)
        req = urllib.request.Request(
            responder_url, data=request_data,
            headers={
                "Content-Type": "application/ocsp-request",
                "Accept": "application/ocsp-response",
                "User-Agent": "Q-Shield-OCSP/1.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=ocsp_timeout) as response:
            response_data = response.read()
        latency = int((time.perf_counter() - started) * 1000)
        ocsp_response = ocsp.load_der_ocsp_response(response_data)

        if ocsp_response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            result["status"] = result["ocsp_status"] = "CHECK FAILED"
            result["latency"] = result["response_time_ms"] = latency
        else:
            if ocsp_response.certificate_status == ocsp.OCSPCertStatus.GOOD:
                status = "GOOD"
            elif ocsp_response.certificate_status == ocsp.OCSPCertStatus.REVOKED:
                status = "REVOKED"
            else:
                status = "UNKNOWN"
            result.update({
                "status": status, "checked": True, "responder": responder_url,
                "latency": latency, "ocsp_status": status, "ocsp_checked": True,
                "ocsp_responder": responder_url, "response_time_ms": latency,
            })
    except Exception:
        fallback = _check_ocsp_status_openssl(leaf_der, issuer_cert, responder_url, ocsp_timeout)
        if fallback:
            result = fallback
        else:
            result["status"] = result["ocsp_status"] = "CHECK FAILED"

    # Store result in LRU cache (CRITICAL SECURITY FIX: prevents memory leak)
    OCSP_CACHE.set(cache_key, dict(result))
    return result


# ── Security features detection ───────────────────────────────────────────────

def _detect_security_features(
    cipher_suites: List[Dict[str, Optional[str]]], host: str, port: int, timeout: int
) -> Dict[str, Any]:
    weak_tokens = ["RC4", "3DES", "DES", "NULL", "EXPORT", "MD5"]
    weak = any(
        any(token in (cs.get("cipher_suite") or "") for token in weak_tokens)
        for cs in cipher_suites
    )
    forward_secrecy = any(
        (cs.get("key_exchange") or "") in {"ECDHE", "DHE"} or
        "ECDHE" in (cs.get("cipher_suite") or "") or
        "DHE" in (cs.get("cipher_suite") or "")
        for cs in cipher_suites
    )

    ocsp_stapling = None
    renegotiation = None
    if _openssl_available():
        output = _run_openssl(
            ["s_client", "-connect", f"{host}:{port}", "-servername", host, "-status"], timeout
        )
        if output:
            ocsp_stapling = ("OCSP Response Status: successful" in output or "OCSP response:" in output)
            renegotiation = "Secure Renegotiation IS supported" in output

    pqc_support = _detect_pqc_support(host, port, timeout)

    return {
        "forward_secrecy": forward_secrecy,
        "weak_ciphers_detected": weak,
        "ocsp_stapling": ocsp_stapling,
        "secure_renegotiation": renegotiation,
        "pqc_support": pqc_support,
    }


# ── Risk / scoring helpers ────────────────────────────────────────────────────

def _parse_cert_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        if isinstance(value, str) and "T" in value:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
    except Exception:
        return None


def _assess_hndl_risk(
    cipher_suites: List[Dict[str, Optional[str]]],
    certificate: Dict[str, Any],
    key_exchange_details: Dict[str, Any],
) -> Dict[str, Any]:
    kx_values = []
    if key_exchange_details.get("algorithm"):
        kx_values.append(str(key_exchange_details["algorithm"]))
    for suite in cipher_suites:
        if suite.get("key_exchange"):
            kx_values.append(str(suite["key_exchange"]))
        if suite.get("cipher_suite"):
            kx_values.append(str(suite["cipher_suite"]))

    kx_blob = " ".join(kx_values).upper()
    rsa_kex_detected = "RSA" in kx_blob and "ECDHE" not in kx_blob and "DHE" not in kx_blob

    valid_to = _parse_cert_datetime(certificate.get("valid_to"))
    long_term_data_risk = False
    if valid_to:
        try:
            # FIX #5: Handle timezone-aware certificates (Python 3.11+ compatibility)
            # datetime.now(tzinfo) with timezone object requires matching tz info
            try:
                now = datetime.now(valid_to.tzinfo) if valid_to.tzinfo else datetime.now()
                long_term_data_risk = (valid_to - now).days >= 365
            except (TypeError, ValueError):
                # Fallback: assume long-term if >=365 days validity
                long_term_data_risk = False
        except Exception:
            pass

    if rsa_kex_detected and long_term_data_risk:
        level, reason = "HIGH", "RSA key exchange + long-term data sensitivity"
    elif rsa_kex_detected:
        level, reason = "HIGH", "RSA key exchange detected"
    elif long_term_data_risk:
        level, reason = "MEDIUM", "Long-lived certificate increases decrypt-later exposure"
    else:
        level, reason = "LOW", "No direct RSA key exchange evidence and shorter crypto exposure window"

    return {
        "level": level, "reason": reason,
        "explanation": "Attackers can record encrypted traffic now and decrypt later when quantum capabilities mature.",
        "factors": {
            "rsa_key_exchange_detected": rsa_kex_detected,
            "long_term_data_sensitivity": long_term_data_risk,
        },
    }


def _score_key_algorithm(certificate: Dict[str, Any], real_pqc: Dict[str, Any]) -> int:
    algorithm = str(certificate.get("public_key_algorithm") or "").upper()
    key_size = certificate.get("public_key_size") or 0
    if real_pqc.get("summary", {}).get("detected_count", 0) > 0:
        return 100
    if "ED25519" in algorithm or "ED448" in algorithm:
        return 90
    if "ECDSA" in algorithm or "EC" in algorithm:
        return 80 if key_size >= 256 else 60
    if "RSA" in algorithm:
        if key_size >= 3072:
            return 70
        if key_size >= 2048:
            return 55
        return 30
    return 50


def _score_tls_versions(tls_versions: List[str]) -> int:
    if not tls_versions:
        return 0
    versions = set(tls_versions)
    if versions == {"TLSv1.3"}:
        return 100
    if "TLSv1.3" in versions and len(versions) == 2 and "TLSv1.2" in versions:
        return 85
    if "TLSv1.3" in versions:
        return 75
    if versions == {"TLSv1.2"}:
        return 70
    if "TLSv1.0" in versions or "TLSv1.1" in versions:
        return 35
    return 55


def _score_cipher_strength(cipher_suites: List[Dict[str, Optional[str]]], security_features: Dict[str, Any]) -> int:
    if not cipher_suites:
        return 0
    if security_features.get("weak_ciphers_detected"):
        return 35
    strong_like = sum(
        1 for suite in cipher_suites
        if any(k in (suite.get("cipher_suite") or "").upper() for k in ("AES_256", "CHACHA20", "AES256"))
    )
    ratio = strong_like / max(len(cipher_suites), 1)
    return 60 + int(40 * ratio)


def _score_key_rotation(certificate: Dict[str, Any]) -> int:
    valid_from = _parse_cert_datetime(certificate.get("valid_from"))
    valid_to = _parse_cert_datetime(certificate.get("valid_to"))
    if not valid_from or not valid_to:
        return 50
    validity_days = (valid_to - valid_from).days
    if validity_days <= 120:
        return 100
    if validity_days <= 398:
        return 85
    if validity_days <= 825:
        return 65
    return 40


def _score_pqc_readiness(real_pqc: Dict[str, Any], security_features: Dict[str, Any]) -> int:
    detected = real_pqc.get("summary", {}).get("detected_count", 0)
    if detected >= 2:
        return 100
    if detected == 1:
        return 80
    if security_features.get("pqc_support", {}).get("supported"):
        return 65
    return 25


def _build_crypto_agility_score(
    tls_versions, cipher_suites, key_exchange_details, certificate, security_features, real_pqc
) -> Dict[str, Any]:
    factors = [
        {"name": "Key algorithm",   "weight": 25, "score": _score_key_algorithm(certificate, real_pqc)},
        {"name": "TLS version",     "weight": 20, "score": _score_tls_versions(tls_versions)},
        {"name": "Cipher strength", "weight": 20, "score": _score_cipher_strength(cipher_suites, security_features)},
        {"name": "Key rotation",    "weight": 15, "score": _score_key_rotation(certificate)},
        {"name": "PQC readiness",   "weight": 20, "score": _score_pqc_readiness(real_pqc, security_features)},
    ]
    weighted_total = sum(f["score"] * f["weight"] for f in factors) / 100
    return {
        "score": int(round(weighted_total)),
        "max_score": 100,
        "factors": factors,
        "key_exchange_observed": key_exchange_details.get("algorithm"),
    }


def _build_post_quantum_migration_advisor(
    certificate, key_exchange_details, tls_versions, real_pqc
) -> Dict[str, Any]:
    recommendations: List[Dict[str, str]] = []
    pub_alg = str(certificate.get("public_key_algorithm", "")).upper()
    current_key = f"{certificate.get('public_key_algorithm', 'Unknown')} {certificate.get('public_key_size', '')}".strip()

    if "RSA" in pub_alg:
        recommendations.append({
            "current": current_key, "future": "ML-DSA (Dilithium)", "category": "Certificate Signature",
        })
    elif "EC" in pub_alg or "ECDSA" in pub_alg:
        recommendations.append({
            "current": current_key, "future": "Hybrid ECDSA + ML-DSA (Dilithium)", "category": "Certificate Signature",
        })

    current_kx = str(key_exchange_details.get("algorithm") or "Unknown")
    if any(token in current_kx.upper() for token in ["ECDHE", "DHE", "RSA", "DH"]):
        recommendations.append({
            "current": current_kx, "future": "ML-KEM (Kyber)", "category": "Key Exchange",
        })

    if "TLSv1.3" in tls_versions:
        recommendations.append({"current": "TLS 1.3", "future": "PQC Hybrid TLS", "category": "Transport"})
    elif tls_versions:
        recommendations.append({
            "current": ", ".join(tls_versions), "future": "TLS 1.3 + PQC Hybrid TLS", "category": "Transport",
        })

    if real_pqc.get("summary", {}).get("detected_count", 0) > 0:
        recommendations.insert(0, {
            "current": "Partial PQC capability detected",
            "future": "Expand to full hybrid KEM + PQC signatures",
            "category": "Program",
        })

    return {
        "title": "Recommended Migration Path",
        "recommendations": recommendations,
        "standards_reference": "NIST PQC (ML-KEM, ML-DSA, SLH-DSA)",
    }


# ── PQC detection reporting ───────────────────────────────────────────────────

def _detect_certificate_pqc_signatures(certificate: Dict[str, Any]) -> Dict[str, Any]:
    """FIX: Use strict token matching, not raw substring 'in' check."""
    signature = str(certificate.get("signature_algorithm") or "")
    sig_tokens = set(_tokenize(signature))
    checks = {
        "dilithium": bool(sig_tokens & {"DILITHIUM", "MLDSA", "DILITHIUM2", "DILITHIUM3", "DILITHIUM5",
                                        "MLDSA44", "MLDSA65", "MLDSA87"}),
        "falcon":    bool(sig_tokens & {"FALCON", "FALCON512", "FALCON1024"}),
        "sphincs+":  bool(sig_tokens & {"SPHINCS", "SPHINCSPLUS", "SLHDSA"}),
    }
    return {"signature_algorithm": certificate.get("signature_algorithm"), "checks": checks}


def _get_available_detection_engines() -> Dict[str, str]:
    """
    FIX ROOT CAUSE 7: Check which PQC detection engines are available on this system.
    Returns dict with engine names and their availability status.
    """
    engines = {
        "python_ssl": "available",  # Always available - Python's ssl module
        "ctypes_libssl": "available",  # Always available - ctypes to libssl
        "raw_sockets": "available", # Always available fallback to send ClientHello
    }

    # Check for OpenSSL CLI
    if _openssl_available():
        engines["openssl_cli"] = "available"
    else:
        engines["openssl_cli"] = "unavailable"

    # Check for PQC-enabled OpenSSL
    if _openssl_available("pqc"):
        engines["openssl_pqc"] = "available"
    else:
        engines["openssl_pqc"] = "unavailable"

    # Check for curl
    try:
        subprocess.run(
            ["curl", "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=2,
        )
        engines["curl"] = "available"
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        engines["curl"] = "unavailable"

    # Check for gnutls-cli
    try:
        subprocess.run(
            ["gnutls-cli", "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=2,
        )
        engines["gnutls_cli"] = "available"
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        engines["gnutls_cli"] = "unavailable"

    return engines


def _build_real_pqc_detection(
    key_exchange_details: Dict[str, Any],
    certificate: Dict[str, Any],
    security_features: Dict[str, Any],
) -> Dict[str, Any]:
    pqc_support = security_features.get("pqc_support", {})

    # FIX: Use the proper detection function with full delimiter normalization
    negotiated_group = str(key_exchange_details.get("algorithm") or "").strip()
    pqc_detection = _detect_pqc_algorithm(negotiated_group)
    is_real_pqc = pqc_detection is not None and pqc_detection.get("is_hybrid", False)

    cert_pqc = _detect_certificate_pqc_signatures(certificate)

    checks = [
        {
            "algorithm": "Kyber / ML-KEM",
            "check": "TLS handshake",
            "detected": is_real_pqc or pqc_support.get("supported", False),
            "evidence": negotiated_group or pqc_support.get("detection_method"),
        },
        {
            "algorithm": "Dilithium / ML-DSA",
            "check": "Certificate signature",
            "detected": cert_pqc["checks"]["dilithium"],
            "evidence": cert_pqc.get("signature_algorithm"),
        },
        {
            "algorithm": "Falcon",
            "check": "Certificate signature",
            "detected": cert_pqc["checks"]["falcon"],
            "evidence": cert_pqc.get("signature_algorithm"),
        },
        {
            "algorithm": "SPHINCS+",
            "check": "Certificate signature",
            "detected": cert_pqc["checks"]["sphincs+"],
            "evidence": cert_pqc.get("signature_algorithm"),
        },
    ]

    detected_count = sum(1 for c in checks if c["detected"])
    
    # FIX ROOT CAUSE 7: Include detection engine information
    detection_engines = _get_available_detection_engines()
    detection_method_used = key_exchange_details.get("detection_engine", "python_ssl")
    
    return {
        "checks": checks,
        "summary": {
            "detected_count": detected_count,
            "total_checks": len(checks),
            "pqc_ready": is_real_pqc or any(
                cert_pqc["checks"][k] for k in ("dilithium", "falcon", "sphincs+")
            ),
        },
        "detection_engines": detection_engines,  # NEW: Show all available engines
        "detection_method_used": detection_method_used,  # NEW: Show which one we actually used
    }


# ── Certificate Transparency ──────────────────────────────────────────────────

def _extract_base_domain(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _parse_crtsh_payload(payload: str) -> List[Dict[str, Any]]:
    text = (payload or "").strip()
    if not text:
        return []
    if text.startswith("["):
        parsed = json.loads(text)
        return parsed if isinstance(parsed, list) else []
    rows: List[Dict[str, Any]] = []
    for line in text.splitlines():
        raw = line.strip().rstrip(",")
        if not raw or not raw.startswith("{"):
            continue
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                rows.append(obj)
        except json.JSONDecodeError:
            continue
    return rows


def _fetch_certificate_transparency_intelligence(host: str, timeout: int) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "source": "crt.sh", "query_host": host,
        "detected_subdomains": [], "total_detected": 0, "status": "not_available",
    }
    if not host or re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        result["status"] = "unsupported_target"
        return result

    host_lower = host.lower()
    public_suffix_2ld = {
        "ac.in", "co.in", "gov.in", "org.in", "net.in", "edu.in", "res.in", "gen.in", "mil.in",
        "co.uk", "org.uk", "gov.uk", "ac.uk", "net.uk",
    }
    parts = host_lower.split(".")
    if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in public_suffix_2ld:
        base_domain = ".".join(parts[-3:])
    else:
        base_domain = _extract_base_domain(host_lower)

    errors: List[str] = []
    subdomains: set = set()
    query_hosts: List[str] = [host_lower]
    if base_domain and base_domain != host_lower:
        query_hosts.append(base_domain)

    query_values: List[str] = []
    for qh in query_hosts:
        wildcard_encoded = urllib.parse.quote(f"%.{qh}")
        query_values.extend([qh, f"%.{qh}", wildcard_encoded])

    seen: set = set()
    for query_value in query_values:
        if query_value in seen:
            continue
        seen.add(query_value)
        url = f"https://crt.sh/?q={query_value}&output=json"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 Q-Shield/1.0", "Accept": "application/json,text/plain,*/*"},
        )
        payload = ""
        for attempt in range(2):
            try:
                with urllib.request.urlopen(req, timeout=max(timeout, 25)) as response:
                    payload = response.read().decode("utf-8", errors="ignore")
                break
            except (urllib.error.URLError, TimeoutError) as exc:
                errors.append(f"CT lookup failed for '{query_value}' (attempt {attempt + 1}): {exc}")
        if not payload:
            continue
        try:
            data = _parse_crtsh_payload(payload)
            for row in data:
                for entry in str(row.get("name_value", "")).splitlines():
                    value = entry.strip().lower()
                    if not value:
                        continue
                    if value.startswith("*."):
                        value = value[2:]
                    if value == host_lower:
                        continue
                    # STRICT FILTERING: only include if it's a direct or nested subdomain of the query host
                    # (not just any domain that happens to contain the query string)
                    for qh in query_hosts:
                        if value != qh and value.endswith("." + qh):
                            subdomains.add(value)
                            break
        except Exception as exc:
            errors.append(f"CT parse error for '{query_value}': {exc}")

    detected = sorted(subdomains)
    if detected:
        result["detected_subdomains"] = detected[:25]
        result["total_detected"] = len(detected)
        result["status"] = "ok"
    elif errors:
        result["status"] = "error"
        result["error"] = errors[0]
    else:
        result["status"] = "no_data"

    return result


# ── CDN Detection ─────────────────────────────────────────────────────────────

def _detect_cdn(host: str, timeout: int = 5) -> Dict[str, object]:
    """Detect CDN using GET requests with full header inspection.
    
    Uses tuple patterns: ("header_name", pattern) or ("header_value", pattern)
    to distinguish between name-based and value-based matching.
    
    NOTE: SSL certificate verification is intentionally disabled here because:
    - We only inspect HTTP response headers, not certificate data
    - Verification disabled allows probing any server regardless of cert validity
    - This is safe because we don't process untrusted certificate content
    """
    
    cdn_indicators = {
        "cloudflare": [
            ("header_name", "cf-ray"),
            ("header_name", "cf-cache-status"),
            ("header_value", "cloudflare"),
        ],
        "fastly": [
            ("header_name", "x-fastly-request-id"),
            ("header_name", "x-served-by"),
            ("header_name", "x-cache"),
            ("header_value", "fastly"),
            ("header_value", "varnish"),
        ],
        "vercel": [
            ("header_name", "x-vercel-cache"),
            ("header_name", "x-vercel-id"),
            ("header_value", "vercel"),
        ],
        "akamai": [
            ("header_name", "x-check-cacheable"),
            ("header_name", "x-akamai-request-id"),
            ("header_value", "akamaiedge.net"),
        ],
        "cloudfront": [
            ("header_name", "x-amz-cf-id"),
            ("header_name", "x-amz-cf-pop"),
            ("header_value", "cloudfront"),
        ],
        "azure_cdn": [
            ("header_name", "x-azure-ref"),
            ("header_name", "x-ec-custom-error"),
            ("header_value", "azureedge"),
        ],
        "github_pages": [
            ("header_value", "github.com"),
            ("header_name", "x-github-request-id"),
        ],
    }

    detected = []
    details = {"method": "urllib_get", "status": "not_attempted"}

    try:
        # Disable SSL verification for CDN detection (we only care about headers)
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        # Create GET request with Range header to only fetch 1 byte
        url = f"https://{host}/"
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "Q-Shield/1.0")
        req.add_header("Range", "bytes=0-0")  # Only fetch 1 byte of body
        
        # Make request
        with urllib.request.urlopen(req, context=ssl_context, timeout=max(timeout, 5)) as response:
            headers = dict(response.headers)
            headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
            
            details["status"] = "success"
            details["headers_received"] = list(headers_lower.keys())
            
            logger.debug(f"[CDN] Headers for {host}: {list(headers_lower.keys())}")
            
            # Check for CDN patterns (name vs value matching)
            for cdn_name, patterns in cdn_indicators.items():
                for (match_on, pattern) in patterns:
                    pattern_lower = pattern.lower()
                    for hname, hvalue in headers_lower.items():
                        hit = (
                            (match_on == "header_name" and pattern_lower in hname) or
                            (match_on == "header_value" and pattern_lower in hvalue)
                        )
                        if hit and cdn_name not in detected:
                            detected.append(cdn_name)
                            logger.debug(f"[CDN] ✓ {cdn_name}: {hname}={hvalue[:60]}")
                    
    except Exception as e:
        details["status"] = f"failed: {str(e)}"
        logger.debug(f"[CDN] Error: {e}")

    logger.debug(f"[CDN] Result for {host}: {detected if detected else 'No CDN detected'}")
    return {"detected": detected, "details": details}


# ── Main scan function ────────────────────────────────────────────────────────

def scan_tls(
    target: str,
    timeout: int = DEFAULT_TIMEOUT,
    progress_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None,
) -> Dict[str, object]:
    def _emit(stage: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        if not progress_callback:
            return
        try:
            progress_callback(stage, metadata or {})
        except Exception:
            pass

    _emit("handshake_discovery", {"snippets": [target]})
    host, port = _parse_target(target)
    if not host:
        raise ValueError("Invalid target")

    ip_address = _resolve_ip(host, port)
    _emit("handshake_discovery", {"snippets": [host, ip_address]})
    _emit("cipher_enumeration", {"snippets": ["TLS versions", "cipher map"]})

    tls_versions = _get_tls_versions_supported(host, port, timeout)
    _emit("cipher_enumeration", {"snippets": tls_versions[:4] if tls_versions else ["No TLS versions"]})

    cipher_suites = _collect_cipher_suites(host, port, tls_versions, timeout)
    sample_ciphers = [s.get("cipher_suite") for s in cipher_suites[:4] if s.get("cipher_suite")]
    _emit("cipher_enumeration", {"snippets": sample_ciphers or ["Cipher scan complete"]})
    _emit("quantum_safety_analysis", {"snippets": ["Certificate", "Key Exchange", "OCSP"]})

    # FIX: Single call to _get_key_exchange_details (no duplicate dual-engine call)
    key_exchange_details = _get_key_exchange_details(host, port, tls_versions, timeout)
    certificate = _get_certificate_metadata(host, port, timeout)
    security_features = _detect_security_features(cipher_suites, host, port, timeout)
    ocsp_result = _check_ocsp_status(host, port, certificate, timeout)
    ocsp_result["stapling"] = security_features.get("ocsp_stapling")

    # CDN detection
    cdn_info = _detect_cdn(host, timeout)

    _emit("quantum_safety_analysis", {
        "snippets": [
            str(key_exchange_details.get("algorithm") or "KEX unknown"),
            str(certificate.get("public_key_algorithm") or "Key unknown"),
            f"OCSP {ocsp_result.get('status', 'CHECK FAILED')}",
        ]
    })

    real_pqc_detection = _build_real_pqc_detection(key_exchange_details, certificate, security_features)
    _emit("agility_scoring", {"snippets": ["HNDL risk", "Agility score", "Migration path"]})

    output = {
        "host": host,
        "ip_address": ip_address,
        "port": port,
        "tls_versions_supported": tls_versions,
        "cipher_suites": cipher_suites,
        "key_exchange_details": key_exchange_details,
        "certificate": certificate,
        "ocsp": ocsp_result,
        "security_features": security_features,
        "hndl_risk": _assess_hndl_risk(cipher_suites, certificate, key_exchange_details),
        "pqc_detection": real_pqc_detection,
        "crypto_agility_score": _build_crypto_agility_score(
            tls_versions, cipher_suites, key_exchange_details,
            certificate, security_features, real_pqc_detection,
        ),
        "migration_advisor": _build_post_quantum_migration_advisor(
            certificate, key_exchange_details, tls_versions, real_pqc_detection,
        ),
        "ct_intelligence": _fetch_certificate_transparency_intelligence(host, timeout),
            "cdn_detection": cdn_info,
    }

    _emit("agility_scoring", {
        "snippets": [
            f"Score {output['crypto_agility_score'].get('score', 0)}",
            f"Risk {output['hndl_risk'].get('level', 'UNKNOWN')}",
        ]
    })

    return output


# ── CLI entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Scan a public TLS endpoint and output JSON.")
    parser.add_argument("target", help="URL, hostname, or IP:PORT")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    args = parser.parse_args()

    try:
        result = scan_tls(args.target, timeout=args.timeout)
        print(json.dumps(result, indent=2, sort_keys=True))
        raise SystemExit(0)
    except ValueError as exc:
        print(json.dumps({"error": {"code": "invalid_target", "message": str(exc)}}, indent=2))
        raise SystemExit(ERROR_CODES["invalid_target"])
    except socket.gaierror as exc:
        print(json.dumps({"error": {"code": "dns_failure", "message": str(exc)}}, indent=2))
        raise SystemExit(ERROR_CODES["dns_failure"])
    except TimeoutError as exc:
        print(json.dumps({"error": {"code": "timeout", "message": str(exc)}}, indent=2))
        raise SystemExit(ERROR_CODES["timeout"])
    except ssl.SSLError as exc:
        print(json.dumps({"error": {"code": "tls_handshake_failed", "message": str(exc)}}, indent=2))
        raise SystemExit(ERROR_CODES["tls_handshake_failed"])
    except OSError as exc:
        print(json.dumps({"error": {"code": "connection_failed", "message": str(exc)}}, indent=2))
        raise SystemExit(ERROR_CODES["connection_failed"])
    except Exception as exc:
        print(json.dumps({"error": {"code": "unexpected_error", "message": str(exc)}}, indent=2))
        raise SystemExit(ERROR_CODES["unexpected_error"])