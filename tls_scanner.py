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

import json
import logging
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Dict, List, Optional, Tuple, Any

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
OCSP_CACHE: Dict[str, Dict[str, Any]] = {}

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
    "X25519MLKEM768",
    "X25519KYBER768",
    "P256MLKEM768",
    "P384MLKEM1024",
    "SECP256R1MLKEM768",
    "P256KYBER512",
    "P384KYBER768",
}

# Known PQC algorithm registry
PQC_ALGORITHMS = {
    "MLKEM512":          {"name": "ML-KEM-512",          "type": "kem",        "nist_level": 1},
    "MLKEM768":          {"name": "ML-KEM-768",          "type": "kem",        "nist_level": 3},
    "MLKEM1024":         {"name": "ML-KEM-1024",         "type": "kem",        "nist_level": 5},
    "KYBER512":          {"name": "Kyber-512",            "type": "kem",        "nist_level": 1},
    "KYBER768":          {"name": "Kyber-768",            "type": "kem",        "nist_level": 3},
    "KYBER1024":         {"name": "Kyber-1024",           "type": "kem",        "nist_level": 5},
    "X25519MLKEM768":    {"name": "X25519+MLKEM768",   "type": "hybrid_kem", "nist_level": 3, "classical": "X25519"},
    "X25519KYBER768":    {"name": "X25519+KYBER768",    "type": "hybrid_kem", "nist_level": 3, "classical": "X25519"},
    "P256MLKEM768":      {"name": "P256+MLKEM768",    "type": "hybrid_kem", "nist_level": 3, "classical": "P-256"},
    "P384MLKEM1024":     {"name": "P384+MLKEM1024",   "type": "hybrid_kem", "nist_level": 5, "classical": "P-384"},
    "SECP256R1MLKEM768": {"name": "secp256r1+MLKEM768","type": "hybrid_kem", "nist_level": 3, "classical": "secp256r1"},
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

# ── Logging ───────────────────────────────────────────────────────────────────

logger = logging.getLogger("qshield.pqc")
logger.setLevel(logging.DEBUG)

# ── OpenSSL helpers ───────────────────────────────────────────────────────────

# FIX: Defined once, deduplicated from 3 copies in original
OPENSSL_NORMAL = shutil.which("openssl") or "openssl"
OPENSSL_PQC    = os.environ.get("OPENSSL_PQC_BIN") or "openssl-pqc"


def _openssl_available(which: str = "normal") -> bool:
    if which == "pqc":
        return shutil.which(OPENSSL_PQC) is not None
    return shutil.which(OPENSSL_NORMAL) is not None


def _run_openssl(args: List[str], timeout: int, which: str = "normal") -> Optional[str]:
    """Run OpenSSL CLI. 'which' selects normal or PQC-enabled binary."""
    effective_timeout = max(timeout, 30)
    run_kwargs: Dict[str, Any] = {}
    if args and args[0] == "s_client":
        run_kwargs["input"] = "Q\n"

    binary = OPENSSL_NORMAL if which == "normal" else OPENSSL_PQC
    try:
        completed = subprocess.run(
            [binary] + args,
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
    Return True only if:
    - The full normalized name is a known hybrid composite (HYBRID_FULL_NAMES), or
    - The full normalized name (stripped of delimiters) is a known PQC algorithm key, or
    - A token exactly equals a known PQC indicator.
    """
    name_upper = normalize_name(name).upper()
    # Exact full-name match: handles "X25519MLKEM768", "MLKEM768" etc.
    if name_upper in HYBRID_FULL_NAMES:
        return True
    if name_upper in PQC_ALGORITHMS:
        return True
    # Normalized without delimiters: handles "X25519+ML-KEM-768" -> "X25519MLKEM768"
    compact = re.sub(r'[-_\s/+]+', '', name_upper)
    if compact in HYBRID_FULL_NAMES or compact in PQC_ALGORITHMS:
        return True
    # Token-level match: handles "ML-KEM-768" tokens ["ML","KEM","768"] — won't match,
    # but "KYBER768" -> ["KYBER768"] — wait, "KYBER768" not in indicators but "KYBER" is
    # Actually split "KYBER768" won't split, but "KYBER" token would. Let's also check
    # if any token STARTS WITH a known indicator (e.g. "KYBER768" starts with "KYBER")
    for tok in _tokenize(name):
        if tok in PQC_ALGORITHM_INDICATORS:
            return True
        if tok in PQC_ALGORITHMS:
            return True
        # Handle "KYBER768", "MLKEM512" etc where number is attached
        for indicator in PQC_ALGORITHM_INDICATORS:
            if tok.startswith(indicator) and tok[len(indicator):].isdigit():
                return True
    return False


def _is_hybrid_full_name(name: str) -> bool:
    """Return True only if the whole normalized name is a known hybrid algorithm."""
    return normalize_name(name).upper() in HYBRID_FULL_NAMES


def _detect_pqc_algorithm(algorithm_str: str) -> Optional[Dict[str, Any]]:
    """
    Detect if an algorithm string identifies a known PQC algorithm.
    Uses strict matching: hybrid names require full-string match;
    pure PQC names require exact token match.
    """
    if not algorithm_str:
        return None

    name_upper = normalize_name(algorithm_str).upper()
    tokens = _tokenize(name_upper)

    # Check registry — longest key first to prefer specific matches
    for key in sorted(PQC_ALGORITHMS.keys(), key=len, reverse=True):
        info = PQC_ALGORITHMS[key]
        is_hybrid_key = info["type"].startswith("hybrid")

        if is_hybrid_key:
            # Hybrid composites must match the entire normalized name
            if name_upper == key:
                logger.debug(f"[PQC DETECT] '{algorithm_str}' exact hybrid match '{key}'")
                return {
                    "detected": True,
                    "algorithm": info["name"],
                    "raw_name": algorithm_str,
                    "type": info["type"],
                    "nist_security_level": info["nist_level"],
                    "is_hybrid": True,
                    "classical_component": info.get("classical"),
                }
        else:
            # Pure PQC keys match if the key appears as a token
            if key in tokens:
                logger.debug(f"[PQC DETECT] '{algorithm_str}' token match '{key}'")
                return {
                    "detected": True,
                    "algorithm": info["name"],
                    "raw_name": algorithm_str,
                    "type": info["type"],
                    "nist_security_level": info["nist_level"],
                    "is_hybrid": False,
                    "classical_component": None,
                }

    # Draft/experimental indicators
    for indicator in PQC_ALGORITHM_INDICATORS:
        if indicator in tokens:
            logger.debug(f"[PQC DETECT] '{algorithm_str}' draft indicator '{indicator}'")
            return {
                "detected": True,
                "algorithm": algorithm_str,
                "raw_name": algorithm_str,
                "type": "unknown_pqc",
                "nist_security_level": None,
                "is_hybrid": _is_hybrid_full_name(algorithm_str),
                "classical_component": None,
            }

    return None


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
    """FIX: removed reference to undefined `os`/`logger` at top of original."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
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
    Dual-engine detection:
    - Standard OpenSSL: ground truth for what the server actually negotiated
    - PQC-enabled OpenSSL (if available): probes whether the server SUPPORTS PQC
      (only trusted when the server explicitly confirms the negotiated group)

    FIX: The old code marked pqc_active/hybrid=True just from "CONNECTED(" in
    the fallback probe output. That only means TCP/TLS succeeded — the server
    could have silently fallen back to X25519. We now only mark PQC active when
    the 'Negotiated TLS1.3 group' line from the server explicitly shows a PQC name.
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
            neg_match = re.search(r"Negotiated TLS1\.3 group:\s*([^\n]+)", std_out, re.IGNORECASE)
            if neg_match:
                group = neg_match.group(1).strip()
                # Normalize: convert "ML-KEM" to "MLKEM" so HTML checks work
                group_normalized = group.replace("-", "").replace(" ", "")
                result["key_exchange"] = group_normalized
                result["pqc_status"]["negotiated_group"] = group_normalized

                pqc_info = _detect_pqc_algorithm(group)
                if pqc_info and pqc_info["is_hybrid"]:
                    result["pqc_status"].update({
                        "mode": "pqc_active",
                        "supported": True,
                        "active": True,
                    })
                    logger.debug(f"[TLS13 DUAL] Standard OpenSSL: PQC active '{group}'")
                else:
                    logger.debug(f"[TLS13 DUAL] Standard OpenSSL: classical '{group}'")
            else:
                # Fallback: Server Temp Key
                tk = re.search(r"Server Temp Key:\s*([^\n]+)", std_out)
                if tk:
                    key_str = tk.group(1).strip().split(",")[0].strip()
                    result["key_exchange"] = key_str
                    result["pqc_status"]["negotiated_group"] = key_str
                    logger.debug(f"[TLS13 DUAL] Server Temp Key: '{key_str}'")
    except Exception as exc:
        logger.debug(f"[TLS13 DUAL] Standard OpenSSL error: {exc}")

    # ── Step 2: PQC OpenSSL — probe support (never used to set active=True) ──
    pqc_groups_supported: List[str] = []
    if _openssl_available("pqc"):
        for group in ["X25519MLKEM768", "X25519KYBER768", "SECP256R1MLKEM768", "MLKEM768"]:
            try:
                pqc_out = _run_openssl(
                    ["s_client", "-connect", f"{host}:{port}", "-servername", host,
                     "-tls1_3", "-groups", group],
                    timeout,
                    which="pqc",
                )
                if pqc_out:
                    m = re.search(r"Negotiated TLS1\.3 group:\s*([^\n]+)", pqc_out, re.IGNORECASE)
                    if m and m.group(1).strip().upper() == group.upper():
                        pqc_groups_supported.append(group)
                        logger.debug(f"[TLS13 DUAL] PQC OpenSSL: server confirmed '{group}'")
            except Exception:
                continue

    result["pqc_status"]["pqc_groups_supported"] = pqc_groups_supported
    if pqc_groups_supported and result["pqc_status"]["mode"] != "pqc_active":
        result["pqc_status"]["mode"] = "pqc_supported"
        result["pqc_status"]["supported"] = True

    return result


# ── Cipher suite collection ───────────────────────────────────────────────────

def _collect_cipher_suites(host: str, port: int, tls_versions: List[str], timeout: int) -> List[Dict[str, Optional[str]]]:
    results: List[Dict[str, Optional[str]]] = []
    label_to_version = {
        "TLSv1.0": ssl.TLSVersion.TLSv1,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
    }

    # Get the actual negotiated TLS 1.3 key exchange (standard OpenSSL only)
    tls13_kex_info = _detect_tls13_key_exchange_dual(host, port, timeout) if "TLSv1.3" in tls_versions else {}
    negotiated_kex = tls13_kex_info.get("key_exchange", "Unknown") if tls13_kex_info else "Unknown"

    for label in tls_versions:
        version = label_to_version.get(label)
        if not version:
            continue

        for cipher in _available_ciphers(version):
            if _probe_cipher(host, port, version, cipher, timeout):
                kx, auth, enc, hsh = _parse_cipher_name(cipher)

                # For TLS 1.3, use the real negotiated KEX (may be classical or PQC)
                if label == "TLSv1.3" and kx is None:
                    kx = negotiated_kex if negotiated_kex != "Unknown" else "TLS1.3"

                results.append({
                    "tls_version": label,
                    "cipher_suite": cipher,
                    "key_exchange": kx,
                    "authentication": auth,
                    "encryption": enc,
                    "hash": hsh,
                })

    # Fallback: if Python ssl couldn't enumerate TLS 1.3 suites
    has_tls13 = any(r.get("tls_version") == "TLSv1.3" for r in results)
    if "TLSv1.3" in tls_versions and not has_tls13 and _openssl_available():
        output = _run_openssl(
            ["s_client", "-connect", f"{host}:{port}", "-servername", host, "-tls1_3"],
            timeout,
        )
        if output:
            cm = re.search(r"New,\s*TLSv1\.3,\s*Cipher is\s*([^\s\n]+)", output, re.IGNORECASE)
            negotiated_cipher = cm.group(1).strip() if cm else None
            if negotiated_cipher:
                _, auth, enc, hsh = _parse_cipher_name(negotiated_cipher)
                results.append({
                    "tls_version": "TLSv1.3",
                    "cipher_suite": negotiated_cipher,
                    "key_exchange": negotiated_kex if negotiated_kex != "Unknown" else "TLS1.3",
                    "authentication": auth,
                    "encryption": enc,
                    "hash": hsh,
                })

    return sorted(results, key=lambda x: (x["tls_version"], x["cipher_suite"]))


# ── Key exchange details ──────────────────────────────────────────────────────

def _get_key_exchange_details(host: str, port: int, tls_versions: List[str], timeout: int) -> Dict[str, Any]:
    """
    FIX: original code in scan_tls() called _detect_tls13_key_exchange_dual() separately
    and then called _get_key_exchange_details() which duplicated work and could disagree.
    Now this is the single source of truth for key exchange info.
    """
    details: Dict[str, Any] = {
        "algorithm": None,
        "curve": None,
        "key_size": None,
        "ephemeral": None,
        "pqc": None,
        "pqc_status": None,
    }

    if not _openssl_available() or not tls_versions:
        return details

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
                details["algorithm"] = parts[0].replace("ECDH", "ECDHE")
            if len(parts) > 1:
                details["curve"] = parts[1]
            if len(parts) > 2:
                m = re.search(r"(\d+)", parts[2])
                if m:
                    details["key_size"] = int(m.group(1))
            details["ephemeral"] = True
            return details

        kx = re.search(r"Key Exchange:\s*([^\n]+)", output)
        if kx:
            details["algorithm"] = kx.group(1).strip()
            details["ephemeral"] = None
            return details

    return details


# ── PQC support probing ───────────────────────────────────────────────────────

def _detect_pqc_support(host: str, port: int, timeout: int) -> Dict[str, Any]:
    """
    Probe whether the server will actually negotiate a PQC/hybrid group.
    FIX: Only marks supported=True when the server's 'Negotiated TLS1.3 group'
    response EXACTLY matches the PQC group we offered — never from CONNECTED alone.
    """
    pqc_support: Dict[str, Any] = {
        "supported": False,
        "algorithms_detected": [],
        "hybrid_mode": False,
        "detection_method": "not_checked",
    }

    if not _openssl_available():
        pqc_support["detection_method"] = "openssl_unavailable"
        return pqc_support

    for group in ["X25519MLKEM768", "X25519KYBER768", "SECP256R1MLKEM768", "MLKEM768"]:
        output = _run_openssl(
            ["s_client", "-connect", f"{host}:{port}", "-servername", host,
             "-tls1_3", "-groups", group],
            timeout,
        )
        if not output:
            continue

        m = re.search(r"Negotiated TLS1\.3 group:\s*([^\n]+)", output, re.IGNORECASE)
        if not m:
            logger.debug(f"[PQC PROBE] No negotiated group for '{group}' — server likely fell back")
            continue

        negotiated = m.group(1).strip()
        if negotiated.upper() != group.upper():
            logger.debug(f"[PQC PROBE] Offered '{group}', server negotiated '{negotiated}' — NOT PQC")
            continue

        # Server confirmed our PQC group
        name_upper = normalize_name(negotiated).upper()
        if name_upper in HYBRID_FULL_NAMES:
            pqc_info = _detect_pqc_algorithm(negotiated)
            if pqc_info:
                pqc_support["supported"] = True
                pqc_support["algorithms_detected"].append(pqc_info)
                pqc_support["hybrid_mode"] = True
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
    cached = OCSP_CACHE.get(cache_key)
    now = time.time()
    if cached and (now - cached.get("timestamp", 0)) <= OCSP_CACHE_TTL_SECONDS:
        return dict(cached.get("value", result))

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

    OCSP_CACHE[cache_key] = {"timestamp": now, "value": dict(result)}
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
            long_term_data_risk = (valid_to - datetime.now(valid_to.tzinfo)).days >= 365
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


def _build_real_pqc_detection(
    key_exchange_details: Dict[str, Any],
    certificate: Dict[str, Any],
    security_features: Dict[str, Any],
) -> Dict[str, Any]:
    pqc_support = security_features.get("pqc_support", {})

    # FIX: Strict check — only trust the actual negotiated algorithm
    negotiated_group = str(key_exchange_details.get("algorithm") or "").strip()
    name_upper = normalize_name(negotiated_group).upper()
    is_real_pqc = name_upper in HYBRID_FULL_NAMES

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
    return {
        "checks": checks,
        "summary": {
            "detected_count": detected_count,
            "total_checks": len(checks),
            "pqc_ready": is_real_pqc or any(
                cert_pqc["checks"][k] for k in ("dilithium", "falcon", "sphincs+")
            ),
        },
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