import json
import re
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
import shutil

# Optional cryptography library for certificate parsing
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


@dataclass
class TargetInfo:
    host: str
    port: int
    ip_address: str


def _parse_target(target: str) -> Tuple[str, int]:
    target = target.strip()
    if "://" in target:
        parsed = urllib.parse.urlparse(target)
        host = parsed.hostname or ""
        port = parsed.port or 443
        return host, port

    # IPv6 in brackets, e.g., [2001:db8::1]:443
    if target.startswith("["):
        match = re.match(r"\[(.+)\](?::(\d+))?$", target)
        if match:
            host = match.group(1)
            port = int(match.group(2)) if match.group(2) else 443
            return host, port

    # Host:port (IPv4 or hostname)
    if ":" in target and target.count(":") == 1:
        host, port_str = target.split(":", 1)
        if port_str.isdigit():
            return host, int(port_str)

    return target, 443


def _resolve_ip(host: str, port: int) -> str:
    info = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return info[0][4][0]


def _make_context(version: ssl.TLSVersion) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = version
    ctx.maximum_version = version
    return ctx


def _handshake(host: str, port: int, ctx: ssl.SSLContext, timeout: int) -> Optional[ssl.SSLSocket]:
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        ssock = ctx.wrap_socket(sock, server_hostname=host)
        ssock.do_handshake()
        return ssock
    except Exception:
        sock.close()
        return None


def _supports_version(host: str, port: int, version: ssl.TLSVersion, timeout: int) -> bool:
    ctx = _make_context(version)
    ssock = _handshake(host, port, ctx, timeout)
    if ssock:
        ssock.close()
        return True
    return False


def _get_tls_versions_supported(host: str, port: int, timeout: int) -> List[str]:
    versions = []
    version_map = [
        ("TLSv1.0", "TLSv1"),
        ("TLSv1.1", "TLSv1_1"),
        ("TLSv1.2", "TLSv1_2"),
        ("TLSv1.3", "TLSv1_3"),
    ]

    for label, attr in version_map:
        if hasattr(ssl.TLSVersion, attr):
            version = getattr(ssl.TLSVersion, attr)
            if _supports_version(host, port, version, timeout):
                versions.append(label)
    return versions


def _parse_cipher_name(cipher_name: str) -> Tuple[Optional[str], Optional[str], str, Optional[str]]:
    """Parse cipher name in either IANA (TLS_*) or OpenSSL (ECDHE-RSA-*) format."""
    # TLS 1.3 IANA style: TLS_AES_128_GCM_SHA256
    if cipher_name.startswith("TLS_") and "_WITH_" not in cipher_name:
        # TLS 1.3 ciphers don't have explicit key exchange
        parts = cipher_name.replace("TLS_", "").split("_")
        # e.g., ["AES", "128", "GCM", "SHA256"]
        if len(parts) >= 4:
            enc = f"{parts[0]}-{parts[1]}-{parts[2]}"
            hsh = parts[3]
            return None, None, enc, hsh
        return None, None, cipher_name.replace("TLS_", "").replace("_", "-"), None

    # TLS 1.2 IANA style: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    match = re.match(r"TLS_(.+)_WITH_(.+)$", cipher_name)
    if match:
        kx_auth = match.group(1)
        enc_hash = match.group(2)

        kx = None
        auth = None
        if "_" in kx_auth:
            kx, auth = kx_auth.split("_", 1)
        else:
            kx = kx_auth

        parts = enc_hash.split("_")
        hash_alg = None
        if parts[-1].startswith("SHA") or parts[-1] in {"MD5"}:
            hash_alg = parts[-1]
            encryption = "-".join(parts[:-1])
        else:
            encryption = "-".join(parts)

        return kx, auth, encryption, hash_alg

    # OpenSSL style: ECDHE-RSA-AES256-GCM-SHA384, DHE-RSA-AES256-GCM-SHA384
    parts = cipher_name.split("-")
    if len(parts) < 2:
        return None, None, cipher_name, None

    kx = None
    auth = None
    enc_start = 0

    # Detect key exchange: ECDHE, DHE, RSA, PSK, etc.
    if parts[0] in {"ECDHE", "DHE", "DH", "ECDH"}:
        kx = parts[0]
        enc_start = 1
        # Second part might be auth: RSA, ECDSA, DSS, PSK
        if len(parts) > 1 and parts[1] in {"RSA", "ECDSA", "DSS", "PSK"}:
            auth = parts[1]
            enc_start = 2
    elif parts[0] == "RSA":
        kx = "RSA"
        auth = "RSA"
        enc_start = 1

    # Extract hash from the end
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


def _detect_tls13_key_exchange(host: str, port: int, timeout: int) -> Dict[str, Any]:
    """
    Detect the actual TLS 1.3 key exchange in use (X25519, P-256, hybrid, etc).
    Uses OpenSSL s_client -tlsextdebug to inspect the negotiated groups.
    Falls back to comprehensive checking if needed.
    """
    kex_info = {
        "key_exchange": "Unknown",
        "hybrid": False,
        "pqc": False,
        "algorithms": []
    }
    
    if not _openssl_available():
        return kex_info
    
    try:
        # OpenSSL s_client with extension debug
        output = _run_openssl(
            ["s_client", "-connect", f"{host}:{port}", "-servername", host, 
             "-tls1_3", "-tlsextdebug"],
            timeout,
        )
        
        if output:
            negotiated_group_match = re.search(r"Negotiated TLS1\.3 group:\s*([^\n]+)", output, re.IGNORECASE)
            if negotiated_group_match:
                negotiated_group = negotiated_group_match.group(1).strip()
                kex_upper = negotiated_group.upper()

                kex_info["key_exchange"] = negotiated_group
                kex_info["algorithms"] = [negotiated_group]

                if "MLKEM" in kex_upper or "KYBER" in kex_upper or "ML-KEM" in kex_upper:
                    kex_info["pqc"] = True
                    kex_info["hybrid"] = "X25519" in kex_upper or "P256" in kex_upper or "P384" in kex_upper or "SECP" in kex_upper

                return kex_info

            # Look for "Server Temp Key:" which shows negotiated ephemeral key exchange
            temp_key_match = re.search(r"Server Temp Key:\s*([^\n]+)", output)
            if temp_key_match:
                temp_key_str = temp_key_match.group(1).strip()
                
                # Parse: "X25519, 253 bits" or "X25519+ML-KEM-768, ..." or "hybrid(...)"
                kex_upper = temp_key_str.upper()
                
                # Check for hybrid/PQC indicators
                if "MLKEM" in kex_upper or "KYBER" in kex_upper or "ML-KEM" in kex_upper:
                    kex_info["pqc"] = True
                    kex_info["hybrid"] = "X25519" in kex_upper or "P256" in kex_upper or "P384" in kex_upper or "SECP" in kex_upper
                    
                    # Extract key exchange name
                    if "X25519MLKEM768" in kex_upper or "X25519+MLKEM768" in kex_upper or "X25519+ML-KEM-768" in kex_upper:
                        kex_info["key_exchange"] = "X25519+ML-KEM-768"
                        kex_info["algorithms"] = ["X25519", "ML-KEM-768"]
                    elif "MLKEM768" in kex_upper or "ML-KEM-768" in kex_upper:
                        kex_info["key_exchange"] = "ML-KEM-768"
                        kex_info["algorithms"] = ["ML-KEM-768"]
                    else:
                        kex_info["key_exchange"] = temp_key_str
                else:
                    # Traditional key exchange: X25519, P-256, P-384, etc.
                    kex_info["key_exchange"] = temp_key_str.split(",")[0].strip()
                    
                    # Extract algorithm name
                    if "X25519" in kex_upper:
                        kex_info["algorithms"] = ["X25519"]
                    elif "P-256" in kex_upper or "PRIME256V1" in kex_upper or "SECP256R1" in kex_upper:
                        kex_info["algorithms"] = ["P-256"]
                    elif "P-384" in kex_upper or "SECP384R1" in kex_upper:
                        kex_info["algorithms"] = ["P-384"]
                    elif "P-521" in kex_upper or "SECP521R1" in kex_upper:
                        kex_info["algorithms"] = ["P-521"]
                
                return kex_info
            
            # Fallback: check for "Server provided group" or similar
            groups_match = re.search(r"supported groups:\s*([^\n]+)", output, re.IGNORECASE)
            if groups_match:
                groups_str = groups_match.group(1).strip()
                groups_upper = groups_str.upper()
                
                # First supported group is usually preferred
                preferred = groups_str.split(",")[0].strip()
                kex_info["key_exchange"] = preferred
                
                if "MLKEM" in groups_upper or "KYBER" in groups_upper:
                    kex_info["pqc"] = True
                    if "X25519" in groups_upper:
                        kex_info["hybrid"] = True
                
                return kex_info
    
    except Exception:
        pass
    
    # Fallback: probe with specific groups to detect hybrid support
    hybrid_groups = [
        "X25519MLKEM768",
        "X25519:X25519MLKEM768",
        "P256MLKEM768",
    ]
    
    for group in hybrid_groups:
        try:
            output = _run_openssl(
                ["s_client", "-connect", f"{host}:{port}", "-servername", host,
                 "-tls1_3", "-groups", group],
                timeout,
            )
            
            if output and ("CONNECTED(" in output or "New, TLSv1.3" in output or "Protocol  : TLSv1.3" in output):
                kex_info["key_exchange"] = group
                kex_info["hybrid"] = True
                kex_info["pqc"] = True
                return kex_info
        except Exception:
            pass
    
    return kex_info


def _collect_cipher_suites(host: str, port: int, tls_versions: List[str], timeout: int) -> List[Dict[str, Optional[str]]]:
    results: List[Dict[str, Optional[str]]] = []
    label_to_version = {
        "TLSv1.0": ssl.TLSVersion.TLSv1,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
        "TLSv1.2": ssl.TLSVersion.TLSv1_2,
        "TLSv1.3": ssl.TLSVersion.TLSv1_3,
    }

    # For TLS 1.3, probe key exchange details via OpenSSL
    tls13_kex = _detect_tls13_key_exchange(host, port, timeout) if "TLSv1.3" in tls_versions else {}

    for label in tls_versions:
        version = label_to_version.get(label)
        if not version:
            continue

        for cipher in _available_ciphers(version):
            if _probe_cipher(host, port, version, cipher, timeout):
                kx, auth, enc, hsh = _parse_cipher_name(cipher)
                
                # For TLS 1.3, key exchange is None in cipher name - use detected value
                if label == "TLSv1.3" and kx is None:
                    kx = tls13_kex.get("key_exchange", "Unknown")
                
                results.append(
                    {
                        "tls_version": label,
                        "cipher_suite": cipher,
                        "key_exchange": kx,
                        "authentication": auth,
                        "encryption": enc,
                        "hash": hsh,
                    }
                )

    # Python's ssl module cannot always enumerate TLS 1.3 suites on some builds.
    # Fallback to OpenSSL negotiated parameters so UI still shows TLS 1.3 + hybrid KEX.
    has_tls13_entry = any(item.get("tls_version") == "TLSv1.3" for item in results)
    if "TLSv1.3" in tls_versions and not has_tls13_entry and _openssl_available():
        output = _run_openssl(["s_client", "-connect", f"{host}:{port}", "-servername", host, "-tls1_3"], timeout)
        if output:
            cipher_match = re.search(r"New,\s*TLSv1\.3,\s*Cipher is\s*([^\s\n]+)", output, re.IGNORECASE)
            negotiated_group_match = re.search(r"Negotiated TLS1\.3 group:\s*([^\n]+)", output, re.IGNORECASE)
            temp_key_match = re.search(r"Server Temp Key:\s*([^\n]+)", output)

            negotiated_cipher = cipher_match.group(1).strip() if cipher_match else None
            negotiated_kex = None
            if negotiated_group_match:
                negotiated_kex = negotiated_group_match.group(1).strip()
            elif temp_key_match:
                negotiated_kex = temp_key_match.group(1).strip().split(",")[0].strip()
            elif tls13_kex.get("key_exchange"):
                negotiated_kex = str(tls13_kex.get("key_exchange"))

            if negotiated_cipher:
                _, auth, enc, hsh = _parse_cipher_name(negotiated_cipher)
                results.append(
                    {
                        "tls_version": "TLSv1.3",
                        "cipher_suite": negotiated_cipher,
                        "key_exchange": negotiated_kex or "Unknown",
                        "authentication": auth,
                        "encryption": enc,
                        "hash": hsh,
                    }
                )

    return sorted(results, key=lambda x: (x["tls_version"], x["cipher_suite"]))


def _openssl_available() -> bool:
    return shutil.which("openssl") is not None


def _run_openssl(args: List[str], timeout: int) -> Optional[str]:
    effective_timeout = max(timeout, 30)
    run_kwargs: Dict[str, Any] = {}
    if args and args[0] == "s_client":
        # Ensure s_client exits after handshake so subprocess does not hang waiting for stdin.
        run_kwargs["input"] = "Q\n"

    try:
        completed = subprocess.run(
            ["openssl"] + args,
            capture_output=True,
            text=True,
            timeout=effective_timeout,
            **run_kwargs,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return None

    output = completed.stdout + completed.stderr
    if completed.returncode != 0:
        return output
    return output


def _get_certificate_metadata(host: str, port: int, timeout: int) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {
        "subject": None,
        "issuer": None,
        "valid_from": None,
        "valid_to": None,
        "signature_algorithm": None,
        "public_key_algorithm": None,
        "public_key_size": None,
        "chain_length": None,
        "san": [],  # Subject Alternative Names
        "serial_number": None,
        "version": None,
        "ocsp_responder": None,
        "issuer_ca_url": None,
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

    # Use cryptography library if available (preferred)
    if CRYPTOGRAPHY_AVAILABLE:
        try:
            cert = x509.load_der_x509_certificate(der)
            metadata["subject"] = cert.subject.rfc4514_string()
            metadata["issuer"] = cert.issuer.rfc4514_string()
            metadata["valid_from"] = cert.not_valid_before_utc.isoformat()
            metadata["valid_to"] = cert.not_valid_after_utc.isoformat()
            metadata["serial_number"] = format(cert.serial_number, 'x').upper()
            metadata["version"] = cert.version.name

            # Signature algorithm
            sig_alg = cert.signature_algorithm_oid._name
            if hasattr(cert.signature_hash_algorithm, 'name'):
                sig_alg = f"{cert.signature_hash_algorithm.name.upper()}with{type(cert.public_key()).__name__.replace('PublicKey', '').replace('_', '')}"
            metadata["signature_algorithm"] = sig_alg

            # Public key info
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
            elif isinstance(pub_key, (ed25519.Ed25519PublicKey,)):
                metadata["public_key_algorithm"] = "Ed25519"
                metadata["public_key_size"] = 256
            elif isinstance(pub_key, (ed448.Ed448PublicKey,)):
                metadata["public_key_algorithm"] = "Ed448"
                metadata["public_key_size"] = 456
            else:
                metadata["public_key_algorithm"] = type(pub_key).__name__

            # Subject Alternative Names
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
            pass  # Fall through to OpenSSL fallback

    # Fallback to OpenSSL CLI if cryptography didn't populate or isn't available
    if metadata["subject"] is None and _openssl_available():
        pem = ssl.DER_cert_to_PEM_cert(der)
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem") as f:
            f.write(pem)
            pem_path = f.name

        output = _run_openssl(["x509", "-in", pem_path, "-noout", "-subject", "-issuer", "-dates", "-text"], timeout)
        if output:
            subject_match = re.search(r"subject=\s*(.+)", output)
            issuer_match = re.search(r"issuer=\s*(.+)", output)
            not_before = re.search(r"notBefore=(.+)", output)
            not_after = re.search(r"notAfter=(.+)", output)
            sig_alg = re.search(r"Signature Algorithm:\s*([^\n]+)", output)
            pub_alg = re.search(r"Public Key Algorithm:\s*([^\n]+)", output)
            pub_key = re.search(r"Public-Key:\s*\((\d+) bit\)", output)

            if subject_match:
                metadata["subject"] = subject_match.group(1).strip()
            if issuer_match:
                metadata["issuer"] = issuer_match.group(1).strip()
            if not_before:
                metadata["valid_from"] = not_before.group(1).strip()
            if not_after:
                metadata["valid_to"] = not_after.group(1).strip()
            if sig_alg:
                metadata["signature_algorithm"] = sig_alg.group(1).strip()
            if pub_alg:
                metadata["public_key_algorithm"] = pub_alg.group(1).strip()
            if pub_key:
                metadata["public_key_size"] = int(pub_key.group(1).strip())

    # Get certificate chain length
    if _openssl_available():
        chain_output = _run_openssl(["s_client", "-connect", f"{host}:{port}", "-servername", host, "-showcerts"], timeout)
        if chain_output:
            metadata["chain_length"] = chain_output.count("BEGIN CERTIFICATE") or None

    return metadata


def _extract_aia_urls(cert: "x509.Certificate") -> Tuple[Optional[str], Optional[str]]:
    """Extract OCSP responder and CA issuer URL from certificate AIA extension."""
    ocsp_url: Optional[str] = None
    ca_issuer_url: Optional[str] = None

    if not CRYPTOGRAPHY_AVAILABLE:
        return ocsp_url, ca_issuer_url

    try:
        # Try to get AIA extension
        try:
            aia_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        except x509.ExtensionNotFound:
            # Certificate doesn't have AIA extension
            return None, None
        
        # Parse AIA access descriptors
        for access_desc in aia_ext.value:
            if not isinstance(access_desc.access_location, x509.UniformResourceIdentifier):
                continue
            value = str(access_desc.access_location.value)
            if access_desc.access_method == AuthorityInformationAccessOID.OCSP and not ocsp_url:
                ocsp_url = value
            elif access_desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS and not ca_issuer_url:
                ca_issuer_url = value
    except Exception as e:
        # Log but don't crash
        pass

    return ocsp_url, ca_issuer_url


def _load_certificate_from_bytes(raw: bytes) -> Optional["x509.Certificate"]:
    """Load DER or PEM encoded X.509 certificate bytes."""
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


def _fetch_issuer_certificate(
    leaf_cert: "x509.Certificate",
    timeout: int,
    host: str,
    port: int,
    ca_issuer_url: Optional[str],
) -> Optional["x509.Certificate"]:
    """Fetch issuer certificate via AIA CA Issuers URL, with OpenSSL chain fallback."""
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
        output = _run_openssl(["s_client", "-connect", f"{host}:{port}", "-servername", host, "-showcerts"], timeout)
        if output:
            blocks = re.findall(
                r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                output,
                flags=re.DOTALL,
            )
            if len(blocks) >= 2:
                try:
                    issuer_pem = blocks[1].encode("utf-8")
                    return x509.load_pem_x509_certificate(issuer_pem)
                except Exception:
                    return None

    return None


def _check_ocsp_status_openssl(
    leaf_der: bytes,
    issuer_cert: "x509.Certificate",
    responder_url: str,
    timeout: int,
) -> Optional[Dict[str, Any]]:
    """Fallback OCSP check using OpenSSL CLI."""
    if not _openssl_available() or not responder_url or not CRYPTOGRAPHY_AVAILABLE:
        return None

    leaf_pem = ssl.DER_cert_to_PEM_cert(leaf_der)
    issuer_pem = issuer_cert.public_bytes(Encoding.PEM).decode("utf-8")

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem") as cert_file, tempfile.NamedTemporaryFile(
        "w", delete=False, suffix=".pem"
    ) as issuer_file:
        cert_file.write(leaf_pem)
        issuer_file.write(issuer_pem)
        cert_path = cert_file.name
        issuer_path = issuer_file.name

    try:
        started = time.perf_counter()
        output = _run_openssl(
            [
                "ocsp",
                "-issuer",
                issuer_path,
                "-cert",
                cert_path,
                "-url",
                responder_url,
                "-no_nonce",
            ],
            timeout,
        )
        latency = int((time.perf_counter() - started) * 1000)
    finally:
        try:
            import os as _os

            _os.unlink(cert_path)
            _os.unlink(issuer_path)
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
        "status": status,
        "checked": True,
        "responder": responder_url,
        "latency": latency,
        "ocsp_status": status,
        "ocsp_checked": True,
        "ocsp_responder": responder_url,
        "response_time_ms": latency,
    }


def _check_ocsp_status(host: str, port: int, certificate_metadata: Dict[str, Any], timeout: int) -> Dict[str, Any]:
    """Check certificate trust in real time using OCSP with caching and graceful fallbacks."""
    responder_url = certificate_metadata.get("ocsp_responder")
    result: Dict[str, Any] = {
        "status": "CHECK FAILED",
        "checked": False,
        "responder": responder_url,
        "latency": None,
        "ocsp_status": "CHECK FAILED",
        "ocsp_checked": False,
        "ocsp_responder": responder_url,
        "response_time_ms": None,
        "stapling": False,
    }

    # If no OCSP responder found, return NOT SUPPORTED
    if not responder_url:
        result["status"] = "NOT SUPPORTED"
        result["ocsp_status"] = "NOT SUPPORTED"
        # Try OpenSSL fallback even without explicit responder URL
        if _openssl_available() and CRYPTOGRAPHY_AVAILABLE:
            try:
                output = _run_openssl(["s_client", "-connect", f"{host}:{port}", "-servername", host], timeout)
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
        ocsp_request = ocsp.OCSPRequestBuilder().add_certificate(leaf_cert, issuer_cert, hashes.SHA1()).build()
        request_data = ocsp_request.public_bytes(Encoding.DER)

        req = urllib.request.Request(
            responder_url,
            data=request_data,
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
            result["status"] = "CHECK FAILED"
            result["ocsp_status"] = "CHECK FAILED"
            result["latency"] = latency
            result["response_time_ms"] = latency
        else:
            if ocsp_response.certificate_status == ocsp.OCSPCertStatus.GOOD:
                status = "GOOD"
            elif ocsp_response.certificate_status == ocsp.OCSPCertStatus.REVOKED:
                status = "REVOKED"
            else:
                status = "UNKNOWN"

            result["status"] = status
            result["checked"] = True
            result["responder"] = responder_url
            result["latency"] = latency
            result["ocsp_status"] = status
            result["ocsp_checked"] = True
            result["ocsp_responder"] = responder_url
            result["response_time_ms"] = latency
    except Exception:
        fallback = _check_ocsp_status_openssl(leaf_der, issuer_cert, responder_url, ocsp_timeout)
        if fallback:
            result = fallback
        else:
            result["status"] = "CHECK FAILED"
            result["ocsp_status"] = "CHECK FAILED"

    OCSP_CACHE[cache_key] = {"timestamp": now, "value": dict(result)}
    return result


# Known PQC algorithm identifiers
PQC_ALGORITHMS = {
    # ML-KEM (formerly Kyber)
    "MLKEM512": {"name": "ML-KEM-512", "type": "kem", "security_level": 1, "nist_level": 1},
    "MLKEM768": {"name": "ML-KEM-768", "type": "kem", "security_level": 3, "nist_level": 3},
    "MLKEM1024": {"name": "ML-KEM-1024", "type": "kem", "security_level": 5, "nist_level": 5},
    "KYBER512": {"name": "Kyber-512", "type": "kem", "security_level": 1, "nist_level": 1},
    "KYBER768": {"name": "Kyber-768", "type": "kem", "security_level": 3, "nist_level": 3},
    "KYBER1024": {"name": "Kyber-1024", "type": "kem", "security_level": 5, "nist_level": 5},
    # Hybrid modes
    "X25519MLKEM768": {"name": "X25519+ML-KEM-768", "type": "hybrid_kem", "security_level": 3, "nist_level": 3, "classical": "X25519"},
    "X25519KYBER768": {"name": "X25519+Kyber-768", "type": "hybrid_kem", "security_level": 3, "nist_level": 3, "classical": "X25519"},
    "P256MLKEM768": {"name": "P-256+ML-KEM-768", "type": "hybrid_kem", "security_level": 3, "nist_level": 3, "classical": "P-256"},
    "P384MLKEM1024": {"name": "P-384+ML-KEM-1024", "type": "hybrid_kem", "security_level": 5, "nist_level": 5, "classical": "P-384"},
    "SECP256R1MLKEM768": {"name": "secp256r1+ML-KEM-768", "type": "hybrid_kem", "security_level": 3, "nist_level": 3, "classical": "secp256r1"},
    # ML-DSA (formerly Dilithium) - for signatures
    "MLDSA44": {"name": "ML-DSA-44", "type": "signature", "security_level": 2, "nist_level": 2},
    "MLDSA65": {"name": "ML-DSA-65", "type": "signature", "security_level": 3, "nist_level": 3},
    "MLDSA87": {"name": "ML-DSA-87", "type": "signature", "security_level": 5, "nist_level": 5},
    "DILITHIUM2": {"name": "Dilithium-2", "type": "signature", "security_level": 2, "nist_level": 2},
    "DILITHIUM3": {"name": "Dilithium-3", "type": "signature", "security_level": 3, "nist_level": 3},
    "DILITHIUM5": {"name": "Dilithium-5", "type": "signature", "security_level": 5, "nist_level": 5},
    # SLH-DSA (formerly SPHINCS+)
    "SLHDSA128": {"name": "SLH-DSA-128", "type": "signature", "security_level": 1, "nist_level": 1},
    "SLHDSA192": {"name": "SLH-DSA-192", "type": "signature", "security_level": 3, "nist_level": 3},
    "SLHDSA256": {"name": "SLH-DSA-256", "type": "signature", "security_level": 5, "nist_level": 5},
}


def _detect_pqc_algorithm(algorithm_str: str) -> Optional[Dict[str, Any]]:
    """Detect if an algorithm string contains PQC indicators."""
    if not algorithm_str:
        return None
    
    # Normalize the string
    alg_upper = algorithm_str.upper().replace("-", "").replace("_", "").replace(" ", "")
    
    # Check for known PQC algorithms. Match longer keys first so hybrid forms
    # like X25519MLKEM768 are not shadowed by generic MLKEM768.
    for key in sorted(PQC_ALGORITHMS.keys(), key=len, reverse=True):
        info = PQC_ALGORITHMS[key]
        if key in alg_upper:
            return {
                "detected": True,
                "algorithm": info["name"],
                "raw_name": algorithm_str,
                "type": info["type"],
                "nist_security_level": info["nist_level"],
                "is_hybrid": info["type"].startswith("hybrid"),
                "classical_component": info.get("classical"),
            }
    
    # Check for draft/experimental naming
    pqc_indicators = ["KYBER", "MLKEM", "DILITHIUM", "MLDSA", "SPHINCS", "SLHDSA", "BIKE", "HQC", "NTRU", "SABER"]
    for indicator in pqc_indicators:
        if indicator in alg_upper:
            return {
                "detected": True,
                "algorithm": algorithm_str,
                "raw_name": algorithm_str,
                "type": "unknown_pqc",
                "nist_security_level": None,
                "is_hybrid": "X25519" in alg_upper or "P256" in alg_upper or "P384" in alg_upper,
                "classical_component": None,
            }
    
    return None


def _get_key_exchange_details(host: str, port: int, tls_versions: List[str], timeout: int) -> Dict[str, Any]:
    details: Dict[str, Any] = {
        "algorithm": None,
        "curve": None,
        "key_size": None,
        "ephemeral": None,
        "pqc": None,  # Post-Quantum Cryptography details
    }

    if not _openssl_available() or not tls_versions:
        return details

    version_flags = {
        "TLSv1.3": "-tls1_3",
        "TLSv1.2": "-tls1_2",
        "TLSv1.1": "-tls1_1",
        "TLSv1.0": "-tls1",
    }

    for label in ["TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0"]:
        if label in tls_versions:
            # Try with PQC groups if OpenSSL supports them
            # OpenSSL 3.2+ with oqs-provider supports: -groups X25519MLKEM768
            output = _run_openssl(
                ["s_client", "-connect", f"{host}:{port}", "-servername", host, version_flags[label]],
                timeout,
            )
            if not output:
                continue

            # OpenSSL 3.x commonly prints this line for TLS 1.3 negotiated group
            negotiated_group = re.search(r"Negotiated TLS1\.3 group:\s*([^\n]+)", output, re.IGNORECASE)
            if negotiated_group:
                group_value = negotiated_group.group(1).strip()
                pqc_info = _detect_pqc_algorithm(group_value)
                if pqc_info:
                    details["pqc"] = pqc_info
                    details["algorithm"] = pqc_info["algorithm"]
                else:
                    details["algorithm"] = group_value
                details["ephemeral"] = True
                return details

            temp_key = re.search(r"Server Temp Key:\s*([^\n]+)", output)
            if temp_key:
                line = temp_key.group(1)
                
                # Check for PQC algorithm
                pqc_info = _detect_pqc_algorithm(line)
                if pqc_info:
                    details["pqc"] = pqc_info
                    details["algorithm"] = pqc_info["algorithm"]
                    details["ephemeral"] = True
                    if pqc_info.get("classical_component"):
                        details["curve"] = pqc_info["classical_component"]
                    return details
                
                # Classical key exchange parsing
                parts = [p.strip() for p in line.split(",")]
                if parts:
                    details["algorithm"] = parts[0].replace("ECDH", "ECDHE")
                if len(parts) > 1:
                    details["curve"] = parts[1]
                if len(parts) > 2:
                    size_match = re.search(r"(\d+)", parts[2])
                    if size_match:
                        details["key_size"] = int(size_match.group(1))
                details["ephemeral"] = True
                return details

            kx = re.search(r"Key Exchange:\s*([^\n]+)", output)
            if kx:
                kx_value = kx.group(1).strip()
                pqc_info = _detect_pqc_algorithm(kx_value)
                if pqc_info:
                    details["pqc"] = pqc_info
                    details["algorithm"] = pqc_info["algorithm"]
                else:
                    details["algorithm"] = kx_value
                details["ephemeral"] = None
                return details

    return details


def _detect_pqc_support(host: str, port: int, timeout: int) -> Dict[str, Any]:
    """
    Attempt to detect PQC support by trying to negotiate with PQC groups.
    This requires OpenSSL 3.2+ with oqs-provider or similar.
    """
    pqc_support = {
        "supported": False,
        "algorithms_detected": [],
        "hybrid_mode": False,
        "detection_method": None,
    }
    
    if not _openssl_available():
        pqc_support["detection_method"] = "openssl_unavailable"
        return pqc_support
    
    # Check OpenSSL version
    version_output = _run_openssl(["version"], timeout)
    if version_output:
        pqc_support["openssl_version"] = version_output.strip()
    
    # Try to list available groups (OpenSSL 3.x)
    # This would show PQC groups if oqs-provider is loaded
    ecparam_output = _run_openssl(["ecparam", "-list_curves"], timeout)
    
    # Try connecting with specific PQC groups
    pqc_groups_to_try = [
        "X25519MLKEM768",
        "X25519Kyber768Draft00", 
        "SecP256r1MLKEM768",
        "MLKEM768",
        "X25519:X25519MLKEM768",  # Hybrid preference
    ]
    
    for group in pqc_groups_to_try:
        output = _run_openssl(
            ["s_client", "-connect", f"{host}:{port}", "-servername", host, 
             "-tls1_3", "-groups", group],
            timeout,
        )
        if output:
            handshake_ok = (
                "CONNECTED(" in output
                or "New, TLSv1.3" in output
                or "Protocol  : TLSv1.3" in output
                or "SSL handshake has read" in output
            )

            negotiated_group_match = re.search(r"Negotiated TLS1\.3 group:\s*([^\n]+)", output, re.IGNORECASE)
            if negotiated_group_match and handshake_ok:
                negotiated_group = negotiated_group_match.group(1).strip()
                pqc_info = _detect_pqc_algorithm(negotiated_group)
                if pqc_info:
                    pqc_support["supported"] = True
                    pqc_support["algorithms_detected"].append(pqc_info)
                    pqc_support["hybrid_mode"] = pqc_info.get("is_hybrid", False)
                    pqc_support["detection_method"] = "openssl_groups_negotiation"
                    break

            # Check if connection succeeded with this group
            if "Server Temp Key:" in output:
                temp_key = re.search(r"Server Temp Key:\s*([^\n]+)", output)
                if temp_key:
                    key_info = temp_key.group(1)
                    pqc_info = _detect_pqc_algorithm(key_info)
                    if pqc_info:
                        pqc_support["supported"] = True
                        pqc_support["algorithms_detected"].append(pqc_info)
                        pqc_support["hybrid_mode"] = pqc_info.get("is_hybrid", False)
                        pqc_support["detection_method"] = "openssl_groups_negotiation"
                        break
            
            # Also check for successful handshake indicators
            if handshake_ok:
                # Connection succeeded, check what was negotiated
                pqc_info = _detect_pqc_algorithm(group)
                if pqc_info:
                    pqc_support["supported"] = True
                    pqc_support["algorithms_detected"].append(pqc_info)
                    pqc_support["detection_method"] = "openssl_groups_negotiation"
    
    if not pqc_support["supported"]:
        pqc_support["detection_method"] = "no_pqc_detected"
    
    return pqc_support


def _detect_security_features(cipher_suites: List[Dict[str, Optional[str]]], host: str, port: int, timeout: int) -> Dict[str, Any]:
    weak_tokens = ["RC4", "3DES", "DES", "NULL", "EXPORT", "MD5"]
    weak = any(any(token in (cs.get("cipher_suite") or "") for token in weak_tokens) for cs in cipher_suites)
    # Check both parsed key_exchange field and raw cipher suite name for forward secrecy indicators
    forward_secrecy = any(
        (cs.get("key_exchange") or "") in {"ECDHE", "DHE"} or
        "ECDHE" in (cs.get("cipher_suite") or "") or
        "DHE" in (cs.get("cipher_suite") or "")
        for cs in cipher_suites
    )

    ocsp_stapling = None
    renegotiation = None

    if _openssl_available():
        output = _run_openssl(["s_client", "-connect", f"{host}:{port}", "-servername", host, "-status"], timeout)
        if output:
            ocsp_stapling = "OCSP Response Status: successful" in output or "OCSP response:" in output
            renegotiation = "Secure Renegotiation IS supported" in output

    # Detect PQC support
    pqc_support = _detect_pqc_support(host, port, timeout)

    return {
        "forward_secrecy": forward_secrecy,
        "weak_ciphers_detected": weak,
        "ocsp_stapling": ocsp_stapling,
        "secure_renegotiation": renegotiation,
        "pqc_support": pqc_support,
    }


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
        kx_values.append(str(key_exchange_details.get("algorithm", "")))
    for suite in cipher_suites:
        if suite.get("key_exchange"):
            kx_values.append(str(suite.get("key_exchange", "")))
        if suite.get("cipher_suite"):
            kx_values.append(str(suite.get("cipher_suite", "")))

    kx_blob = " ".join(kx_values).upper()
    rsa_kex_detected = "RSA" in kx_blob and "ECDHE" not in kx_blob and "DHE" not in kx_blob

    valid_to = _parse_cert_datetime(certificate.get("valid_to"))
    long_term_data_risk = False
    if valid_to:
        try:
            long_term_data_risk = (valid_to - datetime.now(valid_to.tzinfo)).days >= 365
        except Exception:
            long_term_data_risk = False

    if rsa_kex_detected and long_term_data_risk:
        level = "HIGH"
        reason = "RSA key exchange + long-term data sensitivity"
    elif rsa_kex_detected:
        level = "HIGH"
        reason = "RSA key exchange detected"
    elif long_term_data_risk:
        level = "MEDIUM"
        reason = "Long-lived certificate increases decrypt-later exposure"
    else:
        level = "LOW"
        reason = "No direct RSA key exchange evidence and shorter crypto exposure window"

    return {
        "level": level,
        "reason": reason,
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

    strong_like = 0
    for suite in cipher_suites:
        name = (suite.get("cipher_suite") or "").upper()
        if "AES_256" in name or "CHACHA20" in name or "AES256" in name:
            strong_like += 1
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
    tls_versions: List[str],
    cipher_suites: List[Dict[str, Optional[str]]],
    key_exchange_details: Dict[str, Any],
    certificate: Dict[str, Any],
    security_features: Dict[str, Any],
    real_pqc: Dict[str, Any],
) -> Dict[str, Any]:
    factors = [
        {"name": "Key algorithm", "weight": 25, "score": _score_key_algorithm(certificate, real_pqc)},
        {"name": "TLS version", "weight": 20, "score": _score_tls_versions(tls_versions)},
        {"name": "Cipher strength", "weight": 20, "score": _score_cipher_strength(cipher_suites, security_features)},
        {"name": "Key rotation", "weight": 15, "score": _score_key_rotation(certificate)},
        {"name": "PQC readiness", "weight": 20, "score": _score_pqc_readiness(real_pqc, security_features)},
    ]

    weighted_total = sum(f["score"] * f["weight"] for f in factors) / 100
    return {
        "score": int(round(weighted_total)),
        "max_score": 100,
        "factors": factors,
        "key_exchange_observed": key_exchange_details.get("algorithm"),
    }


def _build_post_quantum_migration_advisor(
    certificate: Dict[str, Any],
    key_exchange_details: Dict[str, Any],
    tls_versions: List[str],
    real_pqc: Dict[str, Any],
) -> Dict[str, Any]:
    recommendations: List[Dict[str, str]] = []

    current_key = f"{certificate.get('public_key_algorithm', 'Unknown')} {certificate.get('public_key_size', '')}".strip()
    if "RSA" in str(certificate.get("public_key_algorithm", "")).upper():
        recommendations.append({
            "current": current_key,
            "future": "ML-DSA (Dilithium)",
            "category": "Certificate Signature",
        })
    elif "EC" in str(certificate.get("public_key_algorithm", "")).upper() or "ECDSA" in str(certificate.get("public_key_algorithm", "")).upper():
        recommendations.append({
            "current": current_key,
            "future": "Hybrid ECDSA + ML-DSA (Dilithium)",
            "category": "Certificate Signature",
        })

    current_kx = str(key_exchange_details.get("algorithm") or "Unknown")
    if any(token in current_kx.upper() for token in ["ECDHE", "DHE", "RSA", "DH"]):
        recommendations.append({
            "current": current_kx,
            "future": "ML-KEM (Kyber)",
            "category": "Key Exchange",
        })

    if "TLSv1.3" in tls_versions:
        recommendations.append({
            "current": "TLS 1.3",
            "future": "PQC Hybrid TLS",
            "category": "Transport",
        })
    elif tls_versions:
        recommendations.append({
            "current": ", ".join(tls_versions),
            "future": "TLS 1.3 + PQC Hybrid TLS",
            "category": "Transport",
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


def _detect_certificate_pqc_signatures(certificate: Dict[str, Any]) -> Dict[str, Any]:
    signature = str(certificate.get("signature_algorithm") or "").upper()
    checks = {
        "dilithium": "DILITHIUM" in signature or "MLDSA" in signature or "ML-DSA" in signature,
        "falcon": "FALCON" in signature,
        "sphincs+": "SPHINCS" in signature or "SLHDSA" in signature or "SLH-DSA" in signature,
    }
    return {
        "signature_algorithm": certificate.get("signature_algorithm"),
        "checks": checks,
    }


def _build_real_pqc_detection(
    key_exchange_details: Dict[str, Any],
    certificate: Dict[str, Any],
    security_features: Dict[str, Any],
) -> Dict[str, Any]:
    pqc_support = security_features.get("pqc_support", {})
    key_algorithms = [
        str(key_exchange_details.get("algorithm") or ""),
        *(str(item.get("algorithm") or "") for item in pqc_support.get("algorithms_detected", [])),
    ]
    key_blob = " ".join(key_algorithms).upper()

    cert_pqc = _detect_certificate_pqc_signatures(certificate)

    checks = [
        {
            "algorithm": "Kyber",
            "check": "TLS handshake",
            "detected": "KYBER" in key_blob or "MLKEM" in key_blob or "ML-KEM" in key_blob,
            "evidence": key_exchange_details.get("algorithm") or pqc_support.get("detection_method"),
        },
        {
            "algorithm": "Dilithium",
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

    detected_count = sum(1 for item in checks if item["detected"])
    return {
        "checks": checks,
        "summary": {
            "detected_count": detected_count,
            "total_checks": len(checks),
            "pqc_ready": detected_count > 0,
        },
    }


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

    # Common case: valid JSON array
    if text.startswith("["):
        parsed = json.loads(text)
        return parsed if isinstance(parsed, list) else []

    # Fallback: newline-delimited JSON objects
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
        "source": "crt.sh",
        "query_host": host,
        "detected_subdomains": [],
        "total_detected": 0,
        "status": "not_available",
    }

    if not host or re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        result["status"] = "unsupported_target"
        return result

    host_lower = host.lower()

    # Handle common multi-part public suffixes to avoid over-broad queries (e.g., ac.in).
    # For rru.ac.in, effective domain should remain rru.ac.in (not ac.in).
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
    subdomains = set()

    query_hosts: List[str] = [host_lower]
    if base_domain and base_domain != host_lower:
        query_hosts.append(base_domain)

    query_values: List[str] = []
    for query_host in query_hosts:
        wildcard_encoded = urllib.parse.quote(f"%.{query_host}")
        query_values.extend([
            query_host,
            f"%.{query_host}",
            wildcard_encoded,
        ])

    seen_queries = set()
    for query_value in query_values:
        if query_value in seen_queries:
            continue
        seen_queries.add(query_value)

        url = f"https://crt.sh/?q={query_value}&output=json"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 Q-Shield/1.0",
                "Accept": "application/json,text/plain,*/*",
            },
        )

        payload = ""
        for attempt in range(2):
            try:
                with urllib.request.urlopen(req, timeout=max(timeout, 25)) as response:
                    payload = response.read().decode("utf-8", errors="ignore")
                break
            except (urllib.error.URLError, TimeoutError) as exc:
                errors.append(f"CT lookup failed for '{query_value}' (attempt {attempt + 1}): {str(exc)}")

        if not payload:
            continue

        try:
            data = _parse_crtsh_payload(payload)
            for row in data:
                name_value = str(row.get("name_value", ""))
                for entry in name_value.splitlines():
                    value = entry.strip().lower()
                    if not value:
                        continue
                    if value.startswith("*."):
                        value = value[2:]
                    if value == host_lower:
                        continue
                    if any(value.endswith(query_host) and value != query_host for query_host in query_hosts):
                        subdomains.add(value)
        except (ValueError, json.JSONDecodeError) as exc:
            errors.append(f"CT parse failed for '{query_value}': {str(exc)}")
        except Exception as exc:
            errors.append(f"Unexpected CT parse error for '{query_value}': {str(exc)}")

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
    sample_ciphers = [suite.get("cipher_suite") for suite in cipher_suites[:4] if suite.get("cipher_suite")]
    _emit("cipher_enumeration", {"snippets": sample_ciphers or ["Cipher scan complete"]})

    _emit("quantum_safety_analysis", {"snippets": ["Certificate", "Key Exchange", "OCSP"]})

    key_exchange_details = _get_key_exchange_details(host, port, tls_versions, timeout)
    certificate = _get_certificate_metadata(host, port, timeout)
    security_features = _detect_security_features(cipher_suites, host, port, timeout)
    ocsp = _check_ocsp_status(host, port, certificate, timeout)
    ocsp["stapling"] = security_features.get("ocsp_stapling")
    _emit(
        "quantum_safety_analysis",
        {
            "snippets": [
                str(key_exchange_details.get("algorithm") or "KEX unknown"),
                str(certificate.get("public_key_algorithm") or "Key unknown"),
                f"OCSP {ocsp.get('status', 'CHECK FAILED')}",
            ]
        },
    )

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
        "ocsp": ocsp,
        "security_features": security_features,
        "hndl_risk": _assess_hndl_risk(cipher_suites, certificate, key_exchange_details),
        "pqc_detection": real_pqc_detection,
        "crypto_agility_score": _build_crypto_agility_score(
            tls_versions,
            cipher_suites,
            key_exchange_details,
            certificate,
            security_features,
            real_pqc_detection,
        ),
        "migration_advisor": _build_post_quantum_migration_advisor(
            certificate,
            key_exchange_details,
            tls_versions,
            real_pqc_detection,
        ),
        "ct_intelligence": _fetch_certificate_transparency_intelligence(host, timeout),
    }

    _emit(
        "agility_scoring",
        {
            "snippets": [
                f"Score {output['crypto_agility_score'].get('score', 0)}",
                f"Risk {output['hndl_risk'].get('level', 'UNKNOWN')}",
            ]
        },
    )

    return output


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Scan a public TLS endpoint and output JSON.")
    parser.add_argument("target", help="URL, hostname, or IP:PORT")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Connection timeout in seconds")
    args = parser.parse_args()

    try:
        result = scan_tls(args.target, timeout=args.timeout)
        print(json.dumps(result, indent=2, sort_keys=True))
        raise SystemExit(0)
    except ValueError as exc:
        error = {
            "error": {
                "code": "invalid_target",
                "message": str(exc),
            }
        }
        print(json.dumps(error, indent=2, sort_keys=True))
        raise SystemExit(ERROR_CODES["invalid_target"])
    except socket.gaierror as exc:
        error = {
            "error": {
                "code": "dns_failure",
                "message": str(exc),
            }
        }
        print(json.dumps(error, indent=2, sort_keys=True))
        raise SystemExit(ERROR_CODES["dns_failure"])
    except TimeoutError as exc:
        error = {
            "error": {
                "code": "timeout",
                "message": str(exc),
            }
        }
        print(json.dumps(error, indent=2, sort_keys=True))
        raise SystemExit(ERROR_CODES["timeout"])
    except ssl.SSLError as exc:
        error = {
            "error": {
                "code": "tls_handshake_failed",
                "message": str(exc),
            }
        }
        print(json.dumps(error, indent=2, sort_keys=True))
        raise SystemExit(ERROR_CODES["tls_handshake_failed"])
    except OSError as exc:
        error = {
            "error": {
                "code": "connection_failed",
                "message": str(exc),
            }
        }
        print(json.dumps(error, indent=2, sort_keys=True))
        raise SystemExit(ERROR_CODES["connection_failed"])
    except Exception as exc:
        error = {
            "error": {
                "code": "unexpected_error",
                "message": str(exc),
            }
        }
        print(json.dumps(error, indent=2, sort_keys=True))
        raise SystemExit(ERROR_CODES["unexpected_error"])
