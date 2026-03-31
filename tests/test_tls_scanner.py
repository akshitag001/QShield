import unittest
from unittest.mock import patch

import tls_scanner as scanner


class TestParseTarget(unittest.TestCase):
    def test_parse_url(self):
        host, port = scanner._parse_target("https://example.com")
        self.assertEqual(host, "example.com")
        self.assertEqual(port, 443)

    def test_parse_host_port(self):
        host, port = scanner._parse_target("example.com:8443")
        self.assertEqual(host, "example.com")
        self.assertEqual(port, 8443)

    def test_parse_ipv6_brackets(self):
        host, port = scanner._parse_target("[2001:db8::1]:443")
        self.assertEqual(host, "2001:db8::1")
        self.assertEqual(port, 443)

    def test_parse_default_port(self):
        host, port = scanner._parse_target("example.com")
        self.assertEqual(host, "example.com")
        self.assertEqual(port, 443)


class TestCipherParsing(unittest.TestCase):
    def test_parse_tls13_cipher(self):
        kx, auth, enc, hsh = scanner._parse_cipher_name("TLS_AES_128_GCM_SHA256")
        self.assertIsNone(kx)
        self.assertIsNone(auth)
        self.assertEqual(enc, "AES-128-GCM")
        self.assertEqual(hsh, "SHA256")

    def test_parse_tls12_cipher(self):
        kx, auth, enc, hsh = scanner._parse_cipher_name("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
        self.assertEqual(kx, "ECDHE")
        self.assertEqual(auth, "RSA")
        self.assertEqual(enc, "AES-256-GCM")
        self.assertEqual(hsh, "SHA384")


class TestScanTls(unittest.TestCase):
    @patch("tls_scanner._resolve_ip", return_value="93.184.216.34")
    @patch("tls_scanner._get_tls_versions_supported", return_value=["TLSv1.2", "TLSv1.3"])
    @patch("tls_scanner._collect_cipher_suites", return_value=[
        {
            "tls_version": "TLSv1.2",
            "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "key_exchange": "ECDHE",
            "authentication": "RSA",
            "encryption": "AES-256-GCM",
            "hash": "SHA-384",
        }
    ])
    @patch("tls_scanner._get_key_exchange_details", return_value={
        "algorithm": "ECDHE",
        "curve": "secp256r1",
        "key_size": 256,
        "ephemeral": True,
    })
    @patch("tls_scanner._get_certificate_metadata", return_value={
        "subject": "CN=example.com",
        "issuer": "CN=Example Issuer",
        "valid_from": "2024-01-01",
        "valid_to": "2024-04-01",
        "signature_algorithm": "SHA256withRSA",
        "public_key_algorithm": "RSA",
        "public_key_size": 2048,
        "chain_length": 2,
    })
    @patch("tls_scanner._detect_security_features", return_value={
        "forward_secrecy": True,
        "weak_ciphers_detected": False,
        "ocsp_stapling": True,
        "secure_renegotiation": True,
    })
    @patch("tls_scanner._check_ocsp_status", return_value={
        "status": "GOOD",
        "checked": True,
        "responder": "http://ocsp.example.com",
        "latency": 120,
        "ocsp_status": "GOOD",
        "ocsp_checked": True,
        "ocsp_responder": "http://ocsp.example.com",
        "response_time_ms": 120,
    })
    @patch("tls_scanner._fetch_certificate_transparency_intelligence", return_value={
        "source": "crt.sh",
        "query_host": "example.com",
        "detected_subdomains": [],
        "total_detected": 0,
        "status": "no_data",
    })
    def test_scan_tls(self, *_mocks):
        result = scanner.scan_tls("example.com")
        self.assertEqual(result["host"], "example.com")
        self.assertEqual(result["ip_address"], "93.184.216.34")
        self.assertEqual(result["port"], 443)
        self.assertEqual(result["tls_versions_supported"], ["TLSv1.2", "TLSv1.3"])
        self.assertEqual(len(result["cipher_suites"]), 1)
        self.assertEqual(result["key_exchange_details"]["algorithm"], "ECDHE")
        self.assertEqual(result["certificate"]["public_key_size"], 2048)
        self.assertTrue(result["security_features"]["forward_secrecy"])
        self.assertEqual(result["ocsp"]["status"], "GOOD")
        self.assertTrue(result["ocsp"]["checked"])


if __name__ == "__main__":
    unittest.main()
