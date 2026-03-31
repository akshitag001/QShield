"""
Q-Shield Crypto Inventory Scanner

Main orchestrator for scanning multiple targets and generating CBOM reports.
Supports web servers, APIs, and TLS endpoints.
"""

import argparse
import json
import sys
import socket
import ssl
import re
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from tls_scanner import scan_tls, DEFAULT_TIMEOUT
from cbom_generator import generate_cbom, CBOM


def _probe_common_ports(host: str, timeout: int = 3) -> List[int]:
    """Probe common TLS ports to discover services."""
    common_ports = [443, 8443, 8080, 9443, 3000, 5000, 8000]
    open_ports = []
    
    for port in common_ports:
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
            open_ports.append(port)
        except (socket.timeout, socket.error, OSError):
            pass
    
    return open_ports


def _detect_api_endpoints(base_url: str, timeout: int = 5) -> List[Dict[str, Any]]:
    """
    Detect common API patterns by probing well-known paths.
    Returns metadata about discovered API endpoints.
    """
    api_paths = [
        "/api",
        "/api/v1",
        "/api/v2",
        "/v1",
        "/v2",
        "/graphql",
        "/rest",
        "/.well-known/openid-configuration",
        "/swagger.json",
        "/openapi.json",
        "/health",
        "/status",
    ]
    
    discovered = []
    
    for path in api_paths:
        url = f"{base_url.rstrip('/')}{path}"
        try:
            # Create SSL context that doesn't verify (for scanning purposes)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            req = urllib.request.Request(url, method="HEAD")
            req.add_header("User-Agent", "Q-Shield-Scanner/1.0")
            
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
                if response.status < 400:
                    content_type = response.headers.get("Content-Type", "")
                    discovered.append({
                        "path": path,
                        "url": url,
                        "status": response.status,
                        "content_type": content_type,
                        "is_api": "json" in content_type.lower() or "api" in path.lower(),
                    })
        except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout, ssl.SSLError):
            pass
    
    return discovered


def _extract_headers_crypto_info(base_url: str, timeout: int = 5) -> Dict[str, Any]:
    """Extract security-related HTTP headers."""
    headers_info = {
        "strict_transport_security": None,
        "content_security_policy": None,
        "x_content_type_options": None,
        "x_frame_options": None,
        "server": None,
        "security_headers_present": [],
    }
    
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        req = urllib.request.Request(base_url)
        req.add_header("User-Agent", "Q-Shield-Scanner/1.0")
        
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
            hdrs = response.headers
            
            if hdrs.get("Strict-Transport-Security"):
                headers_info["strict_transport_security"] = hdrs.get("Strict-Transport-Security")
                headers_info["security_headers_present"].append("HSTS")
            
            if hdrs.get("Content-Security-Policy"):
                headers_info["content_security_policy"] = hdrs.get("Content-Security-Policy")
                headers_info["security_headers_present"].append("CSP")
            
            if hdrs.get("X-Content-Type-Options"):
                headers_info["x_content_type_options"] = hdrs.get("X-Content-Type-Options")
                headers_info["security_headers_present"].append("X-Content-Type-Options")
            
            if hdrs.get("X-Frame-Options"):
                headers_info["x_frame_options"] = hdrs.get("X-Frame-Options")
                headers_info["security_headers_present"].append("X-Frame-Options")
            
            headers_info["server"] = hdrs.get("Server")
            
    except Exception:
        pass
    
    return headers_info


def scan_target(target: str, timeout: int = DEFAULT_TIMEOUT, 
                probe_apis: bool = True, probe_headers: bool = True) -> Dict[str, Any]:
    """
    Scan a single target for all cryptographic information.
    
    Args:
        target: URL, hostname, or IP:PORT
        timeout: Connection timeout in seconds
        probe_apis: Whether to probe for API endpoints
        probe_headers: Whether to extract HTTP security headers
    
    Returns:
        Combined scan result with TLS, API, and header information
    """
    # Run TLS scan
    tls_result = scan_tls(target, timeout=timeout)
    
    # Build base URL for HTTP probing
    host = tls_result.get("host", target)
    port = tls_result.get("port", 443)
    base_url = f"https://{host}" if port == 443 else f"https://{host}:{port}"
    
    # Add API endpoint detection
    if probe_apis:
        tls_result["api_endpoints"] = _detect_api_endpoints(base_url, timeout)
    
    # Add HTTP headers analysis
    if probe_headers:
        tls_result["http_security_headers"] = _extract_headers_crypto_info(base_url, timeout)
    
    return tls_result


def scan_multiple_targets(targets: List[str], timeout: int = DEFAULT_TIMEOUT,
                          max_workers: int = 5, probe_apis: bool = True,
                          probe_headers: bool = True) -> List[Dict[str, Any]]:
    """
    Scan multiple targets in parallel.
    
    Args:
        targets: List of URLs, hostnames, or IP:PORT strings
        timeout: Connection timeout in seconds
        max_workers: Maximum parallel scans
        probe_apis: Whether to probe for API endpoints
        probe_headers: Whether to extract HTTP security headers
    
    Returns:
        List of scan results
    """
    results = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_target = {
            executor.submit(scan_target, target, timeout, probe_apis, probe_headers): target
            for target in targets
        }
        
        for future in as_completed(future_to_target):
            target = future_to_target[future]
            try:
                result = future.result()
                result["_scan_status"] = "success"
                results.append(result)
            except Exception as e:
                results.append({
                    "host": target,
                    "_scan_status": "error",
                    "_error": str(e),
                })
    
    return results


def generate_inventory_report(targets: List[str], timeout: int = DEFAULT_TIMEOUT,
                               output_format: str = "cbom") -> str:
    """
    Generate a complete cryptographic inventory report.
    
    Args:
        targets: List of targets to scan
        timeout: Connection timeout
        output_format: "cbom", "json", or "summary"
    
    Returns:
        Formatted report string
    """
    # Scan all targets
    scan_results = scan_multiple_targets(targets, timeout=timeout)
    
    # Filter successful scans
    successful_scans = [r for r in scan_results if r.get("_scan_status") == "success"]
    failed_scans = [r for r in scan_results if r.get("_scan_status") == "error"]
    
    if output_format == "json":
        return json.dumps({
            "scan_results": scan_results,
            "scan_summary": {
                "total_targets": len(targets),
                "successful_scans": len(successful_scans),
                "failed_scans": len(failed_scans),
            }
        }, indent=2, sort_keys=True)
    
    elif output_format == "cbom":
        cbom = generate_cbom(successful_scans)
        
        # Add failed scan info to summary
        cbom.summary["failed_scans"] = [
            {"target": r.get("host"), "error": r.get("_error")} 
            for r in failed_scans
        ]
        
        return cbom.to_json()
    
    elif output_format == "summary":
        cbom = generate_cbom(successful_scans)
        summary = cbom.summary
        
        lines = [
            "=" * 60,
            "CRYPTOGRAPHIC INVENTORY SUMMARY",
            "=" * 60,
            f"Generated: {cbom.generated_at}",
            f"Total Endpoints Scanned: {summary.get('total_endpoints', 0)}",
            f"Total Crypto Assets Found: {summary.get('total_assets', 0)}",
            "",
            "ASSETS BY TYPE:",
        ]
        
        for asset_type, count in summary.get("assets_by_type", {}).items():
            lines.append(f"  - {asset_type}: {count}")
        
        lines.extend([
            "",
            "SECURITY STRENGTH DISTRIBUTION:",
        ])
        
        for strength, count in summary.get("assets_by_strength", {}).items():
            lines.append(f"  - {strength}: {count}")
        
        lines.extend([
            "",
            f"Quantum-Vulnerable Assets: {summary.get('quantum_vulnerable_assets', 0)}",
            f"Endpoints with Weak Crypto: {summary.get('endpoints_with_weak_crypto', 0)}",
            f"Endpoints with Forward Secrecy: {summary.get('endpoints_with_forward_secrecy', 0)}",
            "=" * 60,
        ])
        
        if failed_scans:
            lines.extend([
                "",
                "FAILED SCANS:",
            ])
            for r in failed_scans:
                lines.append(f"  - {r.get('host')}: {r.get('_error')}")
        
        return "\n".join(lines)
    
    else:
        raise ValueError(f"Unknown output format: {output_format}")


def main():
    parser = argparse.ArgumentParser(
        description="Q-Shield Cryptographic Inventory Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py example.com
  python scanner.py example.com api.example.com --format cbom
  python scanner.py -f targets.txt --format summary
  python scanner.py example.com --timeout 10 --no-api-probe
        """
    )
    
    parser.add_argument(
        "targets",
        nargs="*",
        help="Target URLs, hostnames, or IP:PORT (can specify multiple)"
    )
    parser.add_argument(
        "-f", "--file",
        help="File containing targets (one per line)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Connection timeout in seconds (default: {DEFAULT_TIMEOUT})"
    )
    parser.add_argument(
        "--format",
        choices=["cbom", "json", "summary"],
        default="cbom",
        help="Output format (default: cbom)"
    )
    parser.add_argument(
        "--no-api-probe",
        action="store_true",
        help="Skip API endpoint detection"
    )
    parser.add_argument(
        "--no-headers",
        action="store_true",
        help="Skip HTTP security header extraction"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file (default: stdout)"
    )
    
    args = parser.parse_args()
    
    # Collect targets
    targets = list(args.targets) if args.targets else []
    
    if args.file:
        try:
            with open(args.file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
        except FileNotFoundError:
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
    
    if not targets:
        parser.print_help()
        sys.exit(1)
    
    try:
        # For now, scan_multiple_targets handles the parallel scanning
        scan_results = scan_multiple_targets(
            targets, 
            timeout=args.timeout,
            probe_apis=not args.no_api_probe,
            probe_headers=not args.no_headers
        )
        
        output = generate_inventory_report(
            targets,
            timeout=args.timeout,
            output_format=args.format
        )
        
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"Report written to: {args.output}", file=sys.stderr)
        else:
            print(output)
        
        sys.exit(0)
        
    except Exception as e:
        print(json.dumps({
            "error": {
                "code": "scan_failed",
                "message": str(e)
            }
        }, indent=2))
        sys.exit(1)


if __name__ == "__main__":
    main()
