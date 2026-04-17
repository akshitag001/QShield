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
import asyncio
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from tls_scanner import scan_tls, DEFAULT_TIMEOUT
from cbom_generator import generate_cbom, CBOM
from discovery_engine import discover_subdomains
from vpn_scanner import scan_vpn
from ssh_scanner import scan_ssh

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


def _analyze_api_security(endpoint_url: str, timeout: int = 5) -> Dict[str, Any]:
    """
    Analyze API endpoint for security issues: CORS, authentication, rate limiting, headers.
    """
    security_analysis = {
        "cors_enabled": False,
        "cors_allow_origin": None,
        "cors_allow_credentials": False,
        "requires_auth": False,
        "auth_method": None,
        "rate_limit_headers": False,
        "security_headers": [],
        "issues": [],
    }
    
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        # First request - check authentication
        req = urllib.request.Request(endpoint_url, method="GET")
        req.add_header("User-Agent", "Q-Shield-Scanner/1.0")
        req.add_header("Origin", "https://qshield-scan.local")
        
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
                headers = response.headers
                
                # CORS Analysis
                if headers.get("Access-Control-Allow-Origin"):
                    security_analysis["cors_enabled"] = True
                    security_analysis["cors_allow_origin"] = headers.get("Access-Control-Allow-Origin")
                    
                    if headers.get("Access-Control-Allow-Origin") == "*":
                        security_analysis["issues"].append("CORS: Allow-Origin set to '*' (overly permissive)")
                    
                    if headers.get("Access-Control-Allow-Credentials") == "true":
                        security_analysis["cors_allow_credentials"] = True
                        if headers.get("Access-Control-Allow-Origin") == "*":
                            security_analysis["issues"].append("CRITICAL: CORS misconfiguration - * with credentials")
                
                # Rate Limiting
                if headers.get("X-RateLimit-Limit") or headers.get("RateLimit-Limit"):
                    security_analysis["rate_limit_headers"] = True
                
                # Authentication headers in response
                if "Authorization" in headers:
                    security_analysis["requires_auth"] = True
                
                # Security headers on API endpoint
                if headers.get("Strict-Transport-Security"):
                    security_analysis["security_headers"].append("HSTS")
                if headers.get("X-Content-Type-Options"):
                    security_analysis["security_headers"].append("X-Content-Type-Options")
                if headers.get("Content-Security-Policy"):
                    security_analysis["security_headers"].append("CSP")
                
        except urllib.error.HTTPError as e:
            if e.code == 401:
                security_analysis["requires_auth"] = True
                security_analysis["auth_method"] = "Bearer/Basic"
            elif e.code == 403:
                security_analysis["requires_auth"] = True
                security_analysis["auth_method"] = "Access Forbidden (likely API key/OAuth)"
            elif e.code == 429:
                security_analysis["rate_limit_headers"] = True
        
    except Exception:
        pass
    
    return security_analysis


def _extract_openapi_paths(payload: bytes, base_url: str, max_paths: int = 50) -> List[Dict[str, Any]]:
    """Extract endpoint paths from an OpenAPI/Swagger JSON payload."""
    if not payload:
        return []

    try:
        data = json.loads(payload.decode("utf-8", errors="ignore"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return []

    if not isinstance(data, dict) or "paths" not in data:
        return []

    paths = data.get("paths") or {}
    if not isinstance(paths, dict):
        return []

    endpoints = []
    base = base_url.rstrip("/")
    for path in list(paths.keys())[:max_paths]:
        if not isinstance(path, str) or not path:
            continue
        if path.startswith("/"):
            url = f"{base}{path}"
        else:
            url = f"{base}/{path}"

        endpoints.append(
            {
                "path": path,
                "url": url,
                "status": "spec",
                "content_type": "application/json",
                "is_api": True,
                "security_analysis": {
                    "cors_enabled": None,
                    "requires_auth": None,
                    "rate_limit_headers": None,
                },
                "source": "openapi",
            }
        )

    return endpoints


def _detect_api_endpoints(base_url: str, timeout: int = 5) -> List[Dict[str, Any]]:
    """
    Detect common API patterns by probing well-known paths and analyzing security.
    Returns metadata about discovered API endpoints with security analysis.
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
            
            # Using GET instead of HEAD as many APIs reject HEAD requests
            req = urllib.request.Request(url, method="GET")
            req.add_header("User-Agent", "Q-Shield-Scanner/1.0")
            
            # Handle HTTP errors gracefully
            body = b""
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
                    status = response.status
                    content_type = response.headers.get("Content-Type", "")
                    body = response.read(200000)
            except urllib.error.HTTPError as e:
                status = e.code
                content_type = e.headers.get("Content-Type", "") if hasattr(e, 'headers') else ""
                try:
                    body = e.read(200000)
                except Exception:
                    body = b""
            except (urllib.error.URLError, socket.timeout, ssl.SSLError):
                continue
                
            # Treat 401 Unauthorized, 403 Forbidden, 405 Method Not Allowed, 429 Too Many Requests, and 500 Server Error as existing APIs
            if status < 400 or status in (401, 403, 405, 429, 500):
                is_api = "json" in content_type.lower() or "api" in path.lower() or status in (401, 403, 405, 429)
                
                endpoint_data = {
                    "path": path,
                    "url": url,
                    "status": status,
                    "content_type": content_type,
                    "is_api": is_api,
                }
                
                # Analyze API security if it looks like an API
                if is_api:
                    endpoint_data["security_analysis"] = _analyze_api_security(url, timeout)
                
                discovered.append(endpoint_data)

                # Extract paths from OpenAPI/Swagger payloads when available
                if is_api and ("openapi" in content_type.lower() or path in ("/swagger.json", "/openapi.json")):
                    discovered.extend(_extract_openapi_paths(body, base_url))
        except Exception:
            pass
    
    # De-duplicate endpoints by URL or path
    seen = set()
    unique = []
    for item in discovered:
        key = (item.get("url") or item.get("path") or "").lower()
        if not key or key in seen:
            continue
        seen.add(key)
        unique.append(item)

    return unique


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


async def scan_target_async(target: str, timeout: int = DEFAULT_TIMEOUT, 
                            probe_apis: bool = True, probe_headers: bool = True) -> Dict[str, Any]:
    """Scan a target using asyncio, wrapping synchronous TLS scan in to_thread."""
    tls_result = await asyncio.to_thread(scan_tls, target, timeout)
    
    host = tls_result.get("host", target)
    port = tls_result.get("port", 443)
    base_url = f"https://{host}" if port == 443 else f"https://{host}:{port}"
    
    tasks = []
    tasks.append(scan_vpn(host, port, timeout))
    tasks.append(scan_ssh(host, 22, timeout))
    
    if probe_apis:
        tasks.append(asyncio.to_thread(_detect_api_endpoints, base_url, timeout))
    else:
        async def dummy_api(): return []
        tasks.append(dummy_api())
        
    if probe_headers:
        tasks.append(asyncio.to_thread(_extract_headers_crypto_info, base_url, timeout))
    else:
        async def dummy_headers(): return {}
        tasks.append(dummy_headers())
        
    vpn_res, ssh_res, api_res, header_res = await asyncio.gather(*tasks)
    
    if vpn_res["detected"]:
        tls_result["vpn_gateway"] = vpn_res
    if ssh_res["detected"]:
        tls_result["ssh_endpoint"] = ssh_res
    if probe_apis:
        tls_result["api_endpoints"] = api_res
    if probe_headers:
        tls_result["http_security_headers"] = header_res
        
    return tls_result


async def scan_multiple_targets_async(targets: List[str], timeout: int = DEFAULT_TIMEOUT,
                                      max_workers: int = 20, probe_apis: bool = True,
                                      probe_headers: bool = True) -> List[Dict[str, Any]]:
    """Scan multiple targets concurrently with asyncio bounded semaphore."""
    sem = asyncio.Semaphore(max_workers)
    
    async def _bound_scan(target):
        async with sem:
            try:
                result = await scan_target_async(target, timeout, probe_apis, probe_headers)
                result["_scan_status"] = "success"
                return result
            except Exception as e:
                return {"host": target, "_scan_status": "error", "_error": str(e)}

    return await asyncio.gather(*[_bound_scan(t) for t in targets])


def generate_inventory_report(targets: List[str], scan_results: List[Dict[str, Any]], timeout: int = DEFAULT_TIMEOUT,
                               output_format: str = "cbom") -> str:
    """
    Generate a complete cryptographic inventory report.
    """
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
  python scanner.py example.com --auto-discover --format cbom
  python scanner.py -f targets.txt --format summary
        """
    )
    
    parser.add_argument("targets", nargs="*", help="Target URLs, hostnames, or IP:PORT")
    parser.add_argument("-f", "--file", help="File containing targets (one per line)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help=f"Timeout")
    parser.add_argument("--format", choices=["cbom", "json", "summary"], default="cbom")
    parser.add_argument("--no-api-probe", action="store_true", help="Skip API detection")
    parser.add_argument("--no-headers", action="store_true", help="Skip HTTP header extraction")
    parser.add_argument("--auto-discover", action="store_true", help="Automatically discover subdomains via CT Logs")
    parser.add_argument("-o", "--output", help="Output file (default: stdout)")
    
    args = parser.parse_args()
    
    targets = list(args.targets) if args.targets else []
    
    if args.file:
        try:
            with open(args.file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"): targets.append(line)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
            
    if not targets:
        parser.print_help()
        sys.exit(1)
        
    async def __run():
        final_targets = targets
        if args.auto_discover:
            print("[Discovery] Running shadow asset discovery via crt.sh...", file=sys.stderr)
            discovered = set()
            for t in targets:
                subs = await discover_subdomains(t)
                discovered.update(subs)
            final_targets = list(discovered)
            print(f"[Discovery] Expanded target list size: {len(final_targets)}", file=sys.stderr)
            
        print(f"[Scanner] Executing async pipeline across {len(final_targets)} targets...", file=sys.stderr)
        scan_results = await scan_multiple_targets_async(
            final_targets, 
            timeout=args.timeout,
            probe_apis=not args.no_api_probe,
            probe_headers=not args.no_headers,
            max_workers=20
        )
        
        output = generate_inventory_report(
            final_targets,
            scan_results,
            timeout=args.timeout,
            output_format=args.format
        )
        
        if args.output:
            with open(args.output, "w") as f: f.write(output)
            print(f"Report written to: {args.output}", file=sys.stderr)
        else:
            print(output)

    try:
        asyncio.run(__run())
        sys.exit(0)
    except Exception as e:
        print(json.dumps({"error": {"code": "scan_failed", "message": str(e)}}, indent=2))
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
