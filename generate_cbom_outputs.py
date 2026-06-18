import argparse
import html
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cbom_generator import generate_cbom


def _utc_date_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _sanitize_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    return cleaned.strip("_") or "System"


def _load_scan_results(path: Path) -> List[Dict[str, Any]]:
    raw = None
    for encoding in ("utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be"):
        try:
            raw = path.read_text(encoding=encoding)
            break
        except UnicodeDecodeError:
            continue
    if raw is None:
        raise UnicodeError(f"Unable to decode {path} as UTF-8 or UTF-16")
    data = json.loads(raw)
    if isinstance(data, list):
        return data
    return [data]


def _risk_from_strength(strength: str, quantum_vulnerable: bool) -> int:
    base_map = {
        "broken": 4,
        "weak": 3,
        "acceptable": 2,
        "strong": 1,
        "unknown": 2,
    }
    base = base_map.get((strength or "").lower(), 2)
    bump = 1 if quantum_vulnerable else 0
    return min(5, base + bump)


def _risk_score_summary(assets: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not assets:
        return {"average_score": 0, "severity": "LOW", "by_asset": []}

    by_asset = []
    scores = []
    for asset in assets:
        score = _risk_from_strength(asset.get("strength", ""), asset.get("quantum_vulnerable", False))
        scores.append(score)
        by_asset.append(
            {
                "name": asset.get("name"),
                "asset_type": asset.get("asset_type"),
                "strength": asset.get("strength"),
                "quantum_vulnerable": asset.get("quantum_vulnerable"),
                "risk_score": score,
            }
        )

    avg = sum(scores) / len(scores)
    if avg >= 4.0:
        severity = "CRITICAL"
    elif avg >= 3.0:
        severity = "HIGH"
    elif avg >= 2.0:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "average_score": round(avg, 2),
        "severity": severity,
        "by_asset": by_asset,
    }


def _risk_color(risk_score: float) -> str:
    if risk_score >= 4.0:
        return "#d32f2f"
    if risk_score >= 3.0:
        return "#f57c00"
    if risk_score >= 2.0:
        return "#fbc02d"
    return "#388e3c"


def _collect_assets(cbom_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
    assets = []
    for endpoint in cbom_dict.get("endpoints", []):
        assets.extend(endpoint.get("assets", []))
    return assets


def _get_endpoints(cbom_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
    return cbom_dict.get("endpoints", [])


def _detect_pqc_signatures(assets: List[Dict[str, Any]]) -> bool:
    """Detect PQC signature algorithms (ML-DSA, SLH-DSA, DILITHIUM, FALCON, SPHINCS)."""
    for asset in assets:
        if asset.get("asset_type") == "certificate":
            sig = (asset.get("properties", {}).get("signature_algorithm") or "").upper()
            if any(token in sig for token in ["DILITHIUM", "ML-DSA", "FALCON", "SPHINCS", "SLH-DSA"]):
                return True
    return False


def _detect_pqc_kem(assets: List[Dict[str, Any]]) -> bool:
    """
    Detect PQC KEM algorithms (ML-KEM/Kyber) in assets or hybrid key exchanges.
    Also checks cipher suite key_exchange fields for hybrid patterns like x25519-mlkem.
    """
    pqc_kem_keywords = ["MLKEM", "ML-KEM", "KYBER", "ML_KEM", "KYBER-512", "KYBER-768", "KYBER-1024"]
    for asset in assets:
        if asset.get("asset_type") in {"pqc_kem", "hybrid_key_exchange"}:
            return True
        
        name = (asset.get("name") or "").upper()
        if any(keyword in name for keyword in pqc_kem_keywords):
            return True
        
        # Check cipher suite key_exchange field for hybrid MLKEM/KYBER patterns
        if asset.get("asset_type") == "cipher_suite":
            props = asset.get("properties", {}) or {}
            key_ex = (props.get("key_exchange") or "").upper()
            # Detect hybrid like x25519-mlkem768, p256-kyber512, etc.
            if key_ex and any(keyword in key_ex for keyword in pqc_kem_keywords):
                # Verify it's actually a hybrid (has both classical + PQC tokens)
                classical_tokens = ["X25519", "X448", "P256", "P384", "P521", "SECP", "ECDHE", "DHE"]
                if any(token in key_ex for token in classical_tokens):
                    return True
    
    return False


def _detect_slh_dsa(assets: List[Dict[str, Any]]) -> bool:
    """Detect SLH-DSA signature algorithm specifically."""
    for asset in assets:
        if asset.get("asset_type") == "certificate":
            sig = (asset.get("properties", {}).get("signature_algorithm") or "").upper()
            if "SLH-DSA" in sig or "SLH_DSA" in sig:
                return True
    return False


def _fips_mapping(assets: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    pqc_kem = _detect_pqc_kem(assets)
    pqc_sig = _detect_pqc_signatures(assets)
    slh_dsa_detected = _detect_slh_dsa(assets)
    return [
        {
            "standard": "NIST FIPS 203 (ML-KEM)",
            "status": "PARTIAL" if pqc_kem else "NOT MET",
            "evidence": "Hybrid ML-KEM detected" if pqc_kem else "No ML-KEM evidence in scan",
        },
        {
            "standard": "NIST FIPS 204 (ML-DSA)",
            "status": "MET" if pqc_sig else "NOT MET",
            "evidence": "PQC signature detected" if pqc_sig else "Certificates use classical signatures",
        },
        {
            "standard": "NIST FIPS 205 (SLH-DSA)",
            "status": "MET" if slh_dsa_detected else "NOT MET",
            "evidence": "SLH-DSA detected in certificates" if slh_dsa_detected else "No SLH-DSA evidence in scan",
        },
    ]


def _cnsa_mapping(assets: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    pqc_kem = _detect_pqc_kem(assets)
    pqc_sig = _detect_pqc_signatures(assets)
    return [
        {
            "control": "CNSA 2.0 KEM (Hybrid)",
            "status": "PARTIAL" if pqc_kem else "NOT MET",
            "evidence": "Hybrid KEM present" if pqc_kem else "No hybrid KEM detected",
        },
        {
            "control": "CNSA 2.0 PQC Signatures",
            "status": "MET" if pqc_sig else "NOT MET",
            "evidence": "PQC signatures detected" if pqc_sig else "RSA/ECDSA signatures observed",
        },
    ]


def _rbi_mapping(endpoints: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    tls_versions = set()
    forward_secrecy = False
    weak_crypto = False
    for ep in endpoints:
        for version in ep.get("tls_versions", []):
            tls_versions.add(version)
        forward_secrecy = forward_secrecy or bool(ep.get("forward_secrecy"))
        weak_crypto = weak_crypto or bool(ep.get("weak_crypto_detected"))

    tls13 = "TLSv1.3" in tls_versions
    tls12 = "TLSv1.2" in tls_versions

    return [
        {
            "control": "Encryption in transit",
            "status": "MET" if tls12 or tls13 else "NOT MET",
            "evidence": "TLS observed" if tls12 or tls13 else "No TLS evidence",
        },
        {
            "control": "Forward secrecy",
            "status": "MET" if forward_secrecy else "PARTIAL",
            "evidence": "Forward secrecy enabled" if forward_secrecy else "Not observed",
        },
        {
            "control": "Weak crypto avoidance",
            "status": "MET" if not weak_crypto else "GAP",
            "evidence": "No weak crypto detected" if not weak_crypto else "Weak crypto detected",
        },
        {
            "control": "Key management and rotation",
            "status": "NOT ASSESSED",
            "evidence": "Key rotation evidence not available in scan",
        },
    ]


def _build_cyclonedx_1_6(cbom_dict: Dict[str, Any], system_name: str, date_str: str) -> Dict[str, Any]:
    serial = f"urn:uuid:{uuid.uuid4()}"
    bom_ref_root = f"{_sanitize_name(system_name)}@{date_str}"

    assets = _collect_assets(cbom_dict)
    components = []
    for asset in assets:
        asset_type = asset.get("asset_type", "unknown")
        props = asset.get("properties", {})
        bom_ref = f"{asset_type}:{asset.get('name')}:{asset.get('source_endpoint')}"
        crypto_properties: Dict[str, Any] = {
            "assetType": asset_type,
        }
        if asset_type in {"cipher_suite", "symmetric_cipher", "hash_algorithm", "public_key", "key_exchange", "pqc_kem", "pqc_signature", "hybrid_key_exchange"}:
            crypto_properties["algorithmProperties"] = {
                "algorithm": props.get("algorithm") or asset.get("name"),
            }
        if asset_type == "protocol":
            crypto_properties["protocolProperties"] = {"protocolType": "TLS", "version": props.get("version")}
        if asset_type == "certificate":
            crypto_properties["certificateProperties"] = {
                "subjectName": props.get("subject"),
                "issuerName": props.get("issuer"),
                "serialNumber": props.get("serial_number"),
                "notValidBefore": props.get("valid_from"),
                "notValidAfter": props.get("valid_to"),
                "signatureAlgorithm": props.get("signature_algorithm"),
            }

        components.append(
            {
                "bom-ref": bom_ref,
                "type": "cryptographic-asset",
                "name": asset.get("name"),
                "description": f"Discovered on {asset.get('source_endpoint')}",
                "properties": [
                    {"name": "strength", "value": str(asset.get("strength"))},
                    {"name": "quantumVulnerable", "value": str(asset.get("quantum_vulnerable"))},
                    {"name": "sourceEndpoint", "value": asset.get("source_endpoint")},
                ],
                "cryptoProperties": crypto_properties,
            }
        )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "Q-Shield",
                    "name": "Q-Shield TLS Scanner",
                    "version": "1.0.0",
                }
            ],
            "component": {
                "bom-ref": bom_ref_root,
                "type": "application",
                "name": system_name,
                "version": "1.0.0",
            },
        },
        "components": components,
        "properties": [
            {"name": "cbomVersion", "value": cbom_dict.get("cbom_version", "1.0.0")},
            {"name": "generatedAt", "value": cbom_dict.get("generated_at")},
            {"name": "generator", "value": cbom_dict.get("generator")},
        ],
    }


@dataclass
class ReportContext:
    system_name: str
    date_str: str
    cbom_dict: Dict[str, Any]
    scan_results: List[Dict[str, Any]]
    risk_summary: Dict[str, Any]
    fips_mapping: List[Dict[str, str]]
    rbi_mapping: List[Dict[str, str]]
    cnsa_mapping: List[Dict[str, str]]


def _build_report_context(system_name: str, date_str: str, scan_results: List[Dict[str, Any]], cbom_dict: Dict[str, Any]) -> ReportContext:
    assets = _collect_assets(cbom_dict)
    return ReportContext(
        system_name=system_name,
        date_str=date_str,
        cbom_dict=cbom_dict,
        scan_results=scan_results,
        risk_summary=_risk_score_summary(assets),
        fips_mapping=_fips_mapping(assets),
        rbi_mapping=_rbi_mapping(_get_endpoints(cbom_dict)),
        cnsa_mapping=_cnsa_mapping(assets),
    )


def _render_pdf(report_path: Path, ctx: ReportContext, cyclonedx_path: Path) -> None:
    try:
        from xhtml2pdf import pisa
    except ImportError as exc:
        raise ImportError(
            "xhtml2pdf is required for professional PDF output. Install with: pip install xhtml2pdf"
        ) from exc

    html_content = _build_html_cbom(ctx, cyclonedx_path)
    with open(report_path, "wb") as f:
        pisa_status = pisa.CreatePDF(html_content, dest=f)
    
    if pisa_status.err:
        logger.error(f"PDF generation error: {pisa_status.err}")


def _build_html_cbom(ctx: ReportContext, cyclonedx_path: Path) -> str:
    summary = ctx.cbom_dict.get("summary", {})
    endpoints = _get_endpoints(ctx.cbom_dict)

    css = """
    @page {
        size: A4;
        margin: 0.6in;
        @bottom-center {
            content: "Page " counter(page) " of " counter(pages);
            font-size: 9pt;
            color: #999;
        }
    }

    * { margin: 0; padding: 0; box-sizing: border-box; }

    body {
        font-family: "Calibri", "Segoe UI", Arial, sans-serif;
        font-size: 11pt;
        line-height: 1.5;
        color: #1a1a1a;
        background: white;
    }

    .cover {
        page-break-after: always;
        padding-top: 3.5in;
        text-align: center;
        height: 100%;
    }

    .cover h1 {
        font-size: 32pt;
        font-weight: bold;
        color: #0b3d91;
        margin-bottom: 0.5in;
        letter-spacing: 0.5pt;
    }

    .cover .subtitle {
        font-size: 18pt;
        color: #666;
        margin-bottom: 0.3in;
    }

    .cover .meta {
        font-size: 10pt;
        color: #999;
        line-height: 1.8;
        margin-top: 1in;
    }

    .cover .classification {
        background: #0b3d91;
        color: white;
        padding: 10pt;
        border-radius: 4pt;
        margin-top: 1.5in;
        font-weight: bold;
        display: inline-block;
    }

    h1 {
        font-size: 16pt;
        font-weight: bold;
        color: #0b3d91;
        margin-top: 0.3in;
        margin-bottom: 0.15in;
        border-bottom: 2pt solid #0b3d91;
        padding-bottom: 0.1in;
    }

    h2 {
        font-size: 13pt;
        font-weight: bold;
        color: #333;
        margin-top: 0.25in;
        margin-bottom: 0.1in;
    }

    h3 {
        font-size: 11pt;
        font-weight: bold;
        color: #555;
        margin-top: 0.15in;
        margin-bottom: 0.08in;
    }

    code {
        background: #f5f5f5;
        padding: 2pt 4pt;
        font-family: "Courier New", monospace;
        font-size: 9pt;
        border-radius: 2pt;
    }

    table {
        width: 100%;
        border-collapse: collapse;
        margin: 0.15in 0;
        font-size: 10pt;
    }

    th {
        background-color: #0b3d91;
        color: white;
        padding: 8pt;
        text-align: left;
        font-weight: bold;
        font-size: 10pt;
        border: 1pt solid #0b3d91;
    }

    td {
        padding: 8pt;
        border: 1pt solid #ddd;
        vertical-align: top;
    }

    tr:nth-child(even) { background-color: #f5f5f5; }

    .risk-critical { background-color: #ffebee; color: #d32f2f; font-weight: bold; }
    .risk-high { background-color: #fff3e0; color: #f57c00; font-weight: bold; }
    .risk-medium { background-color: #fffde7; color: #fbc02d; font-weight: bold; }
    .risk-low { background-color: #e8f5e9; color: #388e3c; font-weight: bold; }

    .status-met { color: #388e3c; font-weight: bold; }
    .status-partial { color: #f57c00; font-weight: bold; }
    .status-gap { color: #d32f2f; font-weight: bold; }
    .status-notassessed { color: #999; }

    .summary-box {
        background: #f0f7ff;
        border-left: 4pt solid #0b3d91;
        padding: 0.15in;
        margin: 0.1in 0;
        border-radius: 3pt;
    }

    .critical-box {
        background: #ffebee;
        border-left: 4pt solid #d32f2f;
        padding: 0.15in;
        margin: 0.1in 0;
    }

    .text-muted { color: #666; font-size: 9pt; }

    .section-break { page-break-after: always; }

    .audit-trail {
        border-top: 1pt solid #ddd;
        margin-top: 0.3in;
        padding-top: 0.15in;
        font-size: 9pt;
    }

    .signature-line {
        border-bottom: 1pt solid #000;
        width: 2in;
        display: inline-block;
        margin: 0.1in 0.25in;
    }
    """

    risk_score = ctx.risk_summary.get("average_score", 0)
    risk_severity = ctx.risk_summary.get("severity", "UNKNOWN")
    pqc_ready_score = summary.get("pqc_readiness_score", 0)

    html_parts = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        "<meta charset=\"UTF-8\">",
        f"<title>CBOM Report - {html.escape(ctx.system_name)}</title>",
        "<style>",
        css,
        "</style>",
        "</head>",
        "<body>",
        "<div class=\"cover\">",
        "<h1>Cryptographic Bill of Materials (CBOM)</h1>",
        "<div class=\"subtitle\">Post-Quantum Cryptography Readiness Report</div>",
        "<div class=\"meta\">",
        "<strong>Organization:</strong> Punjab National Bank (PNB)<br>",
        f"<strong>System:</strong> {html.escape(ctx.system_name)}<br>",
        f"<strong>Report Date:</strong> {ctx.date_str}<br>",
        "<strong>Report Version:</strong> 1.0<br>",
        "<strong>Generator:</strong> Q-Shield CBOM Assessment Tool v1.6",
        "</div>",
        "<div class=\"classification\">INTERNAL - CONFIDENTIAL</div>",
        "</div>",
        "<h1>Executive Summary</h1>",
        "<div class=\"summary-box\">",
        f"<strong>Risk Severity:</strong> <span style=\"color: {_risk_color(risk_score)}; font-weight: bold;\">{risk_severity}</span> ",
        f"(Average Risk Score: {risk_score:.2f}/5.0)",
        "</div>",
        "<p style=\"margin-bottom: 0.15in;\">",
        "This CBOM provides a comprehensive inventory of cryptographic assets and readiness for post-quantum migration.",
        "</p>",
        "<table class=\"summary-table\">",
        "<tr><th>Metric</th><th>Value</th><th>Status</th></tr>",
        f"<tr><td>Total Cryptographic Assets</td><td>{summary.get('total_assets', 0)}</td><td>Tracked</td></tr>",
        f"<tr><td>Quantum Vulnerable Assets</td><td>{summary.get('quantum_vulnerable_assets', 0)}</td><td class=\"risk-critical\">ACTION REQUIRED</td></tr>",
        f"<tr><td>Quantum Safe Assets</td><td>{summary.get('quantum_safe_assets', 0)}</td><td class=\"risk-low\">COMPLIANT</td></tr>",
        f"<tr><td>Endpoints PQC Ready</td><td>{summary.get('endpoints_pqc_ready', 0)}/{summary.get('total_endpoints', 0)}</td><td>{'OK' if summary.get('endpoints_pqc_ready', 0) > 0 else 'NEEDS WORK'}</td></tr>",
        f"<tr><td>Weak Cryptography Detected</td><td>{summary.get('endpoints_with_weak_crypto', 0)}</td><td class=\"risk-critical\">DEPRECATED</td></tr>",
        f"<tr><td>PQC Readiness Score</td><td>{pqc_ready_score}%</td><td>Target: 100% by 2035</td></tr>",
        "</table>",
        "<div class=\"critical-box\">",
        "<strong>Immediate Actions (Q2-Q4 2026):</strong>",
        "<ul>",
        "<li>Inventory RSA and ECDH key exchanges; plan hybrid ML-KEM rollout.</li>",
        "<li>Audit certificate lifecycle for replacements and PQC pilots.</li>",
        "<li>Establish crypto agility for rapid algorithm rotation.</li>",
        "</ul>",
        "</div>",
        "<div class=\"section-break\"></div>",
        "<h1>Cryptographic Asset Inventory</h1>",
        "<p>This section details cryptographic components discovered per endpoint.</p>",
    ]

    if not endpoints:
        html_parts.append("<p class=\"text-muted\"><em>No endpoint data available.</em></p>")
    else:
        for endpoint in endpoints:
            endpoint_name = html.escape(str(endpoint.get("endpoint") or "Unknown"))
            ip_value = endpoint.get("ip_address") or endpoint.get("ip") or "N/A"
            port_value = endpoint.get("port") or "N/A"
            html_parts.extend(
                [
                    f"<h2>{endpoint_name}</h2>",
                    f"<p class=\"text-muted\">IP/Port: {html.escape(str(ip_value))}:{html.escape(str(port_value))}</p>",
                    "<table>",
                    "<tr><th>Asset Type</th><th>Name</th><th>Strength</th><th>Quantum Vulnerable</th><th>Risk</th><th>Notes</th></tr>",
                ]
            )
            assets = endpoint.get("assets", []) or []
            if not assets:
                html_parts.append("<tr><td colspan=\"6\" class=\"text-muted\"><em>No assets discovered</em></td></tr>")
            else:
                for asset in assets:
                    asset_type = html.escape(str(asset.get("asset_type") or "unknown"))
                    name = html.escape(str(asset.get("name") or "-"))
                    strength = str(asset.get("strength") or "unknown")
                    q_vuln = bool(asset.get("quantum_vulnerable"))
                    risk_value = float(_risk_from_strength(strength, q_vuln))
                    notes = ", ".join(asset.get("notes", []) or ["-"])
                    risk_class = "risk-critical" if risk_value >= 4 else ("risk-high" if risk_value >= 3 else ("risk-medium" if risk_value >= 2 else "risk-low"))
                    q_vuln_class = "risk-critical" if q_vuln else "risk-low"
                    html_parts.append(
                        "<tr>"
                        f"<td>{asset_type}</td>"
                        f"<td>{name}</td>"
                        f"<td>{html.escape(str(strength))}</td>"
                        f"<td><span class=\"{q_vuln_class}\">{'Yes' if q_vuln else 'No'}</span></td>"
                        f"<td><span class=\"{risk_class}\">{risk_value:.1f}/5</span></td>"
                        f"<td class=\"text-muted\">{html.escape(notes)}</td>"
                        "</tr>"
                    )
            html_parts.append("</table>")

    html_parts.extend(
        [
            "<div class=\"section-break\"></div>",
            "<h1>Asset Inventory by Domain</h1>",
            "<p>Comprehensive inventory of all cryptographic assets, API endpoints, and security properties discovered during the scan.</p>",
        ]
    )

    # Organize endpoints by host
    endpoints_by_host = {}
    for endpoint in endpoints:
        host = endpoint.get("endpoint") or "Unknown"
        if host not in endpoints_by_host:
            endpoints_by_host[host] = endpoint

    for host, endpoint in endpoints_by_host.items():
        html_parts.extend(
            [
                f"<h2>Domain: {html.escape(str(host))}</h2>",
                f"<p class=\"text-muted\">IP: {html.escape(str(endpoint.get('ip_address') or endpoint.get('ip') or 'N/A'))} | Port: {html.escape(str(endpoint.get('port') or 'N/A'))}</p>",
                "<h3>TLS/Certificate Assets</h3>",
                "<table>",
                "<tr><th>Asset Type</th><th>Name</th><th>Strength</th><th>Quantum Risk</th><th>Status</th></tr>",
            ]
        )
        
        assets = endpoint.get("assets", []) or []
        if not assets:
            html_parts.append("<tr><td colspan=\"5\" class=\"text-muted\"><em>No cryptographic assets</em></td></tr>")
        else:
            for asset in assets:
                asset_type = html.escape(str(asset.get("asset_type") or "unknown"))
                name = html.escape(str(asset.get("name") or "-"))
                strength = str(asset.get("strength") or "unknown")
                q_vuln = bool(asset.get("quantum_vulnerable"))
                risk_value = float(_risk_from_strength(strength, q_vuln))
                risk_class = "risk-critical" if risk_value >= 4 else ("risk-high" if risk_value >= 3 else ("risk-medium" if risk_value >= 2 else "risk-low"))
                q_vuln_class = "risk-critical" if q_vuln else "risk-low"
                strength_display = html.escape(str(strength))
                
                html_parts.append(
                    "<tr>"
                    f"<td>{asset_type}</td>"
                    f"<td>{name}</td>"
                    f"<td>{strength_display}</td>"
                    f"<td><span class=\"{q_vuln_class}\">{'Quantum Risk' if q_vuln else 'Safe'}</span></td>"
                    f"<td><span class=\"{risk_class}\">{risk_value:.1f}/5</span></td>"
                    "</tr>"
                )
        
        html_parts.append("</table>")
        
        # API Endpoints Section
        api_endpoints = endpoint.get("api_endpoints", []) or []
        html_parts.append("<h3>API Endpoints</h3>")
        
        if not api_endpoints:
            html_parts.append("<p class=\"text-muted\"><em>No API endpoints discovered</em></p>")
        else:
            html_parts.extend(
                [
                    "<table>",
                    "<tr><th>Endpoint Path</th><th>Status</th><th>Type</th><th>CORS</th><th>Auth Required</th><th>Rate Limit</th></tr>",
                ]
            )
            
            for api in api_endpoints:
                path = html.escape(str(api.get("path") or "-"))
                status = api.get("status") or "Unknown"
                content_type = html.escape(str(api.get("content_type") or "-").split(";")[0])
                
                # Security analysis
                sec_analysis = api.get("security_analysis", {})
                cors_status = "Yes" if sec_analysis.get("cors_enabled") else "No"
                auth_status = "Yes" if sec_analysis.get("requires_auth") else "No"
                rate_limit_status = "Yes" if sec_analysis.get("rate_limit_headers") else "No"
                
                cors_class = "risk-high" if sec_analysis.get("cors_enabled") else "risk-low"
                auth_class = "risk-low" if sec_analysis.get("requires_auth") else "risk-high"
                
                html_parts.append(
                    "<tr>"
                    f"<td><code>{path}</code></td>"
                    f"<td>{status}</td>"
                    f"<td>{content_type}</td>"
                    f"<td><span class=\"{cors_class}\">{cors_status}</span></td>"
                    f"<td><span class=\"{auth_class}\">{auth_status}</span></td>"
                    f"<td>{rate_limit_status}</td>"
                    "</tr>"
                )
            
            html_parts.append("</table>")
            
            # API Security Issues Summary
            issues = []
            for api in api_endpoints:
                sec_analysis = api.get("security_analysis", {})
                issues.extend(sec_analysis.get("issues", []))
            
            if issues:
                html_parts.extend(
                    [
                        "<div class=\"critical-box\">",
                        "<strong>API Security Issues Found:</strong>",
                        "<ul>",
                    ]
                )
                for issue in issues:
                    html_parts.append(f"<li>{html.escape(issue)}</li>")
                html_parts.extend(["</ul>", "</div>"])
        
        # HTTP Security Headers Summary
        headers = endpoint.get("http_security_headers", {}) or {}
        html_parts.append("<h3>HTTP Security Headers</h3>")
        
        headers_present = headers.get("security_headers_present", [])
        if headers_present:
            html_parts.extend(["<p><strong>Headers Found:</strong> ", ", ".join(headers_present), "</p>"])
        else:
            html_parts.append("<p class=\"text-muted\"><em>No security headers detected</em></p>")
        
        html_parts.append("")  # spacing
    
    html_parts.extend(
        [
            "<div class=\"section-break\"></div>",
            "<h1>Certificates and Key Material</h1>",
            "<table>",
            "<tr><th>Subject</th><th>Issuer</th><th>Valid From</th><th>Valid To</th><th>Public Key</th><th>Signature Algorithm</th><th>Status</th></tr>",
        ]
    )

    cert_count = 0
    for endpoint in endpoints:
        for asset in endpoint.get("assets", []) or []:
            if asset.get("asset_type") == "certificate":
                cert_count += 1
                props = asset.get("properties", {}) or {}
                subject = html.escape(str(props.get("subject") or "-"))
                issuer = html.escape(str(props.get("issuer") or "-"))
                valid_from = html.escape(str(props.get("valid_from") or "-"))
                valid_to = html.escape(str(props.get("valid_to") or "-"))
                sig_algo = html.escape(str(props.get("signature_algorithm") or "-"))
                
                # Extract public key algorithm and size
                pubkey_algo = html.escape(str(props.get("public_key_algorithm") or "-"))
                pubkey_size = props.get("public_key_size") or "-"
                pubkey_info = f"{pubkey_algo} {pubkey_size}" if pubkey_size != "-" else pubkey_algo
                
                status_class = "status-met" if "ML-DSA" in sig_algo or "SLH-DSA" in sig_algo else "status-gap"
                status_label = "PQC" if "ML-" in sig_algo or "SLH-" in sig_algo else "Classical"
                html_parts.append(
                    "<tr>"
                    f"<td>{subject}</td>"
                    f"<td>{issuer}</td>"
                    f"<td>{valid_from}</td>"
                    f"<td>{valid_to}</td>"
                    f"<td class=\"text-muted\">{pubkey_info}</td>"
                    f"<td>{sig_algo}</td>"
                    f"<td><span class=\"{status_class}\">{status_label}</span></td>"
                    "</tr>"
                )

    if cert_count == 0:
        html_parts.append("<tr><td colspan=\"7\" class=\"text-muted\"><em>No certificates discovered</em></td></tr>")

    html_parts.extend(
        [
            "</table>",
            "<div class=\"section-break\"></div>",
            "<h1>PQC Readiness Assessment</h1>",
            "<p>",
            "Quantum Decrypt-Later Risk (Mosca + CRQC) exposure is assessed based on observed algorithms and key sizes.",
            "</p>",
            "<div class=\"summary-box\">",
            "<strong>Post-quantum replacements:</strong>",
            "<ul>",
            "<li>ML-KEM (FIPS 203) for key establishment.</li>",
            "<li>ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) for signatures.</li>",
            "</ul>",
            "</div>",
            "<div class=\"section-break\"></div>",
            "<h1>Compliance Framework Mapping</h1>",
            "<h2>NIST FIPS 203/204/205 Alignment</h2>",
            "<table>",
            "<tr><th>Standard</th><th>Status</th><th>Evidence</th></tr>",
        ]
    )

    for row in ctx.fips_mapping:
        status_class = "status-met" if row["status"] == "MET" else ("status-partial" if row["status"] == "PARTIAL" else "status-gap")
        html_parts.append(
            "<tr>"
            f"<td>{html.escape(row['standard'])}</td>"
            f"<td><span class=\"{status_class}\">{row['status']}</span></td>"
            f"<td class=\"text-muted\">{html.escape(row['evidence'])}</td>"
            "</tr>"
        )

    html_parts.extend(
        [
            "</table>",
            "<h2>RBI Cyber Framework Alignment</h2>",
            "<table>",
            "<tr><th>Control Area</th><th>Status</th><th>Evidence</th></tr>",
        ]
    )

    for row in ctx.rbi_mapping:
        status_class = "status-met" if row["status"] == "MET" else ("status-partial" if row["status"] == "PARTIAL" else "status-gap")
        html_parts.append(
            "<tr>"
            f"<td>{html.escape(row['control'])}</td>"
            f"<td><span class=\"{status_class}\">{row['status']}</span></td>"
            f"<td class=\"text-muted\">{html.escape(row['evidence'])}</td>"
            "</tr>"
        )

    html_parts.extend(
        [
            "</table>",
            "<h2>NSA CNSA 2.0 Alignment</h2>",
            "<table>",
            "<tr><th>Control</th><th>Status</th><th>Evidence</th></tr>",
        ]
    )

    for row in ctx.cnsa_mapping:
        status_class = "status-met" if row["status"] == "MET" else ("status-partial" if row["status"] == "PARTIAL" else "status-gap")
        html_parts.append(
            "<tr>"
            f"<td>{html.escape(row['control'])}</td>"
            f"<td><span class=\"{status_class}\">{row['status']}</span></td>"
            f"<td class=\"text-muted\">{html.escape(row['evidence'])}</td>"
            "</tr>"
        )

    html_parts.extend(
        [
            "</table>",
            "<div class=\"section-break\"></div>",
            "<h1>Remediation Roadmap</h1>",
            "<table>",
            "<tr><th>Timeline</th><th>Action Item</th><th>Owner</th><th>Priority</th></tr>",
            "<tr><td><strong>Q2-Q4 2026</strong></td><td>Expand hybrid ML-KEM support across all TLS 1.3 endpoints</td><td>Security Engineering</td><td><span class=\"risk-high\">HIGH</span></td></tr>",
            "<tr><td><strong>2027</strong></td><td>Deploy ML-DSA certificate pilots from internal CA</td><td>PKI Team</td><td><span class=\"risk-high\">HIGH</span></td></tr>",
            "<tr><td><strong>2028-2029</strong></td><td>Hybrid ML-KEM + ML-DSA deployment on customer-facing services</td><td>Platform Engineering</td><td><span class=\"risk-medium\">MEDIUM</span></td></tr>",
            "<tr><td><strong>2030</strong></td><td>Deprecate RSA-only certificate chains; full NIST alignment</td><td>Enterprise Security</td><td><span class=\"risk-high\">HIGH</span></td></tr>",
            "<tr><td><strong>2031-2035</strong></td><td>Retire classical-only cryptography where feasible</td><td>Enterprise Security</td><td><span class=\"risk-medium\">MEDIUM</span></td></tr>",
            "</table>",
            "<div class=\"section-break\"></div>",
            "<h1>Audit Trail and Sign-Off</h1>",
            "<div class=\"audit-trail\">",
            f"<p><strong>Report Generated:</strong> {html.escape(datetime.now(timezone.utc).isoformat())}</p>",
            "<p><strong>Generator:</strong> Q-Shield CBOM Assessment Tool v1.6 (CycloneDX 1.6 compliant)</p>",
            "<p><strong>Compliance Standards:</strong> NIST FIPS 203/204/205, RBI Cyber Framework, NSA CNSA 2.0</p>",
            "<p style=\"margin-top: 0.3in;\"><strong>Approvals:</strong></p>",
            "<p>Security Analyst: <span class=\"signature-line\"></span> Date: <span class=\"signature-line\" style=\"width: 1in;\"></span></p>",
            "<p>Security Manager: <span class=\"signature-line\"></span> Date: <span class=\"signature-line\" style=\"width: 1in;\"></span></p>",
            "<p>CIO/CISO: <span class=\"signature-line\"></span> Date: <span class=\"signature-line\" style=\"width: 1in;\"></span></p>",
            "</div>",
            "<p style=\"margin-top: 0.25in; font-size: 9pt; color: #999; border-top: 1pt solid #ddd; padding-top: 0.15in;\">",
            "<strong>Disclaimer:</strong> This CBOM represents cryptographic assets discovered during automated scanning and assessment. "
            "Regenerate after infrastructure changes or at least quarterly.",
            "</p>",
            "</body>",
            "</html>",
        ]
    )

    return "\n".join(html_parts)


def generate_outputs(
    input_path: Path,
    system_name: str,
    date_str: str,
    output_dir: Path,
) -> Tuple[Path, Path]:
    scan_results = _load_scan_results(input_path)
    cbom = generate_cbom(scan_results)
    cbom_dict = cbom.to_dict()

    cyclonedx = _build_cyclonedx_1_6(cbom_dict, system_name, date_str)

    file_system_name = _sanitize_name(system_name)
    json_path = output_dir / f"CBOM_PNB_{file_system_name}_{date_str}_v1.0.json"
    pdf_path = output_dir / f"CBOM_PNB_{file_system_name}_{date_str}_v1.0.pdf"

    json_path.write_text(json.dumps(cyclonedx, indent=2), encoding="utf-8")

    ctx = _build_report_context(system_name, date_str, scan_results, cbom_dict)
    _render_pdf(pdf_path, ctx, json_path)

    return json_path, pdf_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate CycloneDX 1.6 CBOM JSON and PDF report")
    parser.add_argument("--input", default="rru_scan.json", help="Path to scan result JSON")
    parser.add_argument("--system-name", default="Q-Shield", help="System name for the report")
    parser.add_argument("--date", default=_utc_date_str(), help="Report date (YYYY-MM-DD)")
    parser.add_argument("--output-dir", default=".", help="Output directory")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    json_path, pdf_path = generate_outputs(input_path, args.system_name, args.date, output_dir)

    print(f"CycloneDX JSON written to: {json_path}")
    print(f"PDF report written to: {pdf_path}")


if __name__ == "__main__":
    main()
