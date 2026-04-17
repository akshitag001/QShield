import os
import smtplib
import json
import logging
import threading
import time
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formatdate
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from dotenv import load_dotenv
from sqlalchemy import select
from sqlalchemy.orm import Session

# Import project-specific modules
# Note: We assume these are in the same directory
from cbom_generator import generate_cbom
from tls_scanner import scan_tls
from report_pdf import generate_pdf

# Setup logging
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

class ReportingService:
    @staticmethod
    def get_smtp_config():
        return {
            "host": os.getenv("SMTP_HOST", "smtp.gmail.com"),
            "port": int(os.getenv("SMTP_PORT", "587")),
            "user": os.getenv("SMTP_USERNAME"),
            "password": os.getenv("SMTP_PASSWORD"),
            "from_email": os.getenv("SMTP_FROM_EMAIL"),
            "use_tls": os.getenv("SMTP_USE_TLS", "1") != "0",
            "admin_email": os.getenv("ADMIN_EMAIL")
        }

    @staticmethod
    def send_email_with_attachment(
        to_email: str,
        subject: str,
        body_html: str,
        attachment_path: Optional[Path] = None,
        attachment_name: str = "report.pdf"
    ) -> Optional[str]:
        config = ReportingService.get_smtp_config()
        
        if not config["host"] or not config["from_email"]:
            return "SMTP is not configured"

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = config["from_email"]
        msg["To"] = to_email
        if config.get("admin_email") and config["admin_email"] != to_email:
            msg["Cc"] = config["admin_email"]
        msg["Date"] = formatdate(localtime=True)
        msg.set_content("Please view the report in an HTML-compatible email client.")
        msg.add_alternative(body_html, subtype="html")

        if attachment_path and attachment_path.exists():
            with open(attachment_path, "rb") as f:
                file_data = f.read()
                msg.add_attachment(
                    file_data,
                    maintype="application",
                    subtype="pdf",
                    filename=attachment_name
                )

        try:
            with smtplib.SMTP(config["host"], config["port"], timeout=30) as smtp:
                if config["use_tls"]:
                    smtp.starttls()
                if config["user"] and config["password"]:
                    smtp.login(config["user"], config["password"])
                smtp.send_message(msg)
            return None
        except Exception as exc:
            logger.error(f"Failed to send email: {exc}")
            return str(exc)

    @staticmethod
    def extract_quantum_vulnerabilities(cbom: Dict[str, Any], target: Optional[str], scan_id: Optional[str]) -> Dict[str, Any]:
        vulnerabilities = []
        for endpoint in cbom.get("endpoints", []):
            for asset in endpoint.get("assets", []):
                if asset.get("quantum_vulnerable", False):
                    vuln = {
                        "asset_type": asset.get("asset_type"),
                        "name": asset.get("name"),
                        "reason": ReportingService._get_vulnerability_reason(asset),
                        "risk_level": ReportingService._get_risk_level(asset),
                        "recommendation": ReportingService._get_recommendation(asset),
                    }
                    vulnerabilities.append(vuln)
        return {
            "scan_id": scan_id,
            "target": target,
            "total_vulnerabilities": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
        }

    @staticmethod
    def _get_vulnerability_reason(asset: dict) -> str:
        asset_type = asset.get("asset_type", "")
        name = asset.get("name", "").upper()
        props = asset.get("properties", {})
        if asset_type == "public_key":
            alg = props.get("algorithm", "")
            size = props.get("key_size", "")
            if "RSA" in alg.upper(): return f"RSA-{size} can be broken by Shor's algorithm"
            if "EC" in alg.upper() or "ECDSA" in alg.upper(): return f"ECDSA-{size} vulnerable to Shor's algorithm"
        if asset_type == "key_exchange":
            if any(x in name for x in ["ECDH", "DHE", "DH", "RSA"]): return f"{name} key exchange is vulnerable to Shor's algorithm"
        return "Uses classical cryptography vulnerable to quantum attacks"

    @staticmethod
    def _get_risk_level(asset: dict) -> str:
        if asset.get("asset_type") in ["key_exchange", "public_key", "certificate"]: return "HIGH"
        if asset.get("strength") in ["broken", "weak"]: return "CRITICAL"
        return "MEDIUM"

    @staticmethod
    def _get_recommendation(asset: dict) -> str:
        asset_type = asset.get("asset_type", "")
        if asset_type == "public_key": return "Migrate to ML-DSA (Dilithium)"
        if asset_type == "key_exchange": return "Enable ML-KEM (Kyber) or hybrid modes"
        return "Plan migration to NIST post-quantum standards"

    @staticmethod
    def run_scheduled_report(db: Session, schedule, scan_tls_func, generate_cbom_func, log_event_func):
        """
        Orchestrates a single scheduled report execution.
        """
        from app import _build_scheduled_target, _compute_next_run, ScanRecord # Late import to avoid circular dependency
        
        target = _build_scheduled_target(schedule.domain, schedule.codomain)
        scan_id = f"sch_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid4().hex[:6]}"
        now = datetime.now(timezone.utc)

        try:
            logger.info(f"Executing scheduled scan for {target}")
            result = scan_tls_func(target, timeout=20)
            cbom = generate_cbom_func([result])
            cbom_dict = cbom.to_dict()
            vulnerabilities = ReportingService.extract_quantum_vulnerabilities(cbom_dict, target, scan_id)

            # Create ScanRecord
            new_scan = ScanRecord(
                scan_id=scan_id,
                target=target,
                started_at=now,
                completed_at=datetime.now(timezone.utc),
                status="completed",
                result_json=json.dumps(result),
                cbom_json=json.dumps(cbom_dict),
                vulnerabilities_json=json.dumps(vulnerabilities),
                created_by=schedule.created_by,
            )
            db.add(new_scan)

            # Generate PDF using ReportLab
            report_data = {
                "scan_id": scan_id,
                "target": target,
                "started_at": now.isoformat(),
                "status": "completed",
                "result": result,
                "cbom": cbom_dict,
                "vulnerabilities": vulnerabilities,
            }
            temp_pdf = Path(f"temp_report_{scan_id}.pdf")
            generate_pdf(report_data=report_data, output_path=temp_pdf)

            # Prepare HTML Body
            summary = cbom_dict.get("summary", {})
            body_html = f"""
            <html>
            <body style="font-family: sans-serif;">
                <h2 style="color: #0b3d91;">Q-Shield Scheduled Report</h2>
                <p>A scheduled cryptographic scan was completed for <b>{target}</b>.</p>
                <div style="background: #f0f7ff; padding: 15px; border-radius: 5px;">
                    <h3>Summary:</h3>
                    <ul>
                        <li><b>Total Assets:</b> {summary.get('total_assets', 0)}</li>
                        <li><b>Quantum Vulnerable:</b> <span style="color: red;">{summary.get('quantum_vulnerable_assets', 0)}</span></li>
                        <li><b>Quantum Safe:</b> <span style="color: green;">{summary.get('quantum_safe_assets', 0)}</span></li>
                        <li><b>Total Vulnerabilities:</b> {vulnerabilities.get('total_vulnerabilities', 0)}</li>
                    </ul>
                </div>
                <p>Please find the detailed CBOM report attached as a PDF.</p>
                <hr>
                <p style="font-size: 0.8em; color: #666;">Generated by Q-Shield Automated Reporting Service</p>
            </body>
            </html>
            """

            # Send Email
            email_error = ReportingService.send_email_with_attachment(
                schedule.delivery_email,
                f"Q-Shield Report: {target}",
                body_html,
                attachment_path=temp_pdf,
                attachment_name=f"QShield_Report_{target.replace('.','_')}.pdf"
            )

            # Cleanup temp file
            if temp_pdf.exists():
                temp_pdf.unlink()

            # Update schedule
            schedule.last_sent_at = now
            schedule.next_run_at = _compute_next_run(schedule.next_run_at, schedule.frequency, now)
            
            log_event_func(
                db, None, "scheduled_report_executed", 
                resource_type="scheduled_report", 
                resource_id=schedule.schedule_id,
                target=target,
                details={"scan_id": scan_id, "email_status": "sent" if not email_error else "failed", "error": email_error}
            )

        except Exception as e:
            logger.error(f"Scheduled report error for {target}: {e}")
            schedule.next_run_at = _compute_next_run(schedule.next_run_at, schedule.frequency, now)
            log_event_func(db, None, "scheduled_report_failed", target=target, details={"error": str(e)})
