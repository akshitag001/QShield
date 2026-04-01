"""
Q-Shield Web Application
FastAPI backend for cryptographic inventory scanning and CBOM generation
"""

import hashlib
import hmac
import ipaddress
import io
import json
import os
import queue
import re
import secrets
import smtplib
import threading
import time
import traceback
import urllib.parse
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from starlette.middleware.sessions import SessionMiddleware

from cbom_generator import generate_cbom
from tls_scanner import scan_tls


# Initialize FastAPI app
app = FastAPI(
    title="Q-Shield",
    description="Cryptographic Bill of Materials (CBOM) Scanner for Post-Quantum Readiness",
    version="1.0.0",
)

# Templates and static files
BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Try to mount static files if directory exists
static_dir = BASE_DIR / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


# Session configuration
# IMPORTANT for serverless: secret must be stable across invocations/instances,
# otherwise session cookies become invalid and users get logged out between pages.
SESSION_SECRET = os.getenv("SESSION_SECRET_KEY")
if not SESSION_SECRET:
    SESSION_SECRET = "qshield-dev-session-secret-change-in-production"

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="qshield_session",
    same_site="lax",
    https_only=False,
)


# Database configuration
configured_database_url = os.getenv("DATABASE_URL")
if configured_database_url:
    DATABASE_URL = configured_database_url
else:
    # Use writable /tmp on Unix-like/serverless environments, local file on Windows.
    DATABASE_URL = "sqlite:////tmp/qshield.db" if os.name != "nt" else "sqlite:///./qshield.db"

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

_engine_args = {}
if DATABASE_URL.startswith("sqlite"):
    _engine_args["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **_engine_args)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
_db_init_lock = threading.Lock()
_db_initialized = False
DEBUG_RUNTIME_ERRORS = os.getenv("DEBUG_RUNTIME_ERRORS", "0") == "1" or os.getenv("VERCEL") == "1"
SCHEDULE_REPORT_POLL_SECONDS = max(30, int(os.getenv("SCHEDULE_REPORT_POLL_SECONDS", "60")))
_scheduler_lock = threading.Lock()
_scheduler_started = False


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="viewer")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class ScanRecord(Base):
    __tablename__ = "scan_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    target: Mapped[str] = mapped_column(String(255), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(20), index=True)
    result_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cbom_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    vulnerabilities_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    username: Mapped[str] = mapped_column(String(50), index=True)
    role: Mapped[str] = mapped_column(String(20), index=True)
    action: Mapped[str] = mapped_column(String(100), index=True)
    resource_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    resource_id: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    target: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    details_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class ScheduledReport(Base):
    __tablename__ = "scheduled_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    schedule_id: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    codomain: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    frequency: Mapped[str] = mapped_column(String(20), index=True)
    scheduled_date: Mapped[str] = mapped_column(String(20))
    scheduled_time: Mapped[str] = mapped_column(String(20))
    delivery_email: Mapped[str] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    next_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    last_sent_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


class ThirdPartyVendor(Base):
    __tablename__ = "third_party_vendors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    vendor_id: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    vendor_name: Mapped[str] = mapped_column(String(255), index=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    criticality: Mapped[str] = mapped_column(String(20), default="medium", index=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    last_scan_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )


# Pydantic models
class ScanRequest(BaseModel):
    target: str = Field(..., description="Target URL, hostname, or IP:PORT")
    timeout: int = Field(default=10, ge=1, le=60, description="Timeout in seconds")


class MultiScanRequest(BaseModel):
    targets: List[str] = Field(..., description="List of targets to scan")
    timeout: int = Field(default=10, ge=1, le=60)


class SubdomainScanRequest(BaseModel):
    parent_target: str = Field(..., description="Primary scanned domain")
    subdomains: List[str] = Field(default_factory=list, description="Selected subdomains to scan")
    timeout: int = Field(default=10, ge=1, le=60)
    include_parent: bool = Field(default=True, description="Include parent target in combined CBOM")


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    target: str
    started_at: str
    result: Optional[Dict[str, Any]] = None
    cbom: Optional[Dict[str, Any]] = None
    vulnerabilities: Optional[Dict[str, Any]] = None


class ScheduledReportRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=255)
    codomain: Optional[str] = Field(default=None, max_length=255)
    frequency: str = Field(..., description="weekly or monthly")
    schedule_date: str = Field(..., description="YYYY-MM-DD")
    schedule_time: str = Field(..., description="HH:MM")
    delivery_email: str = Field(..., min_length=5, max_length=255)
    enabled: bool = Field(default=True)


class ScheduledReportToggleRequest(BaseModel):
    enabled: bool


class VendorCreateRequest(BaseModel):
    vendor_name: str = Field(..., min_length=1, max_length=255)
    domain: str = Field(..., min_length=1, max_length=255)
    criticality: str = Field(default="medium", description="low|medium|high|critical")
    notes: Optional[str] = Field(default=None, max_length=1000)
    enabled: bool = Field(default=True)


class VendorToggleRequest(BaseModel):
    enabled: bool


class VendorScanRequest(BaseModel):
    vendor_ids: List[str] = Field(default_factory=list)
    timeout: int = Field(default=12, ge=1, le=60)


def _initialize_database() -> None:
    global _db_initialized, engine, SessionLocal, DATABASE_URL
    if _db_initialized:
        return

    with _db_init_lock:
        if _db_initialized:
            return
        try:
            Base.metadata.create_all(bind=engine)
            with SessionLocal() as db:
                _seed_default_admin(db)
            _db_initialized = True
            return
        except Exception:
            # Fallback for constrained serverless filesystems.
            DATABASE_URL = "sqlite:///:memory:"
            fallback_engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
            fallback_session_local = sessionmaker(bind=fallback_engine, autocommit=False, autoflush=False)
            Base.metadata.create_all(bind=fallback_engine)
            with fallback_session_local() as db:
                _seed_default_admin(db)

            engine = fallback_engine
            SessionLocal = fallback_session_local
            _db_initialized = True


def get_db():
    try:
        _initialize_database()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Database initialization failed: {exc}") from exc
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    if DEBUG_RUNTIME_ERRORS:
        details = "\n".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        return PlainTextResponse(f"Unhandled server error:\n{details}", status_code=500)
    return PlainTextResponse("Internal Server Error", status_code=500)


def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    iterations = 200_000
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations).hex()
    return f"pbkdf2_sha256${iterations}${salt}${pwd_hash}"


def _verify_password(password: str, stored_hash: str) -> bool:
    try:
        _, iterations_str, salt, expected_hash = stored_hash.split("$", 3)
        iterations = int(iterations_str)
    except ValueError:
        return False

    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations).hex()
    return hmac.compare_digest(pwd_hash, expected_hash)


def _seed_default_admin(db: Session) -> None:
    has_user = db.scalar(select(User.id).limit(1))
    if has_user:
        return

    admin_username = os.getenv("ADMIN_USERNAME", "admin")
    admin_password = os.getenv("ADMIN_PASSWORD", "admin123")
    admin_role = os.getenv("ADMIN_ROLE", "admin")

    db.add(
        User(
            username=admin_username,
            password_hash=_hash_password(admin_password),
            role=admin_role,
        )
    )
    db.commit()


def _get_current_user(request: Request, db: Session) -> Optional[User]:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return db.get(User, user_id)


def _require_user(request: Request, db: Session) -> User:
    user = _get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def _require_roles(request: Request, db: Session, allowed_roles: List[str]) -> User:
    user = _require_user(request, db)
    if user.role not in allowed_roles:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    return user


def _is_admin(user: User) -> bool:
    return user.role in ["admin", "cyber_lead", "it_lead", "security_head"]


def _log_event(
    db: Session,
    user: Optional[User],
    action: str,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    target: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    username = user.username if user else "anonymous"
    role = user.role if user else "anonymous"
    db.add(
        AuditLog(
            user_id=user.id if user else None,
            username=username,
            role=role,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            target=target,
            details_json=json.dumps(details) if details else None,
        )
    )


def _scan_record_to_dict(scan: ScanRecord, owner_username: Optional[str] = None) -> Dict[str, Any]:
    result = json.loads(scan.result_json) if scan.result_json else None
    cbom = json.loads(scan.cbom_json) if scan.cbom_json else None
    vulnerabilities = json.loads(scan.vulnerabilities_json) if scan.vulnerabilities_json else None

    return {
        "scan_id": scan.scan_id,
        "target": scan.target,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "status": scan.status,
        "result": result,
        "cbom": cbom,
        "vulnerabilities": vulnerabilities,
        "error": scan.error,
        "created_by": scan.created_by,
        "owner_username": owner_username,
    }


def _scheduled_report_to_dict(schedule: ScheduledReport, owner_username: Optional[str] = None) -> Dict[str, Any]:
    return {
        "schedule_id": schedule.schedule_id,
        "domain": schedule.domain,
        "codomain": schedule.codomain,
        "frequency": schedule.frequency,
        "schedule_date": schedule.scheduled_date,
        "schedule_time": schedule.scheduled_time,
        "delivery_email": schedule.delivery_email,
        "enabled": schedule.enabled,
        "next_run_at": schedule.next_run_at.isoformat() if schedule.next_run_at else None,
        "last_sent_at": schedule.last_sent_at.isoformat() if schedule.last_sent_at else None,
        "created_at": schedule.created_at.isoformat() if schedule.created_at else None,
        "updated_at": schedule.updated_at.isoformat() if schedule.updated_at else None,
        "created_by": schedule.created_by,
        "owner_username": owner_username,
    }


def _get_scheduled_report_for_user(db: Session, schedule_id: str, user: User) -> ScheduledReport:
    schedule = db.scalar(select(ScheduledReport).where(ScheduledReport.schedule_id == schedule_id))
    if not schedule:
        raise HTTPException(status_code=404, detail="Scheduled report not found")

    if _is_admin(user):
        return schedule

    if schedule.created_by != user.id:
        raise HTTPException(status_code=403, detail="You can only access your own scheduled reports")
    return schedule


def _vendor_to_dict(vendor: ThirdPartyVendor, owner_username: Optional[str] = None) -> Dict[str, Any]:
    return {
        "vendor_id": vendor.vendor_id,
        "vendor_name": vendor.vendor_name,
        "domain": vendor.domain,
        "criticality": vendor.criticality,
        "notes": vendor.notes,
        "enabled": vendor.enabled,
        "last_scan_at": vendor.last_scan_at.isoformat() if vendor.last_scan_at else None,
        "created_at": vendor.created_at.isoformat() if vendor.created_at else None,
        "updated_at": vendor.updated_at.isoformat() if vendor.updated_at else None,
        "created_by": vendor.created_by,
        "owner_username": owner_username,
    }


def _get_vendor_for_user(db: Session, vendor_id: str, user: User) -> ThirdPartyVendor:
    vendor = db.scalar(select(ThirdPartyVendor).where(ThirdPartyVendor.vendor_id == vendor_id))
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")

    if _is_admin(user):
        return vendor

    if vendor.created_by != user.id:
        raise HTTPException(status_code=403, detail="You can only access your own vendors")
    return vendor


def _build_scheduled_target(domain: str, codomain: Optional[str]) -> str:
    normalized_domain = (domain or "").strip()
    normalized_codomain = (codomain or "").strip()
    if not normalized_codomain:
        return normalized_domain

    if "." in normalized_codomain:
        return normalized_codomain

    return f"{normalized_codomain}.{normalized_domain}"


def _split_target_host_port(target: str) -> tuple[str, Optional[int]]:
    value = (target or "").strip()
    if not value:
        return "", None

    if "://" in value:
        parsed = urllib.parse.urlparse(value)
        return parsed.hostname or "", parsed.port

    if value.startswith("["):
        match = re.match(r"^\[(.+)\](?::(\d+))?$", value)
        if match:
            host = match.group(1)
            port = int(match.group(2)) if match.group(2) else None
            return host, port

    if value.count(":") == 1:
        host, port_str = value.split(":", 1)
        if port_str.isdigit():
            return host, int(port_str)

    return value, None


def _is_valid_hostname(host: str) -> bool:
    name = (host or "").strip().rstrip(".")
    if not name:
        return False

    # Always allow localhost.
    if name.lower() == "localhost":
        return True

    # Accept IP literals.
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        pass

    # Require dot-based hostnames to avoid obvious invalid values like "rruacin".
    if "." not in name:
        return False

    if len(name) > 253:
        return False

    labels = name.split(".")
    label_regex = re.compile(r"^[A-Za-z0-9-]{1,63}$")
    for label in labels:
        if not label_regex.match(label):
            return False
        if label.startswith("-") or label.endswith("-"):
            return False

    tld = labels[-1]
    if tld.lower().startswith("xn--"):
        return len(tld) >= 4

    return bool(re.match(r"^[A-Za-z]{2,63}$", tld))


def _validate_scan_target_or_raise(target: str) -> str:
    host, port = _split_target_host_port(target)
    if not _is_valid_hostname(host):
        raise HTTPException(
            status_code=400,
            detail="Invalid or unresolvable domain format. Use a valid host like example.com or rru.ac.in",
        )

    if port is not None and not (1 <= port <= 65535):
        raise HTTPException(status_code=400, detail="Invalid port. Use a value between 1 and 65535")

    return (target or "").strip()


def _friendly_scan_error_detail(error: Exception) -> str:
    message = str(error or "").strip()
    lowered = message.lower()

    if "getaddrinfo failed" in lowered or "name or service not known" in lowered or "dns" in lowered:
        return "Domain could not be resolved. Please enter a valid reachable hostname (e.g., example.com or rru.ac.in)."

    if "invalid target" in lowered:
        return "Invalid target format. Please enter a valid host like example.com or rru.ac.in."

    if "timed out" in lowered or "timeout" in lowered:
        return "Connection timed out while scanning this target."

    return message or "Scan failed"


def _parse_schedule_datetime(date_value: str, time_value: str) -> datetime:
    try:
        date_obj = datetime.strptime(date_value, "%Y-%m-%d").date()
        time_obj = datetime.strptime(time_value, "%H:%M").time()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid date/time format. Use YYYY-MM-DD and HH:MM") from exc

    return datetime(
        year=date_obj.year,
        month=date_obj.month,
        day=date_obj.day,
        hour=time_obj.hour,
        minute=time_obj.minute,
        tzinfo=timezone.utc,
    )


def _add_one_month(value: datetime) -> datetime:
    if value.month == 12:
        return value.replace(year=value.year + 1, month=1)
    return value.replace(month=value.month + 1)


def _compute_next_run(base_time: datetime, frequency: str, now: Optional[datetime] = None) -> datetime:
    current = now or datetime.now(timezone.utc)
    freq = (frequency or "").strip().lower()

    next_time = base_time
    if freq == "weekly":
        while next_time <= current:
            next_time = next_time + timedelta(days=7)
        return next_time

    if freq == "monthly":
        while next_time <= current:
            next_time = _add_one_month(next_time)
        return next_time

    raise HTTPException(status_code=400, detail="Frequency must be weekly or monthly")


def _send_scheduled_report_email(
    schedule: ScheduledReport,
    target: str,
    scan_id: str,
    cbom_dict: Dict[str, Any],
    vulnerabilities: Dict[str, Any],
) -> Optional[str]:
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")
    smtp_from = os.getenv("SMTP_FROM_EMAIL") or smtp_user
    smtp_use_tls = os.getenv("SMTP_USE_TLS", "1") != "0"

    if not smtp_host or not smtp_from:
        return "SMTP is not configured (set SMTP_HOST and SMTP_FROM_EMAIL/SMTP_USERNAME)"

    summary = cbom_dict.get("summary", {}) if cbom_dict else {}
    total_vulns = vulnerabilities.get("total_vulnerabilities", 0) if vulnerabilities else 0

    subject = f"Q-Shield Scheduled Report | {target}"
    body = (
        f"Scheduled report executed successfully.\n\n"
        f"Target: {target}\n"
        f"Scan ID: {scan_id}\n"
        f"Generated At: {datetime.now(timezone.utc).isoformat()}\n\n"
        f"CBOM Summary:\n"
        f"- Total Endpoints: {summary.get('total_endpoints', 0)}\n"
        f"- Total Assets: {summary.get('total_assets', 0)}\n"
        f"- Quantum Vulnerable Assets: {summary.get('quantum_vulnerable_assets', 0)}\n"
        f"- Quantum Safe Assets: {summary.get('quantum_safe_assets', 0)}\n"
        f"- PQC Ready Endpoints: {summary.get('endpoints_pqc_ready', 0)}\n"
        f"- Total Vulnerabilities: {total_vulns}\n"
    )

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = smtp_from
    message["To"] = schedule.delivery_email
    message.set_content(body)

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as smtp:
            if smtp_use_tls:
                smtp.starttls()
            if smtp_user and smtp_password:
                smtp.login(smtp_user, smtp_password)
            smtp.send_message(message)
        return None
    except Exception as exc:
        return str(exc)


def _run_scheduled_reports_cycle() -> None:
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        due_items = db.scalars(
            select(ScheduledReport).where(
                ScheduledReport.enabled.is_(True),
                ScheduledReport.next_run_at.is_not(None),
                ScheduledReport.next_run_at <= now,
            )
        ).all()

        if not due_items:
            return

        user_cache: Dict[int, Optional[User]] = {}
        for schedule in due_items:
            owner = None
            if schedule.created_by:
                if schedule.created_by not in user_cache:
                    user_cache[schedule.created_by] = db.get(User, schedule.created_by)
                owner = user_cache.get(schedule.created_by)

            target = _build_scheduled_target(schedule.domain, schedule.codomain)
            schedule_scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid4().hex[:6]}"

            try:
                result = scan_tls(target, timeout=15)
                cbom = generate_cbom([result])
                cbom_dict = cbom.to_dict()
                vulnerabilities = _extract_quantum_vulnerabilities(cbom_dict, target, schedule_scan_id)

                db.add(
                    ScanRecord(
                        scan_id=schedule_scan_id,
                        target=target,
                        started_at=now,
                        completed_at=datetime.now(timezone.utc),
                        status="completed",
                        result_json=json.dumps(result),
                        cbom_json=json.dumps(cbom_dict),
                        vulnerabilities_json=json.dumps(vulnerabilities),
                        created_by=schedule.created_by,
                    )
                )

                email_error = _send_scheduled_report_email(schedule, target, schedule_scan_id, cbom_dict, vulnerabilities)
                schedule.last_sent_at = datetime.now(timezone.utc)
                schedule.next_run_at = _compute_next_run(schedule.next_run_at, schedule.frequency, datetime.now(timezone.utc))
                schedule.updated_at = datetime.now(timezone.utc)

                _log_event(
                    db,
                    owner,
                    "scheduled_report_executed",
                    resource_type="scheduled_report",
                    resource_id=schedule.schedule_id,
                    target=target,
                    details={
                        "scan_id": schedule_scan_id,
                        "email_status": "sent" if not email_error else "failed",
                        "email_error": email_error,
                    },
                )
            except Exception as exc:
                schedule.next_run_at = _compute_next_run(schedule.next_run_at, schedule.frequency, datetime.now(timezone.utc))
                schedule.updated_at = datetime.now(timezone.utc)
                _log_event(
                    db,
                    owner,
                    "scheduled_report_failed",
                    resource_type="scheduled_report",
                    resource_id=schedule.schedule_id,
                    target=target,
                    details={"error": str(exc)},
                )

        db.commit()


def _scheduled_reports_worker() -> None:
    while True:
        try:
            _run_scheduled_reports_cycle()
        except Exception:
            pass
        time.sleep(SCHEDULE_REPORT_POLL_SECONDS)


def _ensure_scheduler_worker() -> None:
    global _scheduler_started

    if os.getenv("DISABLE_SCHEDULE_WORKER", "0") == "1":
        return
    if os.getenv("VERCEL") == "1":
        return

    with _scheduler_lock:
        if _scheduler_started:
            return

        thread = threading.Thread(target=_scheduled_reports_worker, daemon=True)
        thread.start()
        _scheduler_started = True


def _get_scan_for_user(db: Session, scan_id: str, user: User) -> ScanRecord:
    scan = db.scalar(select(ScanRecord).where(ScanRecord.scan_id == scan_id))
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if _is_admin(user):
        return scan

    if scan.created_by != user.id:
        raise HTTPException(status_code=403, detail="You can only access your own scan data")
    return scan


def _render_template(request: Request, template_name: str, context: Dict[str, Any], status_code: int = 200):
    try:
        return templates.TemplateResponse(
            request,
            template_name,
            context,
            status_code=status_code,
        )
    except (TypeError, ValueError):
        context_with_request = dict(context)
        context_with_request["request"] = request
        return templates.TemplateResponse(template_name, context_with_request, status_code=status_code)


@app.on_event("startup")
def on_startup() -> None:
    _initialize_database()
    _ensure_scheduler_worker()


# Web routes
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    """Main dashboard page"""
    user = _get_current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    if _is_admin(user):
        recent_scans = db.scalars(select(ScanRecord).order_by(ScanRecord.started_at.desc()).limit(10)).all()
        total_scans = db.query(ScanRecord).count()
    else:
        recent_scans = db.scalars(
            select(ScanRecord).where(ScanRecord.created_by == user.id).order_by(ScanRecord.started_at.desc()).limit(10)
        ).all()
        total_scans = db.query(ScanRecord).filter(ScanRecord.created_by == user.id).count()

    usernames_by_id = {row.id: row.username for row in db.scalars(select(User)).all()}

    return _render_template(
        request,
        "dashboard.html",
        {
            "request": request,
            "scan_count": total_scans,
            "recent_scans": [_scan_record_to_dict(scan, usernames_by_id.get(scan.created_by)) for scan in recent_scans],
            "current_user": {"username": user.username, "role": user.role},
        },
    )


@app.get("/learn", response_class=HTMLResponse)
async def learn(request: Request, db: Session = Depends(get_db)):
    """Quantum security education page"""
    user = _get_current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    return _render_template(
        request,
        "education.html",
        {
            "request": request,
            "current_user": {"username": user.username, "role": user.role},
        },
    )


@app.get("/scheduled-reporting", response_class=HTMLResponse)
async def scheduled_reporting_page(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    return _render_template(
        request,
        "scheduled_reporting.html",
        {
            "request": request,
            "current_user": {"username": user.username, "role": user.role},
            "smtp_configured": bool(os.getenv("SMTP_HOST") and (os.getenv("SMTP_FROM_EMAIL") or os.getenv("SMTP_USERNAME"))),
        },
    )


@app.get("/vendors", response_class=HTMLResponse)
async def vendors_page(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    return _render_template(
        request,
        "vendors.html",
        {
            "request": request,
            "current_user": {"username": user.username, "role": user.role},
        },
    )


@app.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request, db: Session = Depends(get_db)):
    """Dedicated audit logs page (admin/lead only)"""
    user = _require_roles(request, db, ["admin", "cyber_lead", "it_lead", "security_head"])

    return _render_template(
        request,
        "logs.html",
        {
            "request": request,
            "current_user": {"username": user.username, "role": user.role},
        },
    )


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse(url="/", status_code=302)
    return _render_template(request, "login.html", {"request": request, "error": None})


@app.post("/login", response_class=HTMLResponse)
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = db.scalar(select(User).where(User.username == username))
    if not user or not _verify_password(password, user.password_hash):
        return _render_template(
            request,
            "login.html",
            {"request": request, "error": "Invalid username or password"},
            status_code=401,
        )

    request.session["user_id"] = user.id
    request.session["username"] = user.username
    request.session["role"] = user.role
    _log_event(db, user, "login_success")
    db.commit()
    return RedirectResponse(url="/", status_code=302)


@app.get("/logout")
async def logout(request: Request):
    user_id = request.session.get("user_id")
    if user_id:
        with SessionLocal() as db:
            user = db.get(User, user_id)
            _log_event(db, user, "logout")
            db.commit()
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)


# API Routes
@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/api/cert-info/{domain}")
async def get_cert_info(domain: str):
    """
    Quickly fetch certificate expiry date for a domain.
    Used for displaying cert info in the subdomain list.
    """
    from tls_scanner import _get_certificate_metadata
    
    domain = domain.strip().lower()
    if not domain or len(domain) < 3:
        return {"domain": domain, "expiry": None, "valid": False, "error": "Invalid domain"}
    
    try:
        cert_info = _get_certificate_metadata(domain, 443, timeout=5)
        expiry = cert_info.get("valid_to")
        subject = cert_info.get("subject", "")
        
        if expiry:
            # Parse ISO format date
            try:
                expiry_date = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
                now = datetime.now(timezone.utc) if expiry_date.tzinfo else datetime.now()
                is_valid = now < expiry_date
                days_until_expiry = (expiry_date.date() - now.date()).days if is_valid else -((now.date() - expiry_date.date()).days)
                
                return {
                    "domain": domain,
                    "expiry": expiry,
                    "subject": subject,
                    "valid": is_valid,
                    "days_until_expiry": days_until_expiry,
                    "status": "ok"
                }
            except Exception as e:
                return {"domain": domain, "expiry": expiry, "valid": False, "error": f"Date parse error: {str(e)}", "status": "parse_error"}
        else:
            return {"domain": domain, "expiry": None, "valid": False, "error": "Could not retrieve cert info", "status": "no_cert"}
    except Exception as e:
        return {"domain": domain, "expiry": None, "valid": False, "error": str(e), "status": "error"}


@app.post("/api/scan", response_model=ScanResponse)
async def scan_target(scan_request: ScanRequest, request: Request, db: Session = Depends(get_db)):
    """
    Scan a single target for TLS/cryptographic information.
    Admin and analyst roles are allowed.
    """
    user = _require_roles(request, db, ["admin", "analyst"])
    normalized_target = _validate_scan_target_or_raise(scan_request.target)

    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid4().hex[:6]}"
    started_at = datetime.now(timezone.utc)

    try:
        result = scan_tls(normalized_target, timeout=scan_request.timeout)
        cbom = generate_cbom([result])
        cbom_dict = cbom.to_dict()
        vulnerabilities = _extract_quantum_vulnerabilities(cbom_dict, normalized_target, scan_id)

        scan_row = ScanRecord(
            scan_id=scan_id,
            target=normalized_target,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
            status="completed",
            result_json=json.dumps(result),
            cbom_json=json.dumps(cbom_dict),
            vulnerabilities_json=json.dumps(vulnerabilities),
            created_by=user.id,
        )
        db.add(scan_row)
        _log_event(db, user, "scan_completed", resource_type="scan", resource_id=scan_id, target=normalized_target)
        db.commit()

        return ScanResponse(
            scan_id=scan_id,
            status="completed",
            target=normalized_target,
            started_at=started_at.isoformat(),
            result=result,
            cbom=cbom_dict,
            vulnerabilities=vulnerabilities,
        )
    except Exception as e:
        error_detail = _friendly_scan_error_detail(e)
        db.add(
            ScanRecord(
                scan_id=scan_id,
                target=normalized_target,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                status="failed",
                error=error_detail,
                created_by=user.id,
            )
        )
        _log_event(
            db,
            user,
            "scan_failed",
            resource_type="scan",
            resource_id=scan_id,
            target=normalized_target,
            details={"error": error_detail, "raw_error": str(e)},
        )
        db.commit()
        raise HTTPException(status_code=400, detail=error_detail)


@app.get("/api/scan/stream")
async def scan_target_stream(
    target: str,
    timeout: int = 15,
    request: Request = None,
    db: Session = Depends(get_db),
):
    """Run scan and stream stage events for real-time visualization."""
    user = _require_roles(request, db, ["admin", "analyst"])
    normalized_target = _validate_scan_target_or_raise(target)
    timeout = max(1, min(timeout, 60))

    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid4().hex[:6]}"
    started_at = datetime.now(timezone.utc)
    event_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue()
    done_event = threading.Event()

    stage_messages = {
        "handshake_discovery": "Handshake & endpoint discovery in progress",
        "cipher_enumeration": "Enumerating TLS versions and cipher suites",
        "quantum_safety_analysis": "Analyzing certificate trust and quantum exposure",
        "agility_scoring": "Computing crypto agility score",
    }

    def _enqueue(event_name: str, payload: Dict[str, Any]) -> None:
        event_queue.put({"event": event_name, "payload": payload})

    def _progress_callback(stage: str, metadata: Dict[str, Any]) -> None:
        _enqueue(
            "stage",
            {
                "stage": stage,
                "message": stage_messages.get(stage, stage.replace("_", " ").title()),
                "metadata": metadata or {},
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

    def _worker() -> None:
        local_db = SessionLocal()
        try:
            worker_user = local_db.get(User, user.id)
            result = scan_tls(normalized_target, timeout=timeout, progress_callback=_progress_callback)
            cbom = generate_cbom([result])
            cbom_dict = cbom.to_dict()
            vulnerabilities = _extract_quantum_vulnerabilities(cbom_dict, normalized_target, scan_id)

            local_db.add(
                ScanRecord(
                    scan_id=scan_id,
                    target=normalized_target,
                    started_at=started_at,
                    completed_at=datetime.now(timezone.utc),
                    status="completed",
                    result_json=json.dumps(result),
                    cbom_json=json.dumps(cbom_dict),
                    vulnerabilities_json=json.dumps(vulnerabilities),
                    created_by=worker_user.id if worker_user else user.id,
                )
            )
            if worker_user:
                _log_event(local_db, worker_user, "scan_completed", resource_type="scan", resource_id=scan_id, target=normalized_target)
            local_db.commit()

            _enqueue(
                "completed",
                {
                    "scan_id": scan_id,
                    "status": "completed",
                    "target": normalized_target,
                    "started_at": started_at.isoformat(),
                    "result": result,
                    "cbom": cbom_dict,
                    "vulnerabilities": vulnerabilities,
                },
            )
        except Exception as exc:
            error_detail = _friendly_scan_error_detail(exc)
            local_db.add(
                ScanRecord(
                    scan_id=scan_id,
                    target=normalized_target,
                    started_at=started_at,
                    completed_at=datetime.now(timezone.utc),
                    status="failed",
                    error=error_detail,
                    created_by=user.id,
                )
            )
            worker_user = local_db.get(User, user.id)
            if worker_user:
                _log_event(
                    local_db,
                    worker_user,
                    "scan_failed",
                    resource_type="scan",
                    resource_id=scan_id,
                    target=normalized_target,
                    details={"error": error_detail, "raw_error": str(exc)},
                )
            local_db.commit()
            _enqueue("scan_error", {"detail": error_detail, "scan_id": scan_id})
        finally:
            done_event.set()
            local_db.close()

    threading.Thread(target=_worker, daemon=True).start()

    def _event_stream():
        yield "retry: 1200\n\n"
        while not (done_event.is_set() and event_queue.empty()):
            try:
                item = event_queue.get(timeout=0.5)
                payload = json.dumps(item["payload"], separators=(",", ":"))
                yield f"event: {item['event']}\ndata: {payload}\n\n"
            except queue.Empty:
                yield ": keepalive\n\n"

    return StreamingResponse(
        _event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/api/scan/multi")
async def scan_multiple_targets(scan_request: MultiScanRequest, request: Request, db: Session = Depends(get_db)):
    """Scan multiple targets and return combined CBOM"""
    user = _require_roles(request, db, ["admin", "analyst"])

    results = []
    errors = []

    for target in scan_request.targets:
        try:
            normalized_target = _validate_scan_target_or_raise(target)
            result = scan_tls(normalized_target, timeout=scan_request.timeout)
            results.append(result)
        except Exception as e:
            errors.append({"target": target, "error": _friendly_scan_error_detail(e)})

    cbom = generate_cbom(results)
    _log_event(
        db,
        user,
        "multi_scan_completed",
        resource_type="multi_scan",
        details={
            "total_targets": len(scan_request.targets),
            "successful": len(results),
            "failed": len(errors),
        },
    )
    db.commit()

    return {
        "total_targets": len(scan_request.targets),
        "successful_scans": len(results),
        "failed_scans": len(errors),
        "errors": errors,
        "cbom": cbom.to_dict(),
    }


@app.post("/api/scan/subdomains")
async def scan_subdomains(scan_request: SubdomainScanRequest, request: Request, db: Session = Depends(get_db)):
    """Scan selected subdomains and return combined CBOM"""
    user = _require_roles(request, db, ["admin", "analyst", "cyber_lead", "it_lead", "security_head"])

    selected = []
    for item in scan_request.subdomains:
        value = (item or "").strip().lower()
        if value and value not in selected:
            selected.append(value)

    targets_to_scan: List[str] = []
    if scan_request.include_parent:
        targets_to_scan.append(scan_request.parent_target.strip())
    targets_to_scan.extend(selected)

    if not targets_to_scan:
        raise HTTPException(status_code=400, detail="No targets selected for subdomain scan")

    results = []
    errors = []

    for target in targets_to_scan:
        try:
            normalized_target = _validate_scan_target_or_raise(target)
            result = scan_tls(normalized_target, timeout=scan_request.timeout)
            results.append(result)
        except Exception as exc:
            errors.append({"target": target, "error": _friendly_scan_error_detail(exc)})

    if not results:
        _log_event(
            db,
            user,
            "subdomain_scan_failed",
            resource_type="subdomain_scan",
            target=scan_request.parent_target,
            details={"selected_count": len(selected), "errors": len(errors)},
        )
        db.commit()
        raise HTTPException(status_code=400, detail="Unable to scan selected targets")

    cbom = generate_cbom(results)
    cbom_dict = cbom.to_dict()
    vulnerabilities = _extract_quantum_vulnerabilities(cbom_dict, scan_request.parent_target, None)

    _log_event(
        db,
        user,
        "subdomain_scan_completed",
        resource_type="subdomain_scan",
        target=scan_request.parent_target,
        details={
            "selected_count": len(selected),
            "include_parent": scan_request.include_parent,
            "successful": len(results),
            "failed": len(errors),
        },
    )
    db.commit()

    return {
        "parent_target": scan_request.parent_target,
        "selected_subdomains": selected,
        "include_parent": scan_request.include_parent,
        "total_targets_requested": len(targets_to_scan),
        "successful_scans": len(results),
        "failed_scans": len(errors),
        "errors": errors,
        "results": results,
        "cbom": cbom_dict,
        "vulnerabilities": vulnerabilities,
    }


@app.get("/api/scan/{scan_id}")
async def get_scan_result(scan_id: str, request: Request, db: Session = Depends(get_db)):
    """Get a specific scan result by ID"""
    user = _require_user(request, db)
    scan = _get_scan_for_user(db, scan_id, user)
    owner = db.get(User, scan.created_by) if scan.created_by else None
    return _scan_record_to_dict(scan, owner.username if owner else None)


@app.get("/api/history")
async def get_scan_history(request: Request, limit: int = 50, db: Session = Depends(get_db)):
    """Get scan history"""
    user = _require_user(request, db)

    if _is_admin(user):
        scans = db.scalars(select(ScanRecord).order_by(ScanRecord.started_at.desc()).limit(limit)).all()
        total = db.query(ScanRecord).count()
    else:
        scans = db.scalars(
            select(ScanRecord).where(ScanRecord.created_by == user.id).order_by(ScanRecord.started_at.desc()).limit(limit)
        ).all()
        total = db.query(ScanRecord).filter(ScanRecord.created_by == user.id).count()

    usernames_by_id = {row.id: row.username for row in db.scalars(select(User)).all()}

    return {
        "total": total,
        "scans": [_scan_record_to_dict(scan, usernames_by_id.get(scan.created_by)) for scan in scans],
    }


@app.get("/api/cbom/{scan_id}")
async def get_cbom(scan_id: str, request: Request, db: Session = Depends(get_db)):
    """Get CBOM for a specific scan"""
    user = _require_user(request, db)
    scan = _get_scan_for_user(db, scan_id, user)
    if not scan or not scan.cbom_json:
        raise HTTPException(status_code=404, detail="CBOM not found")
    return json.loads(scan.cbom_json)


@app.get("/api/cbom/{scan_id}/download")
async def download_cbom(scan_id: str, request: Request, db: Session = Depends(get_db)):
    """Download CBOM as JSON file"""
    user = _require_user(request, db)
    scan = _get_scan_for_user(db, scan_id, user)
    if not scan or not scan.cbom_json:
        raise HTTPException(status_code=404, detail="CBOM not found")

    cbom = json.loads(scan.cbom_json)
    filename = f"cbom_{scan.target.replace(':', '_').replace('/', '_')}_{scan.scan_id}.json"
    content = json.dumps(cbom, indent=2, sort_keys=True)

    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Content-Type": "application/json",
        },
    )


@app.get("/api/cbom/{scan_id}/download/pdf")
async def download_cbom_pdf(scan_id: str, request: Request, db: Session = Depends(get_db)):
    """Download CBOM as PDF report"""
    user = _require_user(request, db)

    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.lib.enums import TA_CENTER
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
        from html import escape
    except ImportError as e:
        raise HTTPException(status_code=500, detail=f"ReportLab not installed: {str(e)}")

    scan = _get_scan_for_user(db, scan_id, user)
    if not scan or not scan.cbom_json:
        raise HTTPException(status_code=404, detail="CBOM not found")

    try:
        cbom = json.loads(scan.cbom_json)
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"Invalid CBOM JSON: {str(e)}")

    target = scan.target

    try:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=0.5 * inch, bottomMargin=0.5 * inch)

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("Title", parent=styles["Title"], fontSize=24, spaceAfter=20, textColor=colors.HexColor("#1e3a5f"))
        heading_style = ParagraphStyle("Heading", parent=styles["Heading2"], fontSize=14, spaceAfter=10, spaceBefore=20, textColor=colors.HexColor("#4c1d95"))
        normal_style = ParagraphStyle("Normal", parent=styles["Normal"], fontSize=10, spaceAfter=6)

        elements = []
        elements.append(Paragraph("Q-Shield CBOM Report", title_style))
        elements.append(Paragraph("Cryptographic Bill of Materials", styles["Heading3"]))
        elements.append(Spacer(1, 20))

        elements.append(Paragraph(f"<b>Target:</b> {escape(target)}", normal_style))
        elements.append(Paragraph(f"<b>Scan ID:</b> {escape(scan_id)}", normal_style))
        elements.append(Paragraph(f"<b>Generated:</b> {escape(str(cbom.get('generated_at', 'N/A')))}", normal_style))
        elements.append(Paragraph(f"<b>Generator:</b> {escape(str(cbom.get('generator', 'Q-Shield')))}", normal_style))
        elements.append(Spacer(1, 15))

        summary = cbom.get("summary", {})
        elements.append(Paragraph("Executive Summary", heading_style))

        summary_data = [
            ["Metric", "Value"],
            ["Total Crypto Assets", str(summary.get("total_assets", 0))],
            ["Quantum Vulnerable", str(summary.get("quantum_vulnerable_assets", 0))],
            ["Quantum Safe", str(summary.get("quantum_safe_assets", 0))],
            ["Endpoints Scanned", str(summary.get("total_endpoints", 0))],
            ["PQC Ready", str(summary.get("endpoints_pqc_ready", 0))],
            ["Weak Crypto Detected", str(summary.get("endpoints_with_weak_crypto", 0))],
        ]

        summary_table = Table(summary_data, colWidths=[3 * inch, 2 * inch])
        summary_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#4c1d95")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f5f3ff")),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
                ]
            )
        )
        elements.append(summary_table)
        elements.append(Spacer(1, 20))

        for endpoint_data in cbom.get("endpoints", []):
            elements.append(Paragraph(f"Endpoint: {escape(str(endpoint_data.get('endpoint', 'N/A')))}", heading_style))
            elements.append(Paragraph(f"IP: {escape(str(endpoint_data.get('ip_address', 'N/A')))} | Port: {endpoint_data.get('port', 'N/A')}", normal_style))
            tls_versions = ", ".join(endpoint_data.get("tls_versions", []))
            elements.append(Paragraph(f"TLS Versions: {escape(tls_versions)}", normal_style))
            elements.append(Paragraph(f"Forward Secrecy: {'Yes' if endpoint_data.get('forward_secrecy') else 'No'}", normal_style))
            elements.append(Spacer(1, 10))

            assets = endpoint_data.get("assets", [])
            if assets:
                elements.append(Paragraph("Cryptographic Assets", styles["Heading4"]))

                def clean_type(asset_type):
                    asset_type = str(asset_type)
                    if "." in asset_type:
                        asset_type = asset_type.split(".")[-1]
                    return asset_type.replace("_", " ").title()

                def clean_strength(strength):
                    strength = str(strength)
                    if "." in strength:
                        strength = strength.split(".")[-1]
                    return strength.capitalize()

                asset_data = [["Type", "Name", "Strength", "Q-Safe"]]
                for asset in assets[:20]:
                    asset_type = clean_type(asset.get("asset_type", "-"))
                    name = asset.get("name", "-")
                    if len(name) > 35:
                        name = f"{name[:32]}..."
                    strength = clean_strength(asset.get("strength", "-"))
                    q_safe = "Y" if not asset.get("quantum_vulnerable", True) else "N"
                    asset_data.append([asset_type, name, strength, q_safe])

                asset_table = Table(asset_data, colWidths=[1.3 * inch, 3 * inch, 0.9 * inch, 0.5 * inch])
                asset_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                            ("ALIGN", (3, 0), (3, -1), "CENTER"),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, 0), 9),
                            ("FONTSIZE", (0, 1), (-1, -1), 8),
                            ("TOPPADDING", (0, 0), (-1, -1), 6),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
                            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
                            ("TEXTCOLOR", (3, 1), (3, -1), colors.HexColor("#059669")),
                        ]
                    )
                )
                elements.append(asset_table)

                if len(assets) > 20:
                    elements.append(Paragraph(f"... and {len(assets) - 20} more assets", normal_style))

            elements.append(Spacer(1, 15))

        elements.append(Spacer(1, 30))
        elements.append(
            Paragraph(
                "Generated by Q-Shield | Post-Quantum Cryptographic Assessment Tool",
                ParagraphStyle("Footer", parent=normal_style, fontSize=8, textColor=colors.gray, alignment=TA_CENTER),
            )
        )

        doc.build(elements)
        buffer.seek(0)

        filename = f"cbom_{target.replace(':', '_').replace('/', '_')}_{scan_id}.pdf"

        return StreamingResponse(
            buffer,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    except Exception as e:
        import traceback
        error_detail = "".join(traceback.format_exception(type(e), e, e.__traceback__))
        logger.error(f"PDF generation error: {error_detail}")
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")


@app.get("/api/stats")
async def get_statistics(request: Request, db: Session = Depends(get_db)):
    """Get aggregate statistics from all scans"""
    user = _require_user(request, db)

    if _is_admin(user):
        all_scans = db.scalars(select(ScanRecord)).all()
        total_scans = len(all_scans)
    else:
        all_scans = db.scalars(select(ScanRecord).where(ScanRecord.created_by == user.id)).all()
        total_scans = len(all_scans)

    if total_scans == 0:
        return {
            "total_scans": 0,
            "successful_scans": 0,
            "failed_scans": 0,
            "unique_targets": 0,
            "aggregate_stats": None,
        }

    successful = [s for s in all_scans if s.status == "completed"]
    failed = [s for s in all_scans if s.status == "failed"]
    unique_targets = len({s.target for s in all_scans})

    total_assets = 0
    quantum_vulnerable = 0
    quantum_safe = 0
    pqc_ready_endpoints = 0
    weak_crypto_endpoints = 0

    strength_distribution = {}
    asset_type_distribution = {}
    tls_version_distribution = {}

    for scan in successful:
        cbom = json.loads(scan.cbom_json) if scan.cbom_json else {}
        summary = cbom.get("summary", {})

        total_assets += summary.get("total_assets", 0)
        quantum_vulnerable += summary.get("quantum_vulnerable_assets", 0)
        quantum_safe += summary.get("quantum_safe_assets", 0)
        pqc_ready_endpoints += summary.get("endpoints_pqc_ready", 0)
        weak_crypto_endpoints += summary.get("endpoints_with_weak_crypto", 0)

        for strength, count in summary.get("assets_by_strength", {}).items():
            strength_distribution[strength] = strength_distribution.get(strength, 0) + count

        for asset_type, count in summary.get("assets_by_type", {}).items():
            asset_type_distribution[asset_type] = asset_type_distribution.get(asset_type, 0) + count

        for endpoint in cbom.get("endpoints", []):
            for version in endpoint.get("tls_versions", []):
                tls_version_distribution[version] = tls_version_distribution.get(version, 0) + 1

    return {
        "total_scans": total_scans,
        "successful_scans": len(successful),
        "failed_scans": len(failed),
        "unique_targets": unique_targets,
        "aggregate_stats": {
            "total_assets": total_assets,
            "quantum_vulnerable_assets": quantum_vulnerable,
            "quantum_safe_assets": quantum_safe,
            "pqc_ready_endpoints": pqc_ready_endpoints,
            "weak_crypto_endpoints": weak_crypto_endpoints,
            "strength_distribution": strength_distribution,
            "asset_type_distribution": asset_type_distribution,
            "tls_version_distribution": tls_version_distribution,
        },
    }


@app.get("/api/vulnerabilities/{scan_id}")
async def get_quantum_vulnerabilities(scan_id: str, request: Request, db: Session = Depends(get_db)):
    """Get detailed quantum vulnerability breakdown for a scan"""
    user = _require_user(request, db)
    scan = _get_scan_for_user(db, scan_id, user)
    if not scan or not scan.cbom_json:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.vulnerabilities_json:
        return json.loads(scan.vulnerabilities_json)

    cbom = json.loads(scan.cbom_json)
    return _extract_quantum_vulnerabilities(cbom, scan.target, scan_id)


def _extract_quantum_vulnerabilities(cbom: Dict[str, Any], target: Optional[str], scan_id: Optional[str]) -> Dict[str, Any]:
    vulnerabilities = []

    for endpoint in cbom.get("endpoints", []):
        for asset in endpoint.get("assets", []):
            if asset.get("quantum_vulnerable", False):
                vuln = {
                    "asset_type": asset.get("asset_type"),
                    "name": asset.get("name"),
                    "reason": _get_vulnerability_reason(asset),
                    "risk_level": _get_risk_level(asset),
                    "recommendation": _get_recommendation(asset),
                }
                vulnerabilities.append(vuln)

    return {
        "scan_id": scan_id,
        "target": target,
        "total_vulnerabilities": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
    }


def _get_vulnerability_reason(asset: dict) -> str:
    """Explain why an asset is quantum vulnerable"""
    asset_type = asset.get("asset_type", "")
    name = asset.get("name", "").upper()
    props = asset.get("properties", {})

    if asset_type == "public_key":
        alg = props.get("algorithm", "")
        size = props.get("key_size", "")
        if "RSA" in alg.upper():
            return f"RSA-{size} can be broken by Shor's algorithm on a quantum computer"
        if "EC" in alg.upper() or "ECDSA" in alg.upper():
            return f"ECDSA-{size} uses elliptic curve discrete log, broken by Shor's algorithm"

    if asset_type == "key_exchange":
        kex = props.get("method", name)
        if "ECDH" in kex.upper():
            return "ECDH key exchange uses elliptic curve Diffie-Hellman, vulnerable to quantum attacks"
        if "DHE" in kex.upper() or "DH" in kex.upper():
            return "Diffie-Hellman key exchange is vulnerable to Shor's algorithm"
        if "RSA" in kex.upper():
            return "RSA key exchange is vulnerable to Shor's algorithm"

    if asset_type == "cipher_suite":
        if "ECDH" in name or "DHE" in name or "DH" in name:
            return "Cipher suite uses classical key exchange vulnerable to quantum attacks"
        if "RSA" in name:
            return "Cipher suite uses RSA key exchange, vulnerable to Shor's algorithm"

    if asset_type == "certificate":
        sig = props.get("signature_algorithm", "")
        if "RSA" in sig.upper():
            return "Certificate uses RSA signature, forgeable with quantum computer"
        if "ECDSA" in sig.upper():
            return "Certificate uses ECDSA signature, forgeable with quantum computer"

    return "Uses classical cryptography vulnerable to quantum computing attacks"


def _get_risk_level(asset: dict) -> str:
    """Assess risk level of quantum vulnerability"""
    asset_type = asset.get("asset_type", "")
    strength = asset.get("strength", "unknown")

    if asset_type in ["key_exchange", "public_key"]:
        return "HIGH"
    if asset_type == "certificate":
        return "HIGH"
    if asset_type == "cipher_suite":
        return "MEDIUM"
    if strength in ["broken", "weak"]:
        return "CRITICAL"
    return "MEDIUM"


def _get_recommendation(asset: dict) -> str:
    """Provide migration recommendation"""
    asset_type = asset.get("asset_type", "")
    name = asset.get("name", "").upper()
    props = asset.get("properties", {})

    if asset_type == "public_key":
        alg = props.get("algorithm", "")
        if "RSA" in alg.upper():
            return "Migrate to ML-DSA (Dilithium) or hybrid RSA+ML-DSA certificate"
        if "EC" in alg.upper():
            return "Migrate to ML-DSA (Dilithium) or hybrid ECDSA+ML-DSA certificate"

    if asset_type == "key_exchange":
        if "ECDH" in name:
            return "Enable ML-KEM (Kyber) or hybrid X25519+ML-KEM key exchange"
        if "DHE" in name:
            return "Enable ML-KEM (Kyber) or hybrid DH+ML-KEM key exchange"

    if asset_type == "cipher_suite":
        return "Prefer TLS 1.3 cipher suites with PQC key exchange when available"

    if asset_type == "certificate":
        return "Request PQC-signed certificate from CA when available"

    return "Plan migration to NIST post-quantum standards (ML-KEM, ML-DSA, SLH-DSA)"


@app.delete("/api/history/clear")
async def clear_history(request: Request, db: Session = Depends(get_db)):
    """Clear scan history (admin only)"""
    user = _require_roles(request, db, ["admin", "cyber_lead", "it_lead", "security_head"])

    count = db.query(ScanRecord).count()
    db.query(ScanRecord).delete()
    _log_event(db, user, "history_cleared", resource_type="scan_history", details={"cleared_count": count})
    db.commit()
    return {"message": f"Cleared {count} scan records"}


@app.get("/api/admin/logs")
async def get_admin_logs(request: Request, limit: int = 200, db: Session = Depends(get_db)):
    """Get platform audit logs (admin/lead only)"""
    _require_roles(request, db, ["admin", "cyber_lead", "it_lead", "security_head"])

    logs = db.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)).all()
    return {
        "total": len(logs),
        "logs": [
            {
                "id": log.id,
                "user_id": log.user_id,
                "username": log.username,
                "role": log.role,
                "action": log.action,
                "resource_type": log.resource_type,
                "resource_id": log.resource_id,
                "target": log.target,
                "details": json.loads(log.details_json) if log.details_json else None,
                "created_at": log.created_at.isoformat() if log.created_at else None,
            }
            for log in logs
        ],
    }


@app.get("/api/scheduled-reports")
async def list_scheduled_reports(request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)

    if _is_admin(user):
        schedules = db.scalars(select(ScheduledReport).order_by(ScheduledReport.created_at.desc())).all()
    else:
        schedules = db.scalars(
            select(ScheduledReport).where(ScheduledReport.created_by == user.id).order_by(ScheduledReport.created_at.desc())
        ).all()

    usernames_by_id = {row.id: row.username for row in db.scalars(select(User)).all()}
    return {
        "total": len(schedules),
        "items": [_scheduled_report_to_dict(item, usernames_by_id.get(item.created_by)) for item in schedules],
    }


@app.post("/api/scheduled-reports")
async def create_scheduled_report(
    payload: ScheduledReportRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    user = _require_roles(request, db, ["admin", "analyst", "cyber_lead", "it_lead", "security_head"])

    frequency = payload.frequency.strip().lower()
    if frequency not in {"weekly", "monthly"}:
        raise HTTPException(status_code=400, detail="Frequency must be weekly or monthly")

    if "@" not in payload.delivery_email:
        raise HTTPException(status_code=400, detail="Valid delivery email is required")

    domain = payload.domain.strip()
    codomain = payload.codomain.strip() if payload.codomain else None
    if not domain:
        raise HTTPException(status_code=400, detail="Domain is required")

    _validate_scan_target_or_raise(domain)
    if codomain:
        _validate_scan_target_or_raise(_build_scheduled_target(domain, codomain))

    first_run = _parse_schedule_datetime(payload.schedule_date, payload.schedule_time)
    next_run = _compute_next_run(first_run, frequency)

    schedule = ScheduledReport(
        schedule_id=f"sched_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid4().hex[:6]}",
        domain=domain,
        codomain=codomain,
        frequency=frequency,
        scheduled_date=payload.schedule_date,
        scheduled_time=payload.schedule_time,
        delivery_email=payload.delivery_email.strip(),
        enabled=payload.enabled,
        next_run_at=next_run if payload.enabled else None,
        created_by=user.id,
    )

    db.add(schedule)
    _log_event(
        db,
        user,
        "scheduled_report_created",
        resource_type="scheduled_report",
        resource_id=schedule.schedule_id,
        target=_build_scheduled_target(domain, codomain),
        details={
            "frequency": frequency,
            "delivery_email": schedule.delivery_email,
            "enabled": schedule.enabled,
            "next_run_at": schedule.next_run_at.isoformat() if schedule.next_run_at else None,
        },
    )
    db.commit()

    owner = db.get(User, schedule.created_by) if schedule.created_by else None
    return _scheduled_report_to_dict(schedule, owner.username if owner else None)


@app.patch("/api/scheduled-reports/{schedule_id}/enabled")
async def toggle_scheduled_report(
    schedule_id: str,
    payload: ScheduledReportToggleRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    user = _require_roles(request, db, ["admin", "analyst", "cyber_lead", "it_lead", "security_head"])
    schedule = _get_scheduled_report_for_user(db, schedule_id, user)

    schedule.enabled = payload.enabled
    if payload.enabled:
        base_time = _parse_schedule_datetime(schedule.scheduled_date, schedule.scheduled_time)
        schedule.next_run_at = _compute_next_run(base_time, schedule.frequency)
    else:
        schedule.next_run_at = None
    schedule.updated_at = datetime.now(timezone.utc)

    _log_event(
        db,
        user,
        "scheduled_report_toggled",
        resource_type="scheduled_report",
        resource_id=schedule.schedule_id,
        target=_build_scheduled_target(schedule.domain, schedule.codomain),
        details={"enabled": payload.enabled},
    )
    db.commit()

    owner = db.get(User, schedule.created_by) if schedule.created_by else None
    return _scheduled_report_to_dict(schedule, owner.username if owner else None)


@app.get("/api/vendors")
async def list_vendors(request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db)

    if _is_admin(user):
        vendors = db.scalars(select(ThirdPartyVendor).order_by(ThirdPartyVendor.created_at.desc())).all()
    else:
        vendors = db.scalars(
            select(ThirdPartyVendor)
            .where(ThirdPartyVendor.created_by == user.id)
            .order_by(ThirdPartyVendor.created_at.desc())
        ).all()

    usernames_by_id = {row.id: row.username for row in db.scalars(select(User)).all()}
    return {
        "total": len(vendors),
        "items": [_vendor_to_dict(item, usernames_by_id.get(item.created_by)) for item in vendors],
    }


@app.post("/api/vendors")
async def create_vendor(payload: VendorCreateRequest, request: Request, db: Session = Depends(get_db)):
    user = _require_roles(request, db, ["admin", "analyst", "cyber_lead", "it_lead", "security_head"])

    criticality = payload.criticality.strip().lower()
    if criticality not in {"low", "medium", "high", "critical"}:
        raise HTTPException(status_code=400, detail="Criticality must be low, medium, high, or critical")

    vendor_name = payload.vendor_name.strip()
    domain = payload.domain.strip().lower()
    if not vendor_name or not domain:
        raise HTTPException(status_code=400, detail="Vendor name and domain are required")

    _validate_scan_target_or_raise(domain)

    vendor = ThirdPartyVendor(
        vendor_id=f"vendor_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid4().hex[:6]}",
        vendor_name=vendor_name,
        domain=domain,
        criticality=criticality,
        notes=(payload.notes or "").strip() or None,
        enabled=payload.enabled,
        created_by=user.id,
    )
    db.add(vendor)
    _log_event(
        db,
        user,
        "vendor_created",
        resource_type="vendor",
        resource_id=vendor.vendor_id,
        target=vendor.domain,
        details={"vendor_name": vendor.vendor_name, "criticality": vendor.criticality, "enabled": vendor.enabled},
    )
    db.commit()

    owner = db.get(User, vendor.created_by) if vendor.created_by else None
    return _vendor_to_dict(vendor, owner.username if owner else None)


@app.patch("/api/vendors/{vendor_id}/enabled")
async def toggle_vendor(vendor_id: str, payload: VendorToggleRequest, request: Request, db: Session = Depends(get_db)):
    user = _require_roles(request, db, ["admin", "analyst", "cyber_lead", "it_lead", "security_head"])
    vendor = _get_vendor_for_user(db, vendor_id, user)

    vendor.enabled = payload.enabled
    vendor.updated_at = datetime.now(timezone.utc)
    _log_event(
        db,
        user,
        "vendor_toggled",
        resource_type="vendor",
        resource_id=vendor.vendor_id,
        target=vendor.domain,
        details={"enabled": payload.enabled},
    )
    db.commit()

    owner = db.get(User, vendor.created_by) if vendor.created_by else None
    return _vendor_to_dict(vendor, owner.username if owner else None)


@app.delete("/api/vendors/{vendor_id}")
async def delete_vendor(vendor_id: str, request: Request, db: Session = Depends(get_db)):
    user = _require_roles(request, db, ["admin", "analyst", "cyber_lead", "it_lead", "security_head"])
    vendor = _get_vendor_for_user(db, vendor_id, user)

    vendor_dict = _vendor_to_dict(vendor)
    _log_event(
        db,
        user,
        "vendor_deleted",
        resource_type="vendor",
        resource_id=vendor.vendor_id,
        target=vendor.domain,
        details={"vendor_name": vendor.vendor_name},
    )
    db.delete(vendor)
    db.commit()
    return {"message": "Vendor deleted", "vendor": vendor_dict}


@app.post("/api/vendors/scan")
async def scan_vendors(payload: VendorScanRequest, request: Request, db: Session = Depends(get_db)):
    user = _require_roles(request, db, ["admin", "analyst", "cyber_lead", "it_lead", "security_head"])

    selected_ids: List[str] = []
    for item in payload.vendor_ids:
        value = (item or "").strip()
        if value and value not in selected_ids:
            selected_ids.append(value)

    if not selected_ids:
        raise HTTPException(status_code=400, detail="Select at least one vendor")

    timeout = max(1, min(payload.timeout, 60))
    successful_results: List[Dict[str, Any]] = []
    successful_count = 0
    failed_count = 0
    items: List[Dict[str, Any]] = []

    for vendor_id in selected_ids:
        vendor = _get_vendor_for_user(db, vendor_id, user)
        target = vendor.domain.strip()
        scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid4().hex[:6]}"
        started_at = datetime.now(timezone.utc)

        try:
            result = scan_tls(target, timeout=timeout)
            cbom = generate_cbom([result])
            cbom_dict = cbom.to_dict()
            vulnerabilities = _extract_quantum_vulnerabilities(cbom_dict, target, scan_id)

            db.add(
                ScanRecord(
                    scan_id=scan_id,
                    target=target,
                    started_at=started_at,
                    completed_at=datetime.now(timezone.utc),
                    status="completed",
                    result_json=json.dumps(result),
                    cbom_json=json.dumps(cbom_dict),
                    vulnerabilities_json=json.dumps(vulnerabilities),
                    created_by=user.id,
                )
            )

            vendor.last_scan_at = datetime.now(timezone.utc)
            vendor.updated_at = datetime.now(timezone.utc)
            successful_count += 1
            successful_results.append(result)

            items.append(
                {
                    "vendor_id": vendor.vendor_id,
                    "vendor_name": vendor.vendor_name,
                    "domain": vendor.domain,
                    "status": "completed",
                    "scan_id": scan_id,
                    "vulnerabilities": vulnerabilities.get("total_vulnerabilities", 0),
                }
            )
        except Exception as exc:
            error_detail = _friendly_scan_error_detail(exc)
            failed_count += 1
            db.add(
                ScanRecord(
                    scan_id=scan_id,
                    target=target,
                    started_at=started_at,
                    completed_at=datetime.now(timezone.utc),
                    status="failed",
                    error=error_detail,
                    created_by=user.id,
                )
            )
            items.append(
                {
                    "vendor_id": vendor.vendor_id,
                    "vendor_name": vendor.vendor_name,
                    "domain": vendor.domain,
                    "status": "failed",
                    "scan_id": scan_id,
                    "error": error_detail,
                }
            )

    combined_cbom = generate_cbom(successful_results).to_dict() if successful_results else None
    combined_vulnerabilities = (
        _extract_quantum_vulnerabilities(combined_cbom, "third_party_vendors", None) if combined_cbom else None
    )

    _log_event(
        db,
        user,
        "vendor_scan_completed",
        resource_type="vendor_scan",
        details={
            "selected": len(selected_ids),
            "successful": successful_count,
            "failed": failed_count,
        },
    )
    db.commit()

    return {
        "total_selected": len(selected_ids),
        "successful_scans": successful_count,
        "failed_scans": failed_count,
        "items": items,
        "cbom": combined_cbom,
        "vulnerabilities": combined_vulnerabilities,
    }


@app.delete("/api/admin/logs/clear")
async def clear_admin_logs(request: Request, db: Session = Depends(get_db)):
    """Clear platform audit logs (admin/lead only)"""
    user = _require_roles(request, db, ["admin", "cyber_lead", "it_lead", "security_head"])

    count = db.query(AuditLog).count()
    db.query(AuditLog).delete()
    _log_event(db, user, "logs_cleared", resource_type="audit_logs", details={"cleared_count": count})
    db.commit()
    return {"message": f"Cleared {count} audit logs"}


# Run with: uvicorn app:app --reload
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
