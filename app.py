"""
Q-Shield Web Application
FastAPI backend for cryptographic inventory scanning and CBOM generation
"""

import hashlib
import hmac
import ipaddress
import io
import asyncio
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

import logging

from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, create_engine, inspect, select, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# --- Timezone Helpers ---
def _to_iso_utc(dt: Optional[datetime]) -> Optional[str]:
    if not dt:
        return None
    # If naive, assume UTC as per app convention
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    # Ensure it's converted to UTC if it was somehow in another TZ
    # Use 'Z' or +00:00 suffix for unambiguous ISO8601
    return dt.astimezone(timezone.utc).isoformat()

# Setup logging FIRST
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

from cbom_generator import generate_cbom
from generate_cbom_outputs import _build_html_cbom, _build_report_context
from report_pdf import generate_pdf, LATEST_REPORT_PATH
from tls_scanner import scan_tls
from scanner import _detect_api_endpoints
from vpn_scanner import scan_vpn
from ssh_scanner import scan_ssh

# Firebase Authentication imports
try:
    import requests
    FIREBASE_AVAILABLE = True
except ImportError:
    FIREBASE_AVAILABLE = False
    logger.warning("requests library not available - Firebase authentication will be disabled")

from firebase_auth.firebase_auth_backend import (
    verify_firebase_id_token,
    get_or_create_firebase_user,
    create_session_from_firebase,
    FirebaseAuthError
)

from dotenv import load_dotenv
load_dotenv()
from reporting_service import ReportingService

# Argon2 password hasher setup
ph = PasswordHasher()


# Initialize rate limiter (CRITICAL SECURITY FIX)
limiter = Limiter(key_func=get_remote_address)

# Initialize FastAPI app
app = FastAPI(
    title="Q-Shield",
    description="Cryptographic Bill of Materials (CBOM) Scanner for Post-Quantum Readiness",
    version="1.0.0",
)
app.state.limiter = limiter

# Templates and static files
BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Try to mount static files if directory exists
static_dir = BASE_DIR / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


# Session middleware removed for deployment simplicity.
# The app runs in sessionless mode (no login session state).


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

# Firebase Configuration
FIREBASE_API_KEY = os.getenv("FIREBASE_API_KEY", "AIzaSyDzu1KxLQsJgIchEgsIiKU97Ga2Derz6a4")

# Validate Firebase configuration is available
if not FIREBASE_API_KEY or FIREBASE_API_KEY == "AIzaSyDzu1KxLQsJgIchEgsIiKU97Ga2Derz6a4":
    logger.warning("Firebase API Key loaded from default configuration - update with environment variable for production")
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
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    session_token: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    # Email-based OTP login (added alongside existing password auth; does not replace it)
    email: Mapped[Optional[str]] = mapped_column(String(255), unique=True, nullable=True, index=True)
    is_demo_account: Mapped[bool] = mapped_column(Boolean, default=False, index=True)


class LoginOtp(Base):
    """One-time-passcodes issued for email-based login."""
    __tablename__ = "login_otps"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(255), index=True)
    otp_hash: Mapped[str] = mapped_column(String(255))
    purpose: Mapped[str] = mapped_column(String(20), default="login")
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    consumed: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


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
    perimeter_ports: Optional[List[int]] = Field(
        default=None,
        description="Optional comma-separated list of perimeter ports (VPN/SSH) to probe",
    )
    openapi_urls: Optional[List[str]] = Field(
        default=None,
        description="Optional OpenAPI/Swagger URLs or paths to enumerate endpoints",
    )


class MultiScanRequest(BaseModel):
    targets: List[str] = Field(..., description="List of targets to scan")
    timeout: int = Field(default=10, ge=1, le=60)
    perimeter_ports: Optional[List[int]] = Field(default=None, description="Optional perimeter ports to probe")
    openapi_urls: Optional[List[str]] = Field(
        default=None,
        description="Optional OpenAPI/Swagger URLs or paths to enumerate endpoints",
    )


class SubdomainScanRequest(BaseModel):
    parent_target: str = Field(..., description="Primary scanned domain")
    subdomains: List[str] = Field(default_factory=list, description="Selected subdomains to scan")
    timeout: int = Field(default=10, ge=1, le=60)
    include_parent: bool = Field(default=True, description="Include parent target in combined CBOM")
    perimeter_ports: Optional[List[int]] = Field(default=None, description="Optional perimeter ports to probe")
    openapi_urls: Optional[List[str]] = Field(
        default=None,
        description="Optional OpenAPI/Swagger URLs or paths to enumerate endpoints",
    )


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


class OtpRequestBody(BaseModel):
    email: str = Field(..., min_length=3, max_length=255)


class OtpVerifyBody(BaseModel):
    email: str = Field(..., min_length=3, max_length=255)
    otp: str = Field(..., min_length=6, max_length=6)


class VendorScanRequest(BaseModel):
    vendor_ids: List[str] = Field(default_factory=list)
    timeout: int = Field(default=12, ge=1, le=60)
    perimeter_ports: Optional[List[int]] = Field(default=None, description="Optional perimeter ports to probe")
    openapi_urls: Optional[List[str]] = Field(
        default=None,
        description="Optional OpenAPI/Swagger URLs or paths to enumerate endpoints",
    )


def _initialize_database() -> None:
    global _db_initialized, engine, SessionLocal, DATABASE_URL
    if _db_initialized:
        return

    with _db_init_lock:
        if _db_initialized:
            return
        try:
            logger.info(f"Initializing database with URL: {DATABASE_URL[:50]}...")
            Base.metadata.create_all(bind=engine)
            with SessionLocal() as db:
                _seed_default_admin(db)
            _db_initialized = True
            logger.info("Database initialized successfully.")
            return
        except Exception as db_exc:
            logger.error(f"Database initialization failed: {db_exc}")
            logger.warning("CRITICAL: Falling back to in-memory database. Data will NOT persist between requests!")
            logger.warning("Please configure a persistent database using DATABASE_URL environment variable.")
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
            logger.warning("Using in-memory database. Scans will be lost on app restart!")


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


@app.exception_handler(RateLimitExceeded)
async def rate_limit_exception_handler(request: Request, exc: RateLimitExceeded):
    """Handle rate limit exceeded errors gracefully"""
    logger.warning(f"Rate limit exceeded for {request.client.host}: {exc.detail}")
    return JSONResponse(
        status_code=429,
        content={
            "detail": "Rate limit exceeded. Please try again later.",
            "retry_after": exc.detail
        }
    )


def _hash_password(password: str) -> str:
    """Hash password using Argon2id (OWASP 2023 recommended).
    
    Falls back to PBKDF2 if Argon2 fails (for compatibility).
    """
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")
    
    try:
        # Use Argon2id (OWASP 2023 recommendation)
        hash_value = ph.hash(password)
        return hash_value
    except Exception as e:
        logger.warning(f"Argon2 hashing failed, falling back to PBKDF2: {e}")
        # Fallback to PBKDF2 sha256 (600k iterations per OWASP)
        salt = secrets.token_hex(16)
        iterations = 600_000  # FIXED: was 200k, now 600k per OWASP
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), iterations).hex()
        return f"pbkdf2_sha256${iterations}${salt}${pwd_hash}"


def _verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against stored hash (supports both Argon2 and PBKDF2)."""
    if not stored_hash:
        return False
    
    try:
        # Try Argon2 first (hashes start with $argon2id$, $argon2i$, or $argon2d$)
        if stored_hash.startswith("$argon2"):
            try:
                ph.verify(stored_hash, password)
                return True
            except VerifyMismatchError:
                return False
        
        # Fall back to PBKDF2 (for legacy hashes)
        if stored_hash.startswith("pbkdf2_sha256$"):
            try:
                _, iterations_str, salt, expected_hash = stored_hash.split("$", 3)
                iterations = int(iterations_str)
            except ValueError:
                return False
            
            pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), iterations).hex()
            return hmac.compare_digest(pwd_hash, expected_hash)
    
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False
    
    return False


# ============================================================================
# LIGHTWEIGHT SCHEMA MIGRATION
# Adds columns introduced after initial deployment (e.g. email-based OTP
# login) to a pre-existing database without requiring Alembic. Base.metadata
# .create_all() only creates missing *tables*, not missing *columns* on
# tables that already exist, so new nullable columns need this explicit step.
# ============================================================================
def _run_light_migrations() -> None:
    try:
        insp = inspect(engine)
        if "users" not in insp.get_table_names():
            return  # fresh DB: create_all() will create the up-to-date schema
        existing_cols = {c["name"] for c in insp.get_columns("users")}
        with engine.begin() as conn:
            if "email" not in existing_cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN email VARCHAR(255)"))
                logger.info("Migration: added users.email column")
            if "is_demo_account" not in existing_cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN is_demo_account BOOLEAN DEFAULT 0"))
                logger.info("Migration: added users.is_demo_account column")
            # Backfill email for previously self-registered users (username == email already)
            conn.execute(text(
                "UPDATE users SET email = username "
                "WHERE (email IS NULL OR email = '') AND username LIKE '%@%'"
            ))
        try:
            with engine.begin() as conn:
                conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email_unique ON users(email)"))
        except Exception as idx_exc:
            logger.warning(f"Could not create unique index on users.email: {idx_exc}")
    except Exception as e:
        logger.error(f"Light migration failed: {e}")


# Demo accounts covering every RBAC role, so the OTP flow can be demonstrated
# end-to-end without a real mailbox. Passwords are kept only for backward
# compatibility with the legacy password-based /login route.
DEMO_USERS = [
    {"username": "admin", "email": "admin.demo@qshield.local", "password": "admin123", "role": "admin"},
    {"username": "analyst_demo", "email": "analyst.demo@qshield.local", "password": "analyst123", "role": "analyst"},
    {"username": "viewer_demo", "email": "viewer.demo@qshield.local", "password": "viewer123", "role": "viewer"},
    {"username": "cyberlead_demo", "email": "cyberlead.demo@qshield.local", "password": "cyberlead123", "role": "cyber_lead"},
    {"username": "itlead_demo", "email": "itlead.demo@qshield.local", "password": "itlead123", "role": "it_lead"},
    {"username": "securityhead_demo", "email": "securityhead.demo@qshield.local", "password": "securityhead123", "role": "security_head"},
]


def _seed_demo_users(db: Session) -> None:
    """Idempotently ensure the demo account for every role exists and is flagged is_demo_account."""
    for spec in DEMO_USERS:
        user = db.query(User).filter(User.username == spec["username"]).first()
        if user:
            changed = False
            if not user.email:
                user.email = spec["email"]
                changed = True
            if not user.is_demo_account:
                user.is_demo_account = True
                changed = True
            if changed:
                db.add(user)
        else:
            db.add(
                User(
                    username=spec["username"],
                    email=spec["email"],
                    password_hash=_hash_password(spec["password"]),
                    role=spec["role"],
                    is_active=True,
                    is_demo_account=True,
                )
            )
    db.commit()


# ============================================================================
# AUTO-INITIALIZATION: Database and Demo User Setup on Startup
# ============================================================================
def _auto_initialize_database():
    """Auto-initialize database, run migrations, and seed demo users on first startup."""
    try:
        # Create all tables
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created/verified")

        _run_light_migrations()

        db = SessionLocal()
        try:
            _seed_demo_users(db)
            logger.info("Demo users seeded/verified for all roles (see DEMO_USERS).")
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Error during database auto-initialization: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")


# Run auto-initialization on module load
_auto_initialize_database()


def _seed_default_admin(db: Session) -> None:
    """Initialize default admin user from environment variables.
    
    CRITICAL SECURITY FIX: Requires environment variables, no hardcoded defaults!
    """
    has_user = db.scalar(select(User.id).limit(1))
    if has_user:
        return

    # FIXED: Require environment variables, no hardcoded defaults
    admin_username = os.getenv("ADMIN_USERNAME")
    admin_password = os.getenv("ADMIN_PASSWORD")
    admin_role = os.getenv("ADMIN_ROLE", "admin")

    if not admin_username or not admin_password:
        logger.warning(
            "No admin credentials in environment (ADMIN_USERNAME, ADMIN_PASSWORD). "
            "Skipping admin user creation. Set these to initialize."
        )
        return

    # Validate password strength (minimum 8 characters, checked in _hash_password)
    if len(admin_password) < 8:
        logger.error("Admin password must be at least 8 characters. Skipping admin user creation.")
        return

    try:
        db.add(
            User(
                username=admin_username,
                password_hash=_hash_password(admin_password),
                role=admin_role,
            )
        )
        db.commit()
        logger.info(f"Default admin user '{admin_username}' created successfully.")
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to create admin user: {e}")


class _NoUser:
    """Placeholder for unauthenticated users."""
    def __init__(self) -> None:
        self.id = None
        self.username = None
        self.role = None


def _create_session_token() -> str:
    """Create a secure session token for a user."""
    return secrets.token_urlsafe(32)


# ============================================================================
# EMAIL-BASED OTP LOGIN
# ============================================================================
OTP_TTL_SECONDS = 45
OTP_MAX_ATTEMPTS = 5
# Pepper used to hash OTP codes at rest. A per-process random fallback is fine
# since OTPs live for OTP_TTL_SECONDS only and never need to survive a restart.
_OTP_PEPPER = os.getenv("OTP_SECRET_PEPPER") or secrets.token_hex(32)


def _generate_otp() -> str:
    """Generate a cryptographically random 6-digit OTP (zero-padded)."""
    return f"{secrets.randbelow(1_000_000):06d}"


def _hash_otp(otp: str, email: str) -> str:
    """Hash an OTP code for storage (never store OTPs in plaintext)."""
    msg = f"{email.strip().lower()}:{otp}".encode("utf-8")
    return hmac.new(_OTP_PEPPER.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def _send_otp_email(to_email: str, otp: str) -> Optional[str]:
    """Send an OTP code by email using the same SMTP_* settings as scheduled reports.

    Returns an error string on failure, or None on success.
    """
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")
    smtp_from = os.getenv("SMTP_FROM_EMAIL") or smtp_user
    smtp_use_tls = os.getenv("SMTP_USE_TLS", "1") != "0"

    if not smtp_host or not smtp_from:
        return "SMTP is not configured (set SMTP_HOST and SMTP_FROM_EMAIL/SMTP_USERNAME)"

    message = EmailMessage()
    message["Subject"] = "Your Q-Shield login OTP"
    message["From"] = smtp_from
    message["To"] = to_email
    message.set_content(
        f"Your Q-Shield one-time login code is: {otp}\n\n"
        f"This code expires in {OTP_TTL_SECONDS} seconds and can only be used once.\n"
        f"If you did not request this, you can safely ignore this email."
    )

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


def _get_current_user(request: Request, db: Session) -> Optional[User]:
    """Get the current authenticated user from session cookie."""
    session_token = request.cookies.get("session_id")
    if not session_token:
        return None
    
    # Find user with this session token
    try:
        user = db.query(User).filter(User.session_token == session_token).first()
        return user
    except Exception as e:
        logger.error(f"Session lookup error: {e}")
        return None


def _require_user(request: Request, db: Session) -> User:
    user = _get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Your account has been disabled")
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
        "started_at": _to_iso_utc(scan.started_at),
        "completed_at": _to_iso_utc(scan.completed_at),
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
        "next_run_at": _to_iso_utc(schedule.next_run_at),
        "last_sent_at": _to_iso_utc(schedule.last_sent_at),
        "created_at": _to_iso_utc(schedule.created_at),
        "updated_at": _to_iso_utc(schedule.updated_at),
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
        "last_scan_at": _to_iso_utc(vendor.last_scan_at),
        "created_at": _to_iso_utc(vendor.created_at),
        "updated_at": _to_iso_utc(vendor.updated_at),
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

    # Normalize internationalized domains to ASCII for validation.
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError:
        return False

    # Require dot-based hostnames to avoid obvious invalid values like "rruacin".
    if "." not in name:
        return False

    if len(name) > 253:
        return False

    labels = name.split(".")
    label_regex = re.compile(r"^[A-Za-z0-9_-]{1,63}$")
    for label in labels:
        if not label_regex.match(label):
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if label.startswith("_") or label.endswith("_"):
            return False

    tld = labels[-1]
    if tld.lower().startswith("xn--"):
        return len(tld) >= 4

    return bool(re.match(r"^[A-Za-z0-9-]{2,63}$", tld))


def _validate_scan_target_or_raise(target: str) -> str:
    host, port = _split_target_host_port(target)
    if not (host or "").strip():
        raise HTTPException(status_code=400, detail="Invalid target format. Provide a hostname or IP.")

    if port is not None and not (1 <= port <= 65535):
        raise HTTPException(status_code=400, detail="Invalid port. Use a value between 1 and 65535")

    return (target or "").strip()


def _build_base_url(target: str) -> Optional[str]:
    value = (target or "").strip()
    if not value:
        return None

    if "://" in value:
        parsed = urllib.parse.urlparse(value)
        if not parsed.hostname:
            return None
        scheme = parsed.scheme or "https"
        host = parsed.hostname
        port = parsed.port
    else:
        host, port = _split_target_host_port(value)
        if not host:
            return None
        if port == 80:
            scheme = "http"
        else:
            scheme = "https"

    if port and port not in (80, 443):
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


DEFAULT_VPN_PORTS = [80, 443, 8443, 10443, 1443, 9443]
DEFAULT_SSH_PORTS = [22, 2222, 2200]
DEFAULT_PERIMETER_PORTS = DEFAULT_VPN_PORTS + DEFAULT_SSH_PORTS


def _normalize_ports(ports: Optional[List[int]]) -> List[int]:
    if not ports:
        return []
    normalized: List[int] = []
    for port in ports:
        try:
            value = int(port)
        except (TypeError, ValueError):
            continue
        if 1 <= value <= 65535 and value not in normalized:
            normalized.append(value)
    return normalized


def _get_perimeter_ports(ports: Optional[List[int]]) -> List[int]:
    normalized = _normalize_ports(ports)
    return normalized if normalized else list(DEFAULT_PERIMETER_PORTS)


def _split_perimeter_ports(ports: List[int]) -> tuple[List[int], List[int]]:
    if not ports:
        return list(DEFAULT_VPN_PORTS), list(DEFAULT_SSH_PORTS)
    ssh_candidates = {22, 2222, 2200, 22222}
    ssh_ports = [p for p in ports if p in ssh_candidates]
    vpn_ports = [p for p in ports if p not in ssh_candidates]
    if not ssh_ports:
        ssh_ports = list(DEFAULT_SSH_PORTS)
    if not vpn_ports:
        vpn_ports = list(DEFAULT_VPN_PORTS)
    return vpn_ports, ssh_ports


def _parse_ports_param(value: Optional[str]) -> Optional[List[int]]:
    if not value:
        return None
    ports = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if not part.isdigit():
            continue
        ports.append(int(part))
    return ports or None


def _attach_api_endpoints(
    result: Dict[str, Any],
    target: str,
    timeout: int,
    openapi_urls: Optional[List[str]] = None,
) -> None:
    if not result or result.get("api_endpoints"):
        return
    base_url = _build_base_url(target)
    if not base_url:
        return
    try:
        api_timeout = max(3, min(timeout, 8))
        result["api_endpoints"] = _detect_api_endpoints(
            base_url,
            timeout=api_timeout,
            openapi_urls=openapi_urls,
        )
    except Exception as exc:
        logger.debug(f"API endpoint discovery failed for {base_url}: {exc}")


def _get_perimeter_target(result: Dict[str, Any], target: str) -> tuple[Optional[str], int]:
    host = result.get("host") if result else None
    port = result.get("port") if result else None
    if not host:
        host, port_from_target = _split_target_host_port(target)
        if port is None:
            port = port_from_target
    if port is None:
        port = 443
    return host, port


async def _attach_perimeter_async(
    result: Dict[str, Any],
    target: str,
    timeout: int,
    perimeter_ports: Optional[List[int]] = None,
) -> None:
    if not result:
        return
    if result.get("vpn_gateway") or result.get("ssh_endpoint"):
        return
    host, port = _get_perimeter_target(result, target)
    if not host:
        return

    perimeter_timeout = max(3, min(timeout, 8))
    ports = _get_perimeter_ports(perimeter_ports)
    vpn_ports, ssh_ports = _split_perimeter_ports(ports)
    try:
        vpn_res, ssh_res = await asyncio.gather(
            scan_vpn(host, vpn_ports, perimeter_timeout),
            scan_ssh(host, ssh_ports, perimeter_timeout),
        )
        if vpn_res and vpn_res.get("detected"):
            result["vpn_gateway"] = vpn_res
        if ssh_res and ssh_res.get("detected"):
            result["ssh_endpoint"] = ssh_res
        result["perimeter_checks"] = {
            "vpn_ports": vpn_ports,
            "ssh_ports": ssh_ports,
            "vpn_checked_ports": (vpn_res or {}).get("checked_ports", vpn_ports),
            "ssh_checked_ports": (ssh_res or {}).get("checked_ports", ssh_ports),
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as exc:
        logger.debug(f"Perimeter discovery failed for {host}: {exc}")


def _attach_perimeter_sync(
    result: Dict[str, Any],
    target: str,
    timeout: int,
    perimeter_ports: Optional[List[int]] = None,
) -> None:
    try:
        asyncio.run(_attach_perimeter_async(result, target, timeout, perimeter_ports))
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(_attach_perimeter_async(result, target, timeout, perimeter_ports))
        finally:
            loop.close()


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

    # Parse the user's input as IST (UTC +5:30)
    from datetime import timedelta
    local_dt = datetime(
        year=date_obj.year,
        month=date_obj.month,
        day=date_obj.day,
        hour=time_obj.hour,
        minute=time_obj.minute,
        tzinfo=timezone(timedelta(hours=5, minutes=30)),
    )
    # Convert immediately to UTC for internal storage
    return local_dt.astimezone(timezone.utc)


def _add_one_month(value: datetime) -> datetime:
    if value.month == 12:
        return value.replace(year=value.year + 1, month=1)
    return value.replace(month=value.month + 1)


def _compute_next_run(base_time: datetime, frequency: str, now: Optional[datetime] = None) -> datetime:
    current = now or datetime.now(timezone.utc)
    freq = (frequency or "").strip().lower()

    next_time = base_time
    # SQLite returns offset-naive datetimes, ensure it matches current
    if next_time.tzinfo is None:
        next_time = next_time.replace(tzinfo=timezone.utc)

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

        for schedule in due_items:
            ReportingService.run_scheduled_report(
                db, 
                schedule, 
                scan_tls, 
                generate_cbom, 
                _log_event
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
        logger.warning(f"Scan not found: {scan_id} (user: {user.username if user else 'unknown'})")
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


@app.get("/asset-inventory", response_class=HTMLResponse)
async def asset_inventory_page(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    return _render_template(
        request,
        "asset_inventory.html",
        {
            "request": request,
            "current_user": {"username": user.username, "role": user.role},
        },
    )


@app.get("/history", response_class=HTMLResponse)
async def history_page(request: Request, db: Session = Depends(get_db)):
    user = _get_current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    return _render_template(
        request,
        "history.html",
        {
            "request": request,
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


@app.get("/tls-scanner-test", response_class=HTMLResponse)
async def tls_scanner_test(request: Request):
    """TLS Scanner test interface (public, no auth required)"""
    return _render_template(request, "tls_scanner_test.html", {"request": request})


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Show login page"""
    return _render_template(request, "login.html", {"request": request})


@app.post("/login", response_class=HTMLResponse)
@limiter.limit("5/minute")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    """Authenticate user and create session."""
    try:
        logger.info(f"Login attempt for username: {username}")
        
        # Find user by username
        user = db.query(User).filter(User.username == username).first()
        if not user:
            logger.warning(f"User not found: {username}")
            # Return login page with error
            return _render_template(
                request,
                "login.html",
                {
                    "request": request,
                    "error": "Invalid username or password",
                },
            )
        
        logger.info(f"User found: {username}, checking password...")
        
        # Verify password
        if not _verify_password(password, user.password_hash):
            logger.warning(f"Password verification failed for user: {username}")
            return _render_template(
                request,
                "login.html",
                {
                    "request": request,
                    "error": "Invalid username or password",
                },
            )
        
        logger.info(f"Password verified for user: {username}")
        
        # Check if user is active
        if not user.is_active:
            return _render_template(
                request,
                "login.html",
                {
                    "request": request,
                    "error": "Your account is pending admin verification. Please wait or contact an administrator.",
                },
            )
        
        # Create session token
        session_token = _create_session_token()
        user.session_token = session_token
        user.last_login = datetime.now(timezone.utc)
        db.commit()
        
        # Create response with session cookie
        response = RedirectResponse(url="/", status_code=302)
        response.set_cookie(
            key="session_id",
            value=session_token,
            max_age=86400 * 7,  # 7 days
            httponly=True,
            secure=False,  # Set to True in production with HTTPS
            samesite="lax",
        )
        _log_event(db, user, "login_successful")
        return response
    
    except Exception as e:
        logger.error(f"Login error: {type(e).__name__}: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return _render_template(
            request,
            "login.html",
            {
                "request": request,
                "error": f"An error occurred during login: {str(e)}",
            },
        )


@app.post("/api/auth/otp/request")
@limiter.limit("6/minute")
async def otp_request(request: Request, body: OtpRequestBody, db: Session = Depends(get_db)):
    """Issue a fresh 6-digit login OTP for the given email.

    - Real accounts: OTP is emailed via SMTP; the code is never returned in the response.
    - Demo accounts (is_demo_account=True): no email is sent (the address isn't real);
      the code is returned in the response so the UI can display it inline.
    """
    email = body.email.strip().lower()
    if "@" not in email or "." not in email.split("@")[-1]:
        raise HTTPException(status_code=400, detail="Please enter a valid email address")

    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="No account found with this email address")
    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="Your account is pending admin verification. Please wait or contact an administrator.",
        )

    now = datetime.now(timezone.utc)

    # Resend protection: block a new OTP while a previous one is still valid.
    active_otp = (
        db.query(LoginOtp)
        .filter(LoginOtp.email == email, LoginOtp.purpose == "login", LoginOtp.consumed.is_(False))
        .order_by(LoginOtp.id.desc())
        .first()
    )
    if active_otp:
        expires_at = active_otp.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        remaining = int((expires_at - now).total_seconds())
        if remaining > 0:
            raise HTTPException(
                status_code=429,
                detail=f"An OTP was already sent. Please wait {remaining}s before requesting a new one.",
            )
        active_otp.consumed = True  # expired: invalidate before issuing a new one

    # Invalidate any other stale, unconsumed OTPs for this email
    db.query(LoginOtp).filter(
        LoginOtp.email == email, LoginOtp.purpose == "login", LoginOtp.consumed.is_(False)
    ).update({"consumed": True})

    otp = _generate_otp()
    otp_row = LoginOtp(
        email=email,
        otp_hash=_hash_otp(otp, email),
        purpose="login",
        is_demo=bool(user.is_demo_account),
        attempts=0,
        consumed=False,
        expires_at=now + timedelta(seconds=OTP_TTL_SECONDS),
    )
    db.add(otp_row)
    db.commit()

    response: Dict[str, Any] = {
        "success": True,
        "expires_in": OTP_TTL_SECONDS,
        "is_demo": bool(user.is_demo_account),
    }

    if user.is_demo_account:
        # No real mailbox exists for demo accounts; surface the code directly.
        response["demo_otp"] = otp
        response["message"] = "Demo account — OTP shown below (no email is sent)."
        logger.info(f"Demo OTP issued for {email}")
    else:
        send_error = _send_otp_email(email, otp)
        if send_error:
            logger.error(f"Failed to send OTP email to {email}: {send_error}")
            db.rollback()
            raise HTTPException(
                status_code=502,
                detail="Could not send OTP email. Please contact your administrator to verify SMTP configuration.",
            )
        response["message"] = f"OTP sent to {email}."

    _log_event(db, user, "otp_requested", target=email, details={"is_demo": bool(user.is_demo_account)})
    db.commit()
    return response


@app.post("/api/auth/otp/verify")
@limiter.limit("10/minute")
async def otp_verify(request: Request, body: OtpVerifyBody, db: Session = Depends(get_db)):
    """Verify a submitted OTP and, on success, create a login session (same session
    mechanism as the existing password login route)."""
    email = body.email.strip().lower()
    submitted = body.otp.strip()

    if not submitted.isdigit() or len(submitted) != 6:
        raise HTTPException(status_code=400, detail="OTP must be a 6-digit code")

    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="No account found with this email address")

    otp_row = (
        db.query(LoginOtp)
        .filter(LoginOtp.email == email, LoginOtp.purpose == "login", LoginOtp.consumed.is_(False))
        .order_by(LoginOtp.id.desc())
        .first()
    )
    if not otp_row:
        raise HTTPException(status_code=400, detail="No active OTP found. Please request a new OTP.")

    now = datetime.now(timezone.utc)
    expires_at = otp_row.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if now > expires_at:
        otp_row.consumed = True
        db.commit()
        raise HTTPException(status_code=400, detail="OTP expired. Please request a new OTP.")

    if otp_row.attempts >= OTP_MAX_ATTEMPTS:
        otp_row.consumed = True
        db.commit()
        raise HTTPException(status_code=429, detail="Too many incorrect attempts. Please request a new OTP.")

    expected_hash = _hash_otp(submitted, email)
    if not hmac.compare_digest(expected_hash, otp_row.otp_hash):
        otp_row.attempts += 1
        db.commit()
        remaining = OTP_MAX_ATTEMPTS - otp_row.attempts
        if remaining <= 0:
            otp_row.consumed = True
            db.commit()
            raise HTTPException(status_code=429, detail="Too many incorrect attempts. Please request a new OTP.")
        raise HTTPException(status_code=400, detail=f"Incorrect OTP. {remaining} attempt(s) remaining.")

    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="Your account is pending admin verification. Please wait or contact an administrator.",
        )

    # Success: consume the OTP and create a session, identical to password login.
    otp_row.consumed = True
    session_token = _create_session_token()
    user.session_token = session_token
    user.last_login = now
    db.commit()

    response = JSONResponse({
        "success": True,
        "redirect": "/",
        "user": {"username": user.username, "role": user.role},
    })
    response.set_cookie(
        key="session_id",
        value=session_token,
        max_age=86400 * 7,  # 7 days
        httponly=True,
        secure=False,  # Set to True in production with HTTPS
        samesite="lax",
    )
    _log_event(db, user, "login_successful_otp", target=email)
    return response


@app.get("/logout")
async def logout(request: Request, db: Session = Depends(get_db)):
    """Clear session and logout user."""
    try:
        # Get current user
        user = _get_current_user(request, db)
        if user:
            # Clear session token
            user.session_token = None
            db.commit()
            _log_event(db, user, "logout")
    except Exception as e:
        logger.error(f"Logout error: {e}")
    
    # Create response with cleared session cookie
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie(key="session_id")
    return response


# Firebase Authentication Endpoints
@app.post("/api/auth/firebase-login")
async def firebase_login(request: Request, db: Session = Depends(get_db)):
    """Handle Firebase Google Sign-In authentication and create session."""
    try:
        body = await request.json()
        id_token = body.get("idToken")
        
        if not id_token:
            raise HTTPException(status_code=400, detail="No Firebase token provided")
        
        # Verify Firebase ID token
        firebase_user_data = verify_firebase_id_token(id_token, FIREBASE_API_KEY)
        
        # Get or create user from Firebase data
        user = get_or_create_firebase_user(db, User, firebase_user_data)
        
        # Create application session from Firebase authentication
        session_token = create_session_from_firebase(db, user, _create_session_token)
        
        # Create response with session cookie
        response = JSONResponse({
            "success": True,
            "user": {
                "username": user.username,
                "role": user.role,
                "email": firebase_user_data.get("email")
            }
        })
        
        response.set_cookie(
            key="session_id",
            value=session_token,
            max_age=86400 * 7,  # 7 days
            httponly=True,
            secure=False,  # Set to True in production with HTTPS
            samesite="lax"
        )
        
        _log_event(db, user, "login_google_signin", details={
            "email": firebase_user_data.get("email"),
            "firebase_uid": firebase_user_data.get("uid")
        })
        
        return response
    
    except FirebaseAuthError as e:
        logger.error(f"Firebase token verification failed: {e}")
        raise HTTPException(status_code=401, detail=f"Firebase authentication failed: {str(e)}")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Firebase login error: {e}")
        logger.exception(f"Firebase login full traceback:")
        raise HTTPException(status_code=500, detail=f"Firebase authentication error: {str(e)}")


@app.post("/api/auth/register")
async def register_user(request: Request, db: Session = Depends(get_db)):
    """Self-registration: Create a new user account (requires admin verification before first login)"""
    try:
        body = await request.json()
        full_name = body.get("full_name", "").strip()
        email = body.get("email", "").strip()
        password = body.get("password", "").strip()
        role = body.get("role", "analyst").strip().lower()
        
        # Validate inputs
        if not full_name or not email or not password:
            raise HTTPException(status_code=400, detail="Full name, email, and password required")
        
        if len(password) < 8:
            raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
        
        if "@" not in email:
            raise HTTPException(status_code=400, detail="Valid email address required")
        
        # Validate role
        valid_roles = ["viewer", "analyst", "cyber_lead", "it_lead", "security_head"]
        if role not in valid_roles:
            raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {', '.join(valid_roles)}")
        
        # Check if user already exists (by email or username)
        existing_email = db.query(User).filter(User.username == email).first()
        if existing_email:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Create new user (inactive until admin verifies)
        new_user = User(
            username=email,  # Use email as username
            email=email,
            password_hash=_hash_password(password),
            role=role,
            is_active=False  # Require admin verification before first login
        )
        
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        # Log the registration request
        _log_event(
            db, None, "user_registration_requested",
            resource_type="user",
            resource_id=str(new_user.id),
            target=email,
            details={
                "full_name": full_name,
                "role": role,
                "status": "pending_admin_verification"
            }
        )
        
        return {
            "success": True,
            "message": "Account created successfully! Awaiting admin verification.",
            "user_id": new_user.id,
            "email": email,
            "status": "pending_admin_verification"
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {e}")
        raise HTTPException(status_code=500, detail=f"Registration error: {str(e)}")


@app.post("/api/auth/firebase-logout")
async def firebase_logout(request: Request, db: Session = Depends(get_db)):
    """Handle Firebase logout and clear session."""
    try:
        user = _get_current_user(request, db)
        if user:
            user.session_token = None
            db.commit()
            _log_event(db, user, "logout_google_signin")
        
        response = JSONResponse({"success": True})
        response.delete_cookie(key="session_id")
        return response
    
    except Exception as e:
        logger.error(f"Firebase logout error: {e}")
        raise HTTPException(status_code=500, detail="Logout failed")


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


@app.post("/api/scan/public")
@limiter.limit("20/hour")  # Public endpoint - higher rate limit
async def scan_target_public(scan_request: ScanRequest, request: Request):
    """
    PUBLIC TLS Scan endpoint (no authentication required).
    For testing and demonstration purposes.
    Scans a single target for TLS/cryptographic information.
    """
    normalized_target = _validate_scan_target_or_raise(scan_request.target)
    
    try:
        result = scan_tls(normalized_target, timeout=scan_request.timeout)
        _attach_api_endpoints(result, normalized_target, scan_request.timeout, scan_request.openapi_urls)
        await _attach_perimeter_async(result, normalized_target, scan_request.timeout, scan_request.perimeter_ports)
        cbom = generate_cbom([result])
        cbom_dict = cbom.to_dict()
        vulnerabilities = _extract_quantum_vulnerabilities(cbom_dict, normalized_target, "public_scan")
        
        return {
            "status": "completed",
            "target": normalized_target,
            "result": result,
            "cbom": cbom_dict,
            "vulnerabilities": vulnerabilities,
        }
    except Exception as e:
        error_detail = _friendly_scan_error_detail(e)
        raise HTTPException(status_code=400, detail=error_detail)


@app.post("/api/scan", response_model=ScanResponse)
@limiter.limit("10/hour")  # CRITICAL SECURITY FIX: Rate limit scans to 10 per hour
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
        _attach_api_endpoints(result, normalized_target, scan_request.timeout, scan_request.openapi_urls)
        await _attach_perimeter_async(result, normalized_target, scan_request.timeout, scan_request.perimeter_ports)
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

        # Save latest report so /api/report/download-pdf can serve it
        try:
            latest = {
                "scan_id": scan_id,
                "target": normalized_target,
                "started_at": started_at.isoformat(),
                "status": "completed",
                "result": result,
                "cbom": cbom_dict,
                "vulnerabilities": vulnerabilities,
            }
            LATEST_REPORT_PATH.write_text(json.dumps(latest, indent=2), encoding="utf-8")
        except Exception as _save_err:
            logger.warning(f"Could not save latest_report.json: {_save_err}")

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
    perimeter_ports: Optional[str] = None,
    openapi_urls: Optional[str] = None,
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

    parsed_perimeter_ports = _parse_ports_param(perimeter_ports)
    parsed_openapi_urls = [part.strip() for part in (openapi_urls or "").split(",") if part.strip()]

    def _worker() -> None:
        local_db = SessionLocal()
        try:
            worker_user = local_db.get(User, user.id)
            result = scan_tls(normalized_target, timeout=timeout, progress_callback=_progress_callback)
            _attach_api_endpoints(result, normalized_target, timeout, parsed_openapi_urls or None)
            _attach_perimeter_sync(result, normalized_target, timeout, parsed_perimeter_ports)
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

            # Save latest report for /api/report/download-pdf
            try:
                latest = {
                    "scan_id": scan_id,
                    "target": normalized_target,
                    "started_at": started_at.isoformat(),
                    "status": "completed",
                    "result": result,
                    "cbom": cbom_dict,
                    "vulnerabilities": vulnerabilities,
                }
                LATEST_REPORT_PATH.write_text(json.dumps(latest, indent=2), encoding="utf-8")
            except Exception as _save_err:
                logger.warning(f"Could not save latest_report.json: {_save_err}")

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
@limiter.limit("10/hour")  # CRITICAL SECURITY FIX: Rate limit multi-scans to 10 per hour
async def scan_multiple_targets(scan_request: MultiScanRequest, request: Request, db: Session = Depends(get_db)):
    """Scan multiple targets and return combined CBOM"""
    user = _require_roles(request, db, ["admin", "analyst"])

    results = []
    errors = []

    for target in scan_request.targets:
        try:
            normalized_target = _validate_scan_target_or_raise(target)
            result = scan_tls(normalized_target, timeout=scan_request.timeout)
            _attach_api_endpoints(result, normalized_target, scan_request.timeout, scan_request.openapi_urls)
            await _attach_perimeter_async(result, normalized_target, scan_request.timeout, scan_request.perimeter_ports)
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
@limiter.limit("5/hour")  # CRITICAL SECURITY FIX: Rate limit subdomain scans to 5 per hour
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
            _attach_api_endpoints(result, normalized_target, scan_request.timeout, scan_request.openapi_urls)
            await _attach_perimeter_async(result, normalized_target, scan_request.timeout, scan_request.perimeter_ports)
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


# ===========================
# User Management Endpoints (Admin Only)
# ===========================

@app.get("/user_management", response_class=HTMLResponse)
async def user_management_page(request: Request, db: Session = Depends(get_db)):
    """Admin user management dashboard"""
    user = _require_roles(request, db, ["admin"])
    return _render_template(request, "user_management.html", {"current_user": {"username": user.username}})


@app.get("/api/users")
async def list_users(request: Request, db: Session = Depends(get_db)):
    """Get all users (admin only)"""
    user = _require_roles(request, db, ["admin"])
    
    users = db.query(User).all()
    users_data = []
    
    for u in users:
        users_data.append({
            "id": u.id,
            "username": u.username,
            "role": u.role,
            "is_active": u.is_active,
            "last_login": u.last_login.isoformat() if u.last_login else None,
            "created_at": u.created_at.isoformat() if u.created_at else None,
        })
    
    _log_event(db, user, "view_users", resource_type="user")
    return {"users": users_data}


@app.put("/api/users/{user_id}")
async def update_user(request: Request, user_id: int, db: Session = Depends(get_db)):
    """Update user role and access status (admin only)"""
    admin_user = _require_roles(request, db, ["admin"])
    
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    body = await request.json()
    role = body.get("role")
    is_active = body.get("is_active")
    
    # Validate role
    valid_roles = ["viewer", "analyst", "analyst", "cyber_lead", "it_lead", "security_head", "admin"]
    if role and role not in valid_roles:
        raise HTTPException(status_code=400, detail="Invalid role")
    
    # Update user
    if role:
        target_user.role = role
    if is_active is not None:
        target_user.is_active = is_active
    
    db.commit()
    
    _log_event(
        db, admin_user, "update_user", 
        resource_type="user", 
        resource_id=str(user_id),
        target=target_user.username,
        details={"role": role, "is_active": is_active}
    )
    
    return {"success": True, "message": f"User {target_user.username} updated"}


@app.post("/api/users")
async def create_user(request: Request, db: Session = Depends(get_db)):
    """Create new user (admin only)"""
    admin_user = _require_roles(request, db, ["admin"])
    
    body = await request.json()
    username = body.get("username")
    password = body.get("password")
    role = body.get("role", "viewer")
    
    # Validate input
    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")
    
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    
    # Check if user exists
    existing = db.query(User).filter(User.username == username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Validate role
    valid_roles = ["viewer", "analyst", "cyber_lead", "it_lead", "security_head", "admin"]
    if role not in valid_roles:
        raise HTTPException(status_code=400, detail="Invalid role")
    
    # Create new user
    new_user = User(
        username=username,
        password_hash=_hash_password(password),
        role=role,
        is_active=True
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    _log_event(
        db, admin_user, "create_user",
        resource_type="user",
        resource_id=str(new_user.id),
        target=username,
        details={"role": role}
    )
    
    return {"success": True, "user_id": new_user.id, "username": username}


@app.delete("/api/users/{user_id}")
async def delete_user(request: Request, user_id: int, db: Session = Depends(get_db)):
    """Delete user (admin only)"""
    admin_user = _require_roles(request, db, ["admin"])
    
    # Prevent deleting the current user
    if admin_user.id == user_id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    username = target_user.username
    db.delete(target_user)
    db.commit()
    
    _log_event(
        db, admin_user, "delete_user",
        resource_type="user",
        resource_id=str(user_id),
        target=username
    )
    
    return {"success": True, "message": f"User {username} deleted"}


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

    scan = _get_scan_for_user(db, scan_id, user)
    if not scan or not scan.cbom_json:
        raise HTTPException(status_code=404, detail="CBOM not found")

    try:
        cbom = json.loads(scan.cbom_json)
        result = json.loads(scan.result_json) if scan.result_json else {}
        vulns = json.loads(scan.vulnerabilities_json) if scan.vulnerabilities_json else []
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"Invalid stored JSON: {str(e)}")

    try:
        report_data = {
            "scan_id": scan_id,
            "target": scan.target,
            "started_at": scan.started_at.isoformat() if scan.started_at else "N/A",
            "status": scan.status or "completed",
            "result": result,
            "cbom": cbom,
            "vulnerabilities": vulns,
        }
        filename = f"cbom_{scan.target.replace(':', '_').replace('/', '_')}_{scan_id}.pdf"
        out_path = Path(__file__).parent / filename
        pdf_path = generate_pdf(report_data=report_data, output_path=out_path)

        return FileResponse(
            path=pdf_path,
            media_type="application/pdf",
            filename=filename,
        )
    except Exception as e:
        error_detail = "".join(traceback.format_exception(type(e), e, e.__traceback__))
        logger.error(f"PDF generation error: {error_detail}")
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")


@app.get("/api/report/download-pdf")
async def download_report_pdf(request: Request, db: Session = Depends(get_db)):
    """
    Download the latest scan report as a PDF.
    Flow: reads latest_report.json → reportlab generates qshield_report.pdf → FileResponse
    """
    user = _require_user(request, db)

    if not LATEST_REPORT_PATH.exists():
        raise HTTPException(status_code=404, detail="No scan report available yet. Run a scan first.")

    try:
        pdf_path = generate_pdf()  # reads latest_report.json, writes qshield_report.pdf
        return FileResponse(
            path=pdf_path,
            media_type="application/pdf",
            filename="qshield_report.pdf",
        )
    except Exception as e:
        logger.error(f"PDF generation error: {traceback.format_exc()}")
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
                "created_at": _to_iso_utc(log.created_at),
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


@app.delete("/api/scheduled-reports/{schedule_id}")
async def delete_scheduled_report(
    schedule_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """Delete a scheduled report"""
    user = _require_roles(request, db, ["admin", "analyst", "cyber_lead", "it_lead", "security_head"])
    schedule = _get_scheduled_report_for_user(db, schedule_id, user)

    schedule_dict = _scheduled_report_to_dict(schedule)
    _log_event(
        db,
        user,
        "scheduled_report_deleted",
        resource_type="scheduled_report",
        resource_id=schedule.schedule_id,
        target=_build_scheduled_target(schedule.domain, schedule.codomain),
        details={"delivery_email": schedule.delivery_email, "frequency": schedule.frequency},
    )
    db.delete(schedule)
    db.commit()
    return {"message": "Scheduled report deleted", "schedule": schedule_dict}


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
            _attach_api_endpoints(result, target, timeout, payload.openapi_urls)
            await _attach_perimeter_async(result, target, timeout, payload.perimeter_ports)
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

    uvicorn.run(app, host="0.0.0.0", port=9000)
