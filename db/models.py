"""SQLAlchemy models for encrypted SQLite storage.

Tables:
- targets: Authorized target systems
- findings: Vulnerability findings with CVSS scores
- auth_tokens: Authorization tokens with signatures
- domains_intel: Threat intelligence for domains
- audit_log: Immutable append-only action log
- llm_cache: LLM response cache (SHA-256 keyed)
- cve_mirror: Local NVD CVE mirror
- mitre_techniques: ATT&CK technique database

All sensitive fields encrypted with AES-256-GCM at application layer.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Column, Integer, String, Text, Float, DateTime, Boolean,
    ForeignKey, JSON, Index, UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    """SQLAlchemy declarative base."""
    pass


# ---------------------------------------------------------------------------
# Targets Table
# ---------------------------------------------------------------------------

class Target(Base):
    """Authorized target systems."""
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)  # IPv6 max 45 chars
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    findings = relationship("Finding", back_populates="target", cascade="all, delete-orphan")
    auth_tokens = relationship("AuthTokenRecord", back_populates="target", cascade="all, delete-orphan")

    __table_args__ = (UniqueConstraint("domain", "ip_address", name="uq_target_domain_ip"),)


# ---------------------------------------------------------------------------
# Findings Table
# ---------------------------------------------------------------------------

class Finding(Base):
    """Vulnerability findings with CVSS scores."""
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False, index=True)
    scan_id = Column(String(36), nullable=False, index=True)  # UUID for scan session
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)  # Encrypted
    severity = Column(String(20), nullable=False)  # Critical, High, Medium, Low, Info
    cvss_vector = Column(String(100), nullable=True)  # CVSS:3.1/AV:N/AC:L/...
    cvss_score = Column(Float, nullable=True)
    cwe_id = Column(String(20), nullable=True)  # CWE-89
    cve_ids = Column(Text, nullable=True)  # JSON array of CVE IDs
    affected_component = Column(String(500), nullable=True)
    evidence = Column(Text, nullable=True)  # Encrypted
    remediation = Column(Text, nullable=True)  # Encrypted
    mitre_attack_ids = Column(Text, nullable=True)  # JSON array of ATT&CK IDs
    status = Column(String(20), default="open")  # open, confirmed, false_positive, fixed, accepted_risk
    source = Column(String(50), nullable=True)  # nmap, zap, nuclei, sslyze, manual
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    target = relationship("Target", back_populates="findings")

    __table_args__ = (
        Index("idx_findings_severity", "severity"),
        Index("idx_findings_scan_id", "scan_id"),
        Index("idx_findings_status", "status"),
    )


# ---------------------------------------------------------------------------
# Auth Tokens Table
# ---------------------------------------------------------------------------

class AuthTokenRecord(Base):
    """Authorization tokens with Ed25519 signatures."""
    __tablename__ = "auth_tokens"

    id = Column(Integer, primary_key=True, autoincrement=True)
    token_id = Column(String(36), unique=True, nullable=False, index=True)  # UUID v4
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=True)
    token_json = Column(Text, nullable=False)  # Encrypted full AuthToken JSON
    token_hash = Column(String(64), nullable=False, index=True)  # SHA-256 of canonical payload
    status = Column(String(20), default="created", nullable=False)  # created, active, expired, revoked, archived
    approver_name = Column(String(200), nullable=False)  # Encrypted
    operator_name = Column(String(200), nullable=False)  # Encrypted
    scope = Column(Text, nullable=False)  # JSON array of ScopeItem values
    expiry_unix = Column(Integer, nullable=False)
    issued_at_unix = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    target = relationship("Target", back_populates="auth_tokens")

    __table_args__ = (
        Index("idx_auth_tokens_status", "status"),
        Index("idx_auth_tokens_expiry", "expiry_unix"),
    )


# ---------------------------------------------------------------------------
# Domain Intelligence Table
# ---------------------------------------------------------------------------

class DomainIntel(Base):
    """Threat intelligence data for domains."""
    __tablename__ = "domains_intel"

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain = Column(String(255), unique=True, nullable=False, index=True)
    risk_score = Column(Float, nullable=True)  # 0-100 composite score
    vt_detections = Column(Float, nullable=True)  # VirusTotal detection ratio (0-1)
    vt_categories = Column(Text, nullable=True)  # JSON array of VT categories
    phishtank_hits = Column(Integer, default=0)
    openphish_hits = Column(Integer, default=0)
    urlhaus_hits = Column(Integer, default=0)
    domain_age_days = Column(Integer, nullable=True)
    whois_data = Column(Text, nullable=True)  # JSON WHOIS data (encrypted)
    secroberta_score = Column(Float, nullable=True)  # Phishing probability (0-1)
    secroberta_labels = Column(Text, nullable=True)  # JSON: {phishing: 0.9, scam: 0.1, malware: 0.05}
    last_checked = Column(DateTime, nullable=True)
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_domains_intel_risk", "risk_score"),
    )


# ---------------------------------------------------------------------------
# Audit Log Table
# ---------------------------------------------------------------------------

class AuditLog(Base):
    """Immutable append-only action log.

    Every scan action, token creation, and report generation is recorded here.
    Records are INSERT ONLY — no UPDATE or DELETE operations allowed.
    """
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    action = Column(String(100), nullable=False)  # scan_start, scan_complete, authorize_create, report_generate, etc.
    actor = Column(String(200), nullable=False)  # operator_name
    target = Column(String(255), nullable=True)  # target domain or IP
    token_id = Column(String(36), nullable=True)  # AuthToken ID
    token_hash = Column(String(64), nullable=True)  # SHA-256 of token payload
    scan_type = Column(String(50), nullable=True)  # ScopeItem value
    details = Column(Text, nullable=True)  # JSON details (encrypted)
    result = Column(String(20), nullable=True)  # success, denied, error
    error_message = Column(Text, nullable=True)

    __table_args__ = (
        Index("idx_audit_log_timestamp", "timestamp"),
        Index("idx_audit_log_action", "action"),
    )


# ---------------------------------------------------------------------------
# LLM Cache Table
# ---------------------------------------------------------------------------

class LLMCache(Base):
    """LLM response cache keyed by SHA-256 of prompt.

    Caches responses for 7 days to avoid redundant API calls.
    """
    __tablename__ = "llm_cache"

    id = Column(Integer, primary_key=True, autoincrement=True)
    prompt_hash = Column(String(64), unique=True, nullable=False, index=True)  # SHA-256 of prompt
    provider = Column(String(50), nullable=False)  # claude, openai, ollama
    model = Column(String(100), nullable=False)
    prompt = Column(Text, nullable=False)  # Encrypted
    response = Column(Text, nullable=False)  # Encrypted
    tokens_used = Column(Integer, nullable=True)
    cost_usd = Column(Float, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=False)  # 7-day TTL

    __table_args__ = (
        Index("idx_llm_cache_expires", "expires_at"),
    )


# ---------------------------------------------------------------------------
# CVE Mirror Table
# ---------------------------------------------------------------------------

class CVEMirror(Base):
    """Local NVD CVE database mirror for offline lookup."""
    __tablename__ = "cve_mirror"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(20), unique=True, nullable=False, index=True)  # CVE-2024-1234
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=True)  # CRITICAL, HIGH, MEDIUM, LOW
    cvss_vector = Column(String(100), nullable=True)  # CVSS:3.1/AV:N/AC:L/...
    cvss_score = Column(Float, nullable=True)
    cwe_ids = Column(Text, nullable=True)  # JSON array of CWE IDs
    affected_products = Column(Text, nullable=True)  # JSON array of CPE strings
    references = Column(Text, nullable=True)  # JSON array of reference URLs
    published_date = Column(DateTime, nullable=True)
    last_modified = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_cve_mirror_severity", "severity"),
        Index("idx_cve_mirror_published", "published_date"),
    )


# ---------------------------------------------------------------------------
# MITRE ATT&CK Techniques Table
# ---------------------------------------------------------------------------

class MITRETechnique(Base):
    """MITRE ATT&CK technique database."""
    __tablename__ = "mitre_techniques"

    id = Column(Integer, primary_key=True, autoincrement=True)
    technique_id = Column(String(20), unique=True, nullable=False, index=True)  # T1190
    name = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    tactic = Column(String(100), nullable=True)  # Initial Access, Execution, etc.
    sub_technique = Column(Boolean, default=False)
    parent_technique_id = Column(String(20), nullable=True)
    platforms = Column(Text, nullable=True)  # JSON array
    mitigations = Column(Text, nullable=True)  # JSON array
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_mitre_tactic", "tactic"),
    )


# ---------------------------------------------------------------------------
# Scans Table
# ---------------------------------------------------------------------------

class Scan(Base):
    """Scan session records."""
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(36), unique=True, nullable=False, index=True)  # UUID
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=True)
    token_id = Column(String(36), ForeignKey("auth_tokens.token_id"), nullable=False)
    scan_types = Column(Text, nullable=False)  # JSON array of ScopeItem values
    status = Column(String(20), default="pending")  # pending, running, completed, failed
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    result_summary = Column(Text, nullable=True)  # JSON summary
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    target = relationship("Target")
    findings = relationship("Finding", back_populates="target", foreign_keys="Finding.target_id")
