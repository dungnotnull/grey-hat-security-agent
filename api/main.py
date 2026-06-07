"""FastAPI application entry point.

Endpoints:
- POST /api/v1/auth/token    - Create auth token
- POST /api/v1/auth/sign     - Sign auth token
- POST /api/v1/auth/verify   - Verify auth token
- POST /api/v1/scan           - Start authorized scan
- GET  /api/v1/scan/{id}      - Get scan results
- POST /api/v1/intel/score    - Score domain risk
- POST /api/v1/intel/check    - Check threat intelligence
- POST /api/v1/report/generate - Generate report
- GET  /api/v1/dashboard      - Finding visualization
- POST /api/v1/knowledge/update - Update knowledge base
- POST /api/v1/analysis/cvss  - Calculate CVSS scores
- GET  /api/v1/analysis/cve/{id} - Look up CVE
- GET  /api/v1/analysis/mitre/{cwe} - Map CWE to ATT&CK
- POST /api/v1/analysis/code-scan - Scan code snippet
- GET  /health                 - Health check
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from config.settings import settings, configure_logging, check_environment
from core.auth.token import AuthToken, AuthTokenManager, ScopeItem
from core.auth.gate import AuthorizationGate, AuthorizationError
from core.intel.risk_score import calculate_composite_risk_score, RiskScoreInput, RiskScoreResult
from models.llm_provider import LLMProvider
from core.reporting.generator import ReportGenerator

# Configure logging on module load
configure_logging()
logger = logging.getLogger(__name__)

# Check environment and warn about missing config
_env_warnings = check_environment()
for _w in _env_warnings:
    logger.warning(_w)

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

# Initialize FastAPI app
app = FastAPI(
    title="grey-hat-security-agent",
    description="Authorized Cybersecurity Research & Red-Team Intelligence Agent API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware — configurable origins
_allowed_origins = [o.strip() for o in settings.cors_allowed_origins.split(",")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limit error handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Global instances
auth_gate = AuthorizationGate()
llm_provider = LLMProvider()
report_generator = ReportGenerator(llm_provider=llm_provider)


# ---------------------------------------------------------------------------
# Startup / Shutdown
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def startup_event():
    """Initialize database on startup."""
    from db.session import init_db
    await init_db()
    logger.info("Database initialized")


@app.on_event("shutdown")
async def shutdown_event():
    """Clean up resources on shutdown."""
    from db.session import close_db
    await close_db()
    logger.info("Database connection closed")


# ---------------------------------------------------------------------------
# Request/Response Models
# ---------------------------------------------------------------------------

class TokenCreateRequest(BaseModel):
    target_domains: list[str]
    target_ip_ranges: list[str] = []
    scope: list[str] = ["port_scan", "service_detection", "cve_lookup"]
    approver_name: str = "Unknown"
    operator_name: str = "Unknown"
    expiry_hours: int = 168
    excluded: list[str] = []
    notes: str = ""


class TokenSignRequest(BaseModel):
    token_json: str
    private_key_pem: str
    passphrase: Optional[str] = None


class TokenVerifyRequest(BaseModel):
    token_json: str


class DomainScoreRequest(BaseModel):
    domain: str
    vt_detections: float = 0.0
    vt_malicious: int = 0
    vt_total: int = 0
    phishtank_hits: int = 0
    openphish_hits: int = 0
    urlhaus_hits: int = 0
    secroberta_phishing: float = 0.0
    secroberta_scam: float = 0.0
    secroberta_malware: float = 0.0
    domain_age_days: int = 0
    whois_anomaly_score: float = 0.0


class DomainCheckRequest(BaseModel):
    domain: str


class ScanRequest(BaseModel):
    target: str
    scan_types: list[str] = ["port_scan", "service_detection", "ssl_tls_check", "cve_lookup"]
    token_json: str


class ScanResponse(BaseModel):
    scan_id: str
    target: str
    status: str
    message: str


class ReportRequest(BaseModel):
    scan_id: str
    format: str = "markdown"
    auth_token_id: str = ""


class KnowledgeUpdateRequest(BaseModel):
    source: str = "all"


# ---------------------------------------------------------------------------
# Auth Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/v1/auth/token")
@limiter.limit("10/minute")
async def create_auth_token(request: Request, req: TokenCreateRequest):
    """Create a new authorization token (unsigned)."""
    try:
        scope_items = [ScopeItem(s) for s in req.scope]
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid scope item: {e}")

    token = AuthTokenManager.create_unsigned(
        target_domains=req.target_domains,
        target_ip_ranges=req.target_ip_ranges,
        scope=scope_items,
        approver_name=req.approver_name,
        operator_name=req.operator_name,
        expiry_hours=req.expiry_hours,
        excluded=req.excluded,
        notes=req.notes,
    )

    return {
        "message": "Token created (unsigned). Sign with Ed25519 private key to activate.",
        "token": token.model_dump(mode="json"),
        "token_hash": AuthTokenManager.get_token_hash(token),
    }


@app.post("/api/v1/auth/sign")
@limiter.limit("10/minute")
async def sign_auth_token(request: Request, req: TokenSignRequest):
    """Sign an authorization token with an Ed25519 private key."""
    try:
        token_data = json.loads(req.token_json)
        token = AuthToken(**token_data)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid token JSON: {e}")

    try:
        signed_token = AuthTokenManager.sign_token(token, req.private_key_pem, req.passphrase)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Signing failed: {e}")

    return {
        "message": "Token signed successfully.",
        "token": signed_token.model_dump(mode="json"),
        "signature_valid": AuthTokenManager.verify_token(signed_token),
    }


@app.post("/api/v1/auth/verify")
@limiter.limit("30/minute")
async def verify_auth_token(request: Request, req: TokenVerifyRequest):
    """Verify an authorization token's signature and validity."""
    try:
        token_data = json.loads(req.token_json)
        token = AuthToken(**token_data)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid token JSON: {e}")

    is_valid = AuthTokenManager.verify_token(token)
    is_expired = AuthTokenManager.is_expired(token)
    status = auth_gate.check_status(token)

    return {
        "is_valid": is_valid,
        "is_expired": is_expired,
        "status": status.value,
        "token_id": token.token_id,
        "target": token.target.domains,
        "scope": [s.value for s in token.scope],
        "expiry_unix": token.expiry_unix,
    }


# ---------------------------------------------------------------------------
# Intel Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/v1/intel/score")
@limiter.limit("30/minute")
async def score_domain_risk(request: Request, req: DomainScoreRequest):
    """Score a domain's risk based on threat intelligence data."""
    risk_input = RiskScoreInput(
        domain=req.domain,
        vt_detections=req.vt_detections,
        vt_malicious=req.vt_malicious,
        vt_total=req.vt_total,
        phishtank_hits=req.phishtank_hits,
        openphish_hits=req.openphish_hits,
        urlhaus_hits=req.urlhaus_hits,
        secroberta_phishing=req.secroberta_phishing,
        secroberta_scam=req.secroberta_scam,
        secroberta_malware=req.secroberta_malware,
        domain_age_days=req.domain_age_days,
        whois_anomaly_score=req.whois_anomaly_score,
    )

    result = calculate_composite_risk_score(risk_input)

    return {
        "domain": req.domain,
        "risk_score": result.composite_score,
        "risk_level": result.level,
        "recommendation": result.recommendation,
        "breakdown": result.breakdown,
    }


@app.post("/api/v1/intel/check")
@limiter.limit("10/minute")
async def check_domain_intelligence(request: Request, req: DomainCheckRequest):
    """Check domain against all threat intelligence feeds."""
    results = {}
    errors = []

    # PhishTank
    try:
        from core.intel.phishtank import PhishTankClient
        client = PhishTankClient()
        phish_result = await client.check_url(f"http://{req.domain}")
        results["phishtank"] = {"found": phish_result is not None, "data": phish_result}
        await client.close()
    except Exception as e:
        errors.append(f"phishtank: {e}")

    # OpenPhish
    try:
        from core.intel.openphish import OpenPhishClient
        client = OpenPhishClient()
        entries = await client.fetch_recent()
        domain_entries = [e for e in entries if e.get("domain") == req.domain]
        results["openphish"] = {"found": len(domain_entries) > 0, "count": len(domain_entries)}
        await client.close()
    except Exception as e:
        errors.append(f"openphish: {e}")

    # URLhaus
    try:
        from core.intel.urlhaus import URLhausClient
        client = URLhausClient()
        urlhaus_entries = await client.query_host(req.domain)
        results["urlhaus"] = {"found": len(urlhaus_entries) > 0, "count": len(urlhaus_entries)}
        await client.close()
    except Exception as e:
        errors.append(f"urlhaus: {e}")

    # VirusTotal
    try:
        from core.intel.virustotal import VirusTotalClient
        client = VirusTotalClient()
        vt_result = await client.get_domain_report(req.domain)
        results["virustotal"] = vt_result or {"found": False}
        await client.close()
    except Exception as e:
        errors.append(f"virustotal: {e}")

    # Shodan
    try:
        from core.intel.shodan_client import ShodanClient
        client = ShodanClient()
        shodan_result = await client.get_host(req.domain)
        results["shodan"] = shodan_result or {"found": False}
        await client.close()
    except Exception as e:
        errors.append(f"shodan: {e}")

    # Risk score
    risk_input = RiskScoreInput(domain=req.domain)
    risk_result = calculate_composite_risk_score(risk_input)
    results["risk_score"] = {
        "score": risk_result.composite_score,
        "level": risk_result.level,
        "recommendation": risk_result.recommendation,
    }

    if errors:
        results["errors"] = errors

    return results


# ---------------------------------------------------------------------------
# Scan Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/v1/scan", response_model=ScanResponse)
@limiter.limit("5/minute")
async def start_scan(request: Request, req: ScanRequest):
    """Start an authorized scan against a target. Requires valid signed AuthToken."""
    # Parse and verify auth token
    try:
        token_data = json.loads(req.token_json)
        token = AuthToken(**token_data)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid token JSON: {e}")

    # Verify authorization
    try:
        scope_items = [ScopeItem(s) for s in req.scan_types]
        primary_scope = scope_items[0] if scope_items else ScopeItem.PORT_SCAN
        auth_gate.authorize(token, req.target, primary_scope)
    except AuthorizationError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid scope: {e}")

    # Store scan in database
    scan_id = str(uuid.uuid4())
    try:
        from db.session import get_sync_session
        from db.models import Scan
        session = get_sync_session()
        try:
            # Find or create target
            target = session.query(Target).filter(Target.domain == req.target).first()
            if not target:
                target = Target(domain=req.target)
                session.add(target)
                session.flush()

            scan_record = Scan(
                scan_id=scan_id,
                target_id=target.id,
                token_id=token.token_id,
                scan_types=json.dumps([s.value for s in scope_items]),
                status="accepted",
            )
            session.add(scan_record)
            session.commit()
        finally:
            session.close()
    except Exception as e:
        logger.warning(f"Failed to store scan in database: {e}")

    return ScanResponse(
        scan_id=scan_id,
        target=req.target,
        status="accepted",
        message=f"Scan accepted. Authorization verified for {req.target}. Use GET /api/v1/scan/{scan_id} for results.",
    )


@app.get("/api/v1/scan/{scan_id}")
async def get_scan_results(scan_id: str):
    """Get results of a completed scan."""
    try:
        from db.session import get_sync_session
        from db.models import Scan
        session = get_sync_session()
        try:
            scan = session.query(Scan).filter(Scan.scan_id == scan_id).first()
            if scan:
                return {
                    "scan_id": scan.scan_id,
                    "status": scan.status,
                    "target_id": scan.target_id,
                    "token_id": scan.token_id,
                    "scan_types": json.loads(scan.scan_types) if scan.scan_types else [],
                    "started_at": scan.started_at.isoformat() if scan.started_at else None,
                    "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                    "error_message": scan.error_message,
                }
        finally:
            session.close()
    except Exception as e:
        logger.warning(f"Failed to query scan from database: {e}")

    return {"scan_id": scan_id, "status": "not_found", "message": "Scan not found in database"}


# ---------------------------------------------------------------------------
# Report Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/v1/report/generate")
@limiter.limit("5/minute")
async def generate_report(request: Request, req: ReportRequest):
    """Generate a security assessment report for a scan."""
    report = await report_generator.generate_report(
        findings=[],  # In production, load from database by scan_id
        scan_info={"target": "unknown", "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"), "scan_type": "full"},
        auth_token_id=req.auth_token_id,
        format=req.format,
    )

    return {
        "report_id": report.get("report_id"),
        "format": req.format,
        "scan_id": req.scan_id,
        "status": "generated",
        "total_findings": report.get("total_findings", 0),
    }


# ---------------------------------------------------------------------------
# Knowledge Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/v1/knowledge/update")
@limiter.limit("2/hour")
async def update_knowledge(request: Request, req: KnowledgeUpdateRequest, background_tasks: BackgroundTasks):
    """Trigger a knowledge base update from security feeds."""
    from core.knowledge.updater import KnowledgeUpdater

    async def _update():
        updater = KnowledgeUpdater()
        try:
            if req.source == "all":
                results = await updater.update_all()
            elif req.source == "arxiv":
                results = {"arxiv": await updater.update_arxiv()}
            elif req.source == "nvd":
                results = {"nvd": await updater.update_nvd()}
            elif req.source == "exploitdb":
                results = {"exploitdb": await updater.update_exploitdb()}
            elif req.source == "mitre":
                results = {"mitre": await updater.update_mitre()}
            elif req.source == "huggingface":
                results = {"hf_papers": await updater.update_huggingface()}
            else:
                results = {"error": f"Unknown source: {req.source}"}
            await updater.close()
            logger.info(f"Knowledge update completed: {results}")
        except Exception as e:
            logger.error(f"Knowledge update failed: {e}")

    background_tasks.add_task(_update)

    return {
        "message": f"Knowledge update started for source: {req.source}",
        "source": req.source,
        "status": "processing",
    }


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.get("/api/v1/dashboard")
async def dashboard():
    """Finding visualization dashboard data."""
    try:
        from db.session import get_sync_session
        from db.models import Finding
        from sqlalchemy import func
        session = get_sync_session()
        try:
            total = session.query(func.count(Finding.id)).scalar() or 0
            by_severity = {}
            for sev in ["Critical", "High", "Medium", "Low", "Info"]:
                by_severity[sev] = session.query(func.count(Finding.id)).filter(Finding.severity == sev).scalar() or 0
            return {
                "total_findings": total,
                "severity_counts": by_severity,
                "recent_scans": [],
            }
        finally:
            session.close()
    except Exception:
        return {
            "total_findings": 0,
            "severity_counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0},
            "recent_scans": [],
        }


# ---------------------------------------------------------------------------
# Analysis Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/v1/analysis/cvss")
async def calculate_cvss(vector_string: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"):
    """Calculate CVSS v3.1 scores from a vector string."""
    from core.analysis.cvss import calculate_all_scores

    try:
        scores = calculate_all_scores(vector_string)
        return scores
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid CVSS vector string: {e}")


@app.get("/api/v1/analysis/cve/{cve_id}")
async def lookup_cve(cve_id: str):
    """Look up a specific CVE by ID."""
    from core.analysis.cve_matcher import CVEMatcher

    matcher = CVEMatcher()
    result = matcher.find_cve_by_id(cve_id)
    if result:
        return result
    raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found in local mirror")


@app.get("/api/v1/analysis/mitre/{cwe_id}")
async def map_cwe_to_mitre(cwe_id: str):
    """Map a CWE ID to MITRE ATT&CK techniques."""
    from core.analysis.mitre_mapper import MITREMapper

    mapper = MITREMapper()
    techniques = mapper.map_finding_to_techniques(cwe_id=cwe_id)
    return {"cwe_id": cwe_id, "techniques": techniques}


@app.post("/api/v1/analysis/code-scan")
async def scan_code(code: str, language: str = "python"):
    """Scan a code snippet for vulnerability patterns."""
    from models.codebert import CodeBERTScanner

    scanner = CodeBERTScanner()
    hits = scanner.scan_code_snippet(code, language)
    return {"hits": hits, "total": len(hits)}


# ---------------------------------------------------------------------------
# Health Check
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    """Health check endpoint."""
    db_status = "unknown"
    try:
        from db.session import get_sync_session
        session = get_sync_session()
        session.close()
        db_status = "connected"
    except Exception:
        db_status = "error"

    return {
        "status": "healthy",
        "version": "1.0.0",
        "database": db_status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
