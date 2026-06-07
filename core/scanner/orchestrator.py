"""Scanner orchestrator that coordinates multi-phase scans.

Phases:
1. Reconnaissance (nmap SYN scan + version detection)
2. SSL/TLS Assessment (sslyze)
3. Web Crawling (ZAP spider)
4. Web Scanning (ZAP active scan)
5. CVE Targeting (nuclei templates)
6. Vulnerability Matching (NVD lookup)

All phases require valid AuthToken before execution.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from core.auth.gate import AuthorizationGate
from core.auth.token import AuthToken, ScopeItem
from core.scanner.nmap_wrapper import NmapScanner, ScanResult as NmapScanResult, Service
from core.scanner.ssl_checker import SSLChecker, SSLScanResult
from core.scanner.zap_scanner import ZAPScanner, ZAPScanResult
from core.scanner.nuclei_scanner import NucleiScanner, NucleiScanResult

logger = logging.getLogger(__name__)


@dataclass
class OrchestratedScanResult:
    """Combined result from all scan phases."""
    scan_id: str
    target: str
    timestamp: str
    nmap_result: Optional[NmapScanResult] = None
    ssl_result: Optional[SSLScanResult] = None
    zap_result: Optional[ZAPScanResult] = None
    nuclei_result: Optional[NucleiScanResult] = None
    cve_matches: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    error: str = ""


class ScannerOrchestrator:
    """Coordinates multi-phase security scans."""

    def __init__(
        self,
        nmap_path: str = "nmap",
        zap_url: str = "http://localhost:8090",
        nuclei_path: str = "nuclei",
    ):
        self.nmap_scanner = NmapScanner(nmap_path=nmap_path)
        self.ssl_checker = SSLChecker()
        self.zap_scanner = ZAPScanner(zap_url=zap_url)
        self.nuclei_scanner = NucleiScanner(nuclei_path=nuclei_path)

    def full_scan(
        self,
        target: str,
        token: AuthToken,
        gate: AuthorizationGate,
        skip_phases: Optional[list[str]] = None,
    ) -> OrchestratedScanResult:
        """Run full orchestrated scan against target.

        Args:
            target: Target hostname or IP.
            token: Valid AuthToken with required scope items.
            gate: Authorization gate for verification.
            skip_phases: List of phase names to skip ('nmap', 'ssl', 'zap', 'nuclei').

        Returns:
            OrchestratedScanResult with combined findings.
        """
        skip = skip_phases or []
        scan_id = str(uuid.uuid4())
        result = OrchestratedScanResult(
            scan_id=scan_id,
            target=target,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        try:
            # Phase 1: Reconnaissance (nmap)
            if "nmap" not in skip:
                logger.info(f"[Phase 1/5] nmap scan: {target}")
                try:
                    result.nmap_result = self.nmap_scanner.scan(
                        target, token, gate,
                        arguments="-sV --top-ports 1000",
                    )
                    for svc in result.nmap_result.services:
                        result.findings.append({
                            "source": "nmap",
                            "type": "service_detected",
                            "host": svc.host,
                            "port": svc.port,
                            "protocol": svc.protocol,
                            "service": svc.service_name,
                            "version": svc.service_version,
                            "product": svc.product,
                            "severity": "info",
                        })
                except Exception as e:
                    logger.warning(f"nmap phase failed: {e}")

            # Phase 2: SSL/TLS Assessment
            if "ssl" not in skip:
                logger.info(f"[Phase 2/5] SSL/TLS check: {target}")
                try:
                    result.ssl_result = self.ssl_checker.scan(target, token, gate)
                    for finding in result.ssl_result.findings:
                        result.findings.append({
                            "source": "sslyze",
                            "type": "ssl_tls_finding",
                            "severity": finding.severity.lower(),
                            "title": finding.title,
                            "description": finding.description,
                            "cwe_id": finding.cwe_id,
                            "recommendation": finding.recommendation,
                        })
                except Exception as e:
                    logger.warning(f"SSL phase failed: {e}")

            # Phase 3+4: Web Scanning (ZAP)
            if "zap" not in skip:
                logger.info(f"[Phase 3/5] ZAP scan: {target}")
                try:
                    result.zap_result = self.zap_scanner.scan(target, token, gate, scan_type="active")
                    for finding in result.zap_result.findings:
                        result.findings.append({
                            "source": "zap",
                            "type": "web_vulnerability",
                            "severity": self._zap_severity(finding.severity),
                            "title": finding.name,
                            "description": finding.description,
                            "url": finding.url,
                            "cwe_id": finding.cwe_id,
                            "solution": finding.solution,
                        })
                except Exception as e:
                    logger.warning(f"ZAP phase failed: {e}")

            # Phase 5: CVE Targeting (nuclei)
            if "nuclei" not in skip:
                logger.info(f"[Phase 4/5] nuclei scan: {target}")
                try:
                    result.nuclei_result = self.nuclei_scanner.scan(target, token, gate)
                    for finding in result.nuclei_result.findings:
                        result.findings.append({
                            "source": "nuclei",
                            "type": "template_match",
                            "severity": finding.severity,
                            "title": finding.template_name,
                            "cve_id": finding.cve_id,
                            "cwe_id": finding.cwe_id,
                            "url": finding.url,
                            "description": finding.description,
                        })
                except Exception as e:
                    logger.warning(f"nuclei phase failed: {e}")

            # Phase 6: CVE Matching
            logger.info(f"[Phase 5/5] CVE matching for {len(result.nmap_result.services if result.nmap_result else [])} services")
            # CVE matching is done separately via core.analysis.cve_matcher

        except Exception as e:
            result.error = f"Orchestrated scan error: {e}"
            logger.error(result.error)

        logger.info(f"Orchestrated scan complete: {len(result.findings)} total findings")
        return result

    @staticmethod
    def _zap_severity(zap_risk: str) -> str:
        """Convert ZAP risk code to severity string."""
        mapping = {"3": "high", "2": "medium", "1": "low", "0": "info"}
        return mapping.get(zap_risk, "info")
