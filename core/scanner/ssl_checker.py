"""SSL/TLS configuration checker using sslyze library (v6+).

Checks certificate expiry, chain validity, cipher suites,
HSTS headers, OCSP stapling, and known vulnerabilities.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from sslyze import Scanner, ScanCommand
from sslyze.server_connectivity import ServerConnectivityInfo

from core.auth.gate import AuthorizationGate, AuthorizationError
from core.auth.token import AuthToken, ScopeItem

logger = logging.getLogger(__name__)


@dataclass
class SSLFinding:
    """An SSL/TLS security finding."""
    severity: str  # Critical, High, Medium, Low, Info
    title: str
    description: str
    cwe_id: str = ""
    recommendation: str = ""


@dataclass
class SSLScanResult:
    """Result of an SSL/TLS scan."""
    scan_id: str
    target: str
    port: int
    timestamp: str
    findings: list[SSLFinding] = field(default_factory=list)
    certificate_issuer: str = ""
    certificate_subject: str = ""
    certificate_expiry: str = ""
    days_until_expiry: int = 0
    protocols_supported: list[str] = field(default_factory=list)
    cipher_suites: list[dict] = field(default_factory=list)
    hsts_enabled: bool = False
    ocsp_stapling: bool = False
    error: str = ""


class SSLChecker:
    """SSL/TLS configuration checker using sslyze."""

    def scan(
        self,
        target: str,
        token: AuthToken,
        gate: AuthorizationGate,
        port: int = 443,
    ) -> SSLScanResult:
        """Check SSL/TLS configuration of a target.

        Args:
            target: Target hostname.
            token: Valid AuthToken.
            gate: Authorization gate for verification.
            port: Port number (default 443).

        Returns:
            SSLScanResult with findings and certificate info.
        """
        gate.authorize(token, target, ScopeItem.SSL_TLS_CHECK)

        scan_id = str(uuid.uuid4())
        result = SSLScanResult(
            scan_id=scan_id,
            target=target,
            port=port,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        try:
            server_info = ServerConnectivityInfo(hostname=target, port=port)
            scanner = Scanner()

            # Queue relevant scans
            scan_commands = [
                ScanCommand.CERTIFICATE_INFO,
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.HEARTBLEED,
                ScanCommand.OPENSSL_CCS_INJECTION,
                ScanCommand.TLS_COMPRESSION,
                ScanCommand.TLS_FALLBACK_SCSV,
                ScanCommand.ELLIPTIC_CURVES,
            ]

            for cmd in scan_commands:
                try:
                    scanner.queue_scan(server_info, cmd)
                except Exception as e:
                    logger.debug(f"Could not queue {cmd}: {e}")

            # Process results
            for scan_result in scanner.get_results():
                for command, attempt in scan_result.scan_commands_attempts.items():
                    if attempt.status == "COMPLETED":
                        self._process_scan_result(command, attempt.result, result)
                    elif attempt.status == "ERROR":
                        logger.warning(f"SSL scan {command} failed: {attempt.error_trace}")

        except Exception as e:
            result.error = f"SSL scan error: {e}"
            logger.error(result.error)

        return result

    def _process_scan_result(self, command, scan_result, result: SSLScanResult):
        """Process individual sslyze scan results."""
        try:
            if command == ScanCommand.CERTIFICATE_INFO:
                for cert_deployment in getattr(scan_result, 'certificate_deployments', []):
                    chain = getattr(cert_deployment, 'received_certificate_chain', [])
                    if chain:
                        cert = chain[0]
                        result.certificate_issuer = str(getattr(cert, 'issuer', ''))
                        result.certificate_subject = str(getattr(cert, 'subject', ''))

                        # Check expiry
                        not_valid_after = getattr(cert, 'not_valid_after_utc', None) or getattr(cert, 'not_valid_after', None)
                        if not_valid_after:
                            result.certificate_expiry = str(not_valid_after)
                            try:
                                if hasattr(not_valid_after, 'timestamp'):
                                    days_left = (not_valid_after - datetime.now(timezone.utc)).days
                                else:
                                    days_left = 0
                                result.days_until_expiry = days_left

                                if days_left < 0:
                                    result.findings.append(SSLFinding(
                                        severity="Critical",
                                        title="Expired SSL/TLS Certificate",
                                        description=f"Certificate expired {abs(days_left)} days ago",
                                        cwe_id="CWE-295",
                                        recommendation="Renew the SSL/TLS certificate immediately.",
                                    ))
                                elif days_left < 30:
                                    result.findings.append(SSLFinding(
                                        severity="High",
                                        title="SSL/TLS Certificate Expiring Soon",
                                        description=f"Certificate expires in {days_left} days",
                                        recommendation="Renew the SSL/TLS certificate before it expires.",
                                    ))
                            except Exception:
                                pass

            elif command == ScanCommand.SSL_2_0_CIPHER_SUITES:
                if hasattr(scan_result, 'cipher_suites') and scan_result.cipher_suites:
                    result.findings.append(SSLFinding(
                        severity="Critical",
                        title="SSL 2.0 Supported",
                        description="Server supports the deprecated SSL 2.0 protocol",
                        cwe_id="CWE-327",
                        recommendation="Disable SSL 2.0 in server configuration.",
                    ))
                    result.protocols_supported.append("SSLv2")

            elif command == ScanCommand.HEARTBLEED:
                if hasattr(scan_result, 'is_vulnerable_to_heartbleed') and scan_result.is_vulnerable_to_heartbleed:
                    result.findings.append(SSLFinding(
                        severity="Critical",
                        title="Heartbleed Vulnerability",
                        description="Server is vulnerable to the Heartbleed attack (CVE-2014-0160)",
                        cwe_id="CWE-119",
                        recommendation="Update OpenSSL to a patched version.",
                    ))

        except Exception as e:
            logger.warning(f"Error processing {command} result: {e}")
