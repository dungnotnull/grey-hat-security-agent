"""Nuclei template-based vulnerability scanner integration.

Runs nuclei as subprocess with JSON output for CVE-specific
template scanning. Complements ZAP for targeted CVE detection.
"""

from __future__ import annotations

import json
import logging
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from core.auth.gate import AuthorizationGate, AuthorizationError
from core.auth.token import AuthToken, ScopeItem

logger = logging.getLogger(__name__)


@dataclass
class NucleiFinding:
    """A vulnerability finding from nuclei scan."""
    template_id: str
    template_name: str
    severity: str  # critical, high, medium, low, info
    cve_id: str = ""
    cwe_id: str = ""
    url: str = ""
    matcher_name: str = ""
    description: str = ""
    reference: list[str] = field(default_factory=list)
    evidence: str = ""


@dataclass
class NucleiScanResult:
    """Result of a nuclei scan."""
    scan_id: str
    target: str
    timestamp: str
    findings: list[NucleiFinding] = field(default_factory=list)
    total_templates: int = 0
    error: str = ""


class NucleiScanner:
    """Nuclei template-based vulnerability scanner."""

    def __init__(self, nuclei_path: str = "nuclei"):
        self.nuclei_path = nuclei_path

    def scan(
        self,
        target: str,
        token: AuthToken,
        gate: AuthorizationGate,
        severity: str = "critical,high,medium",
        templates: Optional[str] = None,
        rate_limit: int = 50,
        timeout: int = 600,
    ) -> NucleiScanResult:
        """Run nuclei scan against a target.

        Args:
            target: Target URL to scan.
            token: Valid AuthToken.
            gate: Authorization gate for verification.
            severity: Severity levels to include.
            templates: Specific template directory or file.
            rate_limit: Requests per second.
            timeout: Scan timeout in seconds.

        Returns:
            NucleiScanResult with findings.
        """
        gate.authorize(token, target, ScopeItem.WEB_ACTIVE_SCAN)

        scan_id = str(uuid.uuid4())
        result = NucleiScanResult(
            scan_id=scan_id,
            target=target,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        cmd = [
            self.nuclei_path,
            "-u", target,
            "-json",
            "-severity", severity,
            "-rate-limit", str(rate_limit),
            "-timeout", str(timeout),
            "-no-color",
        ]

        if templates:
            cmd.extend(["-t", templates])

        try:
            logger.info(f"nuclei scan starting: target={target}")
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 60,
            )

            # Parse JSON output line by line
            for line in proc.stdout.strip().splitlines():
                try:
                    entry = json.loads(line)
                    if entry.get("type") == "result":
                        finding = NucleiFinding(
                            template_id=entry.get("template-id", ""),
                            template_name=entry.get("info", {}).get("name", ""),
                            severity=entry.get("info", {}).get("severity", "info"),
                            cve_id=self._extract_cve(entry),
                            cwe_id=self._extract_cwe(entry),
                            url=entry.get("matched-at", entry.get("host", "")),
                            matcher_name=entry.get("matcher-name", ""),
                            description=entry.get("info", {}).get("description", ""),
                            reference=entry.get("info", {}).get("reference", []),
                            evidence=entry.get("extracted-results", [""])[0] if entry.get("extracted-results") else "",
                        )
                        result.findings.append(finding)
                except json.JSONDecodeError:
                    continue

            if proc.returncode not in (0, 1):
                result.error = f"nuclei exited with code {proc.returncode}: {proc.stderr[:500]}"

        except subprocess.TimeoutExpired:
            result.error = f"nuclei scan timed out after {timeout} seconds"
            logger.error(result.error)
        except FileNotFoundError:
            result.error = "nuclei binary not found. Install from https://github.com/projectdiscovery/nuclei"
            logger.error(result.error)
        except Exception as e:
            result.error = f"nuclei scan error: {e}"
            logger.error(result.error)

        logger.info(f"nuclei scan complete: {len(result.findings)} findings")
        return result

    def _extract_cve(self, entry: dict) -> str:
        """Extract CVE ID from nuclei result."""
        references = entry.get("info", {}).get("reference", [])
        for ref in references:
            if "CVE-" in ref.upper():
                import re
                match = re.search(r'CVE-\d{4}-\d{4,}', ref, re.IGNORECASE)
                if match:
                    return match.group(0).upper()
        tags = entry.get("info", {}).get("tags", [])
        for tag in tags:
            if tag.upper().startswith("CVE-"):
                return tag.upper()
        return ""

    def _extract_cwe(self, entry: dict) -> str:
        """Extract CWE ID from nuclei result."""
        tags = entry.get("info", {}).get("tags", [])
        for tag in tags:
            if tag.upper().startswith("CWE-"):
                return tag.upper()
        classification = entry.get("info", {}).get("classification", {})
        cwe_id = classification.get("cwe-id", "")
        if isinstance(cwe_id, list):
            return cwe_id[0] if cwe_id else ""
        return str(cwe_id) if cwe_id else ""
