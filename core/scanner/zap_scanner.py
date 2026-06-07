"""OWASP ZAP scanner integration via REST API.

Runs ZAP in daemon mode (Docker) and orchestrates:
1. Spider (passive crawl)
2. Passive scan
3. Active scan (auth-gated)
Returns structured finding objects.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import httpx

from core.auth.gate import AuthorizationGate, AuthorizationError
from core.auth.token import AuthToken, ScopeItem
from config.settings import settings

logger = logging.getLogger(__name__)


@dataclass
class ZAPFinding:
    """A vulnerability finding from ZAP scan."""
    alert_id: str
    name: str
    description: str
    severity: str  # informational, low, medium, high
    confidence: str
    url: str
    solution: str = ""
    cwe_id: str = ""
    wasc_id: str = ""
    reference: list[str] = field(default_factory=list)
    evidence: str = ""


@dataclass
class ZAPScanResult:
    """Result of a ZAP scan."""
    scan_id: str
    target: str
    timestamp: str
    spider_results: list[str] = field(default_factory=list)
    findings: list[ZAPFinding] = field(default_factory=list)
    error: str = ""


class ZAPScanner:
    """OWASP ZAP scanner integration via REST API."""

    def __init__(self, zap_url: Optional[str] = None, api_key: str = ""):
        self.zap_url = (zap_url or settings.zap_api_url).rstrip("/")
        self.api_key = api_key or settings.zap_api_key or ""
        self.client = httpx.Client(timeout=120.0)

    def _zap_get(self, endpoint: str, params: Optional[dict] = None) -> dict:
        """Send GET request to ZAP API."""
        params = params or {}
        if self.api_key:
            params["apikey"] = self.api_key
        url = f"{self.zap_url}{endpoint}"
        response = self.client.get(url, params=params)
        response.raise_for_status()
        return response.json()

    def _zap_post(self, endpoint: str, data: Optional[dict] = None) -> dict:
        """Send POST request to ZAP API."""
        data = data or {}
        if self.api_key:
            data["apikey"] = self.api_key
        url = f"{self.zap_url}{endpoint}"
        response = self.client.post(url, data=data)
        response.raise_for_status()
        return response.json()

    def _wait_for_completion(self, endpoint: str, status_key: str, max_wait: int = 600, poll_interval: int = 5) -> bool:
        """Poll ZAP until a scan completes."""
        elapsed = 0
        while elapsed < max_wait:
            try:
                result = self._zap_get(endpoint)
                status = result.get(status_key, "0")
                if str(status) == "100":
                    return True
                time.sleep(poll_interval)
                elapsed += poll_interval
            except Exception as e:
                logger.warning(f"ZAP poll error: {e}")
                time.sleep(poll_interval)
                elapsed += poll_interval
        return False

    def scan(
        self,
        target: str,
        token: AuthToken,
        gate: AuthorizationGate,
        scan_type: str = "active",  # "passive" or "active"
    ) -> ZAPScanResult:
        """Run ZAP scan against a target.

        Args:
            target: Target URL to scan.
            token: Valid AuthToken.
            gate: Authorization gate for verification.
            scan_type: "passive" (spider+passive) or "active" (full scan).

        Returns:
            ZAPScanResult with findings.
        """
        scope = ScopeItem.WEB_ACTIVE_SCAN if scan_type == "active" else ScopeItem.WEB_PASSIVE_SCAN
        gate.authorize(token, target, scope)

        scan_id = str(uuid.uuid4())
        result = ZAPScanResult(
            scan_id=scan_id,
            target=target,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        try:
            # Step 1: Spider
            logger.info(f"ZAP: Starting spider for {target}")
            self._zap_post("/json/spider/action/scan/", {"url": target})
            self._wait_for_completion("/json/spider/view/status/", "status", max_wait=300)

            # Step 2: Wait for passive scan
            if scan_type in ("passive", "active"):
                logger.info("ZAP: Waiting for passive scan to complete")
                for _ in range(60):
                    records = self._zap_get("/json/pscan/view/recordsToScan/")
                    if int(records.get("recordsToScan", "1")) == 0:
                        break
                    time.sleep(5)

            # Step 3: Active scan (if requested)
            if scan_type == "active":
                logger.info(f"ZAP: Starting active scan for {target}")
                self._zap_post("/json/ascan/action/scan/", {"url": target})
                self._wait_for_completion("/json/ascan/view/status/", "status", max_wait=600)

            # Step 4: Get alerts
            alerts = self._zap_get("/json/core/view/alerts/", {"baseurl": target})
            for alert in alerts.get("alerts", []):
                finding = ZAPFinding(
                    alert_id=str(alert.get("alertId", "")),
                    name=alert.get("alert", ""),
                    description=alert.get("description", ""),
                    severity=alert.get("riskcode", "0"),
                    confidence=alert.get("confidence", "0"),
                    url=alert.get("url", target),
                    solution=alert.get("solution", ""),
                    cwe_id=str(alert.get("cweid", "")),
                    wasc_id=str(alert.get("wascid", "")),
                    reference=alert.get("reference", "").split("\n") if alert.get("reference") else [],
                    evidence=alert.get("evidence", ""),
                )
                result.findings.append(finding)

        except Exception as e:
            result.error = f"ZAP scan error: {e}"
            logger.error(result.error)

        logger.info(f"ZAP scan complete: {len(result.findings)} findings")
        return result

    def shutdown(self):
        """Shutdown ZAP daemon."""
        try:
            self._zap_get("/json/core/action/shutdown/")
        except Exception:
            pass
        self.client.close()
