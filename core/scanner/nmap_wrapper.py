"""nmap Python wrapper for port scanning and service detection.

Uses python-nmap library for SYN scans (-sS) and version
detection (-sV). Returns structured Service objects.
Requires valid AuthToken before execution.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

import nmap

from core.auth.gate import AuthorizationGate, AuthorizationError
from core.auth.token import AuthToken, ScopeItem

logger = logging.getLogger(__name__)


@dataclass
class Service:
    """Detected service from nmap scan."""
    host: str
    port: int
    protocol: str  # tcp, udp
    service_name: str
    service_version: str = ""
    product: str = ""
    extra_info: str = ""
    cpe: list[str] = field(default_factory=list)
    state: str = "open"


@dataclass
class ScanResult:
    """Result of an nmap scan."""
    scan_id: str
    target: str
    timestamp: str
    services: list[Service] = field(default_factory=list)
    os_matches: list[dict] = field(default_factory=list)
    raw_output: str = ""
    error: str = ""


class NmapScanner:
    """Port scanner using python-nmap."""

    def __init__(self, nmap_path: str = "nmap"):
        """Initialize with path to nmap binary."""
        self.nm = nmap.PortScanner(nmap_path=nmap_path)

    def scan(
        self,
        target: str,
        token: AuthToken,
        gate: AuthorizationGate,
        ports: str = "1-10000",
        arguments: str = "-sV -O --top-ports 1000",
        timeout: int = 300,
    ) -> ScanResult:
        """Run nmap scan on target.

        Args:
            target: Target IP or hostname.
            token: Valid AuthToken.
            gate: Authorization gate for verification.
            ports: Port specification (e.g., '1-10000', '80,443').
            arguments: Nmap arguments.
            timeout: Scan timeout in seconds.

        Returns:
            ScanResult with detected services.

        Raises:
            AuthorizationError: If token doesn't authorize port_scan.
        """
        # Verify authorization
        gate.authorize(token, target, ScopeItem.PORT_SCAN)

        scan_id = str(uuid.uuid4())
        result = ScanResult(
            scan_id=scan_id,
            target=target,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        try:
            logger.info(f"nmap scan starting: target={target}, ports={ports}")
            self.nm.scan(target, ports=ports, arguments=arguments)

            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    for port in self.nm[host][proto]:
                        port_info = self.nm[host][proto][port]
                        service = Service(
                            host=host,
                            port=port,
                            protocol=proto,
                            service_name=port_info.get("name", "unknown"),
                            service_version=port_info.get("version", ""),
                            product=port_info.get("product", ""),
                            extra_info=port_info.get("extrainfo", ""),
                            cpe=port_info.get("cpe", []),
                            state=port_info.get("state", "unknown"),
                        )
                        result.services.append(service)

            # OS detection
            for host in self.nm.all_hosts():
                if "osmatch" in self.nm[host]:
                    for os_match in self.nm[host]["osmatch"]:
                        result.os_matches.append({
                            "name": os_match.get("name", ""),
                            "accuracy": os_match.get("accuracy", ""),
                            "osclass": os_match.get("osclass", []),
                        })

            result.raw_output = self.nm.command_line

        except nmap.PortScannerError as e:
            result.error = f"nmap scan error: {e}"
            logger.error(result.error)
        except Exception as e:
            result.error = f"unexpected error: {e}"
            logger.error(result.error)

        logger.info(f"nmap scan complete: {len(result.services)} services found")
        return result

    def scan_services_only(
        self,
        target: str,
        token: AuthToken,
        gate: AuthorizationGate,
        ports: str = "1-10000",
    ) -> list[Service]:
        """Quick service detection scan without OS detection.

        Args:
            target: Target IP or hostname.
            token: Valid AuthToken.
            gate: Authorization gate for verification.
            ports: Port specification.

        Returns:
            List of detected Service objects.
        """
        gate.authorize(token, target, ScopeItem.SERVICE_DETECTION)
        result = self.scan(target, token, gate, ports=ports, arguments="-sV --top-ports 1000")
        return result.services
