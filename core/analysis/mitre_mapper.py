"""MITRE ATT&CK technique mapper.

Maps vulnerability findings to ATT&CK Tactic + Technique IDs
using the local STIX 2.1 bundle. Includes technique descriptions
and mitigation references in generated reports.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select

from db.models import MITRETechnique
from db.session import get_sync_session

logger = logging.getLogger(__name__)

# Mapping of common vulnerability types to ATT&CK techniques
CWE_TO_ATTACK = {
    "CWE-79": ["T1059.007"],     # XSS → Command and Scripting Interpreter: JavaScript
    "CWE-89": ["T1190"],          # SQL Injection → Exploit Public-Facing Application
    "CWE-22": ["T1190"],          # Path Traversal → Exploit Public-Facing Application
    "CWE-78": ["T1190", "T1059"], # OS Command Injection → Exploit PFA / Command Scripting
    "CWE-125": ["T1190"],         # Out-of-bounds Read → Exploit Public-Facing Application
    "CWE-287": ["T1078"],         # Improper Authentication → Valid Accounts
    "CWE-306": ["T1078"],         # Missing Authentication → Valid Accounts
    "CWE-502": ["T1190"],         # Deserialization → Exploit Public-Facing Application
    "CWE-862": ["T1190"],         # Missing Authorization → Exploit Public-Facing Application
    "CWE-918": ["T1190"],         # SSRF → Exploit Public-Facing Application
    "CWE-190": ["T1190"],         # Integer Overflow → Exploit Public-Facing Application
    "CWE-352": ["T1190"],         # CSRF → Exploit Public-Facing Application
    "CWE-434": ["T1190"],         # Unrestricted Upload → Exploit Public-Facing Application
    "CWE-798": ["T1078"],         # Hard-coded Credentials → Valid Accounts
    "CWE-200": ["T1046"],         # Information Exposure → Network Service Discovery
    "CWE-295": ["T1190"],         # Improper Certificate Validation → Exploit PFA
    "CWE-327": ["T1190"],         # Broken Crypto → Exploit Public-Facing Application
    "CWE-613": ["T1078"],         # Session Fixation → Valid Accounts
}

# Mapping of service types to ATT&CK techniques
SERVICE_TO_ATTACK = {
    "ssh": ["T1021.004"],     # SSH Remote Services
    "ftp": ["T1078", "T1021.002"],  # FTP
    "smb": ["T1021.002"],     # SMB
    "rdp": ["T1021.001"],     # RDP
    "dns": ["T1071.004"],    # DNS
    "http": ["T1071.001"],   # HTTP
    "https": ["T1071.001"],  # HTTPS
    "smtp": ["T1071.003"],   # SMTP
    "mysql": ["T1078", "T1558"],   # Database
    "postgresql": ["T1078", "T1558"],
    "mssql": ["T1078", "T1558"],
    "redis": ["T1078"],
}


class MITREMapper:
    """Map findings to MITRE ATT&CK techniques."""

    def __init__(self):
        self._sync_db = None

    def _get_sync_db(self):
        if self._sync_db is None:
            self._sync_db = get_sync_session()
        return self._sync_db

    def map_finding_to_techniques(
        self,
        cwe_id: str = "",
        cve_ids: list[str] | None = None,
        service_name: str = "",
    ) -> list[dict]:
        """Map a vulnerability finding to ATT&CK techniques.

        Args:
            cwe_id: CWE ID of the vulnerability.
            cve_ids: List of CVE IDs associated with the finding.
            service_name: Affected service name.

        Returns:
            List of technique dicts with id, name, tactic, description.
        """
        techniques = []
        seen_ids = set()

        # Map from CWE
        if cwe_id and cwe_id in CWE_TO_ATTACK:
            for tech_id in CWE_TO_ATTACK[cwe_id]:
                if tech_id not in seen_ids:
                    technique = self._get_technique(tech_id)
                    if technique:
                        techniques.append(technique)
                        seen_ids.add(tech_id)

        # Map from service
        svc_lower = (service_name or "").lower()
        for key, tech_ids in SERVICE_TO_ATTACK.items():
            if key in svc_lower:
                for tech_id in tech_ids:
                    if tech_id not in seen_ids:
                        technique = self._get_technique(tech_id)
                        if technique:
                            techniques.append(technique)
                            seen_ids.add(tech_id)

        # Default mapping for any web vulnerability
        if not techniques:
            techniques.append({
                "technique_id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "description": "Adversaries may exploit vulnerabilities in public-facing applications.",
                "mitigations": ["Apply patches", "Input validation", "WAF"],
            })

        return techniques

    def _get_technique(self, technique_id: str) -> Optional[dict]:
        """Look up an ATT&CK technique from the local database.

        Falls back to hardcoded data if database is empty.
        """
        try:
            session = self._get_sync_db()
            result = session.execute(
                select(MITRETechnique).where(
                    MITRETechnique.technique_id == technique_id
                )
            ).scalar_one_or_none()

            if result:
                return {
                    "technique_id": result.technique_id,
                    "name": result.name,
                    "tactic": result.tactic,
                    "description": result.description,
                    "mitigations": json.loads(result.mitigations) if result.mitigations else [],
                }
        except Exception:
            pass

        # Hardcoded fallback for common techniques
        FALLBACK = {
            "T1190": {"technique_id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "description": "Adversaries exploit vulnerabilities in applications exposed to the internet.", "mitigations": ["Apply patches", "Input validation", "WAF"]},
            "T1059": {"technique_id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution", "description": "Adversaries abuse command and script interpreters.", "mitigations": ["Input validation", "Output encoding", "Least privilege"]},
            "T1059.007": {"technique_id": "T1059.007", "name": "Command and Scripting Interpreter: JavaScript", "tactic": "Execution", "description": "Adversaries abuse JavaScript execution.", "mitigations": ["CSP headers", "Input sanitization"]},
            "T1078": {"technique_id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion", "description": "Adversaries use stolen credentials to authenticate.", "mitigations": ["MFA", "Strong password policy", "Account monitoring"]},
            "T1046": {"technique_id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery", "description": "Adversaries discover network services.", "mitigations": ["Network segmentation", "Service hardening"]},
            "T1021.001": {"technique_id": "T1021.001", "name": "Remote Services: RDP", "tactic": "Lateral Movement", "description": "Adversaries use RDP for lateral movement.", "mitigations": ["MFA for RDP", "Network segmentation"]},
            "T1021.002": {"technique_id": "T1021.002", "name": "Remote Services: SMB", "tactic": "Lateral Movement", "description": "Adversaries use SMB for lateral movement.", "mitigations": ["SMB signing", "Network segmentation"]},
            "T1021.004": {"technique_id": "T1021.004", "name": "Remote Services: SSH", "tactic": "Lateral Movement", "description": "Adversaries use SSH for lateral movement.", "mitigations": ["Key-based auth", "Fail2ban"]},
            "T1071.001": {"technique_id": "T1071.001", "name": "Application Layer Protocol: Web", "tactic": "Command and Control", "description": "Adversaries use HTTP/HTTPS for C2.", "mitigations": ["SSL inspection", "Network monitoring"]},
            "T1071.003": {"technique_id": "T1071.003", "name": "Application Layer Protocol: Mail", "tactic": "Command and Control", "description": "Adversaries use SMTP for C2.", "mitigations": ["Email filtering", "DMARC"]},
            "T1071.004": {"technique_id": "T1071.004", "name": "Application Layer Protocol: DNS", "tactic": "Command and Control", "description": "Adversaries use DNS for C2.", "mitigations": ["DNS monitoring", "DNS filtering"]},
            "T1558": {"technique_id": "T1558", "name": "Steal or Forge Kerberos Tickets", "tactic": "Credential Access", "description": "Adversaries steal Kerberos tickets.", "mitigations": ["Kerberos hardening", "Monitoring"]},
        }

        return FALLBACK.get(technique_id, {
            "technique_id": technique_id,
            "name": technique_id,
            "tactic": "Unknown",
            "description": f"ATT&CK technique {technique_id}",
            "mitigations": [],
        })

    def ingest_stix_bundle(self, techniques: list[dict]) -> int:
        """Ingest ATT&CK technique data from STIX bundle.

        Args:
            techniques: List of technique dicts.

        Returns:
            Number of new/updated entries.
        """
        session = self._get_sync_db()
        count = 0
        try:
            for tech in techniques:
                tech_id = tech.get("technique_id", "")
                if not tech_id:
                    continue

                existing = session.execute(
                    select(MITRETechnique).where(
                        MITRETechnique.technique_id == tech_id
                    )
                ).scalar_one_or_none()

                if existing:
                    existing.name = tech.get("name", existing.name)
                    existing.description = tech.get("description", existing.description)
                    existing.tactic = tech.get("tactic", existing.tactic)
                    existing.mitigations = json.dumps(tech.get("mitigations", []))
                    existing.updated_at = datetime.now(timezone.utc)
                else:
                    new_tech = MITRETechnique(
                        technique_id=tech_id,
                        name=tech.get("name", ""),
                        description=tech.get("description", ""),
                        tactic=tech.get("tactic", ""),
                        sub_technique="." in tech_id,
                        platforms=json.dumps(tech.get("platforms", [])),
                        mitigations=json.dumps(tech.get("mitigations", [])),
                    )
                    session.add(new_tech)
                count += 1

            session.commit()
            logger.info(f"Ingested {count} ATT&CK techniques")
            return count
        except Exception as e:
            session.rollback()
            logger.error(f"ATT&CK ingestion error: {e}")
            return 0
