"""Threat intelligence feed clients.

Provides async clients for:
- PhishTank (phishing URL database)
- OpenPhish (community phishing feed)
- URLhaus (malware URL database)
- VirusTotal (domain/IP reputation)
- Shodan (internet device scanning)
- Risk score calculator
"""

from core.intel.phishtank import PhishTankClient
from core.intel.openphish import OpenPhishClient
from core.intel.urlhaus import URLhausClient
from core.intel.virustotal import VirusTotalClient
from core.intel.shodan_client import ShodanClient
from core.intel.risk_score import calculate_composite_risk_score, RiskScoreInput, RiskScoreResult

__all__ = [
    "PhishTankClient",
    "OpenPhishClient",
    "URLhausClient",
    "VirusTotalClient",
    "ShodanClient",
    "calculate_composite_risk_score",
    "RiskScoreInput",
    "RiskScoreResult",
]
