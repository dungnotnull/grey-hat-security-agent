"""Composite risk score calculator for domain intelligence.

Formula (0-100 scale):
- VirusTotal detections: 30%
- Feed hits (PhishTank + OpenPhish + URLhaus): 20%
- SecRoBERTa NLP classification: 25%
- Domain age: 15%
- WHOIS anomalies: 10%
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RiskScoreInput:
    """Input data for composite risk score calculation."""
    domain: str = ""                     # Domain being scored (for reference only)
    vt_detections: float = 0.0           # VirusTotal detection ratio (0.0-1.0)
    vt_malicious: int = 0                # VT malicious engine count
    vt_total: int = 0                    # VT total engine count
    phishtank_hits: int = 0              # PhishTank entry count
    openphish_hits: int = 0              # OpenPhish entry count
    urlhaus_hits: int = 0               # URLhaus entry count
    secroberta_phishing: float = 0.0     # SecRoBERTa phishing probability (0.0-1.0)
    secroberta_scam: float = 0.0         # SecRoBERTa scam probability (0.0-1.0)
    secroberta_malware: float = 0.0      # SecRoBERTa malware probability (0.0-1.0)
    domain_age_days: int = 0             # Days since domain registration
    whois_anomaly_score: float = 0.0    # WHOIS anomaly score (0.0-1.0)


@dataclass
class RiskScoreResult:
    """Result of composite risk score calculation."""
    composite_score: float            # 0-100
    level: str                        # Low/Moderate/High/Critical/Imminent
    breakdown: dict = field(default_factory=dict)
    recommendation: str = ""


# Risk level thresholds
RISK_LEVELS = [
    (0, 20, "Low", "Monitor only — no action required."),
    (20, 40, "Moderate", "Investigate further — consider manual review."),
    (40, 60, "High", "Flag for review — likely malicious."),
    (60, 80, "Critical", "Report to authority — high confidence malicious."),
    (80, 101, "Imminent", "Immediate report to CERT/Safe Browsing — very high confidence."),
]


def calculate_composite_risk_score(input_data: RiskScoreInput) -> RiskScoreResult:
    """Calculate composite risk score (0-100) for a domain.

    Args:
        input_data: Input data for risk calculation.

    Returns:
        RiskScoreResult with composite score, level, breakdown, and recommendation.
    """
    # 1. VirusTotal score (0-1)
    vt_score = input_data.vt_detections if input_data.vt_detections > 0 else 0.0
    if input_data.vt_total > 0:
        vt_score = input_data.vt_malicious / input_data.vt_total

    # 2. Feed hits score (0-1, diminishing returns)
    total_feed_hits = input_data.phishtank_hits + input_data.openphish_hits + input_data.urlhaus_hits
    feed_score = 1 - (1 / (1 + total_feed_hits))

    # 3. SecRoBERTa NLP score (max of phishing, scam, malware)
    nlp_score = max(
        input_data.secroberta_phishing,
        input_data.secroberta_scam,
        input_data.secroberta_malware,
    )

    # 4. Domain age score (younger = riskier)
    if input_data.domain_age_days <= 0:
        age_score = 1.0  # Unknown age or just registered
    else:
        age_score = 1 - min(input_data.domain_age_days / 365, 1.0)

    # 5. WHOIS anomaly score
    whois_score = input_data.whois_anomaly_score

    # Weighted composite score
    composite = (
        0.30 * vt_score +
        0.20 * feed_score +
        0.25 * nlp_score +
        0.15 * age_score +
        0.10 * whois_score
    )

    score = round(composite * 100, 1)
    score = max(0.0, min(100.0, score))

    # Determine risk level
    level = "Low"
    recommendation = "Monitor only — no action required."
    for low, high, lvl, rec in RISK_LEVELS:
        if low <= score < high:
            level = lvl
            recommendation = rec
            break

    breakdown = {
        "vt_score": round(vt_score * 100, 1),
        "vt_weight": 30,
        "feed_score": round(feed_score * 100, 1),
        "feed_weight": 20,
        "feed_hits": total_feed_hits,
        "nlp_score": round(nlp_score * 100, 1),
        "nlp_weight": 25,
        "age_score": round(age_score * 100, 1),
        "age_weight": 15,
        "whois_score": round(whois_score * 100, 1),
        "whois_weight": 10,
    }

    return RiskScoreResult(
        composite_score=score,
        level=level,
        breakdown=breakdown,
        recommendation=recommendation,
    )
