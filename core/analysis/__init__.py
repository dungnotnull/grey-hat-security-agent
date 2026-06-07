"""Security analysis modules.

Provides:
- CVSS v3.1 calculator with spec-correct Roundup
- CVE matcher against local NVD mirror
- MITRE ATT&CK technique mapper
"""

from core.analysis.cvss import (
    calculate_base_score,
    calculate_temporal_score,
    calculate_environmental_score,
    calculate_all_scores,
    parse_vector_string,
    CVSS3Vector,
    CVSS3Metric,
    roundup1,
)
from core.analysis.cve_matcher import CVEMatcher
from core.analysis.mitre_mapper import MITREMapper

__all__ = [
    "calculate_base_score",
    "calculate_temporal_score",
    "calculate_environmental_score",
    "calculate_all_scores",
    "parse_vector_string",
    "CVSS3Vector",
    "CVSS3Metric",
    "roundup1",
    "CVEMatcher",
    "MITREMapper",
]
