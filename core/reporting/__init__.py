"""Report generation modules.

Provides:
- ReportGenerator: LLM-powered report generation with fallback chain
- PDFRenderer: Professional PDF reports via ReportLab
- Templates: LLM prompt templates and disclosure email template
"""

from core.reporting.generator import ReportGenerator
from core.reporting.pdf_renderer import PDFRenderer
from core.reporting.templates import (
    SYSTEM_PROMPT,
    EXECUTIVE_SUMMARY_TEMPLATE,
    FINDING_NARRATIVE_TEMPLATE,
    REMEDIATION_TEMPLATE,
    THREAT_INTEL_TEMPLATE,
    DISCLOSURE_EMAIL_TEMPLATE,
)

__all__ = [
    "ReportGenerator",
    "PDFRenderer",
    "SYSTEM_PROMPT",
    "EXECUTIVE_SUMMARY_TEMPLATE",
    "FINDING_NARRATIVE_TEMPLATE",
    "REMEDIATION_TEMPLATE",
    "THREAT_INTEL_TEMPLATE",
    "DISCLOSURE_EMAIL_TEMPLATE",
]
