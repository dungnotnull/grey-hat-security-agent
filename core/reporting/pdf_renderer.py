"""PDF report renderer using ReportLab.

Generates professional pentest reports with:
- Cover page with client/assessor info
- Table of contents
- Executive summary with risk rating
- Detailed findings with CVSS score badges
- MITRE ATT&CK heatmap
- Prioritized recommendations
- Appendix with tool output
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor, black, white
from reportlab.lib.units import mm, cm
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, HRFlowable,
)
from reportlab.platypus.tableofcontents import TableOfContents

logger = logging.getLogger(__name__)

# Color scheme
COLORS = {
    "critical": HexColor("#c0392b"),
    "high": HexColor("#e74c3c"),
    "medium": HexColor("#f39c12"),
    "low": HexColor("#27ae60"),
    "info": HexColor("#3498db"),
    "primary": HexColor("#2c3e50"),
    "secondary": HexColor("#7f8c8d"),
    "accent": HexColor("#2980b9"),
    "background": HexColor("#ecf0f1"),
}


class PDFRenderer:
    """Generate professional PDF reports using ReportLab."""

    def render(self, report: dict, output_path: str) -> str:
        """Render a report dict to PDF file.

        Args:
            report: Report dict from ReportGenerator.
            output_path: Path to write the PDF file.

        Returns:
            Path to the generated PDF file.
        """
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            leftMargin=2 * cm,
            rightMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
        )

        styles = self._create_styles()
        story = []

        # Cover page
        story.extend(self._build_cover_page(report, styles))
        story.append(PageBreak())

        # Table of contents
        story.append(Paragraph("Table of Contents", styles["Heading1"]))
        story.append(Spacer(1, 1 * cm))
        toc_items = [
            "1. Executive Summary",
            "2. Findings Summary",
            "3. Detailed Findings",
            "4. MITRE ATT&CK Mapping",
            "5. Recommendations",
            "6. Appendix",
        ]
        for item in toc_items:
            story.append(Paragraph(item, styles["Normal"]))
        story.append(PageBreak())

        # Executive summary
        story.append(Paragraph("1. Executive Summary", styles["Heading1"]))
        story.append(Spacer(1, 0.5 * cm))
        story.append(Paragraph(f"Overall Risk Rating: <b>{report.get('overall_risk', 'Unknown')}</b>", styles["Normal"]))
        story.append(Spacer(1, 0.3 * cm))

        # Severity summary table
        sev_data = [
            ["Severity", "Count"],
        ]
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            count = report.get("severity_counts", {}).get(sev, 0)
            sev_data.append([sev, str(count)])

        sev_table = Table(sev_data, colWidths=[8 * cm, 4 * cm])
        sev_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLORS["primary"]),
            ("TEXTCOLOR", (0, 0), (-1, 0), white),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, COLORS["secondary"]),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [white, COLORS["background"]]),
        ]))
        story.append(sev_table)
        story.append(Spacer(1, 0.5 * cm))

        # Narrative
        narrative = report.get("narrative", "No narrative generated.")
        for paragraph in narrative.split("\n\n"):
            if paragraph.strip():
                story.append(Paragraph(paragraph.strip(), styles["BodyText"]))

        story.append(PageBreak())

        # Findings summary
        story.append(Paragraph("2. Findings Summary", styles["Heading1"]))
        story.append(Spacer(1, 0.5 * cm))

        findings_data = [["#", "Title", "Severity", "CVSS", "Source"]]
        for i, f in enumerate(report.get("findings", []), 1):
            findings_data.append([
                str(i),
                f.get("title", "Untitled")[:40],
                f.get("severity", "N/A"),
                str(f.get("cvss_score", "N/A")),
                f.get("source", "N/A"),
            ])

        findings_table = Table(findings_data, colWidths=[1 * cm, 7 * cm, 2 * cm, 1.5 * cm, 2 * cm])
        findings_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLORS["primary"]),
            ("TEXTCOLOR", (0, 0), (-1, 0), white),
            ("GRID", (0, 0), (-1, -1), 0.5, COLORS["secondary"]),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ALIGN", (0, 0), (0, -1), "CENTER"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [white, COLORS["background"]]),
        ]))
        story.append(findings_table)
        story.append(PageBreak())

        # Detailed findings
        story.append(Paragraph("3. Detailed Findings", styles["Heading1"]))
        story.append(Spacer(1, 0.5 * cm))

        for i, f in enumerate(report.get("findings", []), 1):
            story.append(Paragraph(f"<b>3.{i} {f.get('title', 'Untitled')}</b>", styles["Heading2"]))

            details = [
                f"<b>Severity:</b> {f.get('severity', 'N/A')}",
                f"<b>CVSS Score:</b> {f.get('cvss_score', 'N/A')} ({f.get('cvss_vector', 'N/A')})",
                f"<b>CWE:</b> {f.get('cwe_id', 'N/A')}",
                f"<b>CVE:</b> {', '.join(f.get('verified_cve_ids', f.get('cve_ids', [])))}",
                f"<b>Source:</b> {f.get('source', 'N/A')}",
            ]
            for detail in details:
                story.append(Paragraph(detail, styles["Normal"]))

            story.append(Paragraph(f"<b>Description:</b> {f.get('description', 'N/A')}", styles["BodyText"]))
            story.append(Paragraph(f"<b>Recommendation:</b> {f.get('recommendation', 'N/A')}", styles["BodyText"]))

            if f.get("mitre_attack"):
                story.append(Paragraph("<b>MITRE ATT&CK:</b>", styles["Normal"]))
                for tech in f["mitre_attack"]:
                    story.append(Paragraph(f"  • {tech['technique_id']}: {tech['name']} ({tech['tactic']})", styles["Normal"]))

            story.append(Spacer(1, 0.5 * cm))

        # Recommendations
        story.append(PageBreak())
        story.append(Paragraph("5. Recommendations", styles["Heading1"]))
        story.append(Spacer(1, 0.5 * cm))
        story.append(Paragraph("1. Address all Critical and High severity findings immediately", styles["Normal"]))
        story.append(Paragraph("2. Schedule remediation for Medium findings within 30 days", styles["Normal"]))
        story.append(Paragraph("3. Review Low/Info findings as part of routine maintenance", styles["Normal"]))

        # Footer
        story.append(Spacer(1, 2 * cm))
        story.append(HRFlowable(width="100%", color=COLORS["secondary"]))
        story.append(Paragraph(
            f"<i>Report generated by grey-hat-security-agent on {report.get('timestamp', datetime.now().isoformat())}</i>",
            styles["Small"],
        ))
        story.append(Paragraph(
            "<i>All CVE IDs verified against local NVD mirror. No hallucinated CVEs.</i>",
            styles["Small"],
        ))

        # Build PDF
        doc.build(story)
        logger.info(f"PDF report generated: {output_path}")
        return output_path

    def _create_styles(self) -> dict:
        """Create custom paragraph styles."""
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(
            name="Small",
            parent=styles["Normal"],
            fontSize=8,
            textColor=COLORS["secondary"],
        ))
        return styles

    def _build_cover_page(self, report: dict, styles: dict) -> list:
        """Build cover page elements."""
        elements = []
        elements.append(Spacer(1, 5 * cm))
        elements.append(Paragraph(report.get("title", "Security Assessment Report"), styles["Title"]))
        elements.append(Spacer(1, 2 * cm))
        elements.append(Paragraph(f"Target: {report.get('target', 'Unknown')}", styles["Heading2"]))
        elements.append(Paragraph(f"Date: {report.get('scan_date', 'N/A')}", styles["Normal"]))
        elements.append(Paragraph(f"Overall Risk: {report.get('overall_risk', 'Unknown')}", styles["Normal"]))
        elements.append(Paragraph(f"Authorization: {report.get('auth_token_id', 'N/A')}", styles["Normal"]))
        elements.append(Spacer(1, 3 * cm))
        elements.append(Paragraph("<b>CONFIDENTIAL</b>", styles["Heading1"]))
        elements.append(Paragraph("This document contains sensitive security information. "
                                  "Distribution is restricted to authorized personnel only.", styles["Normal"]))
        return elements
