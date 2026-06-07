"""Report template definitions for LLM prompt engineering.

Templates for:
- Executive summary
- Finding narrative
- Remediation advice
- Threat intelligence summary
- Responsible disclosure email
"""

from __future__ import annotations


# System prompt for all report generation
SYSTEM_PROMPT = """You are a professional cybersecurity penetration tester writing a security assessment report. 
Follow these rules strictly:
1. Only include CVE IDs that are explicitly listed in the findings data provided to you. NEVER invent CVE IDs.
2. Use precise technical language.
3. Include specific remediation steps, not generic advice.
4. Map findings to MITRE ATT&CK techniques where applicable.
5. Include CVSS scores and severity ratings for every finding.
6. Write in clear, professional English.
7. Include an executive summary suitable for non-technical stakeholders.
8. Prioritize findings by risk severity.
"""

# Executive summary template
EXECUTIVE_SUMMARY_TEMPLATE = """Write an executive summary for the following security assessment.

Target: {target}
Date: {date}
Total Findings: {total_findings}
Severity Breakdown: Critical={critical}, High={high}, Medium={medium}, Low={low}, Info={info}
Overall Risk Rating: {overall_risk}

Write 2-3 paragraphs that:
1. Summarize the overall security posture
2. Highlight the most critical findings
3. Recommend immediate actions
"""

# Finding narrative template
FINDING_NARRATIVE_TEMPLATE = """Write a detailed technical description for the following vulnerability finding:

Title: {title}
Severity: {severity}
CVSS Vector: {cvss_vector}
CVSS Score: {cvss_score}
CWE: {cwe_id}
CVE: {cve_ids}
Affected Component: {affected_component}
Evidence: {evidence}

Write:
1. A detailed description of the vulnerability
2. Step-by-step reproduction instructions
3. Impact analysis (what an attacker could achieve)
4. Specific remediation recommendations
5. References to relevant documentation
"""

# Remediation advice template
REMEDIATION_TEMPLATE = """Provide prioritized remediation recommendations for the following findings:

{findings_list}

For each finding, provide:
1. Immediate mitigation (what to do right now)
2. Long-term remediation (how to fix it properly)
3. Verification steps (how to confirm the fix worked)
4. Estimated effort (hours/days)

Prioritize by severity: Critical > High > Medium > Low > Info.
"""

# Threat intelligence summary template
THREAT_INTEL_TEMPLATE = """Summarize the threat intelligence findings for the following domain:

Domain: {domain}
Risk Score: {risk_score}/100
Risk Level: {risk_level}
VirusTotal Detections: {vt_detections}
PhishTank Hits: {phishtank_hits}
OpenPhish Hits: {openphish_hits}
URLhaus Hits: {urlhaus_hits}
Domain Age: {domain_age_days} days
SecRoBERTa Classification: {secroberta_classification}

Write a threat intelligence brief that:
1. Assesses the overall threat level
2. Explains the key risk indicators
3. Recommends actions (report to CERT, add to blocklist, etc.)
"""

# Responsible disclosure email template
DISCLOSURE_EMAIL_TEMPLATE = """Draft a responsible disclosure email for the following vulnerability:

Target Organization: {organization}
Vulnerability Title: {title}
Severity: {severity}
CVE: {cve_id}
Description: {description}
Impact: {impact}
Remediation: {remediation}

Write a professional responsible disclosure email that:
1. Is polite and collaborative in tone
2. Clearly describes the vulnerability
3. Provides proof of concept (without enabling abuse)
4. Suggests a remediation timeline
5. Sets a 90-day disclosure deadline
6. Includes our contact information
"""
