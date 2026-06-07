# Legal Compliance \& Safe Harbor Research — grey-hat-security-agent

**Document**: Phase 0 Research Deliverable  
**Date**: 2026-06-07  
**Status**: Complete  

---

## 1. Overview

This document surveys the applicable laws, safe harbor provisions, and authorization requirements that govern the design and operation of **grey-hat-security-agent**. The agent operates in two modes — passive threat intelligence and authorized assessment — both of which must comply with computer crime laws in all jurisdictions where the operator may reside or target systems may be located.

**Key Principle**: No active scan, test, or probe shall ever be executed against any system without a cryptographically-signed authorization token from the system owner. This is a non-negotiable architectural constraint, not merely a policy.

---

## 2. United States — Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030

### 2.1 Relevant Provisions
| Section | Offense | Penalty |
|---------|---------|---------|
| §1030(a)(2) | Obtaining information from a protected computer without authorization | Misdemeanor (first) / Felony (prior convictions) |
| §1030(a)(3) | Accessing a non-public government computer without authorization | Misdemeanor |
| §1030(a)(4) | Accessing a protected computer with intent to defraud | Felony |
| §1030(a)(5) | Causing damage to a protected computer (reckless or intentional) | Felony |
| §1030(a)(6) | Trafficking in passwords | Misdemeanor |
| §1030(c)(2)(B)(ii) | Sentencing enhancement if violation committed for commercial advantage or financial gain | Enhanced penalty |

### 2.2 Authorization Doctrine
- **_Van Buren v. United States_ (2021)**: The Supreme Court narrowed "exceeds authorized access" to mean accessing information in areas of the computer that the person was not permitted to access — not violating policies on information use. This means having *any* authorized access defeats CFAA liability for that access, but does not protect unauthorized access.
- **Implicit authorization is insufficient**: Bug bounty program terms of service constitute authorization, but only for the specific scope defined. Scanning beyond that scope may still violate CFAA.
- **Safe harbor for researchers**: The DOJ (2022) announced it would not prosecute "good-faith" security research that doesn't cause harm, but this is a *prosecutorial discretion* memo, not a law. It does not create a binding safe harbor.

### 2.3 Agent Compliance Measures
- [x] **Authorization gate**: Cryptographic auth token required before any active scan. No bypass possible.
- [x] **Scope enforcement**: Auth token specifies exact domains/IPs and test types allowed. Scans that exceed scope are rejected.
- [x] **Expiry enforcement**: Auth tokens have expiry_unix field; expired tokens are cryptographically rejected.
- [x] **Audit trail**: Every scan action is logged immutably with auth token hash, target, timestamp.
- [x] **No autonomous action**: Agent never initiates scans without explicit human command + valid auth token.

---

## 3. United Kingdom — Computer Misuse Act 1990 (CMA)

### 3.1 Relevant Provisions
| Section | Offense | Penalty |
|---------|---------|---------|
| §1 | Unauthorized access to computer material | Up to 2 years imprisonment |
| §2 | Unauthorized access with intent to commit further offenses | Up to 5 years |
| §3 | Unauthorized acts intended to impair computer operation | Up to 10 years |
| §3ZA | Unauthorized acts causing (or creating risk of) serious damage | Up to 14 years |
| §3A | Making, supplying, or obtaining articles for use in CMA offenses | Up to 2 years |

### 3.2 Authorization Requirements
- **Written authorization is mandatory**: A signed letter or contract from the system owner specifying scope and duration is the gold standard for authorization.
- **Bug bounty programs**: Participation in a bug bounty program with defined scope constitutes authorization under §1, but only within the program's stated boundaries.
- **"Making articles" concern (§3A)**: The CMA criminalizes creating or supplying tools that could be used for hacking. Mitigation: the agent is distributed as a security *testing* tool with mandatory authorization controls; it cannot be used without an owner-signed auth token.

### 3.3 Agent Compliance Measures
- [x] Auth token requires pprover_name field — the real name of the person authorizing the test.
- [x] Ed25519 signature on auth token provides cryptographic proof of authorization.
- [x] All findings and audit logs stored in encrypted SQLite, exportable for legal defense.
- [x] Agent startup displays legal notice requiring user acknowledgment.

---

## 4. Vietnam — Cybersecurity Law 2018 (Luật An ninh mạng)

### 4.1 Relevant Provisions
| Article | Provision | Penalty |
|---------|-----------|---------|
| Article 8 | Prohibits unauthorized access, attacks on information systems, and spreading malware | Administrative fine: VND 20M–100M; Criminal: 6 months–5 years (§289 Penal Code) |
| Article 16 | Organizations must protect personal data and verify user identity | Administrative fine |
| Article 21 | Foreign providers must store Vietnamese user data in Vietnam | Administrative compliance |
| Article 26 | Prohibited content: anti-state propaganda, spreading malware, cyberattack organization | Criminal |

### 4.2 Authorization Requirements
- **Written engagement contract**: Vietnamese law requires a formal contract between the security tester and the system owner. Verbal consent is insufficient.
- **VNCERT coordination**: For government systems, testing must be coordinated through Vietnam's Computer Emergency Response Team (VNCERT).
- **Data localization**: If the agent processes Vietnamese citizens' data, it must store data within Vietnam or comply with cross-border data transfer rules.

### 4.3 Agent Compliance Measures
- [x] Auth token's pprover_name and signature fields satisfy the written authorization requirement.
- [x] scope field in auth token explicitly limits what data can be collected.
- [x] Vietnamese-language phishing domain submissions routed to VNCERT (not to international CERTs only).
- [x] All findings encrypted at rest (AES-256-GCM) to protect personal data.

---

## 5. European Union — General Data Protection Regulation (GDPR)

### 5.1 Relevant Provisions
| Article | Requirement |
|---------|-------------|
| Article 6 | Lawful basis for processing personal data (consent, contract, legitimate interest) |
| Article 32 | Security of processing — appropriate technical and organizational measures |
| Article 33 | Breach notification within 72 hours |
| Article 35 | Data Protection Impact Assessment (DPIA) for high-risk processing |

### 5.2 Agent Compliance Measures
- [x] All findings stored with AES-256-GCM encryption at rest (Art. 32 compliance).
- [x] Threat intelligence on domains/IPs does not process personal data unless explicitly in scope.
- [x] Audit trail provides accountability for all data access (Art. 5 "integrity and confidentiality").
- [x] Data retention policy: findings auto-deleted after 90 days unless retained for active engagement.

---

## 6. Safe Harbor Provisions Summary

| Jurisdiction | Safe Harbor Mechanism | Requirements for Agent Operators |
|--------------|----------------------|--------------------------------|
| **United States** | Bug bounty program rules + DOJ good-faith discretion | Operate strictly within bug bounty scope; obtain signed auth tokens; never scan beyond authorized scope |
| **United Kingdom** | Written authorization + defined scope | Signed contract/letter from system owner; scope documented in auth token; report vulnerabilities to vendor before disclosure |
| **Vietnam** | Written engagement contract | Formal contract between tester and system owner; VNCERT coordination for government systems; data localization compliance |
| **European Union** | Legitimate interest (Art. 6(1)(f)) + Art. 32 security measures | Document legitimate interest; implement encryption and access controls; conduct DPIA for systematic scanning |

---

## 7. Bug Bounty Platform Scope Rules

### 7.1 HackerOne
- **Scope extraction**: Program scope defined in JSON at https://hackerone.com/<program>/profile.json
- **Safe harbor**: Programs include safe harbor clauses protecting researchers from legal action
- **Out-of-scope**: Assets not listed are off-limits; testing them may violate CFAA
- **Rate limiting**: Programs often specify request rate limits (e.g., max 10 req/sec)

### 7.2 Bugcrowd
- **Scope extraction**: Program scope at https://bugcrowd.com/<program>/scope
- **Vulnerability rating**: Bugcrowd Priority Assessment Rating (P1–P5) aligns with CVSS severity
- **Submission format**: Structured vulnerability report with PoC steps required

### 7.3 Intigriti
- **Scope extraction**: Available via API for registered researchers
- **Triaging**: Reports are triaged by Intigriti staff before disclosure to the vendor
- **Reward structure**: Varies by program and severity

### 7.4 Agent Integration Plan
- [ ] Implement bug bounty scope parser in Phase 1 MVP
- [ ] Auto-generate auth tokens from program scope definitions
- [ ] Display scope warnings when target is near boundary of authorized scope

---

## 8. Authorization Token Architecture (Legal Compliance View)

The authorization token is the **legal compliance mechanism** of the entire system. It is designed to satisfy the requirements of all four jurisdictions:

`
AuthToken (JSON, signed with Ed25519):
{
  "version": "1.0",
  "target": "example.com",              // CFAA: defines authorized target
  "scope": ["web", "ssl", "port_scan"], // CMA/VC: defines authorized test types
  "expiry_unix": 1751241600,            // All jurisdictions: temporal limitation
  "approver_name": "Jane Doe",          // VC Law: identifies authorizing person
  "approver_role": "CISO",              // Additional context
  "approver_contact": "jane@example.com",
  "authorization_document": "Engagement Letter 2026-06-01", // VC Law: contract reference
  "restrictions": {                     // Program-specific limitations
    "max_concurrent_requests": 10,
    "excluded_paths": ["/admin", "/internal"],
    "excluded_ip_ranges": ["10.0.0.0/8"],
    "testing_window": {
      "start_utc": "09:00",
      "end_utc": "17:00",
      "days": ["mon", "tue", "wed", "thu", "fri"]
    }
  },
  "operator_name": "Security Researcher",
  "operator_contact": "researcher@company.com",
  "issued_at_unix": 1751155200,
  "signature": "Ed25519 signature bytes (base64)"  // Cryptographic proof
}
`

**Legal significance of each field**:
- 	arget: Defines the authorized target system (CFAA §1030(a)(2))
- scope: Limits authorized test types (CMA §1, VC Art. 8)
- expiry_unix: Temporal limitation prevents indefinite authorization
- pprover_name + signature: Written authorization proof (CMA, VC Law)
- uthorization_document: Links to formal engagement contract (VC Law requirement)
- estrictions.testing_window: Ensures testing during business-acceptable hours

---

## 9. Responsible Disclosure Best Practices

| Practice | Implementation in Agent |
|----------|------------------------|
| **Private disclosure first** | Agent generates reports for operator review; never auto-sends to public lists |
| **90-day disclosure deadline** | Report template includes disclosure deadline calculator |
| **Vendor contact before public** | eport email-draft command creates (but does not send) responsible disclosure email |
| **No public PoC without vendor patch** | PoC sandbox runs are local-only; no auto-publication |
| **CVE coordination** | Agent can format reports for CVE submission but operator must review and submit |

---

## 10. Conclusion

The grey-hat-security-agent is designed with **legal compliance as a first-class architectural constraint**. The authorization token system is not merely a feature — it is the mechanism by which the agent satisfies the authorization requirements of CFAA, CMA, Vietnamese Cybersecurity Law, and GDPR. No scan, test, or probe can be executed without a cryptographically-signed token that serves as digital proof of authorization.

**Recommendation**: Before deploying the agent in any jurisdiction, operators must:
1. Obtain written authorization from the target system owner
2. Review the specific bug bounty program rules (if applicable)
3. Consult local legal counsel on jurisdiction-specific requirements
4. Keep audit logs of all activities for legal defense purposes
5. Follow responsible disclosure timelines (minimum 90 days before public disclosure)
