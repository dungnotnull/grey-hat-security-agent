# Authorization Token Schema Specification — grey-hat-security-agent

**Document**: Phase 0 Schema Design Deliverable  
**Date**: 2026-06-07  
**Version**: 1.0  
**Status**: Complete  

---

## 1. Overview

The **Authorization Token** (AuthToken) is the cornerstone legal and technical compliance mechanism of the grey-hat-security-agent. No active scan, vulnerability test, or network probe may be executed without a valid, signed AuthToken stored in the encrypted SQLite database.

**Design Principles**:
1. **Cryptographic proof**: Ed25519 signature provides non-repudiation of authorization
2. **Temporal limitation**: Tokens expire automatically; no indefinite authorization
3. **Scope confinement**: Tokens specify exactly which tests are permitted on which targets
4. **Auditability**: Token hash recorded in every audit log entry for forensic traceability
5. **Multi-jurisdiction compliance**: Fields designed to satisfy CFAA, CMA, Vietnamese Cybersecurity Law, and GDPR requirements

---

## 2. AuthToken JSON Schema

### 2.1 Full Schema Definition

`json
{
  "": "https://json-schema.org/draft/2020-12/schema",
  "": "https://grey-hat-security-agent.local/schemas/auth-token/v1.0",
  "title": "AuthToken",
  "description": "Authorization token for grey-hat-security-agent active assessments. Must be signed with Ed25519 before use.",
  "type": "object",
  "required": ["version", "token_id", "target", "scope", "expiry_unix", "approver_name", "issued_at_unix", "operator_name", "signature"],
  "properties": {
    "version": {
      "type": "string",
      "const": "1.0",
      "description": "Schema version for forward compatibility"
    },
    "token_id": {
      "type": "string",
      "pattern": "^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$",
      "description": "UUID v4 unique identifier for this token"
    },
    "target": {
      "": "#//target_spec",
      "description": "Authorized target systems"
    },
    "scope": {
      "type": "array",
      "items": {
        "": "#//scope_item"
      },
      "minItems": 1,
      "description": "List of authorized assessment activities"
    },
    "expiry_unix": {
      "type": "integer",
      "minimum": 1700000000,
      "description": "Unix timestamp (UTC) when this token expires. Must be in the future."
    },
    "issued_at_unix": {
      "type": "integer",
      "minimum": 1700000000,
      "description": "Unix timestamp (UTC) when this token was issued."
    },
    "approver_name": {
      "type": "string",
      "minLength": 2,
      "maxLength": 200,
      "description": "Full name of the person authorizing the assessment (system owner or their delegate)"
    },
    "approver_role": {
      "type": "string",
      "minLength": 2,
      "maxLength": 100,
      "description": "Role/title of the approver (e.g., CISO, CTO, Security Lead)"
    },
    "approver_contact": {
      "type": "string",
      "format": "email",
      "description": "Email contact of the approver"
    },
    "operator_name": {
      "type": "string",
      "minLength": 2,
      "maxLength": 200,
      "description": "Full name of the person conducting the assessment"
    },
    "operator_contact": {
      "type": "string",
      "format": "email",
      "description": "Email contact of the operator"
    },
    "authorization_document": {
      "type": "string",
      "description": "Reference to formal engagement letter or contract (required for Vietnamese law compliance)"
    },
    "restrictions": {
      "": "#//restrictions",
      "description": "Optional restrictions on testing parameters"
    },
    "notes": {
      "type": "string",
      "maxLength": 2000,
      "description": "Free-form notes from the approver"
    },
    "signature": {
      "": "#//signature",
      "description": "Ed25519 signature over the token payload"
    }
  },
  "additionalProperties": false,

  "": {
    "target_spec": {
      "type": "object",
      "required": ["domains", "ip_ranges"],
      "properties": {
        "domains": {
          "type": "array",
          "items": {
            "type": "string",
            "format": "hostname"
          },
          "description": "List of authorized domain names (e.g., ['example.com', 'api.example.com'])"
        },
        "ip_ranges": {
          "type": "array",
          "items": {
            "type": "string"
          },
          "description": "List of authorized IP ranges in CIDR notation (e.g., ['203.0.113.0/24', '2001:db8::/32'])"
        },
        "excluded": {
          "type": "array",
          "items": {
            "type": "string"
          },
          "description": "Explicitly excluded subdomains or IP ranges (out of scope even if parent is in scope)"
        }
      }
    },

    "scope_item": {
      "type": "string",
      "enum": [
        "port_scan",
        "service_detection",
        "ssl_tls_check",
        "web_crawler",
        "web_passive_scan",
        "web_active_scan",
        "directory_fuzz",
        "parameter_fuzz",
        "cve_lookup",
        "source_code_scan",
        "dns_enum",
        "poc_sandbox"
      ],
      "description": "Authorized assessment activity type"
    },

    "restrictions": {
      "type": "object",
      "properties": {
        "max_concurrent_requests": {
          "type": "integer",
          "minimum": 1,
          "maximum": 100,
          "default": 10,
          "description": "Maximum concurrent HTTP requests during web scanning"
        },
        "requests_per_second": {
          "type": "integer",
          "minimum": 1,
          "maximum": 50,
          "default": 5,
          "description": "Rate limit for HTTP requests per second"
        },
        "excluded_paths": {
          "type": "array",
          "items": {
            "type": "string"
          },
          "description": "URL paths excluded from scanning (e.g., ['/admin', '/internal'])"
        },
        "excluded_ip_ranges": {
          "type": "array",
          "items": {
            "type": "string"
          },
          "description": "IP ranges excluded from scanning even if in authorized range"
        },
        "testing_window": {
          "type": "object",
          "properties": {
            "start_utc": {
              "type": "string",
              "pattern": "^([01]\\d|2[0-3]):[0-5]\\d$",
              "description": "Start time in UTC HH:MM format"
            },
            "end_utc": {
              "type": "string",
              "pattern": "^([01]\\d|2[0-3]):[0-5]\\d$",
              "description": "End time in UTC HH:MM format"
            },
            "days": {
              "type": "array",
              "items": {
                "type": "string",
                "enum": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
              },
              "description": "Days of the week when testing is permitted"
            }
          }
        },
        "no_exploitation": {
          "type": "boolean",
          "default": true,
          "description": "If true, only verify vulnerabilities exist but do not exploit them"
        },
        "no_dos": {
          "type": "boolean",
          "default": true,
          "description": "If true, skip any tests that could cause denial of service"
        }
      }
    },

    "signature": {
      "type": "object",
      "required": ["algorithm", "public_key", "signature_bytes"],
      "properties": {
        "algorithm": {
          "type": "string",
          "const": "Ed25519",
          "description": "Signature algorithm (currently only Ed25519 is supported)"
        },
        "public_key": {
          "type": "string",
          "contentEncoding": "base64",
          "description": "Ed25519 public key of the approver (base64-encoded)"
        },
        "signature_bytes": {
          "type": "string",
          "contentEncoding": "base64",
          "description": "Ed25519 signature over the canonical JSON of the token payload (all fields except signature)"
        },
        "signed_at_unix": {
          "type": "integer",
          "description": "Unix timestamp when the signature was created"
        }
      }
    }
  }
}
`

### 2.2 Example AuthToken (Unsigned Payload)

`json
{
  "version": "1.0",
  "token_id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
  "target": {
    "domains": ["example.com", "api.example.com"],
    "ip_ranges": ["203.0.113.0/24"],
    "excluded": ["staging.example.com"]
  },
  "scope": [
    "port_scan",
    "service_detection",
    "ssl_tls_check",
    "web_passive_scan",
    "web_active_scan",
    "cve_lookup"
  ],
  "expiry_unix": 1751241600,
  "issued_at_unix": 1751155200,
  "approver_name": "Jane Doe",
  "approver_role": "CISO",
  "approver_contact": "jane@example.com",
  "operator_name": "Security Researcher",
  "operator_contact": "researcher@company.com",
  "authorization_document": "Penetration Testing Engagement Letter 2026-06-01",
  "restrictions": {
    "max_concurrent_requests": 10,
    "requests_per_second": 5,
    "excluded_paths": ["/admin/reset", "/internal/dashboard"],
    "excluded_ip_ranges": ["10.0.0.0/8"],
    "testing_window": {
      "start_utc": "09:00",
      "end_utc": "17:00",
      "days": ["mon", "tue", "wed", "thu", "fri"]
    },
    "no_exploitation": true,
    "no_dos": true
  },
  "notes": "Authorized for Q3 2026 external pentest. Do not test staging.",
  "signature": {
    "algorithm": "Ed25519",
    "public_key": "BASE64_ENCODED_ED25519_PUBLIC_KEY",
    "signature_bytes": "BASE64_ENCODED_ED25519_SIGNATURE",
    "signed_at_unix": 1751155200
  }
}
`

---

## 3. Ed25519 Signature Specification

### 3.1 Algorithm Choice
- **Algorithm**: Ed25519 (Edwards-curve Digital Signature Algorithm using Curve25519)
- **Library**: Python cryptography library (cryptography.hazmat.primitives.asymmetric.ed25519)
- **Why Ed25519**: Small keys (32 bytes), small signatures (64 bytes), fast verification, deterministic (no RNG required for signing), widely supported, resistant to side-channel attacks.

### 3.2 Signature Process

`
1. Generate canonical JSON of token payload (all fields EXCEPT "signature")
2. Encode canonical JSON as UTF-8 bytes
3. Hash the payload bytes with SHA-256 (for audit trail)
4. Sign the payload bytes with the approver's Ed25519 private key
5. Base64-encode the signature bytes and public key
6. Insert the "signature" object into the token
7. Store the complete signed token in encrypted SQLite
`

### 3.3 Canonical JSON Rules
To ensure deterministic signing and verification, the payload JSON MUST be canonicalized:
- Keys sorted lexicographically (ascending)
- No whitespace (compact JSON)
- UTF-8 encoding
- No trailing comma
- Numbers serialized without unnecessary precision
- Boolean values: 	rue / alse (lowercase)
- Null values: 
ull

### 3.4 Verification Process

`
1. Extract the "signature" object from the stored token
2. Remove the "signature" object from the token JSON
3. Canonicalize the remaining payload JSON
4. Encode canonical JSON as UTF-8 bytes
5. Verify the Ed25519 signature using the stored public key and payload bytes
6. If verification fails: REJECT the token — do not proceed with any scan
7. Check that expiry_unix > current_time (reject expired tokens)
8. Check that the target domain/IP is in the authorized scope
9. Check that the requested scan type is in the scope array
10. Check that current UTC time falls within testing_window (if specified)
`

### 3.5 Key Management

`
Command: authorize keygen
- Generates Ed25519 keypair using cryptography library
- Saves private key to: ~/.grey-hat-agent/keys/<key_id>.priv (PEM, encrypted with user passphrase)
- Saves public key to: ~/.grey-hat-agent/keys/<key_id>.pub (PEM, plain)
- Prints key_id and public key fingerprint

Command: authorize sign --token-file <unsigned.json> --key-id <key_id>
- Loads unsigned token JSON
- Loads private key (prompts for passphrase)
- Signs the canonical payload
- Outputs signed token JSON

Command: authorize verify --token-file <signed.json>
- Loads signed token JSON
- Verifies Ed25519 signature
- Checks expiry, scope, and testing window
- Prints verification result
`

---

## 4. Token Storage and Lifecycle

### 4.1 Storage
- Tokens stored in uth_tokens table in encrypted SQLite database
- AES-256-GCM encryption at application layer (key derived from master key in .env)
- Token hash (SHA-256 of canonical payload) stored in udit_log for forensic integrity

### 4.2 Lifecycle

`
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   CREATED    │────>│   ACTIVE     │────>│   EXPIRED    │────>│   ARCHIVED   │
│  (unsigned)  │     │  (signed,    │     │  (past       │     │  (retained    │
│              │     │   valid)     │     │   expiry)    │     │   for audit)  │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
                            │
                            │  (revoked by owner)
                            ▼
                     ┌──────────────┐
                     │   REVOKED    │
                     │  (invalid,   │
                     │   rejected)  │
                     └──────────────┘
`

### 4.3 Token Statuses
| Status | Description | Scan Allowed? |
|--------|-------------|----------------|
| created | Unsigned token, awaiting approver signature | No |
| ctive | Signed, verified, not expired, not revoked | Yes |
| expired | Past expiry_unix timestamp | No |
| evoked | Manually revoked by operator or approver | No |
| rchived | Archived for audit purposes after expiry | No |

---

## 5. Enforcement Points

Every active scan command MUST check the auth token at these enforcement points:

### 5.1 CLI Entry Point (scan command)
`python
async def scan_command(target: str, scan_id: str):
    # 1. Load auth token by scan_id from database
    # 2. Verify Ed25519 signature
    # 3. Check expiry
    # 4. Check target is in authorized domains/IPs
    # 5. Check requested scan type is in scope
    # 6. Check current time is within testing_window
    # 7. Log token_hash + action to audit_log
    # 8. Only then proceed with scan
`

### 5.2 API Endpoint (POST /api/v1/scan)
`python
@app.post("/api/v1/scan")
async def api_scan(request: ScanRequest):
    # Same verification steps as CLI
    # Return 403 Forbidden if token is invalid/expired/out-of-scope
`

### 5.3 Docker Sandbox Execution (sandbox run command)
`python
async def sandbox_run(cve_id: str, target: str):
    # 1. Require auth token for the target
    # 2. Verify token validity
    # 3. Log sandbox execution to audit_log
    # 4. Execute PoC in --network none container
`

---

## 6. Security Considerations

| Threat | Mitigation |
|--------|-----------|
| Token forgery | Ed25519 signature verification — 128-bit security level |
| Token replay | expiry_unix prevents indefinite use; issued_at_unix provides ordering |
| Token tampering | Signature covers entire canonical payload; any modification invalidates |
| Private key compromise | Keys stored encrypted with user passphrase; revocation mechanism |
| Database extraction | AES-256-GCM encryption at rest; master key in .env (never committed to git) |
| Insider threat | Audit log records every scan with operator identity and token hash |
| Scope escalation | Scope is a fixed array; no wildcard expansion; each test type must be explicitly listed |

---

## 7. Pydantic Model Preview (for Phase 1 implementation)

`python
from pydantic import BaseModel, Field, EmailStr
from typing import Optional
from enum import Enum

class ScopeItem(str, Enum):
    PORT_SCAN = \"port_scan\"
    SERVICE_DETECTION = \"service_detection\"
    SSL_TLS_CHECK = \"ssl_tls_check\"
    WEB_CRAWLER = \"web_crawler\"
    WEB_PASSIVE_SCAN = \"web_passive_scan\"
    WEB_ACTIVE_SCAN = \"web_active_scan\"
    DIRECTORY_FUZZ = \"directory_fuzz\"
    PARAMETER_FUZZ = \"parameter_fuzz\"
    CVE_LOOKUP = \"cve_lookup\"
    SOURCE_CODE_SCAN = \"source_code_scan\"
    DNS_ENUM = \"dns_enum\"
    POC_SANDBOX = \"poc_sandbox\"

class TokenStatus(str, Enum):
    CREATED = \"created\"
    ACTIVE = \"active\"
    EXPIRED = \"expired\"
    REVOKED = \"revoked\"
    ARCHIVED = \"archived\"

class TargetSpec(BaseModel):
    domains: list[str]
    ip_ranges: list[str]
    excluded: list[str] = Field(default_factory=list)

class TestingWindow(BaseModel):
    start_utc: str  # HH:MM format
    end_utc: str    # HH:MM format
    days: list[str] # ['mon', 'tue', ...]

class Restrictions(BaseModel):
    max_concurrent_requests: int = 10
    requests_per_second: int = 5
    excluded_paths: list[str] = Field(default_factory=list)
    excluded_ip_ranges: list[str] = Field(default_factory=list)
    testing_window: Optional[TestingWindow] = None
    no_exploitation: bool = True
    no_dos: bool = True

class Signature(BaseModel):
    algorithm: str = \"Ed25519\"
    public_key: str  # base64-encoded
    signature_bytes: str  # base64-encoded
    signed_at_unix: int

class AuthToken(BaseModel):
    version: str = \"1.0\"
    token_id: str  # UUID v4
    target: TargetSpec
    scope: list[ScopeItem]
    expiry_unix: int
    issued_at_unix: int
    approver_name: str
    approver_role: Optional[str] = None
    approver_contact: Optional[EmailStr] = None
    operator_name: str
    operator_contact: Optional[EmailStr] = None
    authorization_document: Optional[str] = None
    restrictions: Optional[Restrictions] = None
    notes: Optional[str] = None
    signature: Signature
`

---

## 8. Validation Test Cases (for Phase 1)

| Test Case | Input | Expected Result |
|-----------|-------|-----------------|
| Valid token | Properly signed, unexpired, correct scope | PASS — scan proceeds |
| Expired token | expiry_unix < current time | REJECT — 403 Forbidden |
| Wrong scope | Token has port_scan but user requests web_active_scan | REJECT — 403 Forbidden |
| Wrong target | Token authorizes example.com but user scans other.com | REJECT — 403 Forbidden |
| Tampered payload | Any field modified after signing | REJECT — signature verification fails |
| Forged signature | Random signature bytes | REJECT — signature verification fails |
| Revoked token | Token with evoked status in database | REJECT — 403 Forbidden |
| Outside testing window | Current time is Saturday, testing window is Mon-Fri | REJECT — 403 Forbidden |
| Excluded path | Target URL contains /admin which is in excluded_paths | REJECT — 403 Forbidden |
| No restrictions field | Token without estrictions | PASS — uses defaults (10 req, 5 rps, no exploitation, no DoS) |
