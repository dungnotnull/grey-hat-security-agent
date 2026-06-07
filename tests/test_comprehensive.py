import pytest
import json
import os
import sys
import asyncio
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Core imports
from core.auth.token import AuthTokenManager, ScopeItem, AuthToken, TokenStatus, TargetSpec, Restrictions, TestingWindow
from core.auth.gate import AuthorizationGate, AuthorizationError
from core.analysis.cvss import parse_vector_string, calculate_base_score, calculate_all_scores, roundup1, CVSS3Vector
from core.analysis.mitre_mapper import MITREMapper, CWE_TO_ATTACK, SERVICE_TO_ATTACK
from core.intel.risk_score import calculate_composite_risk_score, RiskScoreInput, RiskScoreResult
from models.codebert import CodeBERTScanner
from models.secroberta import SecRoBERTaClassifier
from models.llm_provider import LLMProvider, LLMResponse
from core.reporting.generator import ReportGenerator
from core.reporting.pdf_renderer import PDFRenderer
from core.reporting.templates import (SYSTEM_PROMPT, EXECUTIVE_SUMMARY_TEMPLATE, FINDING_NARRATIVE_TEMPLATE, REMEDIATION_TEMPLATE, THREAT_INTEL_TEMPLATE, DISCLOSURE_EMAIL_TEMPLATE)
from core.knowledge.updater import KnowledgeUpdater
from utils.crypto import (generate_ed25519_keypair, serialize_private_key, serialize_public_key, sign_payload, verify_signature, encrypt_field, decrypt_field, canonical_json, sha256_hash, hash_token_payload, generate_uuid, utc_now_unix)
from utils.helpers import is_valid_domain, is_valid_ip, is_valid_cidr, ip_in_range, TokenBucketRateLimiter, retry_with_backoff
from db.models import Target, Finding, AuthTokenRecord, DomainIntel, AuditLog, LLMCache, CVEMirror, MITRETechnique, Scan
from db.encryption import FieldEncryptor
from config.settings import Settings

class TestAuthToken:
    def test_create_unsigned_token(self):
        token = AuthTokenManager.create_unsigned(
            target_domains=["example.com"],
            scope=[ScopeItem.PORT_SCAN, ScopeItem.CVE_LOOKUP],
            approver_name="Jane Doe", operator_name="John Smith", expiry_hours=24,
        )
        assert token.token_id is not None
        assert "example.com" in token.target.domains
        assert ScopeItem.PORT_SCAN in token.scope
        assert token.signature is None

    def test_sign_and_verify_token(self):
        token = AuthTokenManager.create_unsigned(target_domains=["test.example.com"], scope=[ScopeItem.PORT_SCAN])
        private_key, _ = generate_ed25519_keypair()
        priv_pem = serialize_private_key(private_key)
        signed = AuthTokenManager.sign_token(token, priv_pem)
        assert signed.signature is not None
        assert AuthTokenManager.verify_token(signed) is True

    def test_tampered_token_fails(self):
        token = AuthTokenManager.create_unsigned(target_domains=["safe.example.com"], scope=[ScopeItem.SSL_TLS_CHECK])
        private_key, _ = generate_ed25519_keypair()
        priv_pem = serialize_private_key(private_key)
        signed = AuthTokenManager.sign_token(token, priv_pem)
        signed.approver_name = "HACKER"
        assert AuthTokenManager.verify_token(signed) is False

    def test_expired_token(self):
        token = AuthTokenManager.create_unsigned(target_domains=["expired.example.com"], scope=[ScopeItem.PORT_SCAN], expiry_hours=-1)
        assert AuthTokenManager.is_expired(token) is True

    def test_scope_check(self):
        token = AuthTokenManager.create_unsigned(target_domains=["scoped.example.com"], scope=[ScopeItem.PORT_SCAN, ScopeItem.SSL_TLS_CHECK])
        assert AuthTokenManager.is_in_scope(token, ScopeItem.PORT_SCAN) is True
        assert AuthTokenManager.is_in_scope(token, ScopeItem.WEB_ACTIVE_SCAN) is False

    def test_target_authorization(self):
        token = AuthTokenManager.create_unsigned(target_domains=["auth.example.com"])
        assert AuthTokenManager.is_target_authorized(token, "auth.example.com") is True
        assert AuthTokenManager.is_target_authorized(token, "other.com") is False

    def test_keypair_generation(self):
        result = AuthTokenManager.create_keypair()
        assert "key_id" in result
        assert "private_key_pem" in result
        assert "BEGIN PRIVATE KEY" in result["private_key_pem"]

    def test_token_hash_deterministic(self):
        token = AuthTokenManager.create_unsigned(target_domains=["hash.example.com"], scope=[ScopeItem.PORT_SCAN])
        h1 = AuthTokenManager.get_token_hash(token)
        h2 = AuthTokenManager.get_token_hash(token)
        assert h1 == h2
        assert len(h1) == 64

    def test_restrictions(self):
        restrictions = Restrictions(max_concurrent_requests=5, no_exploitation=True)
        token = AuthTokenManager.create_unsigned(target_domains=["r.example.com"], scope=[ScopeItem.PORT_SCAN], restrictions=restrictions)
        assert token.restrictions.max_concurrent_requests == 5

    def test_exclusion(self):
        token = AuthTokenManager.create_unsigned(target_domains=["example.com"], excluded=["admin.example.com"])
        assert AuthTokenManager.is_target_authorized(token, "admin.example.com") is False
        assert AuthTokenManager.is_target_authorized(token, "example.com") is True

class TestAuthGate:
    def _make_signed_token(self, domains=None, scope=None):
        domains = domains or ["gate.example.com"]
        scope = scope or [ScopeItem.PORT_SCAN, ScopeItem.SSL_TLS_CHECK]
        token = AuthTokenManager.create_unsigned(target_domains=domains, scope=scope, expiry_hours=24)
        private_key, _ = generate_ed25519_keypair()
        return AuthTokenManager.sign_token(token, serialize_private_key(private_key))

    def test_authorized_scan_passes(self):
        token = self._make_signed_token()
        gate = AuthorizationGate()
        result = gate.authorize(token, "gate.example.com", ScopeItem.PORT_SCAN)
        assert result.token_id == token.token_id

    def test_wrong_target_rejected(self):
        token = self._make_signed_token()
        gate = AuthorizationGate()
        with pytest.raises(AuthorizationError):
            gate.authorize(token, "wrong.example.com", ScopeItem.PORT_SCAN)

    def test_wrong_scope_rejected(self):
        token = self._make_signed_token()
        gate = AuthorizationGate()
        with pytest.raises(AuthorizationError):
            gate.authorize(token, "gate.example.com", ScopeItem.WEB_ACTIVE_SCAN)

    def test_unsigned_token_rejected(self):
        token = AuthTokenManager.create_unsigned(target_domains=["u.example.com"], scope=[ScopeItem.PORT_SCAN])
        gate = AuthorizationGate()
        with pytest.raises(AuthorizationError, match="unsigned"):
            gate.authorize(token, "u.example.com", ScopeItem.PORT_SCAN)

    def test_revoked_token_rejected(self):
        token = self._make_signed_token()
        gate = AuthorizationGate()
        gate.revoke_token(token.token_id)
        with pytest.raises(AuthorizationError, match="revoked"):
            gate.authorize(token, "gate.example.com", ScopeItem.PORT_SCAN)

    def test_expired_token_rejected(self):
        token = AuthTokenManager.create_unsigned(target_domains=["exp.example.com"], scope=[ScopeItem.PORT_SCAN], expiry_hours=-1)
        private_key, _ = generate_ed25519_keypair()
        signed = AuthTokenManager.sign_token(token, serialize_private_key(private_key))
        gate = AuthorizationGate()
        with pytest.raises(AuthorizationError, match="expired"):
            gate.authorize(signed, "exp.example.com", ScopeItem.PORT_SCAN)

    def test_check_status_active(self):
        token = self._make_signed_token()
        gate = AuthorizationGate()
        assert gate.check_status(token) == TokenStatus.ACTIVE

    def test_check_status_created(self):
        token = AuthTokenManager.create_unsigned(target_domains=["s.example.com"])
        gate = AuthorizationGate()
        assert gate.check_status(token) == TokenStatus.CREATED

class TestCVSS:
    def test_roundup_function(self):
        assert roundup1(3.03) == 3.1
        assert roundup1(9.8) == 9.8
        assert roundup1(0.0) == 0.0

    def test_critical_vector(self):
        v = parse_vector_string("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert calculate_base_score(v)[0] == 9.8

    def test_high_vector(self):
        v = parse_vector_string("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
        assert calculate_base_score(v)[0] == 7.5

    def test_medium_vector(self):
        v = parse_vector_string("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
        assert calculate_base_score(v)[0] == 5.3

    def test_low_vector(self):
        v = parse_vector_string("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N")
        assert calculate_base_score(v)[0] == 3.1

    def test_none_vector(self):
        v = parse_vector_string("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        assert calculate_base_score(v)[0] == 0.0

    def test_scope_changed(self):
        vu = parse_vector_string("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
        vc = parse_vector_string("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H")
        assert calculate_base_score(vc)[0] > calculate_base_score(vu)[0]

    def test_all_scores(self):
        r = calculate_all_scores("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert r["base_score"] == 9.8
        assert "temporal_score" in r
        assert "environmental_score" in r

    def test_nist_test_vectors(self):
        vectors = {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N": 7.5,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N": 5.3,
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N": 3.1,
            "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H": 5.5,
        }
        for vector, expected in vectors.items():
            v = parse_vector_string(vector)
            score, _ = calculate_base_score(v)
            assert abs(score - expected) < 0.05, f"CVSS {vector}: expected {expected}, got {score}"

class TestMITRE:
    def test_cwe_mapping(self):
        m = MITREMapper()
        t = m.map_finding_to_techniques(cwe_id="CWE-89")
        assert "T1190" in [x["technique_id"] for x in t]

    def test_service_mapping(self):
        m = MITREMapper()
        t = m.map_finding_to_techniques(service_name="openssh")
        assert "T1021.004" in [x["technique_id"] for x in t]

    def test_default_mapping(self):
        m = MITREMapper()
        t = m.map_finding_to_techniques()
        assert len(t) > 0

    def test_xss_mapping(self):
        m = MITREMapper()
        t = m.map_finding_to_techniques(cwe_id="CWE-79")
        assert "T1059.007" in [x["technique_id"] for x in t]

    def test_hardcoded_creds(self):
        m = MITREMapper()
        t = m.map_finding_to_techniques(cwe_id="CWE-798")
        assert "T1078" in [x["technique_id"] for x in t]

class TestCodeBERT:
    def test_sqli(self):
        s = CodeBERTScanner()
        h = s.scan_code_snippet('query = "SELECT * FROM users WHERE id = " + user_input')
        assert "CWE-89" in [x["cwe_id"] for x in h]

    def test_path_traversal(self):
        s = CodeBERTScanner()
        h = s.scan_code_snippet('f = open("../../../etc/passwd")')
        assert "CWE-22" in [x["cwe_id"] for x in h]

    def test_hardcoded_creds(self):
        s = CodeBERTScanner()
        h = s.scan_code_snippet('password = "admin123"')
        assert "CWE-798" in [x["cwe_id"] for x in h]

    def test_os_command_injection(self):
        s = CodeBERTScanner()
        h = s.scan_code_snippet('os.system(user_input)')
        assert "CWE-78" in [x["cwe_id"] for x in h]

    def test_xss(self):
        s = CodeBERTScanner()
        h = s.scan_code_snippet('document.write(user_input)')
        assert "CWE-79" in [x["cwe_id"] for x in h]

    def test_ssrf(self):
        s = CodeBERTScanner()
        h = s.scan_code_snippet('requests.get(user_supplied_url)')
        assert "CWE-918" in [x["cwe_id"] for x in h]

    def test_clean_code(self):
        s = CodeBERTScanner()
        h = s.scan_code_snippet('x = 1 + 2')
        assert len(h) == 0 or all(x["model"] == "heuristic" for x in h)

class TestSecRoBERTa:
    def test_heuristic_critical(self):
        r = SecRoBERTaClassifier._heuristic_severity("Remote code execution vulnerability")
        assert r["severity"] == "Critical"

    def test_heuristic_high(self):
        r = SecRoBERTaClassifier._heuristic_severity("SQL injection vulnerability found")
        assert r["severity"] == "High"

    def test_heuristic_medium(self):
        r = SecRoBERTaClassifier._heuristic_severity("Denial of service attack possible")
        assert r["severity"] == "Medium"

    def test_heuristic_phishing(self):
        r = SecRoBERTaClassifier._heuristic_phishing("Click here to verify your account. Urgent!")
        assert r["classification"] == "phishing"

    def test_heuristic_benign(self):
        r = SecRoBERTaClassifier._heuristic_phishing("Welcome to our website. Browse our catalog.")
        assert r["classification"] == "benign"
