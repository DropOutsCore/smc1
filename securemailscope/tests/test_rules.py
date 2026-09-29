"""
Tests for the rule engine.
"""

from __future__ import annotations

import pytest
from securemailscope.rules.engine import RuleEngine


def test_deprecated_tls10_fires(mock_session, mock_tls_info):
    """deprecated-tls-10 rule fires for TLS 1.0."""
    engine = RuleEngine()
    findings = engine.evaluate(mock_session, mock_tls_info, None)
    rule_ids = [f.id for f in findings]
    assert "deprecated-tls-10" in rule_ids


def test_no_pfs_fires(mock_session, mock_tls_info):
    """no-pfs rule fires when PFS is False."""
    engine = RuleEngine()
    findings = engine.evaluate(mock_session, mock_tls_info, None)
    rule_ids = [f.id for f in findings]
    assert "no-pfs" in rule_ids


def test_weak_cipher_fires(mock_session, mock_tls_info):
    """weak-cipher rule fires for TLS_RSA_WITH_AES_128_CBC_SHA (weak)."""
    engine = RuleEngine()
    findings = engine.evaluate(mock_session, mock_tls_info, None)
    rule_ids = [f.id for f in findings]
    assert "weak-cipher" in rule_ids


def test_cert_expired_fires(mock_session, mock_tls_info, mock_cert_info_expired):
    """cert-expired rule fires for expired certificate."""
    from securemailscope.certs.extractor import ChainValidationResult
    chain = ChainValidationResult(
        valid=False, is_self_signed=True, chain_length=1,
        certificates=[mock_cert_info_expired],
    )
    engine = RuleEngine()
    findings = engine.evaluate(mock_session, mock_tls_info, chain)
    rule_ids = [f.id for f in findings]
    assert "cert-expired" in rule_ids


def test_self_signed_fires(mock_session, mock_tls_info, mock_cert_info_expired):
    """self-signed-cert rule fires for self-signed cert."""
    from securemailscope.certs.extractor import ChainValidationResult
    chain = ChainValidationResult(
        valid=False, is_self_signed=True, chain_length=1,
        certificates=[mock_cert_info_expired],
    )
    engine = RuleEngine()
    findings = engine.evaluate(mock_session, mock_tls_info, chain)
    rule_ids = [f.id for f in findings]
    assert "self-signed-cert" in rule_ids


def test_weak_key_fires(mock_session, mock_tls_info, mock_cert_info_expired):
    """weak-key-rsa rule fires for RSA 1024 bit key."""
    from securemailscope.certs.extractor import ChainValidationResult
    chain = ChainValidationResult(
        valid=False, certificates=[mock_cert_info_expired],
    )
    engine = RuleEngine()
    findings = engine.evaluate(mock_session, mock_tls_info, chain)
    rule_ids = [f.id for f in findings]
    assert "weak-key-rsa" in rule_ids


def test_downgrade_fires(mock_tcp_stream):
    """starttls-downgrade rule fires when downgrade_suspected=True."""
    from securemailscope.ingestion.models import EmailSession
    import uuid
    session = EmailSession(
        session_id=str(uuid.uuid4()),
        protocol="SMTP",
        src_ip="1.2.3.4", dst_ip="5.6.7.8",
        src_port=12345, dst_port=25,
        stream=mock_tcp_stream,
        starttls_detected=True,
        downgrade_suspected=True,
        downgrade_evidence_packet=1,
        packet_refs=[1],
    )
    engine = RuleEngine()
    findings = engine.evaluate(session, None, None)
    rule_ids = [f.id for f in findings]
    assert "starttls-downgrade" in rule_ids


def test_no_starttls_fires():
    """no-starttls rule fires when starttls_detected=False and not implicit TLS."""
    from securemailscope.ingestion.models import EmailSession, TCPStream, RawSegment
    import uuid
    segs = [RawSegment(1, 0, b"220 plain server\r\n", 1700000000.0, "1.2.3.4", "5.6.7.8", 12345, 25)]
    stream = TCPStream(
        "1.2.3.4:12345-5.6.7.8:25", "1.2.3.4", "5.6.7.8", 12345, 25,
        client_data=b"", server_data=b"220 plain\r\n", combined_data=b"220 plain\r\n",
        segments=segs, first_packet=1, last_packet=1,
    )
    session = EmailSession(
        session_id=str(uuid.uuid4()),
        protocol="SMTP",
        src_ip="1.2.3.4", dst_ip="5.6.7.8",
        src_port=12345, dst_port=25,
        stream=stream,
        starttls_detected=False,
        is_implicit_tls=False,
        packet_refs=[1],
    )
    engine = RuleEngine()
    findings = engine.evaluate(session, None, None)
    rule_ids = [f.id for f in findings]
    assert "no-starttls" in rule_ids


def test_clean_session_no_critical(mock_session):
    """A clean TLS 1.3 + ECDHE session produces no critical findings."""
    from securemailscope.tls_analysis.handshake_parser import TLSHandshakeInfo
    from securemailscope.certs.extractor import CertificateInfo, ChainValidationResult
    import datetime

    tls = TLSHandshakeInfo(
        tls_version="TLS1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        cipher_strength="strong",
        key_exchange="ECDHE (TLS 1.3)",
        pfs=True,
        sni="mail.example.com",
    )
    cert = CertificateInfo(
        subject="CN=mail.example.com",
        issuer="CN=TrustCA",
        key_algorithm="RSA",
        key_length=4096,
        key_strength="strong",
        signature_algorithm="sha256",
        signature_algorithm_weak=False,
        not_after=datetime.datetime.now(datetime.timezone.utc).replace(year=2030),
        is_expired=False,
        days_until_expiry=1200,
        is_self_signed=False,
        hostname_match=True,
    )
    chain = ChainValidationResult(valid=True, certificates=[cert])
    engine = RuleEngine()
    findings = engine.evaluate(mock_session, tls, chain)
    critical = [f for f in findings if f.severity == "critical"]
    assert critical == []


def test_all_findings_have_evidence_ref(mock_session, mock_tls_info, mock_cert_info_expired):
    """Every finding must have a resolvable evidence_ref with a packet_number."""
    from securemailscope.certs.extractor import ChainValidationResult
    chain = ChainValidationResult(
        valid=False, certificates=[mock_cert_info_expired],
    )
    engine = RuleEngine()
    findings = engine.evaluate(mock_session, mock_tls_info, chain)
    for f in findings:
        assert "packet_number" in f.evidence_ref, f"Finding {f.id} missing packet_number in evidence_ref"
        assert isinstance(f.evidence_ref["packet_number"], int)
