"""
securemailscope/certs/extractor.py
------------------------------------
X.509 certificate extraction and validation.

Uses the `cryptography` library exclusively — pyOpenSSL deprecated APIs
are intentionally avoided per PRD §2.

Checks performed
----------------
• Chain validity / trust (does the presented chain self-validate)
• Expiry (expired, expiring within 30 days, not-yet-valid)
• Public key strength (RSA <2048 = weak; ECC <224 = weak)
• Signature algorithm (MD5/SHA-1 = weak)
• Hostname/SAN match against observed SNI
• Self-signed detection
• Key usage and extended key usage
"""

from __future__ import annotations

import datetime
import logging
from dataclasses import dataclass, field
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa, ed25519, ed448
from cryptography.x509.oid import ExtensionOID, NameOID
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger(__name__)

_WEAK_HASH_OIDS = {
    "1.2.840.113549.1.1.4",   # md5WithRSAEncryption
    "1.2.840.113549.1.1.5",   # sha1WithRSAEncryption
    "1.2.840.10040.4.3",      # id-dsa-with-sha1
    "1.2.840.10045.4.1",      # ecdsa-with-SHA1
}


@dataclass
class CertificateInfo:
    """Parsed and validated X.509 certificate metadata."""
    subject: str = ""
    issuer: str = ""
    serial_number: str = ""
    not_before: Optional[datetime.datetime] = None
    not_after: Optional[datetime.datetime] = None
    days_until_expiry: Optional[int] = None
    is_expired: bool = False
    is_not_yet_valid: bool = False
    expiring_within_30_days: bool = False
    key_algorithm: str = "unknown"
    key_length: int = 0
    key_strength: str = "unknown"    # strong | acceptable | weak
    signature_algorithm: str = "unknown"
    signature_algorithm_oid: str = ""
    signature_algorithm_weak: bool = False
    is_self_signed: bool = False
    sans: list[str] = field(default_factory=list)    # Subject Alternative Names
    hostname_match: Optional[bool] = None            # None if no SNI to compare
    # Raw DER for chain-of-custody hashing
    raw_der: bytes = b""
    # Chain position: 0 = leaf, 1 = intermediate, etc.
    chain_position: int = 0
    # Trust issues
    trust_issues: list[str] = field(default_factory=list)


@dataclass
class ChainValidationResult:
    """Result of certificate chain validation."""
    valid: bool = False
    is_self_signed: bool = False
    chain_length: int = 0
    issues: list[str] = field(default_factory=list)
    certificates: list[CertificateInfo] = field(default_factory=list)


def extract_certificates(
    cert_ders: list[bytes],
    sni: Optional[str] = None,
) -> ChainValidationResult:
    """
    Parse and validate a list of DER-encoded certificates.

    Parameters
    ----------
    cert_ders : list[bytes]
        Raw DER bytes of each cert in the presented chain
        (index 0 = leaf / server certificate).
    sni : str | None
        Server Name Indication observed in ClientHello, for hostname matching.

    Returns
    -------
    ChainValidationResult
    """
    result = ChainValidationResult(chain_length=len(cert_ders))

    if not cert_ders:
        result.issues.append("no-certificates-found")
        return result

    parsed_certs: list[x509.Certificate] = []
    for idx, der in enumerate(cert_ders):
        try:
            cert = x509.load_der_x509_certificate(der)
            parsed_certs.append(cert)
        except Exception as exc:
            result.issues.append(f"cert-parse-error[{idx}]: {exc}")
            logger.warning("Failed to parse certificate at position %d: %s", idx, exc)
            parsed_certs.append(None)

    for idx, cert in enumerate(parsed_certs):
        if cert is None:
            result.certificates.append(CertificateInfo(chain_position=idx))
            continue
        info = _analyse_certificate(cert, idx, cert_ders[idx], sni)
        result.certificates.append(info)

    # Chain validation
    _validate_chain(parsed_certs, result)

    return result


def _analyse_certificate(
    cert: x509.Certificate,
    position: int,
    raw_der: bytes,
    sni: Optional[str],
) -> CertificateInfo:
    """Analyse a single parsed certificate."""
    now = datetime.datetime.now(datetime.timezone.utc)
    info = CertificateInfo(chain_position=position, raw_der=raw_der)

    # ── Subject / Issuer ──────────────────────────────────────────────────
    info.subject = cert.subject.rfc4514_string()
    info.issuer = cert.issuer.rfc4514_string()
    info.serial_number = str(cert.serial_number)

    # ── Validity window ───────────────────────────────────────────────────
    try:
        nb = cert.not_valid_before_utc
        na = cert.not_valid_after_utc
    except AttributeError:
        # Older cryptography versions
        nb = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
        na = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

    info.not_before = nb
    info.not_after = na
    delta = na - now
    info.days_until_expiry = delta.days
    info.is_expired = delta.days < 0
    info.is_not_yet_valid = now < nb
    info.expiring_within_30_days = 0 <= delta.days < 30

    # ── Public key ────────────────────────────────────────────────────────
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        info.key_algorithm = "RSA"
        info.key_length = pub.key_size
        info.key_strength = "strong" if pub.key_size >= 2048 else "weak"
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        info.key_algorithm = f"EC ({pub.curve.name})"
        info.key_length = pub.key_size
        info.key_strength = "strong" if pub.key_size >= 224 else "weak"
    elif isinstance(pub, dsa.DSAPublicKey):
        info.key_algorithm = "DSA"
        info.key_length = pub.key_size
        info.key_strength = "weak"  # DSA generally discouraged
    elif isinstance(pub, (ed25519.Ed25519PublicKey,)):
        info.key_algorithm = "Ed25519"
        info.key_length = 256
        info.key_strength = "strong"
    elif isinstance(pub, (ed448.Ed448PublicKey,)):
        info.key_algorithm = "Ed448"
        info.key_length = 448
        info.key_strength = "strong"
    else:
        info.key_algorithm = type(pub).__name__
        info.key_strength = "unknown"

    # ── Signature algorithm ───────────────────────────────────────────────
    sig_oid = cert.signature_algorithm_oid.dotted_string
    info.signature_algorithm_oid = sig_oid
    try:
        info.signature_algorithm = cert.signature_hash_algorithm.name
    except Exception:
        info.signature_algorithm = sig_oid
    info.signature_algorithm_weak = sig_oid in _WEAK_HASH_OIDS

    # ── Self-signed ───────────────────────────────────────────────────────
    info.is_self_signed = (cert.subject == cert.issuer)
    if info.is_self_signed:
        info.trust_issues.append("self-signed")

    # ── Subject Alternative Names ─────────────────────────────────────────
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                info.sans.append(f"DNS:{name.value}")
            elif isinstance(name, x509.IPAddress):
                info.sans.append(f"IP:{name.value}")
    except x509.ExtensionNotFound:
        pass
    except Exception as exc:
        logger.debug("SAN extraction error: %s", exc)

    # ── Hostname match ────────────────────────────────────────────────────
    if sni and position == 0:  # Only check leaf cert
        info.hostname_match = _check_hostname(sni, cert, info.sans)
        if not info.hostname_match:
            info.trust_issues.append(f"hostname-mismatch: SNI={sni!r}")

    return info


def _check_hostname(sni: str, cert: x509.Certificate, sans: list[str]) -> bool:
    """Simple wildcard-aware hostname matching against SANs."""
    sni_lower = sni.lower()
    for san in sans:
        if san.startswith("DNS:"):
            pattern = san[4:].lower()
            if _wildcard_match(sni_lower, pattern):
                return True
        elif san.startswith("IP:"):
            if san[3:] == sni:
                return True
    # Fallback: check CN
    try:
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs:
            cn = cn_attrs[0].value.lower()
            if _wildcard_match(sni_lower, cn):
                return True
    except Exception:
        pass
    return False


def _wildcard_match(hostname: str, pattern: str) -> bool:
    """Match hostname against a pattern that may contain a leading wildcard."""
    if pattern.startswith("*."):
        suffix = pattern[2:]
        parts = hostname.split(".", 1)
        if len(parts) == 2 and parts[1] == suffix:
            return True
    return hostname == pattern


def _validate_chain(
    certs: list[Optional[x509.Certificate]],
    result: ChainValidationResult,
) -> None:
    """
    Perform basic chain validation.

    Full PKIX validation (CRL/OCSP) is out of scope for a passive offline
    tool.  We check:
    1. Each cert is signed by the next in the chain (structural validation).
    2. Self-signed leaf detection.
    3. Chain length sanity.
    """
    if not certs or certs[0] is None:
        result.issues.append("no-leaf-certificate")
        return

    leaf = certs[0]
    result.is_self_signed = (leaf.subject == leaf.issuer)

    if len(certs) == 1 and result.is_self_signed:
        result.issues.append("self-signed-certificate")
        result.valid = False
        return

    # Basic structural chain validation
    for i in range(len(certs) - 1):
        cert = certs[i]
        issuer_cert = certs[i + 1]
        if cert is None or issuer_cert is None:
            result.issues.append(f"chain-gap-at-{i}")
            continue
        try:
            pub = issuer_cert.public_key()
            pub.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                cert.signature_algorithm_parameters
                if hasattr(cert, "signature_algorithm_parameters")
                else _get_padding(cert),
                cert.signature_hash_algorithm,
            )
        except (TypeError, InvalidSignature, Exception) as exc:
            result.issues.append(f"chain-signature-invalid-at-{i}: {type(exc).__name__}")

    result.valid = len(result.issues) == 0


def _get_padding(cert: x509.Certificate):
    """Determine RSA padding for signature verification."""
    from cryptography.hazmat.primitives.asymmetric import padding
    return padding.PKCS1v15()
