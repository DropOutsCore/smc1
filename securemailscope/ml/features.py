"""
securemailscope/ml/features.py
--------------------------------
Feature engineering for ML risk classification and anomaly detection.

Feature vector (22 features):
 [0]  protocol_smtp         (0/1)
 [1]  protocol_imap         (0/1)
 [2]  protocol_pop3         (0/1)
 [3]  tls_version_score     (SSLv3=0, TLS1.0=1, TLS1.1=2, TLS1.2=3, TLS1.3=4, unknown=-1)
 [4]  cipher_strength_score (insecure=0, weak=1, acceptable=2, strong=3, unknown=-1)
 [5]  pfs_enabled           (0/1)
 [6]  key_length_norm       (key_length / 4096, clipped to [0,1])
 [7]  rsa_key               (0/1)
 [8]  ecc_key               (0/1)
 [9]  sig_algo_weak         (0/1)
[10]  cert_expired          (0/1)
[11]  cert_expiring_soon    (0/1)
[12]  cert_not_yet_valid    (0/1)
[13]  days_until_expiry_norm  (days/365, clipped [-1,1]; negative=expired)
[14]  self_signed           (0/1)
[15]  hostname_mismatch     (0/1)
[16]  starttls_detected     (0/1)
[17]  downgrade_suspected   (0/1)
[18]  implicit_tls          (0/1)
[19]  has_tls               (0/1 — any TLS at all observed)
[20]  has_certificate       (0/1)
[21]  chain_valid           (0/1)

These 22 features must remain stable across model versions to allow
joblib-saved models to be reloaded without retraining.
"""

from __future__ import annotations

from typing import Optional

import numpy as np

from securemailscope.certs.extractor import CertificateInfo, ChainValidationResult
from securemailscope.ingestion.models import EmailSession
from securemailscope.tls_analysis.handshake_parser import TLSHandshakeInfo

_TLS_VERSION_SCORES = {
    "SSLv3": 0,
    "TLS1.0": 1,
    "TLS1.1": 2,
    "TLS1.2": 3,
    "TLS1.3": 4,
}

_CIPHER_STRENGTH_SCORES = {
    "insecure": 0,
    "weak": 1,
    "acceptable": 2,
    "strong": 3,
}

FEATURE_NAMES = [
    "protocol_smtp", "protocol_imap", "protocol_pop3",
    "tls_version_score", "cipher_strength_score", "pfs_enabled",
    "key_length_norm", "rsa_key", "ecc_key", "sig_algo_weak",
    "cert_expired", "cert_expiring_soon", "cert_not_yet_valid",
    "days_until_expiry_norm", "self_signed", "hostname_mismatch",
    "starttls_detected", "downgrade_suspected", "implicit_tls",
    "has_tls", "has_certificate", "chain_valid",
]

NUM_FEATURES = len(FEATURE_NAMES)


def build_feature_vector(
    session: EmailSession,
    tls: Optional[TLSHandshakeInfo],
    chain: Optional[ChainValidationResult],
) -> np.ndarray:
    """
    Convert session + TLS + cert analysis into a fixed-length feature vector.

    All values are numeric and scaled/clipped to a stable range so that
    saved models can be reloaded without preprocessing drift.
    """
    proto = session.protocol.upper()
    feat: list[float] = [
        1.0 if proto == "SMTP" else 0.0,                 # [0]
        1.0 if proto == "IMAP" else 0.0,                 # [1]
        1.0 if proto == "POP3" else 0.0,                 # [2]
    ]

    if tls:
        feat.append(float(_TLS_VERSION_SCORES.get(tls.tls_version, -1)))   # [3]
        feat.append(float(_CIPHER_STRENGTH_SCORES.get(tls.cipher_strength, -1)))  # [4]
        feat.append(1.0 if tls.pfs else 0.0)             # [5]
    else:
        feat += [-1.0, -1.0, 0.0]

    leaf: Optional[CertificateInfo] = None
    if chain and chain.certificates:
        leaf = chain.certificates[0]

    if leaf:
        key_norm = np.clip(leaf.key_length / 4096.0, 0.0, 1.0)
        feat.append(float(key_norm))                      # [6]
        feat.append(1.0 if leaf.key_algorithm == "RSA" else 0.0)  # [7]
        feat.append(1.0 if "EC" in leaf.key_algorithm else 0.0)   # [8]
        feat.append(1.0 if leaf.signature_algorithm_weak else 0.0)  # [9]
        feat.append(1.0 if leaf.is_expired else 0.0)      # [10]
        feat.append(1.0 if leaf.expiring_within_30_days else 0.0)  # [11]
        feat.append(1.0 if leaf.is_not_yet_valid else 0.0)  # [12]
        days = leaf.days_until_expiry if leaf.days_until_expiry is not None else 0
        days_norm = float(np.clip(days / 365.0, -1.0, 1.0))
        feat.append(days_norm)                            # [13]
        feat.append(1.0 if leaf.is_self_signed else 0.0)  # [14]
        feat.append(1.0 if leaf.hostname_match is False else 0.0)  # [15]
    else:
        feat += [0.0] * 10

    feat.append(1.0 if session.starttls_detected else 0.0)    # [16]
    feat.append(1.0 if session.downgrade_suspected else 0.0)  # [17]
    feat.append(1.0 if session.is_implicit_tls else 0.0)      # [18]
    feat.append(1.0 if tls is not None else 0.0)              # [19]
    feat.append(1.0 if leaf is not None else 0.0)             # [20]
    chain_valid = 1.0 if (chain and chain.valid) else 0.0
    feat.append(chain_valid)                                   # [21]

    assert len(feat) == NUM_FEATURES, f"Feature count mismatch: {len(feat)} != {NUM_FEATURES}"
    return np.array(feat, dtype=np.float32)
