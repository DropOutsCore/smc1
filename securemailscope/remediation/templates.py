"""
securemailscope/remediation/templates.py
------------------------------------------
Deterministic, auditable remediation config-snippet templates.

Templates are keyed by (finding_category, detected_server_software).
Server software is inferred from the SMTP/IMAP banner when available.
All guidance is template-driven — no freeform AI generation, so every
recommendation can be reviewed and audited.

To add a new template: edit the TEMPLATES dict or add a separate YAML
file and call load_templates() with its path.
"""

from __future__ import annotations

import re
from typing import Optional

# ---------------------------------------------------------------------------
# Template registry
# Key: (category, server_hint) — server_hint is lowercase partial match
# Special key ("*", "*") is the fallback for any category/server
# ---------------------------------------------------------------------------
TEMPLATES: dict[tuple[str, str], str] = {

    # ── Deprecated TLS ──────────────────────────────────────────────────

    ("deprecated-protocol", "postfix"): """\
# Postfix: Disable deprecated TLS versions
# Add to /etc/postfix/main.cf:
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
# Reload: postfix reload""",

    ("deprecated-protocol", "dovecot"): """\
# Dovecot: Disable deprecated TLS versions
# Add to /etc/dovecot/conf.d/10-ssl.conf:
ssl_min_protocol = TLSv1.2
# Reload: doveadm reload""",

    ("deprecated-protocol", "exim"): """\
# Exim: Disable TLS 1.0/1.1
# Add to /etc/exim4/exim4.conf.template or exim4.conf:
tls_require_ciphers = ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:!SSLv3:!TLSv1:!TLSv1.1
openssl_options = +no_sslv2 +no_sslv3 +no_tlsv1 +no_tlsv1_1
# Reload: service exim4 restart""",

    ("deprecated-protocol", "*"): """\
# Generic: Disable deprecated TLS versions
# Ensure only TLS 1.2 and TLS 1.3 are enabled.
# Consult your MTA/IMAP server documentation for the specific config key.
# References: IETF RFC 8996, NIST SP 800-52 Rev.2""",

    # ── Weak ciphers ────────────────────────────────────────────────────

    ("weak-cipher", "postfix"): """\
# Postfix: Configure strong cipher order (TLS 1.2+)
# Add to /etc/postfix/main.cf:
smtpd_tls_ciphers = high
smtpd_tls_exclude_ciphers = aNULL, eNULL, EXPORT, DES, RC4, MD5, PSK, aECDH, EDH-DSS-DES-CBC3-SHA, EDH-RSA-DES-CBC3-SHA, KRB5-DES-CBC3-SHA
smtp_tls_ciphers = high
smtp_tls_exclude_ciphers = aNULL, eNULL, EXPORT, DES, RC4, MD5, PSK
# Reload: postfix reload""",

    ("weak-cipher", "dovecot"): """\
# Dovecot: Remove weak ciphers
# Add to /etc/dovecot/conf.d/10-ssl.conf:
ssl_cipher_list = ECDHE+AESGCM:DHE+AESGCM:ECDHE+AES256:DHE+AES256:!aNULL:!eNULL:!LOW:!RC4:!MD5:!EXP:!3DES
# Reload: doveadm reload""",

    ("weak-cipher", "exim"): """\
# Exim: Enforce strong cipher suites
# Add to exim4 configuration:
tls_require_ciphers = ECDHE+AESGCM:DHE+AESGCM:ECDHE+AES:DHE+AES:!aNULL:!eNULL:!RC4:!DES:!MD5
# Reload: service exim4 restart""",

    ("weak-cipher", "*"): """\
# Generic: Remove weak cipher suites
# Disable: RC4, NULL, EXPORT, 3DES, MD5-based suites.
# Enable: AES-GCM, ChaCha20-Poly1305 with ECDHE/DHE key exchange.
# Reference: NIST SP 800-52 Rev.2, Mozilla SSL Configuration Generator""",

    # ── No PFS ──────────────────────────────────────────────────────────

    ("no-forward-secrecy", "postfix"): """\
# Postfix: Enable PFS-only cipher order
# Add to /etc/postfix/main.cf:
smtpd_tls_ciphers = high
smtpd_tls_mandatory_ciphers = high
# Use ECDHE/DHE ciphers only:
smtpd_tls_eecdh_grade = ultra
smtp_tls_mandatory_ciphers = high
# Reload: postfix reload""",

    ("no-forward-secrecy", "dovecot"): """\
# Dovecot: Enable PFS cipher suites
# Ensure ECDHE/DHE suites are prioritised in ssl_cipher_list:
ssl_cipher_list = ECDHE+AESGCM:DHE+AESGCM:ECDHE+AES:DHE+AES:!RSA:!aNULL
# Reload: doveadm reload""",

    ("no-forward-secrecy", "*"): """\
# Generic: Enable Perfect Forward Secrecy
# Configure your server to prefer ECDHE or DHE key exchange.
# Disable static RSA key exchange.
# Reference: NIST SP 800-52 Rev.2 §3.3.1""",

    # ── Certificate validity ─────────────────────────────────────────────

    ("certificate-validity", "*"): """\
# Renew the server certificate immediately.
# Steps:
#   1. Generate a new CSR: openssl req -new -key server.key -out server.csr
#   2. Submit to your CA or use Let's Encrypt: certbot renew
#   3. Install the new certificate and restart your mail server.
# For Let's Encrypt / Certbot: certbot certonly --standalone -d mail.yourdomain.com""",

    # ── Weak key ────────────────────────────────────────────────────────

    ("weak-key", "*"): """\
# Replace the certificate with one using a stronger key:
#   RSA: minimum 2048 bits (4096 recommended)
#   ECC: minimum P-256 (NIST P-384 recommended)
# Generate RSA 4096 key:
#   openssl genrsa -out server.key 4096
# Generate EC P-384 key:
#   openssl ecparam -name secp384r1 -genkey -noout -out server.key
# Reference: NIST SP 800-57 Part 1 Rev.5""",

    # ── Weak signature algorithm ─────────────────────────────────────────

    ("weak-signature", "*"): """\
# Replace the certificate — MD5 and SHA-1 signatures are no longer accepted
# by modern clients and are considered cryptographically broken.
# Request a new certificate signed with SHA-256 or stronger.
# Reference: CA/Browser Forum Baseline Requirements §7.1.3""",

    # ── Certificate trust ────────────────────────────────────────────────

    ("certificate-trust", "*"): """\
# Replace the self-signed certificate with one from a trusted CA.
# Recommended: Use Let's Encrypt for free, automated certificates:
#   certbot certonly --standalone -d mail.yourdomain.com
# Or purchase from a commercial CA aligned with your compliance requirements.""",

    # ── STARTTLS downgrade ───────────────────────────────────────────────

    ("starttls-downgrade", "*"): """\
# STARTTLS stripping/downgrade was detected.
# Mitigations:
#   1. Postfix: Set smtp_tls_security_level = encrypt and
#      smtpd_tls_security_level = encrypt to reject plaintext.
#   2. Deploy MTA-STS (RFC 8461) to publish a policy that requires TLS.
#   3. Publish SMTP TLS Reporting (TLSRPT) records (RFC 8460) to receive
#      downgrade alerts.
#   4. Consider DANE (RFC 7671) for DNSSEC-authenticated TLS enforcement.
# References: RFC 8461 (MTA-STS), RFC 3207 (STARTTLS), BASTA! research""",

    # ── No STARTTLS ──────────────────────────────────────────────────────

    ("starttls-missing", "postfix"): """\
# Postfix: Enable STARTTLS
# Add to /etc/postfix/main.cf:
smtpd_use_tls = yes
smtpd_tls_cert_file = /etc/ssl/certs/mail.crt
smtpd_tls_key_file = /etc/ssl/private/mail.key
smtpd_tls_security_level = may     # use 'encrypt' to mandate TLS
smtp_tls_security_level = may
# Reload: postfix reload""",

    ("starttls-missing", "dovecot"): """\
# Dovecot: Enable STARTTLS
# Add to /etc/dovecot/conf.d/10-ssl.conf:
ssl = required
ssl_cert = </etc/ssl/certs/dovecot.pem
ssl_key = </etc/ssl/private/dovecot.pem
# Reload: doveadm reload""",

    ("starttls-missing", "*"): """\
# Enable STARTTLS or implicit TLS on your mail server.
# Minimum: configure smtpd_use_tls=yes / ssl=required with a valid cert.
# Reference: RFC 3207 (STARTTLS), RFC 8314 (implicit TLS for submission)""",
}


def _detect_server_software(banner: str) -> str:
    """
    Guess server software from the banner string.

    Returns a lowercase hint: 'postfix', 'dovecot', 'exim', or '*'.
    """
    if not banner:
        return "*"
    banner_lower = banner.lower()
    if "postfix" in banner_lower:
        return "postfix"
    if "dovecot" in banner_lower:
        return "dovecot"
    if "exim" in banner_lower:
        return "exim"
    if "sendmail" in banner_lower:
        return "sendmail"
    return "*"


def get_remediation(category: str, banner: str = "") -> str:
    """
    Look up the deterministic remediation snippet for a finding.

    Parameters
    ----------
    category : str
        The finding category (matches rule YAML 'category' field).
    banner : str
        Server banner string to detect software.

    Returns
    -------
    str
        The remediation config snippet.
    """
    server = _detect_server_software(banner)
    # Try exact match first, then wildcard server, then fallback
    for key in [(category, server), (category, "*"), ("*", "*")]:
        template = TEMPLATES.get(key)
        if template:
            return template.strip()
    return "No remediation template available for this finding type."
