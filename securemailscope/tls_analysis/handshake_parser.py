"""
securemailscope/tls_analysis/handshake_parser.py
--------------------------------------------------
TLS handshake parser — extracts version, cipher suite, key exchange,
PFS status, SNI, ALPN, and anomaly flags from raw TLS record bytes.

VISIBILITY LIMITS (documented per PRD §4.2):
  TLS 1.3 encrypts most handshake fields after the ServerHello.  This
  parser can reliably extract:
    • ClientHello: all fields (unencrypted)
    • ServerHello: version, cipher suite, session ID (unencrypted)
    • Certificate: full chain (sent before encryption in TLS 1.2;
                               inside EncryptedExtensions in TLS 1.3 —
                               often still visible in practice but not
                               guaranteed)
  Fields NOT reliably visible in TLS 1.3 passive captures:
    • CertificateVerify, Finished, NewSessionTicket
  These limitations are included in every report's metadata.

References: RFC 8446 (TLS 1.3), RFC 5246 (TLS 1.2), RFC 6066 (SNI/ALPN)
"""

from __future__ import annotations

import logging
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Load cipher table
# ---------------------------------------------------------------------------
_CIPHER_TABLE_PATH = Path(__file__).parent / "cipher_table.yaml"
_cipher_db: dict = {}


def _load_cipher_db() -> dict:
    global _cipher_db
    if not _cipher_db:
        try:
            with open(_CIPHER_TABLE_PATH, "r") as fh:
                raw = yaml.safe_load(fh)
            _cipher_db = raw.get("ciphers", {})
        except Exception as exc:
            logger.error("Failed to load cipher_table.yaml: %s", exc)
            _cipher_db = {}
    return _cipher_db


# ---------------------------------------------------------------------------
# TLS constants
# ---------------------------------------------------------------------------
_TLS_VERSION_MAP = {
    0x0300: "SSLv3",
    0x0301: "TLS1.0",
    0x0302: "TLS1.1",
    0x0303: "TLS1.2",
    0x0304: "TLS1.3",
}

_HANDSHAKE_TYPES = {
    0x01: "ClientHello",
    0x02: "ServerHello",
    0x0B: "Certificate",
    0x0C: "ServerKeyExchange",
    0x0D: "CertificateRequest",
    0x0E: "ServerHelloDone",
    0x0F: "CertificateVerify",
    0x10: "ClientKeyExchange",
    0x14: "Finished",
}

_TLS_RECORD_TYPE_HANDSHAKE = 0x16
_TLS_RECORD_TYPE_CHANGE_CIPHER = 0x14
_TLS_RECORD_TYPE_ALERT = 0x15
_TLS_RECORD_TYPE_APP_DATA = 0x17

# Extension types
_EXT_SNI = 0x0000
_EXT_ALPN = 0x0010
_EXT_SUPPORTED_VERSIONS = 0x002b
_EXT_KEY_SHARE = 0x0033
_EXT_SUPPORTED_GROUPS = 0x000a
_EXT_SESSION_TICKET = 0x0023
_EXT_RENEGOTIATION = 0xFF01

# Cipher suites that imply PFS
_NAMED_CURVES = {
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x001D: "x25519",
    0x001E: "x448",
}

# Regex to scan for TLS record starts (0x16 Handshake)
_TLS_RECORD_SCAN = re.compile(rb"\x16\x03[\x00-\x04]", re.DOTALL)
_TLS_CLIENT_HELLO_SCAN = re.compile(rb"\x16\x03[\x00-\x04].{2}\x01", re.DOTALL)
_TLS_SERVER_HELLO_SCAN = re.compile(rb"\x16\x03[\x00-\x04].{2}\x02", re.DOTALL)


@dataclass
class TLSHandshakeInfo:
    """Parsed information from a TLS handshake."""
    tls_version: str = "unknown"              # negotiated version
    offered_versions: list[str] = field(default_factory=list)
    cipher_suite: str = "unknown"
    cipher_strength: str = "unknown"          # strong|acceptable|weak|insecure|unknown
    key_exchange: str = "unknown"
    pfs: bool = False
    sni: Optional[str] = None
    alpn: list[str] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)
    # Certificate raw DER bytes (extracted from Certificate message)
    certificate_chain_der: list[bytes] = field(default_factory=list)
    # Forensic reference
    handshake_start_packet: int = 0
    # TLS 1.3 visibility note
    tls13_visibility_limited: bool = False
    # Explicit tracking for unobserved passive telemetry
    not_observable: list[str] = field(default_factory=list)

    TLS13_VISIBILITY_NOTE = (
        "TLS 1.3 encrypts most handshake fields after ServerHello. "
        "Certificate and key-exchange details may not be visible in this capture."
    )


def _parse_records_from_stream(
    data: bytes,
    messages: list,
    info: TLSHandshakeInfo,
    start_offset: int = 0,
) -> None:
    """Scan and parse consecutive TLS records from a byte buffer."""
    if not data or len(data) < 5:
        return

    pos = max(0, start_offset)
    if pos >= len(data):
        return

    # If pos does not point to a TLS record, scan forward for one
    if data[pos] not in (_TLS_RECORD_TYPE_HANDSHAKE,
                         _TLS_RECORD_TYPE_CHANGE_CIPHER,
                         _TLS_RECORD_TYPE_APP_DATA,
                         _TLS_RECORD_TYPE_ALERT):
        m = _TLS_RECORD_SCAN.search(data, pos)
        if m:
            pos = m.start()
        else:
            return

    while pos + 5 <= len(data):
        rec_type = data[pos]
        if rec_type not in (_TLS_RECORD_TYPE_HANDSHAKE,
                             _TLS_RECORD_TYPE_CHANGE_CIPHER,
                             _TLS_RECORD_TYPE_APP_DATA,
                             _TLS_RECORD_TYPE_ALERT):
            # Attempt to resync to the next record
            m = _TLS_RECORD_SCAN.search(data, pos + 1)
            if m:
                pos = m.start()
                continue
            break

        rec_len = struct.unpack("!H", data[pos + 3: pos + 5])[0]
        payload = data[pos + 5: pos + 5 + rec_len]

        if len(payload) < rec_len:
            if rec_type == _TLS_RECORD_TYPE_HANDSHAKE and len(payload) >= 4:
                _parse_handshake_record(payload, messages, info)
            info.anomalies.append(f"truncated-record: expected {rec_len} got {len(payload)}")
            break

        if rec_type == _TLS_RECORD_TYPE_HANDSHAKE:
            _parse_handshake_record(payload, messages, info)
        elif rec_type == _TLS_RECORD_TYPE_CHANGE_CIPHER:
            pass
        elif rec_type == _TLS_RECORD_TYPE_APP_DATA:
            pass

        pos += 5 + rec_len


def parse_handshake(
    stream_data: bytes,
    start_offset: int = 0,
    handshake_start_packet: int = 0,
    client_data: Optional[bytes] = None,
    server_data: Optional[bytes] = None,
) -> TLSHandshakeInfo:
    """
    Parse a TLS handshake from raw bytes beginning at start_offset, or from
    reassembled unidirectional client_data and server_data streams.

    Parameters
    ----------
    stream_data : bytes
        The combined TCP stream payload.
    start_offset : int
        Byte offset where the TLS record layer begins in stream_data.
    handshake_start_packet : int
        Packet number for forensic reference.
    client_data : bytes, optional
        Reassembled client-to-server payload (contains ClientHello, SNI, ALPN).
    server_data : bytes, optional
        Reassembled server-to-client payload (contains ServerHello, Certs, KEX).

    Returns
    -------
    TLSHandshakeInfo
    """
    info = TLSHandshakeInfo(handshake_start_packet=handshake_start_packet)
    messages: list[tuple[str, bytes]] = []

    # 1. Parse client records (ClientHello -> SNI, offered versions, ALPN)
    if client_data:
        c_offset = 0
        cm = _TLS_CLIENT_HELLO_SCAN.search(client_data)
        if cm:
            c_offset = cm.start()
        _parse_records_from_stream(client_data, messages, info, start_offset=c_offset)

    # 2. Parse server records (ServerHello -> Version, Cipher; Certificate; ServerKeyExchange)
    if server_data:
        s_offset = 0
        sm = _TLS_SERVER_HELLO_SCAN.search(server_data)
        if sm:
            s_offset = sm.start()
        elif _TLS_RECORD_SCAN.search(server_data):
            s_offset = _TLS_RECORD_SCAN.search(server_data).start()
        _parse_records_from_stream(server_data, messages, info, start_offset=s_offset)

    # 3. If stream_data provided and (version/cipher still unknown or unidirectional data not provided),
    # parse combined stream_data as fallback:
    if stream_data and (info.tls_version == "unknown" or info.cipher_suite == "unknown" or not client_data):
        _parse_records_from_stream(stream_data, messages, info, start_offset=start_offset)

    # ── Derive key exchange and PFS from cipher suite & handshake ───────────
    _derive_kex_and_pfs(info)

    # ── TLS 1.3 visibility note ───────────────────────────────────────────
    if info.tls_version == "TLS1.3":
        info.tls13_visibility_limited = True
        if not info.certificate_chain_der:
            info.not_observable.append("certificate_chain (encrypted in TLS 1.3)")
            info.anomalies.append(
                "tls13-encrypted-handshake: " + TLSHandshakeInfo.TLS13_VISIBILITY_NOTE
            )

    # Mark unobserved telemetry explicitly
    if info.tls_version == "unknown":
        info.not_observable.append("tls_version (not observable: handshake incomplete)")
    if info.cipher_suite == "unknown":
        info.not_observable.append("cipher_suite (not observable: handshake incomplete)")
    if info.key_exchange == "unknown":
        info.not_observable.append("key_exchange (not observable: handshake incomplete)")

    return info


def _parse_handshake_record(payload: bytes, messages: list, info: TLSHandshakeInfo) -> None:
    """Parse one or more handshake messages from a TLS record payload."""
    pos = 0
    while pos + 4 <= len(payload):
        msg_type = payload[pos]
        msg_len = struct.unpack("!I", b"\x00" + payload[pos + 1: pos + 4])[0]
        msg_body = payload[pos + 4: pos + 4 + msg_len]

        if len(msg_body) < msg_len:
            info.anomalies.append("truncated-handshake-message")
            break

        name = _HANDSHAKE_TYPES.get(msg_type, f"unknown-{msg_type:#04x}")
        messages.append((name, msg_body))

        try:
            if msg_type == 0x01:
                _parse_client_hello(msg_body, info)
            elif msg_type == 0x02:
                _parse_server_hello(msg_body, info)
            elif msg_type == 0x0B:
                _parse_certificate(msg_body, info)
            elif msg_type == 0x0C:
                _parse_server_key_exchange(msg_body, info)
        except Exception as exc:
            info.anomalies.append(f"parse-error-{name}: {exc}")
            logger.debug("Error parsing %s: %s", name, exc)

        pos += 4 + msg_len


_EXT_KEY_SHARE = 0x0033


def _parse_client_hello(body: bytes, info: TLSHandshakeInfo) -> None:
    """Parse ClientHello — extract offered versions, SNI, ALPN."""
    if len(body) < 34:
        return
    pos = 0

    # Legacy version (2 bytes)
    legacy_ver = struct.unpack("!H", body[0:2])[0]
    legacy_str = _TLS_VERSION_MAP.get(legacy_ver, f"0x{legacy_ver:04x}")
    if legacy_str not in info.offered_versions and legacy_ver in _TLS_VERSION_MAP:
        info.offered_versions.append(legacy_str)
    pos = 2

    # Random (32 bytes)
    pos += 32

    # Session ID
    sid_len = body[pos]
    pos += 1 + sid_len

    # Cipher suites
    cs_len = struct.unpack("!H", body[pos: pos + 2])[0]
    pos += 2 + cs_len

    # Compression methods
    comp_len = body[pos]
    pos += 1 + comp_len

    # Extensions
    if pos + 2 > len(body):
        return
    ext_total = struct.unpack("!H", body[pos: pos + 2])[0]
    pos += 2
    ext_end = pos + ext_total
    ext_end = min(ext_end, len(body))

    while pos + 4 <= ext_end:
        ext_type = struct.unpack("!H", body[pos: pos + 2])[0]
        ext_len = struct.unpack("!H", body[pos + 2: pos + 4])[0]
        ext_data = body[pos + 4: pos + 4 + ext_len]
        pos += 4 + ext_len

        if ext_type == _EXT_SNI:
            info.sni = _parse_sni(ext_data)
        elif ext_type == _EXT_ALPN:
            info.alpn = _parse_alpn(ext_data)
        elif ext_type == _EXT_SUPPORTED_VERSIONS:
            # List of 2-byte version codes offered by client
            if len(ext_data) >= 1:
                vl = ext_data[0]
                for i in range(1, vl, 2):
                    if i + 2 <= len(ext_data):
                        ver_code = struct.unpack("!H", ext_data[i: i + 2])[0]
                        ver_str = _TLS_VERSION_MAP.get(ver_code, f"0x{ver_code:04x}")
                        if ver_str not in info.offered_versions:
                            info.offered_versions.append(ver_str)
        elif ext_type == _EXT_RENEGOTIATION:
            info.anomalies.append("renegotiation-extension-present")


def _parse_server_hello(body: bytes, info: TLSHandshakeInfo) -> None:
    """Parse ServerHello — extract negotiated version, cipher suite, and key share."""
    if len(body) < 35:
        return
    pos = 0

    legacy_ver = struct.unpack("!H", body[pos: pos + 2])[0]
    pos += 2

    # Random (32 bytes)
    pos += 32

    # Session ID
    sid_len = body[pos]
    pos += 1 + sid_len

    # Cipher suite
    if pos + 2 > len(body):
        return
    cs_bytes = struct.unpack("!H", body[pos: pos + 2])[0]
    pos += 2
    info.cipher_suite = _cipher_code_to_name(cs_bytes)

    # Compression
    pos += 1

    # Initial version from legacy field
    negotiated_ver = _TLS_VERSION_MAP.get(legacy_ver, f"0x{legacy_ver:04x}")

    # Check extensions
    if pos + 2 <= len(body):
        ext_total = struct.unpack("!H", body[pos: pos + 2])[0]
        pos += 2
        ext_end = pos + ext_total
        while pos + 4 <= ext_end and pos + 4 <= len(body):
            ext_type = struct.unpack("!H", body[pos: pos + 2])[0]
            ext_len = struct.unpack("!H", body[pos + 2: pos + 4])[0]
            ext_data = body[pos + 4: pos + 4 + ext_len]
            pos += 4 + ext_len
            if ext_type == _EXT_SUPPORTED_VERSIONS and len(ext_data) >= 2:
                ver_code = struct.unpack("!H", ext_data[0:2])[0]
                negotiated_ver = _TLS_VERSION_MAP.get(ver_code, f"0x{ver_code:04x}")
            elif ext_type == _EXT_KEY_SHARE and len(ext_data) >= 2:
                group_code = struct.unpack("!H", ext_data[0:2])[0]
                curve_name = _NAMED_CURVES.get(group_code, f"0x{group_code:04X}")
                info.key_exchange = f"ECDHE ({curve_name})"
                info.pfs = True

    info.tls_version = negotiated_ver

    # Cipher strength
    db = _load_cipher_db()
    suite_info = db.get(info.cipher_suite, {})
    info.cipher_strength = suite_info.get("strength", "unknown")


def _parse_server_key_exchange(body: bytes, info: TLSHandshakeInfo) -> None:
    """Parse ServerKeyExchange (type 0x0C) to observe ECDHE curve or DHE parameters."""
    if len(body) < 3:
        return
    curve_type = body[0]
    if curve_type == 3 and len(body) >= 3:  # named_curve
        named_curve = struct.unpack("!H", body[1:3])[0]
        curve_name = _NAMED_CURVES.get(named_curve, f"0x{named_curve:04X}")
        info.key_exchange = f"ECDHE ({curve_name})"
        info.pfs = True
    elif len(body) >= 2:
        p_len = struct.unpack("!H", body[0:2])[0]
        if 64 <= p_len <= 1024 and 2 + p_len <= len(body):
            info.key_exchange = f"DHE ({p_len * 8}-bit)"
            info.pfs = True


def _parse_certificate(body: bytes, info: TLSHandshakeInfo) -> None:
    """Parse Certificate message — extract raw DER-encoded certificates."""
    if len(body) < 3:
        return
    pos = 0
    is_tls13 = (info.tls_version == "TLS1.3")

    if is_tls13:
        # TLS 1.3: skip 1-byte request context length + context bytes
        context_len = body[pos]
        pos += 1 + context_len

    if pos + 3 > len(body):
        return

    total_certs_len = struct.unpack("!I", b"\x00" + body[pos: pos + 3])[0]
    pos += 3

    end = min(pos + total_certs_len, len(body))
    while pos + 3 <= end:
        cert_len = struct.unpack("!I", b"\x00" + body[pos: pos + 3])[0]
        pos += 3
        if cert_len > 0 and pos + cert_len <= len(body):
            cert_der = body[pos: pos + cert_len]
            info.certificate_chain_der.append(cert_der)
        pos += cert_len
        # TLS 1.3 only: each cert has 2-byte extension data length
        if is_tls13 and pos + 2 <= len(body):
            ext_skip = struct.unpack("!H", body[pos: pos + 2])[0]
            pos += 2 + ext_skip


def _parse_sni(data: bytes) -> Optional[str]:
    """Decode the SNI extension value."""
    try:
        if len(data) < 5:
            return None
        list_len = struct.unpack("!H", data[0:2])[0]
        pos = 2
        while pos + 3 <= len(data):
            name_type = data[pos]
            name_len = struct.unpack("!H", data[pos + 1: pos + 3])[0]
            name = data[pos + 3: pos + 3 + name_len]
            if name_type == 0x00:  # host_name
                return name.decode("ascii", errors="ignore")
            pos += 3 + name_len
    except Exception:
        pass
    return None


def _parse_alpn(data: bytes) -> list[str]:
    """Decode the ALPN extension value."""
    protocols: list[str] = []
    try:
        if len(data) < 2:
            return protocols
        list_len = struct.unpack("!H", data[0:2])[0]
        pos = 2
        while pos + 1 <= len(data):
            plen = data[pos]
            pos += 1
            if plen > 0 and pos + plen <= len(data):
                protocols.append(data[pos: pos + plen].decode("ascii", errors="ignore"))
            pos += plen
    except Exception:
        pass
    return protocols


def _cipher_code_to_name(code: int) -> str:
    """
    Convert a 2-byte cipher suite code to its IANA name.

    We maintain a minimal hardcoded reverse-map for the most common suites.
    Unknown codes are returned as 0xXXXX hex strings.
    """
    _CODE_MAP = {
        0x0000: "TLS_NULL_WITH_NULL_NULL",
        0x0001: "TLS_RSA_WITH_NULL_MD5",
        0x0002: "TLS_RSA_WITH_NULL_SHA",
        0x003B: "TLS_RSA_WITH_NULL_SHA256",
        0x0004: "TLS_RSA_WITH_RC4_128_MD5",
        0x0005: "TLS_RSA_WITH_RC4_128_SHA",
        0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
        0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
        0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
        0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        0x1301: "TLS_AES_128_GCM_SHA256",
        0x1302: "TLS_AES_256_GCM_SHA384",
        0x1303: "TLS_CHACHA20_POLY1305_SHA256",
        0x1304: "TLS_AES_128_CCM_SHA256",
        0x1305: "TLS_AES_128_CCM_8_SHA256",
    }
    return _CODE_MAP.get(code, f"0x{code:04X}")


def _derive_kex_and_pfs(info: TLSHandshakeInfo) -> None:
    """Derive key exchange mechanism and PFS from cipher suite name or wire params."""
    if info.key_exchange != "unknown":
        return

    suite = info.cipher_suite.upper()
    db = _load_cipher_db()
    db_entry = db.get(info.cipher_suite, {})

    if "ECDHE" in suite:
        info.key_exchange = "ECDHE"
        info.pfs = True
    elif "DHE" in suite and "ECDHE" not in suite:
        info.key_exchange = "DHE"
        info.pfs = True
    elif info.tls_version == "TLS1.3":
        # TLS 1.3 mandates PFS — always ECDHE or DHE
        info.key_exchange = "ECDHE (TLS 1.3)"
        info.pfs = True
    elif "RSA" in suite:
        info.key_exchange = "RSA"
        info.pfs = False
    else:
        info.key_exchange = db_entry.get("key_exchange", "unknown")
        info.pfs = bool(db_entry.get("pfs", False))
