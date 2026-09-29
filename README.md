# SecureMailScope 🔒

> **Passive Email TLS Forensic & Cryptographic Risk Assessment Framework**  
> *AI-Assisted Cryptographic Security Posture Assessment for Enterprise Email Communications*

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![NIST SP 800-52](https://img.shields.io/badge/standard-NIST%20SP%20800--52%20Rev.2-orange.svg)](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)
[![RFC 8996](https://img.shields.io/badge/RFC-8996%20TLS%20Deprecation-red.svg)](https://www.rfc-editor.org/rfc/rfc8996)
[![Tests Passing](https://img.shields.io/badge/tests-30%20passed-brightgreen.svg)](securemailscope/tests)

---

## 📖 Table of Contents

- [The Real-World Problem: An Invisible Threat](#-the-real-world-problem-an-invisible-threat)
- [What SecureMailScope Solves](#-what-securemailscope-solves)
- [Dual-Input Architecture: PCAP & JSON Report Ingestion](#-dual-input-architecture-pcap--json-report-ingestion)
- [Key Features](#-key-features)
- [System Architecture & 8-Phase Pipeline](#-system-architecture--8-phase-pipeline)
- [Installation & Prerequisites](#-installation--prerequisites)
- [Quick Start Guide](#-quick-start-guide)
- [CLI Reference](#-cli-reference)
- [Interactive Streamlit Dashboard](#-interactive-streamlit-dashboard)
- [REST API Reference](#-rest-api-reference)
- [Weakness Rule Catalog (16 Rules)](#-weakness-rule-catalog-16-rules)
- [AI & ML Risk Intelligence](#-ai--ml-risk-intelligence)
- [Forensic Integrity & Evidentiary Traceability](#-forensic-integrity--evidentiary-traceability)
- [Generating Test PCAP Fixtures](#-generating-test-pcap-fixtures)
- [Running Test Suite](#-running-test-suite)
- [Project Directory Layout](#-project-directory-layout)
- [Standards & Compliance References](#-standards--compliance-references)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 The Real-World Problem: An Invisible Threat

### The Scenario: Silent Exfiltration at a Regional Financial Firm

Imagine **Meridian Financial Partners**, a firm handling private equity transactions and client tax documentation. Their email infrastructure spans internal Microsoft Exchange servers, an on-premise postfix relay, and partner gateways. 

Their compliance checklist says:
> *"All email communication is secured via Transport Layer Security (TLS)."*

Yet during a routine capture of mail gateway traffic, nobody noticed what was genuinely happening across the wire:

```text
[Network Tap: SMTP traffic captured -> capture.pcap]

Client (Internal Relay) ──▶ Server (Partner Mail Gateway: 45.33.32.156:25)
  220 mail.partner.com ESMTP
  EHLO client.meridian.internal
  250-STARTTLS
  STARTTLS
  220 Ready to start TLS
  
  [Man-In-The-Middle / Misconfiguration Drops Handshake]
  
  AUTH PLAIN AGFsaWNlAHBhc3N3b3Jk   <── PLAINTEXT CREDENTIALS & PAYLOAD!
  235 Authentication successful
```

#### What happened?
1. **A Silent STARTTLS Downgrade Attack (STRIPTLS):** The client initiated `STARTTLS`, but the TLS `ClientHello` was intercepted or suppressed. The client defaulted back to **unencrypted plaintext authentication**, transmitting confidential passwords, financial attachments, and executive memos in clear text.
2. **Obsolete Protocols on Vendor Links:** Another branch communicated using **TLS 1.0** with **static RSA key exchange (no Forward Secrecy)**. If an adversary ever obtains the private key in the future, years of archived traffic can be retroactively decrypted.
3. **Expired & Self-Signed Certificates:** Key links relied on self-signed certificates with **1024-bit RSA keys** or expired trust chains, making man-in-the-middle attacks trivial.

#### Why Existing Tools Fall Short:
Traditional packet decoders (like Wireshark or tcpdump) **only decode packets**. They dump raw bytes, hex values, and protocol fields. They **do not**:
- Score overall cryptographic risk or assign an actionable posture grade.
- Identify STARTTLS stripping anomalies across millions of TCP segments.
- Correlate weak ciphers, short keys, and certificate expiry against NIST SP 800-52 Rev.2 standards.
- Provide clear, deterministic server configuration fixes (Postfix, Dovecot, Exim).

**SecureMailScope was created to bridge this exact gap.**

---

## 💡 What SecureMailScope Solves

| Without SecureMailScope | With SecureMailScope |
|---|---|
| Raw, unranked packet captures with millions of lines | **Actionable letter grades (A, B, C, D, F)** per host and email session |
| Undetected STARTTLS stripping / downgrade attacks | **Automated detection of STARTTLS downgrade anomalies** with packet-level evidence |
| Manual cross-referencing of cipher suites and RFCs | **16 curated rules** automatically mapping weaknesses to CWEs and RFCs |
| Zero visibility into forward secrecy (PFS) | **Automated detection of static RSA/DH key exchanges** lacking Forward Secrecy |
| No baseline for unusual handshake behavior | **AI/ML Supervised Classifier + Isolation Forest Anomaly Detector** |
| Complex manual compliance reporting | **Automated export to JSON, self-contained HTML, and forensic PDF** |
| Fragile evidence handling | **Forensic-grade read-only ingestion** with source SHA-256 fingerprinting |

---

## 🔄 Dual-Input Architecture: PCAP & JSON Report Ingestion

SecureMailScope is engineered to accept **both raw network captures and existing forensic reports** across all interfaces:

```text
 ┌───────────────────────┐           ┌────────────────────────┐
 │   PCAP / PCAPNG File  │           │   JSON Forensic Report │
 │ (e.g. capture.pcap)   │           │ (e.g. report.json)     │
 └───────────┬───────────┘           └───────────┬────────────┘
             │                                   │
             ▼                                   ▼
 ┌────────────────────────────────────────────────────────────┐
 │                  SecureMailScope System                    │
 │                                                            │
 │  • CLI: `securemailscope analyze <pcap | json>`            │
 │  • Streamlit Dashboard: Drag & Drop either PCAP or JSON    │
 │  • REST API: `POST /analyze` accepts both formats          │
 │  • Pipeline: Autodetects input type and routes seamlessly  │
 └─────────────────────────────┬──────────────────────────────┘
                               │
            ┌──────────────────┴──────────────────┐
            ▼                                     ▼
  [Full Forensic Analysis]              [Instant Posture Rendering]
  • Stream Reassembly                   • Posture Grades & Metrics
  • Handshake & Cert Parsing            • Findings & Drill-Down
  • 16 Rules + ML Anomaly Detection     • Export HTML, PDF, or JSON
```

- **If you provide a PCAP file (`.pcap`, `.pcapng`):** SecureMailScope executes full packet parsing, TCP stream reconstruction, TLS handshake extraction, certificate validation, rule evaluations, ML scoring, and produces a complete report.
- **If you provide a JSON report (`.json`):** SecureMailScope instantly validates the report, renders executive posture grades, enables drill-down investigations in the dashboard or CLI, and allows re-exporting to HTML and PDF without re-running packet capture ingestion.

---

## ✨ Key Features

- **Strictly Passive & Forensic-Grade:** Opens captures strictly in binary read-only (`rb`) mode. Computes SHA-256 custody hashes to verify tamper-proof evidentiary integrity.
- **Protocol Reconstruction:** Reassembles out-of-order TCP segments and identifies SMTP, IMAP, and POP3 sessions (including explicit STARTTLS and implicit TLS on ports 465, 993, 995).
- **Deep TLS Handshake Extraction:** Extracts ClientHello, ServerHello, negotiated TLS versions (SSLv3 through TLS 1.3), cipher suites, key exchange algorithms, SNI, and ALPN tokens.
- **X.509 Certificate Chain Analysis:** Validates validity dates, detects expired or near-expiry (<30 days) certs, verifies RSA (flagging <2048-bit) and ECC (flagging <224-bit) key lengths, flags weak signatures (MD5/SHA-1), and identifies self-signed roots or hostname mismatches.
- **16-Rule Weakness Catalog:** Config-driven in YAML (`securemailscope/rules/rules.yaml`). Every finding links to a CWE identifier, standard reference, severity level, and exact source packet number.
- **Explainable Machine Learning:** Random Forest risk classifier trained with weak supervision from rule baselines. Each finding outputs human-readable `contributing_factors` explaining *why* it received its risk rating.
- **Isolation Forest Anomaly Detection:** Learns baseline environment behavior to flag zero-day or non-standard TLS handshake deviations.
- **Remediation Generator:** Deterministic, copy-paste configuration guidance for Postfix, Dovecot, and Exim.
- **Multi-Format Export & Visual Dashboard:** Export to machine-readable JSON (SIEM/SOAR ingestion), formatted HTML, or executive PDF, plus an interactive dark-mode Streamlit dashboard.

---

## 🏗️ System Architecture & 8-Phase Pipeline

```text
 ┌────────────────────────────────────────────────────────┐
 │                      INPUT SOURCE                      │
 │           Raw PCAP/PCAPNG   OR   JSON Report           │
 └───────────────────────────┬────────────────────────────┘
                             │
 ┌───────────────────────────▼────────────────────────────┐
 │  Phase 1: Ingestion & Forensics Custody                │
 │  • SHA-256 fingerprinting of PCAP                      │
 │  • Zero-copy packet & segment extraction               │
 └───────────────────────────┬────────────────────────────┘
                             │
 ┌───────────────────────────▼────────────────────────────┐
 │  Phase 2: TCP Stream Reassembly & Protocol Detection   │
 │  • Out-of-order segment ordering & deduplication       │
 │  • SMTP/IMAP/POP3 & STARTTLS state tracking            │
 │  • STARTTLS stripping downgrade detection              │
 └───────────────────────────┬────────────────────────────┘
                             │
 ┌───────────────────────────▼────────────────────────────┐
 │  Phase 3: TLS Handshake & Certificate Extraction       │
 │  • Handshake record dissection (Client/Server Hello)   │
 │  • X.509 leaf & chain parsing via cryptography module  │
 └───────────────────────────┬────────────────────────────┘
                             │
 ┌───────────────────────────▼────────────────────────────┐
 │  Phase 4: Rule Engine Evaluation                       │
 │  • Evaluates 16 configurable weakness rules            │
 │  • Assigns CWE, RFC standard refs & packet offsets     │
 └───────────────────────────┬────────────────────────────┘
                             │
 ┌───────────────────────────▼────────────────────────────┐
 │  Phase 5: Feature Extraction & AI/ML Risk Scoring      │
 │  • Generates 22-dimensional feature vector per session │
 │  • Supervised risk classification + Explainability     │
 │  • Isolation Forest anomaly scoring                    │
 └───────────────────────────┬────────────────────────────┘
                             │
 ┌───────────────────────────▼────────────────────────────┐
 │  Phase 6: Posture Scoring & Grading                    │
 │  • Weighted scoring formula per host (0-100)           │
 │  • Letter grades: A, B, C, D, F                        │
 └───────────────────────────┬────────────────────────────┘
                             │
 ┌───────────────────────────▼────────────────────────────┐
 │  Phase 7: Report Generation & Export                   │
 │  • JSON export with cryptographic hash                 │
 │  • Jinja2 offline HTML forensic report                 │
 │  • PDF report generation (WeasyPrint / ReportLab)      │
 └───────────────────────────┬────────────────────────────┘
                             │
 ┌───────────────────────────▼────────────────────────────┐
 │  Phase 8: Persistence & Visual Presentation            │
 │  • SQLite scan history & grade trend tracking          │
 │  • Streamlit Dashboard & FastAPI REST endpoints        │
 └────────────────────────────────────────────────────────┘
```

---

## 💻 Installation & Prerequisites

### Prerequisites
- **Python:** 3.11 or 3.12 (Python 3.13 supported)
- **Packet Driver:**
  - **Windows:** [Npcap](https://npcap.com/) (recommended in WinPcap API-compatible mode)
  - **Linux:** `sudo apt install libpcap-dev`
  - **macOS:** Built-in `libpcap`

### Setup Instructions

```bash
# 1. Clone repository
git clone https://github.com/DropOutsCore/smc1.git
cd smc1

# 2. Create and activate a virtual environment
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux / macOS:
source .venv/bin/activate

# 3. Install in editable development mode
pip install -e ".[dev]"

# Optional: PDF export support via WeasyPrint
pip install -e ".[pdf]"
```

---

## ⚡ Quick Start Guide

### Step 1: Generate Sample PCAP Captures
You do not need an enterprise mail tap to test. Generate 6 realistic scenarios:
```bash
python securemailscope/sample_pcaps/generate_test_pcaps.py
```
This generates:
- `smtp_clean_tls13.pcap` (Clean TLS 1.3 session — Grade A)
- `smtp_tls10_deprecated.pcap` (Deprecated TLS 1.0 — Grade F)
- `smtp_starttls_downgrade.pcap` (Active downgrade attack — Grade D)
- `smtp_no_pfs_rsa.pcap` (Static RSA cipher with no forward secrecy — Grade D)
- `smtp_expired_cert.pcap` (Expired X.509 certificate)
- `smtp_self_signed.pcap` (Self-signed certificate)

### Step 2: Analyze a PCAP or View a Report
```bash
# Analyze a PCAP file:
python -m securemailscope.main analyze capture.pcap

# OR load an existing JSON report directly:
python -m securemailscope.main analyze capture_report.json
```

**Terminal Output:**
```text
============================================================
  SecureMailScope Analysis Complete
============================================================
  Sessions analyzed : 4
  Total findings    : 7

  [F] 198.51.100.5:25                     Grade: F  Score: 60
  [D] 45.33.32.156:25                     Grade: D  Score: 50
  [D] 203.0.113.50:25                     Grade: D  Score: 35
  [A] 203.0.113.10:25                     Grade: A  Score: 0

  JSON : capture_report.json
  HTML : capture_report.html

  Source PCAP SHA-256: 0c96a199e6790537cec5f73b0d9b9730e0852bb8e22eadc8bd0320f8605e7ddc
============================================================
```

### Step 3: Launch the Interactive Dashboard
```bash
streamlit run securemailscope/dashboard/app.py
```
Open **http://localhost:8501** in your browser.

---

## 🖥️ CLI Reference

```text
python -m securemailscope.main [command] [options]
```

### Commands:

| Command | Description |
|---|---|
| `analyze <path>` | Analyze a PCAP file or load and inspect an existing JSON report |
| `history <host>` | Print posture grade history and trend delta for a specific host (`ip:port`) |
| `retrain` | Retrain risk classification and anomaly detection models from past scans |
| `dashboard` | Launch the Streamlit interactive dashboard |

### Options for `analyze`:
- `-o, --output <dir>`: Directory where output JSON, HTML, and PDF files are saved (default: `.`)
- `--rules <path>`: Path to a custom `rules.yaml` file
- `--db <path>`: Custom SQLite database path
- `--enrich`: Enable crt.sh Certificate Transparency log lookup (opt-in network query)
- `--no-ml`: Disable ML risk classification (run rule engine only)
- `--no-anomaly`: Disable Isolation Forest anomaly scoring
- `--no-html`: Suppress HTML report generation
- `--no-pdf`: Suppress PDF report generation
- `-v, --verbose`: Enable detailed debug logging

---

## 📊 Interactive Streamlit Dashboard

The dashboard provides a dark forensic console designed for SOC/DFIR teams:

- **Unified Ingestion:** Drag-and-drop or select any `.pcap`, `.pcapng`, or `.json` report file.
- **Quick Sample Selector:** Test out synthetic scenarios with a single click.
- **Overview Page:**
  - Aggregated metrics (Hosts Analyzed, Email Sessions, Critical Findings, Total Findings).
  - Letter grade badges (A, B, C, D, F) with host breakdown and severity chips.
  - Source PCAP SHA-256 fingerprint display for chain of custody.
- **Findings Explorer:**
  - Filterable by Severity (Critical, High, Medium, Low) and Category.
  - Searchable by host IP or rule description.
  - Packet-level evidence references (`packet_number`, `byte_offset`).
- **Session Drill-Down:**
  - Full handshake inspection (ClientHello / ServerHello).
  - Negotiated cipher suite details and PFS status.
  - X.509 certificate validity window and trust chain status.
  - ML explainability factors showing why a session was flagged.
- **One-Click Export:** Download JSON and self-contained HTML reports directly from the UI.

---

## 🌐 REST API Reference

Run the FastAPI backend:
```bash
uvicorn securemailscope.api.app:app --port 8000 --reload
```
Interactive Swagger documentation is available at **http://localhost:8000/docs**.

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/analyze` | Upload a PCAP, PCAPNG, or JSON report file; returns structured JSON analysis |
| `GET` | `/health` | Service health and version check |
| `GET` | `/history/{host}` | Retrieve grade history and score trend for a given host (`ip:port`) |
| `GET` | `/reports/{id}` | Retrieve a previously generated report by ID |

---

## 📜 Weakness Rule Catalog (16 Rules)

Rules are defined in [`securemailscope/rules/rules.yaml`](securemailscope/rules/rules.yaml) and evaluate against the safe evaluation namespace (`tls`, `cert`, `session`).

| Rule ID | Category | Severity | Standard Reference | CWE |
|---|---|---|---|---|
| `deprecated-tls-ssl3` | Deprecated Protocol | 🔴 Critical | RFC 7568 (POODLE CVE-2014-3566) | CWE-326 |
| `deprecated-tls-10` | Deprecated Protocol | 🟠 High | RFC 8996, NIST SP 800-52 Rev.2 | CWE-326 |
| `deprecated-tls-11` | Deprecated Protocol | 🟠 High | RFC 8996, NIST SP 800-52 Rev.2 | CWE-326 |
| `insecure-cipher` | Weak Cipher | 🔴 Critical | RFC 7465 (RC4), RFC 6151 (MD5) | CWE-327 |
| `weak-cipher` | Weak Cipher | 🟠 High | NIST SP 800-52 Rev.2 | CWE-327 |
| `no-pfs` | No Forward Secrecy | 🟡 Medium | NIST SP 800-52 Rev.2 §3.3.1 | CWE-311 |
| `cert-expired` | Certificate Validity | 🔴 Critical | RFC 5280 §4.1.2.5 | CWE-298 |
| `cert-not-yet-valid` | Certificate Validity | 🟠 High | RFC 5280 §4.1.2.5 | CWE-298 |
| `cert-expiring-soon` | Certificate Validity | 🔵 Low | RFC 5280 (<30 days remaining) | CWE-298 |
| `weak-key-rsa` | Weak Public Key | 🟠 High | NIST SP 800-57 Part 1 Rev.5 (RSA <2048) | CWE-326 |
| `weak-key-ecc` | Weak Public Key | 🟠 High | NIST SP 800-57 Part 1 Rev.5 (ECC <224) | CWE-326 |
| `weak-signature-algorithm` | Weak Signature | 🟠 High | CA/Browser Forum, RFC 6151 (MD5/SHA-1) | CWE-327 |
| `self-signed-cert` | Certificate Trust | 🟡 Medium | RFC 5280 | CWE-295 |
| `hostname-mismatch` | Certificate Trust | 🟠 High | RFC 6125 (Subject SAN vs SNI) | CWE-297 |
| `starttls-downgrade` | Protocol Downgrade | 🔴 Critical | RFC 3207, BASTA! research | CWE-319 |
| `no-starttls` | Missing STARTTLS | 🟠 High | RFC 3207, RFC 8314 | CWE-319 |

---

## 🤖 AI & ML Risk Intelligence

### 1. 22-Dimensional Feature Vector
Each reconstructed session is converted into a numerical feature vector (`securemailscope/ml/features.py`):
- **Protocol & Version:** Encoded TLS version (SSLv3 to TLS 1.3), implicit TLS flag.
- **Cipher Suite Properties:** Strength tier, cipher family, PFS boolean flag, symmetric key length.
- **Certificate Properties:** Key algorithm, key length, validity window days, self-signed flag, trust chain length, hostname match boolean, weak signature flag.
- **Behavioral Indicators:** STARTTLS presence, downgrade attack suspected flag, handshake anomaly indicators.

### 2. Supervised Risk Classification
- **Architecture:** Random Forest / Gradient Boosting with weak supervision derived from rule engine labels.
- **Explainability:** Feature importance analysis exposes `contributing_factors` on every finding so analysts can understand *why* a session was rated Critical.

### 3. Isolation Forest Anomaly Detection
- Unsupervised Isolation Forest model fitted across the observed traffic distribution.
- Flags non-standard handshakes, novel downgrade techniques, and protocol anomalies not yet covered by explicit rules.

---

## 🔒 Forensic Integrity & Evidentiary Traceability

- **Non-Destructive Analysis:** Source PCAP is opened exclusively in read-only mode (`rb`).
- **Cryptographic Custody:** SHA-256 hash of the input capture is computed at load and embedded in every generated report.
- **Packet-Level Traceability:** Every finding includes an `evidence_ref` with exact packet number and byte offset for validation in Wireshark.
- **Reproducible Report Fingerprint:** The generated JSON report is canonicalized and hashed to detect post-scan tampering.

---

## 🧪 Generating Test PCAP Fixtures

To verify your installation and test detection accuracy:
```bash
python securemailscope/sample_pcaps/generate_test_pcaps.py
```
This builds standard PCAP files with valid Ethernet, IPv4, TCP headers, and realistic SMTP/TLS payloads.

---

## 🚦 Running Test Suite

SecureMailScope includes a 30-test suite covering ingestion, TCP reassembly, STARTTLS downgrade detection, rules, ML feature extraction, and report generation:

```bash
# Run tests
pytest -v

# Run with test coverage
pytest --cov=securemailscope --cov-report=term-missing
```

---

## 📁 Project Directory Layout

```text
smc/
├── securemailscope/
│   ├── __init__.py
│   ├── main.py                     # CLI entrypoint (analyze, history, dashboard, retrain)
│   ├── pipeline.py                 # 8-phase analysis pipeline (handles PCAP and JSON)
│   ├── ingestion/
│   │   ├── loader.py               # Read-only PCAP ingestion + SHA-256 hash
│   │   ├── pcap_reader.py          # Zero-dependency packet decoder
│   │   ├── reassembler.py          # TCP stream reassembly & deduplication
│   │   ├── protocol_detector.py    # SMTP/IMAP/POP3 protocol & downgrade detection
│   │   └── models.py               # EmailSession, TCPSegment dataclasses
│   ├── tls_analysis/
│   │   ├── handshake_parser.py     # TLS Client/Server Hello & extension parser
│   │   └── cipher_table.yaml       # IANA cipher suite classification table
│   ├── certs/
│   │   └── extractor.py            # X.509 certificate chain validation
│   ├── rules/
│   │   ├── engine.py               # YAML-driven rule evaluation engine
│   │   └── rules.yaml              # 16 weakness detection rules
│   ├── ml/
│   │   ├── features.py             # 22-dimensional feature vector extraction
│   │   ├── classifier.py           # Supervised risk classifier & anomaly detector
│   │   └── models/                 # Serialized model weights (.joblib)
│   ├── scoring/
│   │   └── grader.py               # Composite posture scoring & grade calculation
│   ├── remediation/
│   │   └── templates.py            # Mail server remediation snippets (Postfix/Dovecot)
│   ├── reports/
│   │   ├── builder.py              # Report assembly & JSON serialization
│   │   ├── exporter.py             # HTML (Jinja2) & PDF report export
│   │   └── templates/              # Report HTML templates
│   ├── storage/
│   │   └── database.py             # SQLite persistence for scan history & trends
│   ├── forensics/
│   │   └── custody.py              # Chain-of-custody metadata & report hashing
│   ├── enrichment/
│   │   └── crtsh.py                # Certificate Transparency log lookup (opt-in)
│   ├── dashboard/
│   │   └── app.py                  # Streamlit forensic console (PCAP & JSON support)
│   ├── api/
│   │   └── app.py                  # FastAPI REST API
│   ├── sample_pcaps/
│   │   ├── generate_test_pcaps.py  # Synthetic PCAP test generator
│   │   └── *.pcap                  # Test scenario fixtures
│   └── tests/                      # 30-unit test suite
├── capture.pcap                    # Multi-scenario synthetic PCAP capture
├── pyproject.toml                  # Project packaging & dependencies
└── README.md                       # Comprehensive documentation
```

---

## 📜 Standards & Compliance References

- **NIST Special Publication 800-52 Rev. 2:** *Guidelines for the Selection, Configuration, and Use of TLS Implementations*
- **NIST Special Publication 800-57 Part 1 Rev. 5:** *Recommendation for Key Management*
- **IETF RFC 8996:** *Deprecating TLS 1.0 and TLS 1.1*
- **IETF RFC 7568:** *Deprecating Secure Sockets Layer Version 3.0*
- **IETF RFC 3207:** *SMTP Service Extension for Secure SMTP over TLS*
- **IETF RFC 8314:** *Cleartext Considered Obsolete: Use of TLS for Email Submission and Access*
- **IETF RFC 6125:** *Representation and Verification of Domain-Based Application Service Identities in TLS*
- **IETF RFC 5280:** *Internet X.509 Public Key Infrastructure Certificate and CRL Profile*
- **CA/Browser Forum Baseline Requirements:** *Requirements for the Issuance and Management of Publicly-Trusted Certificates*

---

## 🤝 Contributing

Contributions are warmly welcomed! Areas for enhancement include:
1. **Rule Definitions:** Adding emerging CVEs and cipher deprecations to `rules/rules.yaml`.
2. **Protocol Decoders:** Additional deep protocol states for complex IMAP and POP3 workflows.
3. **Live Capture Mode:** Real-time analysis mode via live interface taps.
4. **Model Tuning:** Enhanced ML feature engineering from larger real-world PCAP corpora.

---

## ⚖️ License

Distributed under the **MIT License**. See `LICENSE` for details.

---

## 🛡️ Disclaimer

SecureMailScope is a **passive network forensics tool**. It is designed solely for defensive security posture assessments, compliance auditing, and authorized digital forensics. Always obtain written authorization before capturing or analyzing enterprise network traffic.
