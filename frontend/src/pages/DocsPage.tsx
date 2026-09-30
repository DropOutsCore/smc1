import { Layout } from '../components/Layout';
import { Card } from '../components/Card';
import { BookOpen, Terminal, Database, Shield, Cpu, Lock, FileText } from 'lucide-react';
import { AvalokLogoMark } from '../components/AuraPrimitives';

const sections = [
  {
    icon: <BookOpen size={18} />,
    title: 'What is AVALOK?',
    content: `AVALOK (Passive Email TLS Forensics) is an offline cryptographic risk assessment tool for SMTP, IMAP, and POP3 traffic captured in PCAP/PCAPNG files.

It reconstructs TCP streams, parses TLS handshakes, inspects X.509 certificates, evaluates 16 NIST SP 800-52 & RFC security rules, and scores each host with an explainable risk label — 100% passively without connecting to or probing live infrastructure.

AVALOK is designed for:
• Digital forensics investigators analyzing email exfiltration and MITM interception
• Blue teamers validating enterprise mail server TLS and cipher hygiene
• Security auditors reviewing cryptographic posture
• DFIR professionals needing verifiable chain-of-custody evidence`,
  },
  {
    icon: <Shield size={18} />,
    title: 'Supported Protocols & Wire Reassembly',
    content: `Sekure passively reconstructs sessions across critical mail protocols:

SMTP (Port 25, 465, 587)
  - EHLO/HELO banner inspection
  - STARTTLS negotiation and silent downgrade (STRIPTLS) detection
  - Plaintext credential exposure identification (AUTH PLAIN, LOGIN)

IMAP (Port 143, 993)
  - CAPABILITY negotiation inspection
  - STARTTLS and implicit TLS (IMAPS) handshake validation

POP3 (Port 110, 995)
  - CAPA command responses
  - STLS command and implicit TLS (POP3S) validation

All protocols are parsed passively — Sekure strictly reads the PCAP wire stream without active probes.`,
  },
  {
    icon: <Lock size={18} />,
    title: 'Detection Rules & NIST SP 800-52 Compliance',
    content: `Sekure evaluates four tiers of cryptographic weaknesses:

CRITICAL SEVERITY
  • Active STARTTLS Downgrade Attack (STRIPTLS Interception)
  • Plaintext Authentication Credential Exposure on Non-TLS Stream
  • Expired or Forged Leaf X.509 Certificate

HIGH SEVERITY
  • Deprecated TLS 1.0 / 1.1 Protocol Usage (RFC 8996 Violation)
  • SSLv3 / SSLv2 Obsolete Protocols
  • NULL or EXPORT Weak Cipher Suite Selection
  • Self-Signed Untrusted Root Certificate
  • Insufficient RSA Key Length (< 2048 bits)

MEDIUM SEVERITY
  • Missing Perfect Forward Secrecy (Static RSA Key Exchange)
  • SHA-1 Deprecated Signature Algorithm
  • RC4 Stream Cipher Usage (RFC 7465 Prohibited)
  • Certificate Subject Alternative Name (SAN) Mismatch
  • Missing Server Name Indication (SNI) in ClientHello

LOW SEVERITY
  • Certificate Expiring within 30 days
  • 3DES Legacy Cipher Negotiation
  • Sub-optimal TLS 1.2 Cipher Ordering`,
  },
  {
    icon: <Cpu size={18} />,
    title: 'Isolation Forest AI Anomaly Detection',
    content: `Each reassembled wire session passes through an unsupervised Isolation Forest model (v2.4):

Feature Extraction
  Extracts 18 protocol dimensions including packet timing jitter, handshake payload size ratios, cipher suite entropy, certificate validity window, and TLS extension presence.

Anomaly Score Calculation
  Assigns an anomaly score from 0.00 to 1.00. Scores exceeding 0.70 represent high-confidence statistical anomalies indicating potential protocol tampering or covert tunneling.

Explainable AI Output
  Outputs the top determining features (e.g. stripped EHLO capabilities, non-standard cipher preference) directly into the forensic workbench for rapid analyst triage.`,
  },
  {
    icon: <Database size={18} />,
    title: 'Evidence Schema & JSON Output',
    content: `All reports conform to a standardized, deterministic JSON schema:

{
  "report_id":          "UUID string",
  "source_pcap_sha256": "SHA-256 hash of original capture",
  "generated_at":       "ISO 8601 UTC timestamp",
  "tool_version":       "SekureMail 2.4.0-Production",
  "custody": {
    "source_pcap_path":  "capture.pcap",
    "source_size_bytes": 1048576,
    "analyst_host":     "secops-node-01"
  },
  "hosts": [
    {
      "host":           "mail.corp.com:25",
      "posture_grade":  "A+ | A | B | C | D | F",
      "posture_score":  0-100,
      "finding_summary": { "critical": 0, "high": 1, ... },
      "sessions": [ ... ]
    }
  ]
}`,
  },
  {
    icon: <FileText size={18} />,
    title: 'Court-Admissible Chain of Custody',
    content: `Sekure is architected for forensic integrity:

1. Source PCAP SHA-256 hash is computed immediately upon ingestion.
2. An unalterable custody block is embedded in every JSON, HTML, and PDF export.
3. Zero packet modification — source captures are opened strictly in read-only mode.
4. Cryptographic timestamping and reproducible rule execution guarantees that identical PCAP inputs always yield identical forensic outputs.`,
  },
];

export default function DocsPage() {
  return (
    <Layout>
      <div className="max-w-screen-lg mx-auto px-6 py-12 fade-in">
        <div className="mb-10 flex flex-col sm:flex-row sm:items-center justify-between gap-6 pb-6 border-b border-white/10">
          <div>
            <div className="flex items-center gap-2 text-[#48BB36] text-xs font-semibold uppercase tracking-wider mb-2 font-mono">
              <AvalokLogoMark className="w-4 h-4" />
              <span>AVALOK Technical Documentation</span>
            </div>
            <h1 className="text-white text-3xl sm:text-4xl font-extrabold tracking-tight">
              AVALOK Architecture & Reference
            </h1>
            <p className="text-white/60 text-sm mt-2 font-mono">
              Passive Email TLS Forensics & Cryptographic Risk Assessment
            </p>
          </div>
        </div>

        <div className="space-y-6">
          {sections.map(({ icon, title, content }) => (
            <Card key={title} className="bg-[#171c23] border border-white/10 hover:border-[#48BB36]/40 transition-colors">
              <div className="flex items-center gap-3 mb-4">
                <span className="text-[#48BB36]">{icon}</span>
                <h2 className="text-white font-bold text-base tracking-tight">{title}</h2>
              </div>
              <pre className="text-white/70 text-xs font-mono leading-relaxed whitespace-pre-wrap bg-[#10141a] p-4 rounded-lg border border-white/5">
                {content}
              </pre>
            </Card>
          ))}
        </div>
      </div>
    </Layout>
  );
}
