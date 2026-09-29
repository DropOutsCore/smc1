import { Layout } from '../components/Layout';
import { Card } from '../components/Card';
import { BookOpen, Terminal, Database, Shield, Cpu, Network, Lock, FileText } from 'lucide-react';

const sections = [
  {
    icon: <BookOpen size={18} />,
    title: 'What is AVALOK?',
    content: `AVALOK (Passive Email TLS Forensics) is an offline cryptographic risk assessment tool for SMTP, IMAP, and POP3 traffic captured in PCAP files.

It reconstructs TCP streams, parses TLS handshakes, inspects X.509 certificates, evaluates 16 security rules, and scores each host with an explainable ML-assisted risk label — all without generating any network traffic.

AVALOK is designed for:
• Digital forensics investigators analyzing email exfiltration scenarios
• Blue teamers validating mail server TLS configurations
• Security auditors reviewing cryptographic posture
• DFIR professionals needing chain-of-custody evidence`,
  },
  {
    icon: <Shield size={18} />,
    title: 'Supported Protocols',
    content: `AVALOK reconstructs sessions from the following email protocols:

SMTP (Port 25, 465, 587)
  - EHLO/HELO banners
  - STARTTLS negotiation and downgrade detection
  - Authentication mechanism identification

IMAP (Port 143, 993)
  - CAPABILITY responses
  - STARTTLS and implicit TLS (IMAPS)

POP3 (Port 110, 995)
  - CAPA responses
  - STLS command and implicit TLS (POP3S)

All protocols are parsed passively — AVALOK only reads the PCAP.`,
  },
  {
    icon: <Lock size={18} />,
    title: 'Security Rules',
    content: `AVALOK evaluates the following cryptographic weakness categories:

CRITICAL
  • STARTTLS downgrade attack
  • Plaintext authentication credentials
  • Expired X.509 certificate

HIGH
  • Deprecated TLS 1.0/1.1 (RFC 8996)
  • SSLv3/SSLv2 negotiation
  • NULL cipher suite
  • Self-signed certificate
  • RSA key < 2048 bits

MEDIUM
  • No Perfect Forward Secrecy (RSA key exchange)
  • SHA-1 signature algorithm
  • RC4 cipher suite
  • Certificate hostname mismatch
  • No SNI in ClientHello

LOW
  • TLS 1.3 used (limited passive visibility)
  • Certificate expiring within 30 days
  • 3DES cipher suite`,
  },
  {
    icon: <Cpu size={18} />,
    title: 'ML Anomaly Detection',
    content: `Each session is passed through two ML models:

Risk Label Classifier
  Assigns a risk label (low/medium/high/critical) based on TLS feature vectors including cipher strength, PFS status, protocol version, key parameters, and certificate properties.

Anomaly Detector (Isolation Forest)
  Flags statistical outliers in the feature space. Sessions with anomaly_score > 0.5 are considered anomalous. This catches unusual combinations not covered by discrete rules.

Both models output an explainable confidence score and contributing factors.`,
  },
  {
    icon: <Database size={18} />,
    title: 'Report Schema',
    content: `All reports conform to a stable JSON schema (v1):

{
  "report_id":          UUID string
  "source_pcap_sha256": SHA-256 of the source PCAP
  "generated_at":       ISO 8601 timestamp
  "tool_version":       Analyzer version string
  "custody":            Chain-of-custody metadata
  "tls13_visibility_note": Passive capture limitation note
  "hosts": [
    {
      "host":           "ip:port"
      "posture_grade":  A|B|C|D|F
      "posture_score":  0-100
      "finding_summary": { critical, high, medium, low }
      "sessions": [ ... ]
    }
  ]
}`,
  },
  {
    icon: <Network size={18} />,
    title: 'API Reference',
    content: `POST   /api/pcap/upload
  Upload a PCAP file, start async analysis
  Returns: { analysis_id, file_sha256 }

GET    /api/analysis/{id}/status
  Poll analysis progress (status, stage, progress %)

GET    /api/analysis/{id}/result
  Retrieve full report JSON when complete

GET    /api/reports
  List all stored reports with severity summaries

GET    /api/reports/{id}
  Get a specific report by UUID

GET    /api/reports/{id}/download/json
GET    /api/reports/{id}/download/html
GET    /api/reports/{id}/download/pdf
  Download reports in PDF, HTML, or JSON formats

DELETE /api/reports/{id}
  Delete a stored report

GET    /api/health
  Service liveness check`,
  },
  {
    icon: <Terminal size={18} />,
    title: 'CLI Usage',
    content: `# Analyze a PCAP file
python -m securemailscope.main --pcap capture.pcap

# Analyze an existing JSON report
python -m securemailscope.main --json report.json

# Start the API server (for this frontend)
uvicorn securemailscope.api.app:app --host 0.0.0.0 --port 8000

# Enable enrichment (GeoIP, ASN, reverse DNS)
python -m securemailscope.main --pcap capture.pcap --enrich

# Generate HTML report
python -m securemailscope.main --pcap capture.pcap --html`,
  },
  {
    icon: <FileText size={18} />,
    title: 'Chain of Custody',
    content: `AVALOK is designed for forensic evidence integrity:

1. Source PCAP SHA-256 is computed before any analysis
2. A custody block is embedded in every report containing:
   - source_pcap_path
   - source_pcap_sha256
   - source_pcap_size_bytes
   - generated_at (UTC ISO 8601)
   - analyst_host and analyst_platform
   - tool_version
   - report_sha256 (hash of the full report)

3. The source PCAP is opened read-only — never modified
4. All analysis is performed on in-memory copies
5. Temp files are securely deleted after analysis

This allows reports to be submitted as forensic evidence with verifiable chain-of-custody metadata.`,
  },
];

export default function DocsPage() {
  return (
    <Layout>
      <div className="max-w-screen-lg mx-auto px-6 py-10 fade-in">
        <div className="mb-10">
          <div className="text-[#8BFF7A] text-xs font-mono uppercase tracking-[0.4em] mb-2">Documentation</div>
          <h1 className="text-[#F3F7F4] text-3xl font-bold">AVALOK Reference</h1>
          <p className="text-[#7F948B] text-sm mt-2">
            Passive Email TLS Forensics & Cryptographic Risk Assessment
          </p>
        </div>

        <div className="space-y-5">
          {sections.map(({ icon, title, content }) => (
            <Card key={title}>
              <div className="flex items-center gap-3 mb-4">
                <span className="text-[#8BFF7A]">{icon}</span>
                <h2 className="text-[#F3F7F4] font-mono text-sm font-semibold uppercase tracking-wider">{title}</h2>
              </div>
              <pre className="text-[#B8C8C0] text-xs font-mono leading-relaxed whitespace-pre-wrap">
                {content}
              </pre>
            </Card>
          ))}
        </div>
      </div>
    </Layout>
  );
}
