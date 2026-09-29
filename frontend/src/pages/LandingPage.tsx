import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'motion/react';
import {
  Sparkles,
  Shield,
  Activity,
  AlertTriangle,
  Lock,
  Network,
  Upload,
  FileText,
  Search,
  Check,
  ChevronRight,
  Menu,
  X,
  Radio,
  Cpu,
  Terminal,
  Paperclip,
  ExternalLink,
  Copy,
  Sliders,
} from 'lucide-react';
import {
  LogoMark,
  AppleButton,
  SectionEyebrow,
  gradientStyle,
} from '../components/AuraPrimitives';

interface WireSessionItem {
  id: string;
  host: string;
  endpoints: string;
  protocol: 'SMTP' | 'SMTPS' | 'IMAPS' | 'POP3S';
  protocolColor: string;
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  gradeColor: string;
  gradeBg: string;
  title: string;
  summaryTitle: string;
  summaryText: string;
  time: string;
  anomalyScore: number;
  anomalyDetected: boolean;
  packetOffset: string;
  observedValue: string;
  ruleViolated: string;
  remediation: string;
  evidenceChain: string;
  transcript: {
    sender: 'Client' | 'Server' | 'Anomaly';
    text: string;
    anomaly?: boolean;
  }[];
  attachment: string;
}

const WIRE_SESSIONS: WireSessionItem[] = [
  {
    id: '1',
    host: 'mail3.corp.com',
    endpoints: '45.33.32.156:25 ⟷ 192.168.1.50:49210',
    protocol: 'SMTP',
    protocolColor: '#00d2ff',
    grade: 'F',
    gradeColor: 'text-[#FF5C5C]',
    gradeBg: 'bg-[#FF5C5C]/15 border-[#FF5C5C]/30',
    title: 'Silent STARTTLS Downgrade & Plaintext Auth Leak',
    summaryTitle: 'AI Anomaly Flagged: Active STARTTLS Downgrade (STRIPTLS)',
    summaryText:
      'Isolation Forest anomaly score: 0.892. TCP segment reassembly confirmed client initiated STARTTLS, but handshake response was stripped by intermediary. Client fell back to cleartext, exposing raw AUTH credentials.',
    time: '09:41:22 UTC',
    anomalyScore: 0.892,
    anomalyDetected: true,
    packetOffset: 'Packet #42 · Offset 0x01A4',
    observedValue: 'AUTH PLAIN AGFsaWNlAHBhc3N3b3Jk',
    ruleViolated: 'RULE-001 (STARTTLS Downgrade) & RULE-002 (Cleartext Auth)',
    remediation:
      'Configure mandatory TLS in Postfix / Exim: smtpd_tls_security_level = encrypt; disable plaintext authentication mechanisms over non-TLS connections.',
    evidenceChain:
      'PCAP SHA-256: e3b0c442... ➔ Stream 3 ➔ Packet #42 ➔ Frame Offset 0x01A4 ➔ Rule RULE-001',
    transcript: [
      { sender: 'Server', text: '220 mail3.corp.com ESMTP Postfix' },
      { sender: 'Client', text: 'EHLO client.meridian.internal' },
      { sender: 'Server', text: '250-mail3.corp.com\n250-STARTTLS\n250-AUTH LOGIN PLAIN' },
      { sender: 'Client', text: 'STARTTLS' },
      {
        sender: 'Anomaly',
        text: '⚠️ [MITM INJECTED / SUPPRESSED TLS CLIENTHELLO IN PACKET #41]',
        anomaly: true,
      },
      { sender: 'Server', text: '502 5.5.1 Command not implemented (Stripped)' },
      { sender: 'Client', text: 'AUTH PLAIN AGFsaWNlAHBhc3N3b3Jk', anomaly: true },
      { sender: 'Server', text: '235 2.7.0 Authentication successful' },
    ],
    attachment: 'custody-evidence-stream3.json',
  },
  {
    id: '2',
    host: 'relay.partner.net',
    endpoints: '198.51.100.24:587 ⟷ 10.0.2.18:51240',
    protocol: 'SMTPS',
    protocolColor: '#A4F4FD',
    grade: 'D',
    gradeColor: 'text-[#F59342]',
    gradeBg: 'bg-[#F59342]/15 border-[#F59342]/30',
    title: 'Deprecated TLS 1.0 & Insecure RC4/MD5 Cipher',
    summaryTitle: 'NIST SP 800-52 Rev.2 Violation: RFC 8996 Obsolete Protocol',
    summaryText:
      'Handshake negotiated TLS 1.0 using TLS_RSA_WITH_RC4_128_SHA. RC4 stream cipher is cryptographically broken and TLS 1.0 was formally deprecated under RFC 8996.',
    time: '08:12:04 UTC',
    anomalyScore: 0.764,
    anomalyDetected: true,
    packetOffset: 'Packet #19 · Offset 0x00D2',
    observedValue: 'TLS 1.0 (0x0301) / TLS_RSA_WITH_RC4_128_SHA (0x0005)',
    ruleViolated: 'RULE-004 (Deprecated TLS Version) & RULE-006 (Broken Cipher)',
    remediation:
      'Enforce TLS 1.2 / 1.3 only. Modernize cipher suites to AES-GCM or ChaCha20-Poly1305 with Ephemeral Diffie-Hellman.',
    evidenceChain:
      'PCAP SHA-256: 7a82fb10... ➔ Stream 8 ➔ Packet #19 ➔ Handshake ServerHello ➔ Rule RULE-004',
    transcript: [
      { sender: 'Client', text: 'TLS ClientHello (Supported: TLS 1.0 - 1.2)' },
      { sender: 'Server', text: 'TLS ServerHello: Selected TLS 1.0 / RC4-SHA' },
      { sender: 'Server', text: 'Certificate: CN=relay.partner.net' },
      { sender: 'Client', text: 'ClientKeyExchange (RSA static exchange - No PFS)' },
    ],
    attachment: 'custody-evidence-stream8.json',
  },
  {
    id: '3',
    host: 'imap.internal.lan',
    endpoints: '10.0.4.12:993 ⟷ 10.0.10.88:38112',
    protocol: 'IMAPS',
    protocolColor: '#10b981',
    grade: 'C',
    gradeColor: 'text-[#F5B942]',
    gradeBg: 'bg-[#F5B942]/15 border-[#F5B942]/30',
    title: 'Self-Signed X.509 Certificate with 1024-bit RSA Key',
    summaryTitle: 'Certificate Validation Failure: Untrusted Root Authority',
    summaryText:
      'X.509 certificate validation failed chain-of-trust check. Server presents a self-signed leaf certificate signed with obsolete 1024-bit RSA key.',
    time: 'Yesterday 18:20 UTC',
    anomalyScore: 0.612,
    anomalyDetected: false,
    packetOffset: 'Packet #64 · Offset 0x03B0',
    observedValue: 'Self-Signed (Issuer == Subject) · RSA 1024-bit',
    ruleViolated: 'RULE-009 (Untrusted CA) & RULE-010 (Insufficient Key Length)',
    remediation:
      'Replace self-signed certificate with one issued by a trusted enterprise PKI or ACME authority using RSA ≥2048-bit or ECDSA P-256.',
    evidenceChain:
      'PCAP SHA-256: 91c4be81... ➔ Stream 14 ➔ Packet #64 ➔ X.509 ASN.1 Parser ➔ Rule RULE-009',
    transcript: [
      { sender: 'Client', text: 'TLS 1.2 ClientHello' },
      { sender: 'Server', text: 'TLS 1.2 ServerHello (ECDHE-RSA-AES256-GCM)' },
      { sender: 'Server', text: 'Certificate: Issuer="O=Self, CN=internal-mail"' },
      { sender: 'Client', text: 'Encrypted Handshake Message' },
    ],
    attachment: 'custody-evidence-stream14.json',
  },
  {
    id: '4',
    host: 'mx1.meridian.com',
    endpoints: '192.168.1.50:25 ⟷ 198.51.100.12:44110',
    protocol: 'SMTP',
    protocolColor: '#00d2ff',
    grade: 'D',
    gradeColor: 'text-[#F59342]',
    gradeBg: 'bg-[#F59342]/15 border-[#F59342]/30',
    title: 'Missing Perfect Forward Secrecy (Static RSA Exchange)',
    summaryTitle: 'Forward Secrecy Defect: Vulnerable to Retrospective Decryption',
    summaryText:
      'Key exchange negotiated static RSA without Ephemeral Diffie-Hellman (ECDHE/DHE). If the server private key is compromised in the future, all historical sessions can be decrypted.',
    time: 'Yesterday 14:05 UTC',
    anomalyScore: 0.589,
    anomalyDetected: false,
    packetOffset: 'Packet #28 · Offset 0x01E0',
    observedValue: 'TLS_RSA_WITH_AES_256_CBC_SHA (No PFS)',
    ruleViolated: 'RULE-008 (Missing Forward Secrecy)',
    remediation:
      'Configure TLS cipher suite priority to prefer ECDHE or DHE key exchange before static RSA.',
    evidenceChain:
      'PCAP SHA-256: 3c91af22... ➔ Stream 21 ➔ Packet #28 ➔ KeyExchange Decider ➔ Rule RULE-008',
    transcript: [
      { sender: 'Server', text: '220 mx1.meridian.com ESMTP' },
      { sender: 'Client', text: 'STARTTLS' },
      { sender: 'Server', text: '220 2.0.0 Ready to start TLS' },
      { sender: 'Client', text: 'TLS 1.2 ClientHello' },
      { sender: 'Server', text: 'ServerHello: TLS_RSA_WITH_AES_256_CBC_SHA' },
    ],
    attachment: 'custody-evidence-stream21.json',
  },
  {
    id: '5',
    host: 'gateway.cloudmail.com',
    endpoints: '104.244.42.1:25 ⟷ 192.168.1.50:58102',
    protocol: 'SMTP',
    protocolColor: '#00d2ff',
    grade: 'A+',
    gradeColor: 'text-[#3DDC97]',
    gradeBg: 'bg-[#3DDC97]/15 border-[#3DDC97]/30',
    title: 'TLS 1.3 Strict Mode · Perfect Forward Secrecy Enforced',
    summaryTitle: 'Optimal Cryptographic Posture: NIST SP 800-52 Rev.2 Compliant',
    summaryText:
      'Negotiated TLS 1.3 with TLS_AES_256_GCM_SHA384 and X25519 curve key share. Valid CA certificate chain with active OCSP stapling and zero adverse findings.',
    time: 'Mon 11:30 UTC',
    anomalyScore: 0.042,
    anomalyDetected: false,
    packetOffset: 'Packet #8 · Offset 0x00A0',
    observedValue: 'TLS 1.3 (0x0304) · X25519 · AES-256-GCM',
    ruleViolated: 'None (Clean Exchange)',
    remediation: 'No remediation required. Exemplary mail gateway configuration.',
    evidenceChain:
      'PCAP SHA-256: e8d4a921... ➔ Stream 35 ➔ Packet #8 ➔ Handshake Compliant',
    transcript: [
      { sender: 'Server', text: '220 gateway.cloudmail.com ESMTP' },
      { sender: 'Client', text: 'STARTTLS' },
      { sender: 'Server', text: '220 2.0.0 Ready to start TLS' },
      { sender: 'Client', text: 'TLS 1.3 ClientHello (KeyShare: X25519)' },
      { sender: 'Server', text: 'ServerHello: TLS_AES_256_GCM_SHA384' },
      { sender: 'Server', text: 'EncryptedExtensions + Certificate + Finished' },
    ],
    attachment: 'custody-evidence-stream35.json',
  },
  {
    id: '6',
    host: 'pop3.secure-host.org',
    endpoints: '172.16.8.99:995 ⟷ 10.0.8.44:49810',
    protocol: 'POP3S',
    protocolColor: '#f59e0b',
    grade: 'A',
    gradeColor: 'text-[#3DDC97]',
    gradeBg: 'bg-[#3DDC97]/15 border-[#3DDC97]/30',
    title: 'POP3S TLS 1.2 · Strong Cipher & Valid Trust Chain',
    summaryTitle: 'Strong Security Posture: Forward Secrecy Validated',
    summaryText:
      'Negotiated TLS 1.2 using ECDHE-RSA-AES128-GCM-SHA256. Perfect Forward Secrecy active. All certificate fields valid.',
    time: 'Mon 09:15 UTC',
    anomalyScore: 0.098,
    anomalyDetected: false,
    packetOffset: 'Packet #14 · Offset 0x0112',
    observedValue: 'TLS 1.2 · ECDHE-RSA-AES128-GCM · 2048-bit RSA',
    ruleViolated: 'None (Clean Exchange)',
    remediation: 'Consider enabling TLS 1.3 for 1-RTT zero-overhead handshakes.',
    evidenceChain:
      'PCAP SHA-256: 41b9e283... ➔ Stream 41 ➔ Packet #14 ➔ Verified TLS 1.2',
    transcript: [
      { sender: 'Client', text: 'TLS 1.2 ClientHello' },
      { sender: 'Server', text: 'ServerHello: ECDHE-RSA-AES128-GCM-SHA256' },
      { sender: 'Server', text: 'Certificate: CN=pop3.secure-host.org (Valid)' },
      { sender: 'Client', text: 'Encrypted Handshake Complete' },
    ],
    attachment: 'custody-evidence-stream41.json',
  },
];

export default function LandingPage() {
  const navigate = useNavigate();
  const [activeSessionId, setActiveSessionId] = useState<string>('1');
  const [activeFilter, setActiveFilter] = useState<string>('All');
  const [yearly, setYearly] = useState<boolean>(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState<boolean>(false);
  const [copiedEvidence, setCopiedEvidence] = useState<boolean>(false);

  const selectedSession =
    WIRE_SESSIONS.find((s) => s.id === activeSessionId) || WIRE_SESSIONS[0];

  const handleCopyEvidence = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedEvidence(true);
    setTimeout(() => setCopiedEvidence(false), 2000);
  };

  return (
    <div className="relative min-h-screen overflow-x-hidden bg-[#0c0c0c] text-white">
      {/* Root SVG noise filter (subtle grain, multiply blend) */}
      <svg className="absolute w-0 h-0 pointer-events-none" aria-hidden="true">
        <defs>
          <filter id="c3-noise">
            <feTurbulence
              type="fractalNoise"
              baseFrequency="0.9"
              numOctaves="2"
              stitchTiles="stitch"
            />
            <feColorMatrix
              type="matrix"
              values="0 0 0 0 0  0 0 0 0 0  0 0 0 0 0  0 0 0 0.35 0"
            />
            <feComposite in2="SourceGraphic" operator="in" result="noise" />
            <feBlend in="SourceGraphic" in2="noise" mode="multiply" />
          </filter>
        </defs>
      </svg>

      {/* Global background video (fixed, behind everything) */}
      <div className="fixed inset-0 z-0 pointer-events-none">
        <video
          autoPlay
          loop
          muted
          playsInline
          className="w-full h-full object-cover pointer-events-none opacity-80"
          src="https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260508_064122_c4750c0e-7476-4b44-94a2-a85a65c63bf2.mp4"
        />
        <div className="absolute inset-0 bg-radial-vignette pointer-events-none" />
      </div>

      {/* Two fixed vertical guide lines at 36rem container edges */}
      <div className="hidden md:block pointer-events-none fixed inset-y-0 left-1/2 -translate-x-[calc(50%+36rem)] w-px bg-white/10 z-[5]" />
      <div className="hidden md:block pointer-events-none fixed inset-y-0 left-1/2 translate-x-[calc(-50%+36rem)] w-px bg-white/10 z-[5]" />

      {/* SECTION 1 — NAVBAR */}
      <motion.header
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, ease: 'easeOut' }}
        className="relative z-20 w-full pt-6"
      >
        <div className="max-w-6xl mx-auto px-6 flex items-center justify-between">
          {/* Left: LogoMark + AVALOK brand */}
          <Link to="/" className="inline-flex items-center gap-3 transition-transform hover:scale-105 group">
            <LogoMark className="w-8 h-8" />
            <div className="flex flex-col">
              <span className="text-white font-bold text-base tracking-wider uppercase font-mono group-hover:text-cyan-400 transition-colors">
                AVALOK
              </span>
              <span className="text-[10px] font-mono tracking-widest text-white/40 uppercase hidden sm:inline">
                Passive Email TLS Forensics
              </span>
            </div>
          </Link>

          {/* Center: Navigation Links */}
          <nav className="hidden md:flex items-center gap-7">
            {[
              { name: 'Workbench', href: '#workbench' },
              { name: 'Detection Rules', href: '#triage' },
              { name: 'Topology', href: '/sessions' },
              { name: 'Forensic Reports', href: '/reports' },
              { name: 'Pricing & Tiers', href: '#pricing' },
              { name: 'Documentation', href: '/docs' },
            ].map((item, i) => (
              <motion.a
                key={item.name}
                href={item.href}
                initial={{ opacity: 0, y: -8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.4, delay: 0.1 + i * 0.05 }}
                className="text-white/70 text-xs font-mono font-medium hover:text-white transition-colors"
              >
                {item.name}
              </motion.a>
            ))}
          </nav>

          {/* Right desktop: Analyze & Dashboard pills */}
          <div className="hidden md:flex items-center gap-3">
            <Link
              to="/dashboard"
              className="text-xs font-mono text-white/70 hover:text-white px-3.5 py-2 rounded-full border border-white/10 hover:border-white/20 transition-all flex items-center gap-1.5 bg-white/[0.02]"
            >
              <Activity className="w-3.5 h-3.5 text-cyan-400" />
              <span>SOC Dashboard</span>
            </Link>
            <AppleButton
              label="Analyze PCAP"
              icon={<Upload className="w-4 h-4 text-cyan-600" />}
              onClick={() => navigate('/analyze')}
            />
          </div>

          {/* Mobile right: Menu toggle */}
          <div className="md:hidden flex items-center gap-2">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="w-10 h-10 rounded-full border border-white/10 bg-white/5 flex items-center justify-center text-white/80 hover:text-white cursor-pointer"
              aria-label="Toggle menu"
            >
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>

        {/* Mobile menu dropdown */}
        <AnimatePresence>
          {mobileMenuOpen && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="md:hidden bg-[#0c0c0c]/95 border-b border-white/10 px-6 py-4 mt-3 flex flex-col gap-3 backdrop-blur-xl"
            >
              <a
                href="#workbench"
                onClick={() => setMobileMenuOpen(false)}
                className="text-white/80 py-2 text-xs font-mono"
              >
                Forensic Workbench
              </a>
              <a
                href="#triage"
                onClick={() => setMobileMenuOpen(false)}
                className="text-white/80 py-2 text-xs font-mono"
              >
                Detection Rules
              </a>
              <Link
                to="/dashboard"
                onClick={() => setMobileMenuOpen(false)}
                className="text-white/80 py-2 text-xs font-mono flex items-center gap-2"
              >
                <Activity className="w-4 h-4 text-cyan-400" />
                Security Posture Dashboard
              </Link>
              <Link
                to="/sessions"
                onClick={() => setMobileMenuOpen(false)}
                className="text-white/80 py-2 text-xs font-mono flex items-center gap-2"
              >
                <Network className="w-4 h-4 text-emerald-400" />
                Network Topology Graph
              </Link>
              <Link
                to="/reports"
                onClick={() => setMobileMenuOpen(false)}
                className="text-white/80 py-2 text-xs font-mono flex items-center gap-2"
              >
                <FileText className="w-4 h-4 text-blue-400" />
                Forensic Reports
              </Link>
              <a
                href="#pricing"
                onClick={() => setMobileMenuOpen(false)}
                className="text-white/80 py-2 text-xs font-mono"
              >
                Pricing & Deployment
              </a>
              <div className="pt-2">
                <AppleButton
                  full
                  label="Analyze PCAP Now"
                  icon={<Upload className="w-4 h-4 text-cyan-600" />}
                  onClick={() => navigate('/analyze')}
                />
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.header>

      {/* SECTION 2 — HERO (TAILORED FOR AVALOK) */}
      <section className="relative z-10 pt-16 md:pt-28 pb-20 text-center flex flex-col items-center max-w-4xl mx-auto px-6">
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.2 }}
          className="mb-5"
        >
          <SectionEyebrow
            label="Passive Email TLS Forensics"
            tag="NIST SP 800-52 Rev.2 · RFC 8996"
          />
        </motion.div>

        <motion.h1
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.3, ease: [0.22, 1, 0.36, 1] }}
          className="text-5xl sm:text-6xl md:text-8xl font-semibold tracking-tight leading-[0.9] flex flex-col items-center"
        >
          <span className="text-white">Your email wire.</span>
          <span className="animate-shiny mt-1 md:mt-2" style={gradientStyle}>
            Revitalized
          </span>
        </motion.h1>

        <motion.p
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.5 }}
          className="mt-8 text-white/60 max-w-xl text-base leading-[1.6]"
        >
          AVALOK is the premier AI-assisted email TLS forensics platform. It passively inspects SMTP, IMAP, and POP3 captures, detects silent STARTTLS downgrade attacks, audits cipher suites against NIST standards, and delivers bulletproof cryptographic clarity.
        </motion.p>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.7 }}
          className="mt-8 flex flex-col sm:flex-row items-center gap-3.5"
        >
          <AppleButton
            label="Analyze PCAP Now"
            icon={<Upload className="w-4 h-4 text-cyan-600" />}
            onClick={() => navigate('/analyze')}
          />
          <Link
            to="/dashboard"
            className="group inline-flex items-center gap-2 rounded-full border border-white/15 bg-white/5 text-white font-medium text-sm px-5 py-3 hover:bg-white/10 transition-all cursor-pointer shadow-md"
          >
            <Activity className="w-4 h-4 text-cyan-400" />
            <span>Explore SOC Dashboard</span>
            <ChevronRight className="w-4 h-4 transition-transform group-hover:translate-x-[1px]" />
          </Link>
        </motion.div>

        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.6, delay: 0.8 }}
          className="mt-4 text-xs font-mono text-white/40 tracking-wide flex items-center gap-2"
        >
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          <span>100% Passive & Offline · SHA-256 Evidentiary Chain of Custody · Zero Packets Injected</span>
        </motion.div>
      </section>

      {/* SECTION 3 — MACOS MENU BAR STRIP */}
      <motion.section
        initial={{ opacity: 0, y: 15 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.9 }}
        className="relative z-10 w-full h-10 bg-black/40 backdrop-blur-md border-t border-b border-white/10"
      >
        <div className="max-w-6xl mx-auto px-6 h-full flex items-center justify-between text-xs select-none">
          {/* Left menu items */}
          <div className="flex items-center gap-4 text-white/80">
            <div className="flex items-center gap-2">
              <LogoMark className="w-4 h-4" />
              <span className="font-bold text-white tracking-tight font-mono">AVALOK</span>
            </div>
            {['PCAP Ingest', 'Stream Reassembly', 'Weakness Catalog', 'AI Isolation Forest', 'Forensic PDF', 'NIST Audit'].map(
              (item, idx) => (
                <span
                  key={item}
                  className={`cursor-pointer hover:text-white transition-colors font-mono text-[11px] ${
                    idx > 2 ? 'hidden sm:inline' : ''
                  } ${idx > 3 ? 'hidden md:inline' : ''}`}
                >
                  {item}
                </span>
              )
            )}
          </div>

          {/* Right items */}
          <div className="flex items-center gap-3 text-white/60">
            <Search className="w-3.5 h-3.5 cursor-pointer hover:text-white" />
            <span className="font-mono text-[11px] tracking-tight text-cyan-300 bg-white/5 px-2 py-0.5 rounded border border-white/10">
              SHA-256 Verified · Passive Mode
            </span>
            <span className="font-mono text-[11px] tracking-tight text-white/80 hidden sm:inline">
              Wed May 6 1:09 PM
            </span>
          </div>
        </div>
      </motion.section>

      {/* SECTION 4 — REALISTIC FORENSIC WORKBENCH MOCKUP (CUSTOMIZED INBOX MOCKUP) */}
      <section className="relative z-10 max-w-6xl mx-auto px-6 py-16 md:py-24" id="workbench">
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 1.1, ease: [0.22, 1, 0.36, 1] }}
          className="relative rounded-2xl overflow-hidden border border-white/10 bg-[#0e1014]/90 backdrop-blur-2xl shadow-2xl shadow-black/80"
        >
          {/* Title bar with traffic lights */}
          <div className="h-10 border-b border-white/10 bg-black/40 px-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-[#ff5f57] inline-block shadow-sm" />
              <span className="w-3 h-3 rounded-full bg-[#febc2e] inline-block shadow-sm" />
              <span className="w-3 h-3 rounded-full bg-[#28c840] inline-block shadow-sm" />
            </div>
            <div className="text-xs text-white/50 font-mono tracking-wide flex items-center gap-2">
              <Lock className="w-3 h-3 text-cyan-400" />
              <span>AVALOK — Email TLS Forensic Telemetry Workbench</span>
            </div>
            <div className="w-12" />
          </div>

          {/* Body: 3-column forensic inspector */}
          <div className="grid grid-cols-12 h-[560px]">
            {/* Column 1: Stream categories & protocols (Sidebar) */}
            <div className="col-span-12 md:col-span-3 border-r border-white/10 bg-black/30 p-4 flex flex-col justify-between overflow-y-auto">
              <div>
                <button
                  onClick={() => navigate('/analyze')}
                  className="w-full flex items-center justify-center gap-2 rounded-lg bg-white text-black text-xs font-semibold px-3 py-2.5 shadow-md hover:bg-white/90 transition-all cursor-pointer"
                >
                  <Sparkles className="w-3.5 h-3.5 text-cyan-600" />
                  <span>Analyze Capture PCAP</span>
                </button>

                {/* Filters / Folder Navigation */}
                <div className="mt-5 space-y-0.5 text-xs font-medium font-mono">
                  {[
                    { label: 'All Wire Streams', count: 48, icon: Network },
                    { label: 'STARTTLS Downgrades', count: 3, icon: AlertTriangle, highlight: true },
                    { label: 'Deprecated Ciphers', count: 14, icon: Shield },
                    { label: 'Untrusted Certs', count: 5, icon: Lock },
                    { label: 'Strict TLS 1.3 PFS', count: 26, icon: Check },
                  ].map((cat) => {
                    const Icon = cat.icon;
                    const isActive = activeFilter === cat.label || (activeFilter === 'All' && cat.label === 'All Wire Streams');
                    return (
                      <button
                        key={cat.label}
                        onClick={() => setActiveFilter(cat.label)}
                        className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded-md transition-colors cursor-pointer text-left ${
                          isActive
                            ? 'bg-white/10 text-white font-semibold'
                            : 'text-white/60 hover:bg-white/5 hover:text-white'
                        }`}
                      >
                        <div className="flex items-center gap-2 truncate">
                          <Icon className={`w-3.5 h-3.5 ${cat.highlight ? 'text-rose-400' : 'text-white/50'}`} />
                          <span className="truncate">{cat.label}</span>
                        </div>
                        <span
                          className={`text-[10px] px-1.5 py-0.2 rounded-full font-mono ${
                            cat.highlight
                              ? 'bg-rose-500/20 text-rose-300'
                              : isActive
                              ? 'bg-white/20 text-white'
                              : 'text-white/40'
                          }`}
                        >
                          {cat.count}
                        </span>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Protocol Filters */}
              <div className="mt-6 pt-4 border-t border-white/10">
                <div className="text-[10px] font-semibold uppercase tracking-wider text-white/40 mb-2 px-1 font-mono">
                  Captured Protocols
                </div>
                <div className="space-y-1.5 text-xs text-white/70 font-mono">
                  {[
                    { name: 'SMTP (Port 25/587)', color: '#00d2ff' },
                    { name: 'SMTPS (Port 465)', color: '#A4F4FD' },
                    { name: 'IMAPS (Port 993)', color: '#10b981' },
                    { name: 'POP3S (Port 995)', color: '#f59e0b' },
                  ].map((proto) => (
                    <div
                      key={proto.name}
                      className="flex items-center justify-between px-2 py-1 rounded hover:bg-white/5 cursor-pointer"
                    >
                      <div className="flex items-center gap-2">
                        <span
                          className="w-2 h-2 rounded-full"
                          style={{ backgroundColor: proto.color }}
                        />
                        <span className="text-[11px]">{proto.name}</span>
                      </div>
                      <Radio className="w-3 h-3 text-white/30" />
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Column 2: Captured Sessions Stream List */}
            <div className="col-span-12 md:col-span-4 border-r border-white/10 flex flex-col bg-black/15">
              {/* Search bar */}
              <div className="p-3 border-b border-white/10">
                <div className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-white/5 border border-white/10 text-xs text-white/50 focus-within:border-white/30 transition-colors font-mono">
                  <Search className="w-3.5 h-3.5 text-white/40" />
                  <input
                    type="text"
                    placeholder="Search by IP, host, or rule ID..."
                    className="w-full bg-transparent border-none outline-none text-white text-xs placeholder:text-white/40 font-mono"
                  />
                </div>
              </div>

              {/* Sessions list */}
              <div className="flex-1 overflow-y-auto divide-y divide-white/5">
                {WIRE_SESSIONS.map((session) => {
                  const isSelected = session.id === activeSessionId;
                  return (
                    <div
                      key={session.id}
                      onClick={() => setActiveSessionId(session.id)}
                      className={`p-3.5 cursor-pointer transition-colors ${
                        isSelected
                          ? 'bg-white/10 border-l-2 border-cyan-400'
                          : 'hover:bg-white/5'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2 mb-1">
                        <div className="flex items-center gap-2 truncate">
                          <span
                            className="text-[9px] font-mono font-bold px-1.5 py-0.2 rounded border"
                            style={{
                              borderColor: `${session.protocolColor}40`,
                              color: session.protocolColor,
                            }}
                          >
                            {session.protocol}
                          </span>
                          <span
                            className={`text-xs truncate font-mono ${
                              isSelected ? 'font-bold text-white' : 'text-white/80'
                            }`}
                          >
                            {session.host}
                          </span>
                        </div>
                        <span
                          className={`text-[10px] font-mono font-bold px-1.5 py-0.2 rounded border ${session.gradeBg} ${session.gradeColor}`}
                        >
                          Grade {session.grade}
                        </span>
                      </div>
                      <div className="text-xs text-white font-medium truncate mb-1">
                        {session.title}
                      </div>
                      <div className="text-[11px] text-white/50 font-mono truncate">
                        {session.endpoints}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Column 3: Forensic Inspector (Reader) */}
            <div className="col-span-12 md:col-span-5 flex flex-col bg-black/25">
              {/* Toolbar */}
              <div className="h-12 border-b border-white/10 px-4 flex items-center justify-between">
                <div className="flex items-center gap-2 text-xs font-mono text-white/70">
                  <span className="flex items-center gap-1.5 px-2 py-1 rounded bg-white/5 border border-white/10">
                    <Terminal className="w-3 h-3 text-cyan-400" />
                    <span>Reassembled TCP Stream</span>
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleCopyEvidence(selectedSession.evidenceChain)}
                    className="flex items-center gap-1 text-[11px] font-mono text-white/60 hover:text-white px-2 py-1 rounded hover:bg-white/5 transition-colors cursor-pointer"
                    title="Copy SHA-256 Provenance"
                  >
                    <Copy className="w-3 h-3" />
                    <span>{copiedEvidence ? 'Copied!' : 'Evidence Hash'}</span>
                  </button>
                  <Link
                    to="/sessions"
                    className="flex items-center gap-1 text-[11px] font-mono text-cyan-300 hover:text-white px-2 py-1 rounded hover:bg-white/5 transition-colors"
                  >
                    <span>Topology</span>
                    <ExternalLink className="w-3 h-3" />
                  </Link>
                </div>
              </div>

              {/* Inspector Header */}
              <div className="p-4 border-b border-white/5">
                <div className="flex items-center justify-between gap-2 mb-2">
                  <h3 className="text-base font-semibold text-white tracking-tight">
                    {selectedSession.title}
                  </h3>
                  <div className="flex items-center gap-1.5">
                    <span
                      className={`text-xs font-mono font-bold px-2 py-0.5 rounded-lg border ${selectedSession.gradeBg} ${selectedSession.gradeColor}`}
                    >
                      Posture: {selectedSession.grade}
                    </span>
                  </div>
                </div>
                <div className="text-xs font-mono text-white/50 flex flex-wrap items-center gap-2">
                  <span>{selectedSession.endpoints}</span>
                  <span>•</span>
                  <span>{selectedSession.packetOffset}</span>
                </div>
              </div>

              {/* Inspector Content */}
              <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs text-white/80 leading-relaxed font-mono">
                {/* AI Anomaly Assessment Card */}
                <div className="rounded-xl border border-cyan-400/30 bg-gradient-to-br from-cyan-950/30 to-[#0B2551]/30 p-3.5 shadow-inner">
                  <div className="flex items-center gap-2 text-xs font-semibold text-cyan-300 mb-1.5">
                    <Sparkles className="w-3.5 h-3.5 text-cyan-300" />
                    <span>{selectedSession.summaryTitle}</span>
                  </div>
                  <p className="text-[11px] text-white/90 leading-relaxed font-sans">
                    {selectedSession.summaryText}
                  </p>
                  <div className="mt-2.5 pt-2 border-t border-cyan-400/20 flex items-center justify-between text-[10px] text-cyan-200">
                    <span>Observed: <strong className="text-white">{selectedSession.observedValue}</strong></span>
                    <span>Rule: <strong className="text-white">{selectedSession.ruleViolated}</strong></span>
                  </div>
                </div>

                {/* Packet Conversation Transcript */}
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-white/40 mb-2 font-semibold">
                    TCP Reassembled Wire Conversation
                  </div>
                  <div className="rounded-lg bg-black/60 border border-white/10 p-3 space-y-1.5 font-mono text-[11px]">
                    {selectedSession.transcript.map((line, idx) => (
                      <div
                        key={idx}
                        className={`flex gap-2 ${
                          line.anomaly
                            ? 'text-rose-400 bg-rose-950/30 p-1 rounded font-bold'
                            : line.sender === 'Server'
                            ? 'text-cyan-300'
                            : 'text-white/80'
                        }`}
                      >
                        <span className="text-white/40 w-14 shrink-0 font-semibold select-none">
                          [{line.sender}]
                        </span>
                        <span className="break-all whitespace-pre-wrap">{line.text}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Remediation guidance */}
                <div className="rounded-lg bg-white/[0.02] border border-white/10 p-3">
                  <div className="text-[10px] uppercase tracking-wider text-white/40 mb-1 font-semibold flex items-center gap-1.5">
                    <Cpu className="w-3 h-3 text-cyan-400" />
                    <span>Recommended Server Hardening</span>
                  </div>
                  <p className="text-[11px] text-white/70 font-sans leading-relaxed">
                    {selectedSession.remediation}
                  </p>
                </div>

                {/* Evidentiary provenance pill */}
                <div className="pt-1">
                  <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-white/10 bg-white/5 hover:bg-white/10 transition-colors cursor-pointer text-xs text-white/80">
                    <Paperclip className="w-3.5 h-3.5 text-cyan-400" />
                    <span>{selectedSession.attachment} (SHA-256 Verified)</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </motion.div>
      </section>

      {/* SECTION 5 — FEATURE TRIAGE (CUSTOMIZED FOR EMAIL FORENSICS) */}
      <section className="relative z-10 max-w-6xl mx-auto px-6 py-20 md:py-28" id="triage">
        <div className="grid md:grid-cols-2 gap-10 md:gap-16 items-start">
          {/* Left Column Motion */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: '-50px' }}
            transition={{ duration: 0.7 }}
          >
            <SectionEyebrow label="Forensic Triage Engine" tag="Zero-Touch Wire Telemetry" />
            <h2 className="mt-5 text-3xl md:text-5xl font-semibold tracking-tight leading-[1.02]">
              Audit your email wire <br />
              in a single pass.
            </h2>
            <p className="mt-6 text-white/60 text-base leading-[1.6] max-w-md">
              AVALOK parses every packet segment, reconstructs TCP streams across SMTP, IMAP, and POP3, and isolates cryptographic risks from benign chatter. Defend against passive surveillance and active MITM tampering before breaches occur.
            </p>

            {/* Chips row */}
            <div className="mt-8 flex flex-wrap gap-2 font-mono">
              {[
                'STARTTLS Downgrade Detection',
                'NIST SP 800-52 Rev.2 Compliance',
                'Forward Secrecy Verification',
                'X.509 Chain-of-Trust Validation',
                'AI Isolation Forest Anomaly Detection',
                'SHA-256 Evidentiary Chain of Custody',
              ].map((chip) => (
                <span
                  key={chip}
                  className="text-xs text-white/70 px-3 py-1.5 rounded-full border border-white/10 bg-white/[0.03]"
                >
                  {chip}
                </span>
              ))}
            </div>
          </motion.div>

          {/* Right Column: Liquid-glass card */}
          <motion.div
            initial={{ opacity: 0, scale: 0.98 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true, margin: '-50px' }}
            transition={{ duration: 0.7 }}
            className="liquid-glass rounded-2xl p-5"
          >
            <div className="text-xs text-white/50 font-medium mb-4 flex items-center justify-between font-mono">
              <span>Today · 48 email sessions triaged across 4 mail servers</span>
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            </div>

            <div className="space-y-3 font-mono">
              {/* Critical Findings */}
              <div className="liquid-glass rounded-lg p-3">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-[#FF5C5C]" />
                    <span className="text-xs font-semibold text-white">Critical Weaknesses (3)</span>
                  </div>
                  <span className="text-[11px] font-mono text-rose-400 font-bold">Grade F</span>
                </div>
                <div className="space-y-1.5 text-xs text-white/80">
                  <div className="p-1.5 rounded bg-white/[0.03] hover:bg-white/[0.06] transition-colors flex items-center justify-between">
                    <span>mail3.corp.com — STARTTLS Downgrade Attack</span>
                    <span className="text-rose-400 text-[10px]">+40 pts</span>
                  </div>
                  <div className="p-1.5 rounded bg-white/[0.03] hover:bg-white/[0.06] transition-colors flex items-center justify-between">
                    <span>mail3.corp.com — Plaintext AUTH Credentials</span>
                    <span className="text-rose-400 text-[10px]">+35 pts</span>
                  </div>
                </div>
              </div>

              {/* High Weaknesses */}
              <div className="liquid-glass rounded-lg p-3">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-[#F59342]" />
                    <span className="text-xs font-semibold text-white">High Severity (7)</span>
                  </div>
                  <span className="text-[11px] font-mono text-amber-400 font-bold">Grade D</span>
                </div>
                <div className="space-y-1.5 text-xs text-white/80">
                  <div className="p-1.5 rounded bg-white/[0.03] hover:bg-white/[0.06] transition-colors flex items-center justify-between">
                    <span>relay.partner.net — Deprecated TLS 1.0 (RFC 8996)</span>
                    <span className="text-amber-400 text-[10px]">+30 pts</span>
                  </div>
                  <div className="p-1.5 rounded bg-white/[0.03] hover:bg-white/[0.06] transition-colors flex items-center justify-between">
                    <span>mx1.meridian.com — Static RSA without Forward Secrecy</span>
                    <span className="text-amber-400 text-[10px]">+20 pts</span>
                  </div>
                </div>
              </div>

              {/* Medium Weaknesses */}
              <div className="liquid-glass rounded-lg p-3">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-[#F5B942]" />
                    <span className="text-xs font-semibold text-white">Medium Severity (12)</span>
                  </div>
                  <span className="text-[11px] font-mono text-yellow-300 font-bold">Grade C</span>
                </div>
                <div className="space-y-1.5 text-xs text-white/80">
                  <div className="p-1.5 rounded bg-white/[0.03] hover:bg-white/[0.06] transition-colors flex items-center justify-between">
                    <span>imap.internal.lan — Self-Signed Untrusted Root CA</span>
                    <span className="text-yellow-300 text-[10px]">+15 pts</span>
                  </div>
                  <div className="p-1.5 rounded bg-white/[0.03] hover:bg-white/[0.06] transition-colors flex items-center justify-between">
                    <span>pop3.old.internal — Certificate Expires in 6 Days</span>
                    <span className="text-yellow-300 text-[10px]">+10 pts</span>
                  </div>
                </div>
              </div>

              {/* Verified Compliant */}
              <div className="liquid-glass rounded-lg p-3">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-[#3DDC97]" />
                    <span className="text-xs font-semibold text-white">Clean & Compliant (26)</span>
                  </div>
                  <span className="text-[11px] font-mono text-emerald-400 font-bold">Grade A+</span>
                </div>
                <div className="p-1.5 rounded bg-white/[0.03] text-xs text-white/60">
                  gateway.cloudmail.com · Strict TLS 1.3 · X25519 Ephemeral Curve · Zero Flaws
                </div>
              </div>
            </div>
          </motion.div>
        </div>
      </section>

      {/* SECTION 6 — LOGO CLOUD (STANDARDS & ENTERPRISE ECOSYSTEM) */}
      <section className="relative z-10 max-w-6xl mx-auto px-6 py-16 md:py-20">
        <p className="text-center text-xs uppercase tracking-widest text-white/40 font-mono">
          Compliant with global cryptographic standards & mail infrastructure
        </p>
        <div className="mt-10 grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-6 items-center justify-items-center font-mono">
          {[
            'NIST SP 800-52',
            'RFC 8996',
            'Postfix',
            'Dovecot',
            'Exim',
            'Exchange',
            'Wireshark',
            'Suricata',
          ].map((brand, idx) => (
            <motion.span
              key={brand}
              initial={{ opacity: 0, y: 10 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.4, delay: idx * 0.05 }}
              className="text-xs font-semibold tracking-tight text-white/50 hover:text-white transition-colors cursor-pointer select-none text-center"
            >
              {brand}
            </motion.span>
          ))}
        </div>
      </section>

      {/* SECTION 7 — TESTIMONIALS (SOC & FORENSICS LEADERS) */}
      <section
        className="relative z-10 max-w-6xl mx-auto px-6 py-20 md:py-28 border-t border-white/10"
        id="testimonials"
      >
        <div className="grid md:grid-cols-3 gap-6">
          {[
            {
              quote:
                'AVALOK caught a silent STARTTLS stripping attack across our partner relay that our perimeter IDS completely missed. Having packet-level evidentiary provenance made remediation instant.',
              name: 'Marcus Vance',
              role: 'Lead SOC Analyst',
              company: 'MERIDIAN FINANCIAL',
            },
            {
              quote:
                'The deterministic A+ through F posture grades and "Why this grade?" decision breakdown made board compliance reporting seamless. It is SSL Labs for the entire email wire.',
              name: 'Dr. Aris Thorne',
              role: 'Chief Information Security Officer',
              company: 'HEXACORP INFRASTRUCTURE',
            },
            {
              quote:
                'Zero network footprint and strict SHA-256 custody hashing make AVALOK admissible in formal forensic audits. It has fundamentally modernized how we inspect mail server hygiene.',
              name: 'Elena Rostova',
              role: 'Principal Incident Responder',
              company: 'CYBRIS LABS',
            },
          ].map((item, idx) => (
            <motion.figure
              key={item.name}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.6, delay: idx * 0.1 }}
              className="liquid-glass rounded-2xl p-6 flex flex-col justify-between"
            >
              <blockquote className="text-sm text-white/80 leading-[1.6]">
                &ldquo;{item.quote}&rdquo;
              </blockquote>
              <figcaption className="mt-6 pt-5 border-t border-white/10">
                <div className="text-sm font-semibold text-white">{item.name}</div>
                <div className="text-xs text-white/50">{item.role}</div>
                <div className="mt-1 text-xs text-cyan-300 font-mono font-semibold tracking-wide uppercase">
                  {item.company}
                </div>
              </figcaption>
            </motion.figure>
          ))}
        </div>
      </section>

      {/* SECTION 8 — PRICING & DEPLOYMENT TIERS (TAILORED FOR AVALOK) */}
      <section className="c3-pricing-section" id="pricing">
        {/* Pricing specific noise filter */}
        <svg className="absolute w-0 h-0 pointer-events-none" aria-hidden="true">
          <defs>
            <filter id="c3-noise">
              <feTurbulence
                type="fractalNoise"
                baseFrequency="0.5"
                numOctaves="2"
                stitchTiles="stitch"
              />
              <feComponentTransfer>
                <feFuncA type="linear" slope="0.075" />
              </feComponentTransfer>
              <feComposite in2="SourceGraphic" operator="in" result="noise" />
              <feBlend in="SourceGraphic" in2="noise" mode="overlay" />
            </filter>
          </defs>
        </svg>

        {/* Watermark with custom typography */}
        <div className="c3-watermark-container">
          <div className="c3-watermark-main">
            <span className="c3-watermark-line-1">Your email wire.</span>
            <span className="c3-watermark-line-2">Revitalized</span>
          </div>
        </div>

        {/* Pricing Cards Grid */}
        <div className="c3-grid">
          {/* Plan 1: Community / Open Source */}
          <div className="c3-card">
            <span className="c3-tier-small font-mono">Community</span>
            <span className="c3-tier-large">Free</span>
            <p className="c3-desc">
              For security researchers, incident responders, and independent forensic analysts.
            </p>
            <ul className="c3-list">
              <li>
                <span className="c3-check">
                  <Check className="w-3.5 h-3.5 text-white" />
                </span>
                <span>Up to 50MB PCAP file analysis</span>
              </li>
              <li>
                <span className="c3-check">
                  <Check className="w-3.5 h-3.5 text-white" />
                </span>
                <span>16-rule cryptographic weakness catalog</span>
              </li>
              <li>
                <span className="c3-check">
                  <Check className="w-3.5 h-3.5 text-white" />
                </span>
                <span>SMTP, IMAP, POP3 stream reassembly</span>
              </li>
              <li>
                <span className="c3-check">
                  <Check className="w-3.5 h-3.5 text-white" />
                </span>
                <span>Interactive network topology visualization</span>
              </li>
              <li>
                <span className="c3-check">
                  <Check className="w-3.5 h-3.5 text-white" />
                </span>
                <span>100% offline & passive analysis</span>
              </li>
            </ul>
            <button
              onClick={() => navigate('/analyze')}
              className="c3-btn cursor-pointer"
            >
              Analyze PCAP Free
            </button>
          </div>

          {/* Plan 2: Professional SOC */}
          <div className="c3-card">
            <span className="c3-tier-small font-mono">Professional SOC</span>
            <span className="c3-tier-large">{yearly ? '$490/y' : '$49/m'}</span>
            <p className="c3-desc">
              For enterprise SOCs, red/blue teams, and regulatory compliance auditors.
            </p>
            <ul className="c3-list">
              <li>
                <span className="c3-check">
                  <Check className="w-3.5 h-3.5 text-white" />
                </span>
                <span>Unlimited PCAP capture analysis size</span>
              </li>
              <li>
                <span className="c3-check">
                  <Check className="w-3.5 h-3.5 text-white" />
                </span>
                <span>Dual-input: Raw PCAP & JSON report ingestion</span>
              </li>
              <li>
                <span className="c3-check">
                  <Check className="w-3.5 h-3.5 text-white" />
                </span>
                <span>AI Isolation Forest anomaly detection</span>
              </li>
              <li>
                <span className="c3-check">
                  <Check className="w-3.5 h-3.5 text-white" />
                </span>
                <span>Formal forensic PDF & HTML report exports</span>
              </li>
              <li>
                <span className="c3-check">
                  <Check className="w-3.5 h-3.5 text-white" />
                </span>
                <span>SHA-256 evidentiary chain-of-custody tracking</span>
              </li>
            </ul>
            <button
              onClick={() => navigate('/dashboard')}
              className="c3-btn cursor-pointer"
            >
              Deploy Pro SOC
            </button>
          </div>

          {/* Plan 3: Enterprise Air-Gap */}
          <div className="c3-card c3-card-pro">
            <span className="c3-tier-small font-mono">Enterprise Air-Gap</span>
            <span className="c3-tier-large">{yearly ? '$1,990/y' : '$199/m'}</span>
            <p className="c3-desc">
              For critical infrastructure, defense contractors, and air-gapped forensic laboratories.
            </p>
            <ul className="c3-list">
              <li>
                <span className="c3-check">
                  <Check className="w-3.5 h-3.5 text-white" />
                </span>
                <span>Continuous TAP capture ingestion</span>
              </li>
              <li>
                <span className="c3-check">
                  <Check className="w-3.5 h-3.5 text-white" />
                </span>
                <span>Multi-tenant host posture grading (A+ to F)</span>
              </li>
              <li>
                <span className="c3-check">
                  <Check className="w-3.5 h-3.5 text-white" />
                </span>
                <span>SIEM/SOAR integration & REST API access</span>
              </li>
              <li>
                <span className="c3-check">
                  <Check className="w-3.5 h-3.5 text-white" />
                </span>
                <span>100% offline air-gapped container packaging</span>
              </li>
              <li>
                <span className="c3-check">
                  <Check className="w-3.5 h-3.5 text-white" />
                </span>
                <span>Dedicated cryptographic engineer support</span>
              </li>
            </ul>
            <button
              onClick={() => navigate('/docs')}
              className="c3-btn cursor-pointer"
            >
              Contact Enterprise
            </button>
          </div>
        </div>

        {/* Toggle switch below */}
        <div className="c3-toggle-wrap">
          <span className="text-sm font-medium text-white/80 font-mono">Annual Billing (2 Months Free)</span>
          <button
            onClick={() => setYearly(!yearly)}
            className={`c3-toggle ${yearly ? 'active' : ''}`}
            aria-label="Toggle annual billing"
          >
            <div className="c3-toggle-knob" />
          </button>
        </div>
      </section>

      {/* SECTION 9 — FINAL CTA */}
      <section className="relative z-10 max-w-6xl mx-auto px-6 py-20 md:py-32">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.8 }}
          className="liquid-glass relative overflow-hidden rounded-3xl px-8 py-16 md:py-24 text-center"
        >
          {/* Radial glow overlay */}
          <div
            className="absolute inset-0 pointer-events-none"
            style={{
              background:
                'radial-gradient(600px circle at 50% 0%, rgba(0,210,255,0.15), transparent 70%)',
              opacity: 0.35,
            }}
          />

          <h2 className="relative z-10 text-4xl md:text-6xl font-semibold tracking-tight leading-[1.02]">
            Close the blind spots. <br />
            Secure your email wire.
          </h2>

          <p className="relative z-10 mt-6 text-white/60 max-w-lg mx-auto text-sm leading-[1.6]">
            Join cybersecurity operators, forensic investigators, and infrastructure teams who eliminate email cryptographic vulnerabilities before adversaries exploit them.
          </p>

          <div className="relative z-10 mt-8 flex flex-col sm:flex-row items-center justify-center gap-4">
            <AppleButton
              label="Analyze PCAP Ingest"
              icon={<Upload className="w-4 h-4 text-cyan-600" />}
              onClick={() => navigate('/analyze')}
            />
            <button
              onClick={() => navigate('/dashboard')}
              className="group inline-flex items-center gap-2 rounded-full border border-white/15 text-white text-sm font-medium px-5 py-3 hover:bg-white/5 transition-colors cursor-pointer"
            >
              <span>Launch Live Dashboard</span>
              <ChevronRight className="w-4 h-4 transition-transform duration-200 group-hover:translate-x-[1px]" />
            </button>
          </div>
        </motion.div>
      </section>

      {/* FOOTER: CONNECTING AVALOK ENGINE */}
      <footer className="relative z-10 border-t border-white/10 py-12 px-6 bg-black/40 backdrop-blur-md">
        <div className="max-w-6xl mx-auto flex flex-col md:flex-row items-center justify-between gap-6">
          <div className="flex items-center gap-3">
            <LogoMark className="w-6 h-6" />
            <div>
              <div className="text-sm font-semibold tracking-tight text-white font-mono">AVALOK</div>
              <div className="text-xs text-white/40">Passive Email TLS Forensics & Cryptographic Threat Intelligence</div>
            </div>
          </div>

          <div className="flex items-center gap-6 text-xs text-white/60 font-mono">
            <Link to="/dashboard" className="hover:text-white transition-colors">
              SOC Dashboard
            </Link>
            <Link to="/analyze" className="hover:text-white transition-colors">
              Analyze PCAP
            </Link>
            <Link to="/sessions" className="hover:text-white transition-colors">
              Session Graph
            </Link>
            <Link to="/reports" className="hover:text-white transition-colors">
              Evidence Reports
            </Link>
            <Link to="/docs" className="hover:text-white transition-colors">
              Documentation
            </Link>
          </div>

          <div className="text-xs text-white/40 font-mono">
            &copy; 2026 AVALOK // SecureMailScope. All rights reserved.
          </div>
        </div>
      </footer>
    </div>
  );
}
