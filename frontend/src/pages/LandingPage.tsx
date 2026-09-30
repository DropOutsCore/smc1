import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'motion/react';
import {
  Shield,
  ArrowRight,
  Check,
  Terminal,
  AlertTriangle,
  ChevronDown,
  Lock,
  Cpu,
  Layers,
  FileText,
  Search,
} from 'lucide-react';
import { Navbar } from '../components/Navbar';
import type { SectionItem } from '../components/Navbar';
import { AvalokButton, AvalokOutlineButton, SectionEyebrow } from '../components/AuraPrimitives';
import { Squares } from '../components/Squares';
import { HorizontalGallery } from '../components/HorizontalGallery';

const SECTIONS: SectionItem[] = [
  { id: 'hero', label: 'Overview' },
  { id: 'topology', label: 'Topology' },
  { id: 'engine', label: 'Forensic Engine' },
  { id: 'reports', label: 'Protocols & Reports' },
];

export default function LandingPage() {
  const navigate = useNavigate();
  const [activeSection, setActiveSection] = useState('hero');

  // Track active section on scroll
  useEffect(() => {
    const handleScroll = () => {
      const scrollPos = window.scrollY + 200;
      for (const section of SECTIONS) {
        const el = document.getElementById(section.id);
        if (el) {
          const top = el.offsetTop;
          const height = el.offsetHeight;
          if (scrollPos >= top && scrollPos < top + height) {
            setActiveSection(section.id);
            break;
          }
        }
      }
    };
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const scrollToSection = (id: string) => {
    const el = document.getElementById(id);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'start' });
      setActiveSection(id);
    }
  };

  return (
    <div className="min-h-screen bg-[#0d1117] text-white selection:bg-[#48BB36]/30 font-sans relative overflow-x-hidden">
      
      {/* Floating Style Navbar */}
      <Navbar
        sections={SECTIONS}
        activeSection={activeSection}
        onSelectSection={scrollToSection}
      />

      {/* ========================================================
          1. FULL-SCREEN HERO SECTION (WITH SQUARES ANIMATION)
             Left: National Emblem Image
             Right: Headline, Description, Buttons, Badges
         ======================================================== */}
      <section
        id="hero"
        className="min-h-screen w-full relative flex items-center justify-center pt-24 pb-14 px-4 sm:px-6 overflow-hidden border-b border-white/10"
      >
        {/* Animated Squares Background Canvas */}
        <div className="absolute inset-0 z-0">
          <Squares
            direction="diagonal"
            speed={0.4}
            squareSize={46}
            borderColor="rgba(255, 255, 255, 0.05)"
            hoverFillColor="rgba(72, 187, 54, 0.16)"
          />
        </div>

        {/* Hero Content: Parallel Grid (Left: Emblem, Right: Content) */}
        <div className="relative z-10 max-w-7xl mx-auto w-full grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-12 items-center">
          
          {/* Left Side: National Emblem of India */}
          <motion.div
            initial={{ opacity: 0, scale: 0.95, x: -20 }}
            animate={{ opacity: 1, scale: 1, x: 0 }}
            transition={{ duration: 0.6, ease: 'easeOut' }}
            className="lg:col-span-5 flex flex-col items-center justify-center"
          >
            <div className="relative group p-6 sm:p-8 rounded-3xl bg-white/[0.02] border border-white/10 backdrop-blur-xl shadow-2xl flex flex-col items-center">
              {/* Ethereal Glow Backlight */}
              <div className="absolute -inset-1 rounded-3xl bg-gradient-to-b from-[#48BB36]/20 via-white/5 to-transparent blur-2xl opacity-60 group-hover:opacity-90 transition-opacity pointer-events-none" />

              {/* State Emblem Image */}
              <div className="relative w-56 sm:w-64 md:w-72 lg:w-80 h-auto aspect-square flex items-center justify-center">
                <img
                  src="/images/emblem.png"
                  alt="State Emblem of India - Satyameva Jayate"
                  className="max-h-full max-w-full object-contain filter drop-shadow-[0_10px_30px_rgba(0,0,0,0.8)] brightness-105 contrast-105 transition-transform duration-300 group-hover:scale-105"
                />
              </div>

              {/* Emblem Caption */}
              <div className="mt-4 pt-3 border-t border-white/10 w-full text-center">
                <span className="text-white/80 font-mono text-[11px] font-semibold tracking-widest uppercase block">
                  NATIONAL CYBER FORENSICS
                </span>
                <span className="text-white/40 font-mono text-[10px] tracking-wider block mt-0.5">
                  Autonomous Inspection · Zero Wire Injection
                </span>
              </div>
            </div>
          </motion.div>

          {/* Right Side: Headline, Description, Buttons, Badges */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.6, delay: 0.15, ease: 'easeOut' }}
            className="lg:col-span-7 flex flex-col items-start text-left"
          >
            {/* Top Pill */}
            <div className="mb-4 inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/[0.04] border border-white/10 text-xs font-mono text-white/70">
              <span className="w-2 h-2 rounded-full bg-[#48BB36] shadow-[0_0_8px_rgba(72,187,54,0.8)]" />
              <span>NIST SP 800-52 Rev. 2 · RFC 8996 Verified</span>
            </div>

            {/* Headline */}
            <h1 className="text-3xl sm:text-5xl xl:text-6xl font-extrabold tracking-tight text-white leading-[1.08]">
              See the Security <br />
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-white via-white/90 to-[#48BB36]">
                Hidden on the Wire.
              </span>
            </h1>

            {/* Description */}
            <p className="mt-5 text-white/70 text-sm sm:text-base lg:text-lg leading-relaxed max-w-2xl">
              AVALOK analyzes SMTP, IMAP and POP3 traffic directly from PCAP/PCAPNG captures to uncover TLS misconfigurations, cryptographic weaknesses, certificate issues and plaintext email exposure — without connecting to or probing live infrastructure.
            </p>

            {/* Buttons */}
            <div className="mt-7 flex flex-wrap items-center gap-4">
              <AvalokButton
                label="Analyze a PCAP"
                onClick={() => navigate('/analyze')}
                className="px-6 py-3.5 text-xs font-mono"
              />
              <AvalokOutlineButton
                label="View Sample Analysis"
                onClick={() => navigate('/dashboard')}
                className="px-6 py-3.5 text-xs font-mono"
              />
            </div>

            {/* Verification Badges */}
            <div className="mt-8 pt-6 border-t border-white/10 grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs font-mono text-white/70 w-full">
              <div className="flex items-center gap-2">
                <Check className="w-4 h-4 text-[#48BB36] shrink-0" />
                <span>100% Passive</span>
              </div>
              <div className="flex items-center gap-2">
                <Check className="w-4 h-4 text-[#48BB36] shrink-0" />
                <span>Offline Analysis</span>
              </div>
              <div className="flex items-center gap-2">
                <Check className="w-4 h-4 text-[#48BB36] shrink-0" />
                <span>Packet Evidence</span>
              </div>
              <div className="flex items-center gap-2">
                <Check className="w-4 h-4 text-[#48BB36] shrink-0" />
                <span>Explainable Risk</span>
              </div>
            </div>
          </motion.div>
        </div>

        {/* Scroll Down Hint Pill */}
        <div className="absolute bottom-4 left-1/2 -translate-x-1/2 z-10 flex flex-col items-center">
          <button
            onClick={() => scrollToSection('topology')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-white/[0.04] border border-white/10 text-white/50 hover:text-white text-xs font-mono transition-colors cursor-pointer hover:bg-white/10"
          >
            <span>Scroll to inspect wire telemetry</span>
            <ChevronDown className="w-3.5 h-3.5 animate-bounce" />
          </button>
        </div>
      </section>

      {/* ========================================================
          2. LIVE WIRE TOPOLOGY (APPEARS ON SCROLL)
         ======================================================== */}
      <section id="topology" className="py-24 bg-[#090d12] border-b border-white/10">
        <div className="max-w-5xl mx-auto px-6">
          <div className="text-center mb-10">
            <SectionEyebrow label="Live Wire Reassembly Concept" tag="Topology" />
            <h2 className="text-3xl sm:text-4xl font-extrabold text-white mt-2">
              AVALOK PCAP Analysis Architecture
            </h2>
            <p className="text-sm text-white/60 mt-1 max-w-xl mx-auto">
              Real-time visualization of client-to-server email transactions observed passively on the wire.
            </p>
          </div>

          {/* Diagram Container */}
          <div className="rounded-xl border border-white/15 bg-[#12161f] shadow-2xl p-6 sm:p-8 font-mono text-xs overflow-x-auto">
            <div className="flex items-center justify-between pb-4 mb-6 border-b border-white/10 text-white/50 text-[11px]">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-[#48BB36]" />
                <span className="font-bold text-white tracking-wider">CAPTURE STREAM DISSECTION</span>
              </div>
              <span className="text-[#48BB36]">ZERO PACKETS INJECTED · OFFLINE REASSEMBLY</span>
            </div>

            <div className="grid grid-cols-12 gap-4 pb-3 text-white/40 text-[11px] font-bold uppercase tracking-wider">
              <div className="col-span-4 sm:col-span-3">Client Endpoint</div>
              <div className="col-span-4 sm:col-span-6 text-center">Observed Protocol / Wire State</div>
              <div className="col-span-4 sm:col-span-3 text-right">Mail Server (Target)</div>
            </div>

            {/* Stream 1: SMTP */}
            <div className="grid grid-cols-12 gap-4 items-center p-3.5 my-2.5 rounded-lg bg-white/[0.02] border border-white/5 hover:border-[#48BB36]/40 transition-colors">
              <div className="col-span-4 sm:col-span-3">
                <div className="text-white font-bold text-xs sm:text-sm">192.168.1.50</div>
                <div className="text-white/40 text-[10px]">:45120</div>
                <span className="inline-block mt-1 px-2 py-0.5 rounded bg-[#48BB36]/15 text-[#48BB36] font-bold text-[10px] border border-[#48BB36]/30">
                  Grade A+
                </span>
              </div>
              <div className="col-span-4 sm:col-span-6 flex flex-col items-center justify-center">
                <span className="text-white/70 text-xs mb-1">SMTP (Port 587)</span>
                <div className="w-full flex items-center justify-center gap-1 text-[#48BB36]">
                  <div className="h-[2px] w-full bg-[#48BB36]/40" />
                  <ArrowRight className="w-4 h-4 shrink-0 text-[#48BB36]" />
                </div>
                <span className="text-[10px] text-[#48BB36] mt-1 font-semibold">
                  ✓ TLS 1.3 Negotiated · PFS Active
                </span>
              </div>
              <div className="col-span-4 sm:col-span-3 text-right">
                <div className="text-white font-bold text-xs sm:text-sm">10.0.0.25</div>
                <div className="text-white/40 text-[10px]">:587</div>
                <span className="inline-block mt-1 text-xs text-white/60">
                  SMTP / TLS
                </span>
              </div>
            </div>

            {/* Stream 2: IMAP */}
            <div className="grid grid-cols-12 gap-4 items-center p-3.5 my-2.5 rounded-lg bg-white/[0.02] border border-white/5 hover:border-[#48BB36]/40 transition-colors">
              <div className="col-span-4 sm:col-span-3">
                <div className="text-white font-bold text-xs sm:text-sm">192.168.1.51</div>
                <div className="text-white/40 text-[10px]">:45122</div>
                <span className="inline-block mt-1 px-2 py-0.5 rounded bg-[#48BB36]/15 text-[#48BB36] font-bold text-[10px] border border-[#48BB36]/30">
                  Grade A+
                </span>
              </div>
              <div className="col-span-4 sm:col-span-6 flex flex-col items-center justify-center">
                <span className="text-white/70 text-xs mb-1">IMAP (Port 143)</span>
                <div className="w-full flex items-center justify-center gap-1 text-[#48BB36]">
                  <div className="h-[2px] w-full bg-[#48BB36]/40" />
                  <ArrowRight className="w-4 h-4 shrink-0 text-[#48BB36]" />
                </div>
                <span className="text-[10px] text-[#48BB36] mt-1 font-semibold">
                  ✓ STARTTLS Handshake Verified
                </span>
              </div>
              <div className="col-span-4 sm:col-span-3 text-right">
                <div className="text-white font-bold text-xs sm:text-sm">10.0.0.14</div>
                <div className="text-white/40 text-[10px]">:143</div>
                <span className="inline-block mt-1 text-xs text-white/60">
                  STARTTLS
                </span>
              </div>
            </div>

            {/* Stream 3: POP3 NO TLS */}
            <div className="grid grid-cols-12 gap-4 items-center p-3.5 my-2.5 rounded-lg bg-[#ef4444]/10 border border-[#ef4444]/30">
              <div className="col-span-4 sm:col-span-3">
                <div className="text-white font-bold text-xs sm:text-sm">192.168.1.53</div>
                <div className="text-white/40 text-[10px]">:45126</div>
                <span className="inline-block mt-1 px-2 py-0.5 rounded bg-[#ef4444]/20 text-[#ef4444] font-bold text-[10px] border border-[#ef4444]/40">
                  Grade C
                </span>
              </div>
              <div className="col-span-4 sm:col-span-6 flex flex-col items-center justify-center">
                <span className="text-white/70 text-xs mb-1">POP3 (Port 110)</span>
                <div className="w-full flex items-center justify-center gap-1 text-[#ef4444]">
                  <div className="h-[2px] w-full bg-[#ef4444]/60" />
                  <AlertTriangle className="w-4 h-4 shrink-0 text-[#ef4444]" />
                </div>
                <span className="text-[10px] text-[#ef4444] mt-1 font-bold">
                  ⚠ NO TLS · Plaintext Auth Exposed
                </span>
              </div>
              <div className="col-span-4 sm:col-span-3 text-right">
                <div className="text-white font-bold text-xs sm:text-sm">10.0.0.13</div>
                <div className="text-white/40 text-[10px]">:110</div>
                <span className="inline-block mt-1 text-xs text-[#ef4444] font-bold">
                  HIGH RISK
                </span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ========================================================
          3. UNIFIED FORENSIC ENGINE SECTION
             (Merges: What It Does, How It Works with Sticky Horizontal Gallery, and Posture & Risk)
         ======================================================== */}
      <section id="engine" className="bg-[#090d12] border-b border-white/10">
        
        {/* Part A: Capabilities — What AVALOK Does & Core Pillars */}
        <div className="py-24 max-w-6xl mx-auto px-6">
          <div className="text-center max-w-2xl mx-auto mb-14">
            <SectionEyebrow label="Capabilities & Analytical Phases" tag="Forensic Engine" />
            <h2 className="text-3xl sm:text-4xl font-extrabold text-white mt-2">
              From Raw PCAP to Security Intelligence
            </h2>
            <p className="mt-2 text-sm text-white/60">
              Four focused analytical phases transform raw wire captures into definitive, court-admissible findings.
            </p>
          </div>

          {/* 4 Cards: Detect, Assess, Identify Risk, Prove */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
            <div className="bg-[#12161f] border border-white/10 hover:border-[#48BB36]/50 rounded-xl p-6 transition-all shadow-md">
              <div className="text-2xl mb-3">🔍</div>
              <h3 className="text-base font-bold text-white mb-2 font-mono">Detect</h3>
              <p className="text-xs text-white/70 leading-relaxed">
                Identify SMTP, IMAP and POP3 sessions and reconstruct email communication flows from captured network traffic.
              </p>
            </div>

            <div className="bg-[#12161f] border border-white/10 hover:border-[#48BB36]/50 rounded-xl p-6 transition-all shadow-md">
              <div className="text-2xl mb-3">🔐</div>
              <h3 className="text-base font-bold text-white mb-2 font-mono">Assess</h3>
              <p className="text-xs text-white/70 leading-relaxed">
                Analyze TLS versions, cipher suites, key exchange, PFS, STARTTLS usage and certificate properties.
              </p>
            </div>

            <div className="bg-[#12161f] border border-white/10 hover:border-[#48BB36]/50 rounded-xl p-6 transition-all shadow-md">
              <div className="text-2xl mb-3">⚠️</div>
              <h3 className="text-base font-bold text-white mb-2 font-mono">Identify Risk</h3>
              <p className="text-xs text-white/70 leading-relaxed">
                Detect deprecated TLS, weak cryptography, missing STARTTLS, certificate problems and plaintext exposure.
              </p>
            </div>

            <div className="bg-[#12161f] border border-white/10 hover:border-[#48BB36]/50 rounded-xl p-6 transition-all shadow-md">
              <div className="text-2xl mb-3">🧾</div>
              <h3 className="text-base font-bold text-white mb-2 font-mono">Prove</h3>
              <p className="text-xs text-white/70 leading-relaxed">
                Trace findings back to sessions, packets and observed wire values with immutable forensic evidence references.
              </p>
            </div>
          </div>

          {/* 4 Pillars: Why AVALOK */}
          <div className="rounded-2xl border border-white/10 bg-[#12161f] p-8">
            <div className="text-xs font-mono font-bold text-[#48BB36] uppercase tracking-wider mb-4">
              Built for Passive, Evidence-Driven Forensics
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 text-xs">
              <div>
                <span className="font-mono font-bold text-white text-sm block">100% PASSIVE</span>
                <p className="text-white/60 text-xs mt-1 leading-relaxed">No scanning. No probing. No connections to live servers or network disruption.</p>
              </div>
              <div>
                <span className="font-mono font-bold text-white text-sm block">FORENSIC PROVENANCE</span>
                <p className="text-white/60 text-xs mt-1 leading-relaxed">Every finding traces back to raw captured packets, byte offsets, and SHA-256 hashes.</p>
              </div>
              <div>
                <span className="font-mono font-bold text-white text-sm block">EXPLAINABLE RISK</span>
                <p className="text-white/60 text-xs mt-1 leading-relaxed">Risk scores show exactly what contributed to the score without black-box drift.</p>
              </div>
              <div>
                <span className="font-mono font-bold text-white text-sm block">AIR-GAPPED OFFLINE</span>
                <p className="text-white/60 text-xs mt-1 leading-relaxed">Designed to operate in strictly isolated, air-gapped forensic laboratories.</p>
              </div>
            </div>
          </div>
        </div>

        {/* Part B: How It Works — Sticky Horizontal Scroll Gallery (GSAP ScrollTrigger) */}
        <HorizontalGallery />

        {/* Part C: Posture & Explainable Risk Synthesis */}
        <div className="py-24 max-w-6xl mx-auto px-6 border-t border-white/10">
          <div className="text-center max-w-2xl mx-auto mb-14">
            <SectionEyebrow label="Risk Scoring" tag="No Black Boxes" />
            <h2 className="text-3xl sm:text-4xl font-extrabold text-white mt-2">
              Understand Risk at a Glance & Defend Every Score
            </h2>
            <p className="mt-2 text-sm text-white/60">
              Every analyzed endpoint receives an intuitive posture grade derived deterministically from its observed security findings.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
            
            {/* Left: Ladder & Example Card */}
            <div className="lg:col-span-6 bg-[#12161f] border border-white/10 rounded-2xl p-6 flex flex-col justify-between">
              <div>
                <div className="text-xs font-mono text-white/50 uppercase mb-4 font-bold">
                  Deterministic Posture Ladder
                </div>

                <div className="grid grid-cols-5 gap-2 text-center font-mono mb-6">
                  <div className="p-3 rounded-lg bg-[#48BB36]/15 border border-[#48BB36]/30">
                    <span className="text-xl font-bold text-[#48BB36]">A+</span>
                    <div className="text-[10px] text-[#48BB36] mt-1 font-semibold uppercase">Strong</div>
                  </div>
                  <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/25">
                    <span className="text-xl font-bold text-emerald-400">B</span>
                    <div className="text-[10px] text-emerald-400 mt-1 font-semibold uppercase">Good</div>
                  </div>
                  <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/25">
                    <span className="text-xl font-bold text-amber-400">C</span>
                    <div className="text-[10px] text-amber-400 mt-1 font-semibold uppercase">Moderate</div>
                  </div>
                  <div className="p-3 rounded-lg bg-orange-500/10 border border-orange-500/25">
                    <span className="text-xl font-bold text-orange-400">D</span>
                    <div className="text-[10px] text-orange-400 mt-1 font-semibold uppercase">Weak</div>
                  </div>
                  <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/25">
                    <span className="text-xl font-bold text-red-400">F</span>
                    <div className="text-[10px] text-red-400 mt-1 font-semibold uppercase">Critical</div>
                  </div>
                </div>

                {/* Target Card */}
                <div className="p-4 rounded-xl bg-white/5 border border-white/10 font-mono flex items-center justify-between">
                  <div>
                    <div className="text-white/40 text-[10px] uppercase font-bold">Target Endpoint</div>
                    <div className="text-base font-bold text-white mt-0.5">mail.example.com</div>
                    <div className="text-xs text-amber-400 mt-1 font-semibold">1 High Finding (Missing STARTTLS)</div>
                  </div>

                  <div className="text-center">
                    <div className="w-14 h-14 rounded-full bg-amber-500/15 border-2 border-amber-500/40 text-amber-400 flex items-center justify-center text-2xl font-extrabold mx-auto">
                      C
                    </div>
                    <span className="text-[10px] text-amber-400 font-bold block mt-1 uppercase">MODERATE</span>
                  </div>
                </div>
              </div>

              <div className="mt-6 pt-4 border-t border-white/10 flex items-center justify-between text-xs">
                <span className="text-white/60 font-mono">Risk Score: 25 / 100</span>
                <button
                  onClick={() => navigate('/sessions')}
                  className="text-[#48BB36] hover:text-[#5fcf4c] font-mono font-bold flex items-center gap-1.5 cursor-pointer"
                >
                  <span>See Evidence Breakdown</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Right: Explainable Breakdown */}
            <div className="lg:col-span-6 bg-[#12161f] border border-white/10 rounded-2xl p-6 sm:p-8 flex flex-col justify-between font-mono">
              <div>
                <div className="flex items-center justify-between pb-4 border-b border-white/10 text-xs">
                  <span className="font-bold text-white tracking-wider">EXPLAINABLE RISK BREAKDOWN</span>
                  <span className="text-amber-400 font-bold text-sm">25 / 100</span>
                </div>

                <div className="py-5 space-y-3 text-xs">
                  <div className="text-[11px] font-bold text-[#48BB36] uppercase tracking-wider mb-2">
                    WHY THIS SCORE? (ITEMIZED DEDUCTIONS)
                  </div>
                  
                  <div className="flex items-center justify-between text-white/80 py-2 border-b border-white/5">
                    <span>No STARTTLS / Plaintext wire transport</span>
                    <span className="text-amber-400 font-bold">+25 pts</span>
                  </div>
                  <div className="flex items-center justify-between text-white/50 py-2 border-b border-white/5 text-[11px]">
                    <span>Deprecated TLS version deduction</span>
                    <span className="text-white/40">0 pts</span>
                  </div>
                  <div className="flex items-center justify-between text-white/50 py-2 border-b border-white/5 text-[11px]">
                    <span>Certificate validation error deduction</span>
                    <span className="text-white/40">0 pts</span>
                  </div>
                </div>

                <div className="pt-3 border-t border-white/10 flex items-center justify-between text-xs font-bold">
                  <span className="text-white">TOTAL DERIVED RISK SCORE</span>
                  <span className="text-amber-400 text-sm">25 / 100</span>
                </div>
              </div>

              <p className="mt-6 text-xs text-white/50 leading-relaxed font-sans">
                AVALOK connects every risk contribution to an observed feature, rule violation and packet-level evidence rather than an arbitrary AI score.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ========================================================
          6. PROTOCOLS & REPORTS & LAUNCH (APPEARS ON SCROLL)
         ======================================================== */}
      <section id="reports" className="py-24 bg-[#090d12] border-t border-white/10">
        <div className="max-w-6xl mx-auto px-6">
          <div className="text-center max-w-2xl mx-auto mb-14">
            <SectionEyebrow label="Deliverables" tag="Investigation-Ready" />
            <h2 className="text-3xl sm:text-4xl font-extrabold text-white mt-2">
              Supported Protocols & Forensic Reports
            </h2>
            <p className="mt-2 text-sm text-white/60">
              Investigation-ready reports include posture grades, findings, risk reasoning, packet evidence and chain-of-custody.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-12 font-mono text-xs">
            {/* Supported Protocols */}
            <div className="bg-[#12161f] border border-white/10 rounded-2xl p-6">
              <h3 className="text-base font-bold text-white mb-4">Supported Email Protocols</h3>
              <div className="grid grid-cols-3 gap-3">
                <div className="p-3 rounded-lg bg-white/5 border border-white/5">
                  <div className="text-white font-bold text-sm">SMTP</div>
                  <div className="text-[10px] text-white/50 mt-1">STARTTLS</div>
                  <div className="text-[10px] text-[#48BB36] mt-0.5 font-semibold">SMTPS (465)</div>
                </div>
                <div className="p-3 rounded-lg bg-white/5 border border-white/5">
                  <div className="text-white font-bold text-sm">IMAP</div>
                  <div className="text-[10px] text-white/50 mt-1">STARTTLS</div>
                  <div className="text-[10px] text-[#48BB36] mt-0.5 font-semibold">IMAPS (993)</div>
                </div>
                <div className="p-3 rounded-lg bg-white/5 border border-white/5">
                  <div className="text-white font-bold text-sm">POP3</div>
                  <div className="text-[10px] text-white/50 mt-1">STLS</div>
                  <div className="text-[10px] text-[#48BB36] mt-0.5 font-semibold">POP3S (995)</div>
                </div>
              </div>
            </div>

            {/* Investigation Reports */}
            <div className="bg-[#12161f] border border-white/10 rounded-2xl p-6">
              <h3 className="text-base font-bold text-white mb-4">Investigation-Ready Reports</h3>
              <div className="grid grid-cols-3 gap-3">
                <div className="p-3 rounded-lg bg-white/5 border border-white/5">
                  <div className="text-[#48BB36] font-bold text-sm">HTML</div>
                  <div className="text-[10px] text-white/60 mt-1">Interactive investigation</div>
                </div>
                <div className="p-3 rounded-lg bg-white/5 border border-white/5">
                  <div className="text-[#48BB36] font-bold text-sm">PDF</div>
                  <div className="text-[10px] text-white/60 mt-1">Formal forensic report</div>
                </div>
                <div className="p-3 rounded-lg bg-white/5 border border-white/5">
                  <div className="text-[#48BB36] font-bold text-sm">JSON</div>
                  <div className="text-[10px] text-white/60 mt-1">Machine-readable schema</div>
                </div>
              </div>
            </div>
          </div>

          {/* Final Launch Callout */}
          <div className="bg-[#12161f] border border-[#48BB36]/30 rounded-2xl p-8 sm:p-12 text-center shadow-2xl relative overflow-hidden">
            <div className="absolute inset-0 bg-radial-at-c from-[#48BB36]/10 via-transparent to-transparent pointer-events-none" />
            <h3 className="text-2xl sm:text-4xl font-extrabold text-white tracking-tight leading-tight">
              Start with a PCAP. Find what the wire reveals.
            </h3>
            <p className="text-sm sm:text-base text-white/70 mt-3 max-w-xl mx-auto leading-relaxed">
              Upload an SMTP, IMAP or POP3 PCAP/PCAPNG capture and begin passive forensic analysis.
            </p>
            <div className="mt-8 flex justify-center">
              <AvalokButton
                label="Analyze PCAP Now →"
                onClick={() => navigate('/analyze')}
                className="px-8 py-4 text-sm font-mono"
              />
            </div>
            <div className="mt-4 text-xs font-mono text-white/40">
              100% Passive · Offline · Evidence-Driven
            </div>
          </div>
        </div>
      </section>

      {/* ========================================================
          7. MINIMAL FOOTER
         ======================================================== */}
      <footer className="border-t border-white/10 py-10 px-6 bg-[#090d12] text-white/70">
        <div className="max-w-6xl mx-auto flex flex-col md:flex-row items-center justify-between gap-6">
          <div className="flex flex-col text-left">
            <span className="text-white font-extrabold text-sm tracking-wider uppercase font-mono">
              AVALOK
            </span>
            <span className="text-[10px] text-white/40 font-mono">
              Passive Email TLS Forensics
            </span>
          </div>

          <div className="flex items-center gap-6 text-xs text-white/60 font-mono">
            <button onClick={() => scrollToSection('hero')} className="hover:text-white transition-colors cursor-pointer">
              Overview
            </button>
            <button onClick={() => scrollToSection('topology')} className="hover:text-white transition-colors cursor-pointer">
              Topology
            </button>
            <button onClick={() => scrollToSection('engine')} className="hover:text-white transition-colors cursor-pointer">
              Forensic Engine
            </button>
            <button onClick={() => scrollToSection('reports')} className="hover:text-white transition-colors cursor-pointer">
              Protocols & Reports
            </button>
          </div>

          <div className="text-xs text-white/40 font-mono">
            100% Passive · Offline
          </div>
        </div>
      </footer>
    </div>
  );
}
