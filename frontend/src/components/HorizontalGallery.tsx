import { useLayoutEffect, useRef, useState } from 'react';
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { 
  FileCode, 
  Binary, 
  ShieldAlert, 
  Award, 
  Link2, 
  Download, 
  ArrowRight, 
  CheckCircle2, 
  AlertTriangle,
  Lock,
  Cpu,
  Layers
} from 'lucide-react';

gsap.registerPlugin(ScrollTrigger);

interface GalleryCard {
  step: string;
  tag: string;
  title: string;
  subtitle: string;
  description: string;
  icon: typeof FileCode;
  accent: string;
  details: {
    label: string;
    value: string;
    sub?: string;
  }[];
  badge: string;
  footerNote: string;
}

const GALLERY_CARDS: GalleryCard[] = [
  {
    step: 'STAGE 01',
    tag: 'Ingestion & Custody',
    title: 'PCAP Ingestion & SHA-256 Hashing',
    subtitle: 'Zero wire injection · Immutable chain of custody',
    description: 'PCAP and PCAPNG captures are ingested in an isolated offline sandbox. An immediate cryptographic SHA-256 digest is generated upon load, guaranteeing non-repudiation for forensic and legal scrutiny.',
    icon: FileCode,
    accent: '#48BB36',
    badge: '100% PASSIVE AIR-GAPPED',
    details: [
      { label: 'Capture Format', value: 'PCAP / PCAPNG', sub: 'Standard Libpcap & Wireshark' },
      { label: 'Digest Hash', value: 'e3b0c442...855', sub: 'SHA-256 Non-Repudiation' },
      { label: 'Network Impact', value: '0 Packets Injected', sub: 'No active probes or ping' },
    ],
    footerNote: 'Preserves raw capture file integrity before any byte parsing begins.',
  },
  {
    step: 'STAGE 02',
    tag: 'Dissection & Reassembly',
    title: 'Protocol & Cryptographic Dissection',
    subtitle: 'SMTP · IMAP · POP3 · TLS 1.0-1.3 · X.509',
    description: 'Reconstructs TCP conversations across standard and custom mail ports (25, 465, 587, 110, 995, 143, 993). Dissects TLS ClientHello/ServerHello handshakes, cipher negotiation, and extracts raw X.509 certificate chains.',
    icon: Binary,
    accent: '#38bdf8',
    badge: 'DEEP WIRE REASSEMBLY',
    details: [
      { label: 'Protocols', value: 'SMTP, IMAP, POP3', sub: 'STARTTLS state tracking' },
      { label: 'Handshake Fields', value: 'TLS 1.0 - 1.3', sub: 'SNI, ALPN, CipherSuites' },
      { label: 'Certificates', value: 'ASN.1 X.509 Decoded', sub: 'SAN, Expiry, Key Length' },
    ],
    footerNote: 'Maps every TLS handshake parameter back to client and server endpoints.',
  },
  {
    step: 'STAGE 03',
    tag: 'Deterministic Rules',
    title: 'NIST & RFC Security Rule Engine',
    subtitle: '16 forensic detection rules · Zero black-box guesswork',
    description: 'Wire parameters are strictly verified against NIST SP 800-52 Rev. 2 and RFC 8996. Evaluates deprecated ciphers (RC4, 3DES, CBC), weak DH parameters, missing PFS, plaintext fallback, and certificate validity.',
    icon: ShieldAlert,
    accent: '#f59e0b',
    badge: 'NIST SP 800-52 REV. 2',
    details: [
      { label: 'Rule Engine', value: '16 Verified Rules', sub: 'TLS, Cipher, Cert & Plaintext' },
      { label: 'Deprecation Check', value: 'TLS 1.0/1.1 Flags', sub: 'RFC 8996 non-compliance' },
      { label: 'STARTTLS Stripping', value: 'Downgrade Detection', sub: 'Flags unencrypted cleartext' },
    ],
    footerNote: 'Deterministic evaluations ensure repeatable and auditable findings.',
  },
  {
    step: 'STAGE 04',
    tag: 'Posture Synthesis',
    title: 'Transparent Posture Grading & Scoring',
    subtitle: 'From A+ to F with arithmetic deduction logic',
    description: 'Every analyzed host receives an explainable Posture Grade (A+ through F) alongside a 0–100 risk score. Deductions are mathematically computed from verified findings without opaque machine-learning weight drift.',
    icon: Award,
    accent: '#a855f7',
    badge: 'TRANSPARENT SCORING',
    details: [
      { label: 'Grade Range', value: 'A+ (Strong) to F (Critical)', sub: 'Immediate executive clarity' },
      { label: 'Deduction Formula', value: 'Base 100 - Penalties', sub: 'e.g. +25 for Plaintext' },
      { label: 'Explainability', value: '100% Itemized', sub: 'Clear reason for every point' },
    ],
    footerNote: 'Empowers security leadership to defend findings during audits.',
  },
  {
    step: 'STAGE 05',
    tag: 'Proof & Lineage',
    title: '6-Link Evidence Lineage Trail',
    subtitle: 'From root PCAP digest to individual wire frame bytes',
    description: 'Every security finding is permanently bound to its full provenance chain: PCAP SHA-256 → TCP Stream ID → Packet Frame Number → Raw Hex Wire Value → Triggered Rule → Final Defensible Finding.',
    icon: Link2,
    accent: '#48BB36',
    badge: 'COURT-READY PROVENANCE',
    details: [
      { label: 'Traceability', value: 'Packet-Level Proof', sub: 'Exact byte offsets on wire' },
      { label: 'Frame Anchor', value: 'Packet #31 TLS Alert', sub: 'Direct Wireshark frame cross-ref' },
      { label: 'Admissibility', value: 'Cryptographic Chain', sub: 'Audit-ready for forensics' },
    ],
    footerNote: 'Eliminates false-positive disputes by providing irrefutable wire evidence.',
  },
  {
    step: 'STAGE 06',
    tag: 'Forensic Exports',
    title: 'Audit-Grade Artifacts & Reports',
    subtitle: 'Interactive dashboard · Standalone PDF · Structured JSON',
    description: 'Export comprehensive technical and executive reports with full cryptographic evidence citations. Directly stream JSON payloads into SIEM/SOAR platforms (Splunk, Elastic, Sentinel) for threat response.',
    icon: Download,
    accent: '#22c55e',
    badge: 'MULTI-FORMAT ARTIFACTS',
    details: [
      { label: 'Executive PDF', value: 'Board-Ready Reports', sub: 'Summaries & Posture Ladder' },
      { label: 'Technical HTML', value: 'Interactive Inspector', sub: 'Drilldown with packet details' },
      { label: 'Structured JSON', value: 'SIEM / SOAR API Ready', sub: 'Automated ingest & pipelines' },
    ],
    footerNote: 'Provides actionable outputs for operators, analysts, and C-level executives.',
  },
];

export function HorizontalGallery() {
  const containerRef = useRef<HTMLDivElement>(null);
  const trackRef = useRef<HTMLDivElement>(null);
  const [activeSlide, setActiveSlide] = useState(0);

  useLayoutEffect(() => {
    let ctx: gsap.Context | null = null;
    let timer: number | null = null;

    // Technical Requirement: Ensure GSAP initialization is robust.
    // Include a small delay and safety check to ensure DOM is fully rendered
    // and widths are accurate before ScrollTrigger calculates pinning logic.
    const initScrollTrigger = () => {
      const container = containerRef.current;
      const track = trackRef.current;

      if (!container || !track) return;

      // Force recalculation of element geometry
      ScrollTrigger.refresh();

      ctx = gsap.context(() => {
        const totalScroll = track.scrollWidth - container.clientWidth;

        if (totalScroll <= 0) {
          // If content fits without overflow, retry once shortly
          return;
        }

        gsap.to(track, {
          x: -totalScroll,
          ease: 'none',
          scrollTrigger: {
            trigger: container,
            start: 'top top',
            end: () => `+=${totalScroll * 1.2}`,
            pin: true,
            scrub: 0.8,
            anticipatePin: 1,
            invalidateOnRefresh: true,
            onUpdate: (self) => {
              const slideIdx = Math.min(
                GALLERY_CARDS.length - 1,
                Math.round(self.progress * (GALLERY_CARDS.length - 1))
              );
              setActiveSlide(slideIdx);
            },
          },
        });
      }, containerRef);
    };

    // Safety timeout delay to guarantee layout & fonts have painted
    timer = window.setTimeout(initScrollTrigger, 80);

    const handleResize = () => {
      ScrollTrigger.refresh();
    };
    window.addEventListener('resize', handleResize);

    return () => {
      if (timer) clearTimeout(timer);
      window.removeEventListener('resize', handleResize);
      ctx?.revert();
    };
  }, []);

  return (
    <div
      ref={containerRef}
      className="relative w-full h-screen bg-[#07090e] border-y border-white/10 flex flex-col justify-center overflow-hidden"
    >
      {/* Background Ambience */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-[#48BB36]/5 rounded-full blur-3xl" />
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-blue-500/5 rounded-full blur-3xl" />
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,rgba(255,255,255,0.02),transparent_70%)]" />
      </div>

      {/* Sticky Gallery Header (Stays pinned inside the full-screen view) */}
      <div className="relative z-10 max-w-7xl mx-auto px-6 w-full pt-4 pb-4 flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/[0.04] border border-white/10 text-xs font-mono text-white/70 mb-2">
            <span className="w-2 h-2 rounded-full bg-[#48BB36] animate-pulse" />
            <span>HOW IT WORKS · HORIZONTAL EVIDENCE PIPELINE</span>
          </div>
          <h3 className="text-2xl sm:text-3xl lg:text-4xl font-extrabold text-white tracking-tight">
            From Raw Wire Bytes to Defensible Findings
          </h3>
          <p className="text-xs sm:text-sm text-white/60 mt-1 max-w-xl">
            Scroll vertically to slide through each stage of the forensic evaluation pipeline.
          </p>
        </div>

        {/* Slide Indicator & Dots */}
        <div className="flex items-center gap-3 font-mono text-xs">
          <span className="text-white/40">STAGE</span>
          <span className="text-[#48BB36] font-bold text-sm">
            0{activeSlide + 1}
          </span>
          <span className="text-white/30">/</span>
          <span className="text-white/40">0{GALLERY_CARDS.length}</span>
          <div className="flex items-center gap-1.5 ml-2">
            {GALLERY_CARDS.map((_, idx) => (
              <div
                key={idx}
                className={`h-1.5 rounded-full transition-all duration-300 ${
                  activeSlide === idx
                    ? 'w-6 bg-[#48BB36]'
                    : 'w-1.5 bg-white/20'
                }`}
              />
            ))}
          </div>
        </div>
      </div>

      {/* Horizontal Sliding Track */}
      <div className="relative z-10 w-full overflow-visible py-4">
        <div
          ref={trackRef}
          className="flex items-stretch gap-6 sm:gap-8 px-6 sm:px-12 w-max will-change-transform"
        >
          {GALLERY_CARDS.map((card, idx) => {
            const Icon = card.icon;
            const isCurrent = activeSlide === idx;

            return (
              <div
                key={card.step}
                className={`w-[85vw] sm:w-[540px] md:w-[600px] shrink-0 rounded-2xl border transition-all duration-300 p-6 sm:p-8 flex flex-col justify-between backdrop-blur-xl ${
                  isCurrent
                    ? 'bg-[#12161f]/95 border-[#48BB36]/50 shadow-[0_10px_40px_rgba(0,0,0,0.6)]'
                    : 'bg-[#12161f]/75 border-white/10 hover:border-white/20'
                }`}
              >
                {/* Card Top: Step tag + Icon */}
                <div>
                  <div className="flex items-center justify-between pb-4 border-b border-white/10 mb-5">
                    <div className="flex items-center gap-2.5">
                      <span className="px-2.5 py-1 rounded bg-[#48BB36]/15 text-[#48BB36] font-mono text-xs font-bold border border-[#48BB36]/30">
                        {card.step}
                      </span>
                      <span className="text-[11px] font-mono text-white/50 uppercase tracking-wider">
                        {card.tag}
                      </span>
                    </div>

                    <div className="w-10 h-10 rounded-xl bg-white/[0.04] border border-white/10 flex items-center justify-center text-[#48BB36]">
                      <Icon className="w-5 h-5" />
                    </div>
                  </div>

                  {/* Title & Subtitle */}
                  <h4 className="text-xl sm:text-2xl font-bold text-white font-mono tracking-tight leading-snug">
                    {card.title}
                  </h4>
                  <p className="text-xs sm:text-sm text-[#48BB36] font-mono mt-1">
                    {card.subtitle}
                  </p>

                  {/* Description */}
                  <p className="text-xs sm:text-sm text-white/70 mt-3 leading-relaxed">
                    {card.description}
                  </p>

                  {/* Detail Grid */}
                  <div className="mt-5 grid grid-cols-1 sm:grid-cols-3 gap-2.5 font-mono">
                    {card.details.map((d, dIdx) => (
                      <div
                        key={dIdx}
                        className="p-3 rounded-lg bg-white/[0.03] border border-white/5 flex flex-col justify-between"
                      >
                        <span className="text-[10px] text-white/40 uppercase tracking-wider block">
                          {d.label}
                        </span>
                        <span className="text-xs font-bold text-white mt-1 truncate block">
                          {d.value}
                        </span>
                        {d.sub && (
                          <span className="text-[9px] text-[#48BB36] mt-0.5 block truncate">
                            {d.sub}
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Card Footer: Badge + Note */}
                <div className="mt-6 pt-4 border-t border-white/10 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono">
                  <div className="inline-flex items-center gap-1.5 text-[#48BB36] text-[11px] font-semibold">
                    <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                    <span>{card.badge}</span>
                  </div>
                  <span className="text-white/40 text-[10px] sm:text-right">
                    {card.footerNote}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Bottom Scroll Guide */}
      <div className="relative z-10 max-w-7xl mx-auto px-6 w-full pt-2 flex items-center justify-between text-xs font-mono text-white/40">
        <div className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-[#48BB36]" />
          <span>Horizontal lock active · Keep scrolling vertically</span>
        </div>
        <div className="hidden sm:flex items-center gap-1 text-white/60">
          <span>Stage 01 to 06</span>
          <ArrowRight className="w-3.5 h-3.5 text-[#48BB36]" />
        </div>
      </div>
    </div>
  );
}
