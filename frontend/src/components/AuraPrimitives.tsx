import React from 'react';
import { ArrowRight, Shield } from 'lucide-react';

/**
 * Geometric AVALOK Forensics LogoMark
 */
export function AvalokLogoMark({ className = 'w-7 h-7' }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 48 48"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      aria-label="AVALOK Logo"
    >
      <defs>
        <linearGradient id="avalokGrad" x1="0" y1="0" x2="48" y2="48" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#48BB36" />
          <stop offset="100%" stopColor="#22C55E" />
        </linearGradient>
      </defs>
      <rect x="4" y="4" width="40" height="40" rx="8" stroke="url(#avalokGrad)" strokeWidth="2" fill="#141820" />
      <path d="M14 34 L24 14 L34 34" stroke="#48BB36" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M18 27 H30" stroke="#48BB36" strokeWidth="2" strokeLinecap="round" />
      <circle cx="24" cy="21" r="2" fill="#48BB36" />
    </svg>
  );
}

export const LogoMark = AvalokLogoMark;
export const SekureShieldIcon = AvalokLogoMark;

/**
 * AVALOK Brand Header
 */
export function AvalokBrand({ className = '' }: { className?: string }) {
  return (
    <div className={`inline-flex items-center gap-3 ${className}`}>
      <AvalokLogoMark className="w-8 h-8 shrink-0" />
      <div className="flex flex-col text-left">
        <span className="text-white font-extrabold text-lg tracking-wider font-mono uppercase leading-tight">
          AVALOK
        </span>
        <span className="text-[10px] tracking-wide text-white/50 uppercase font-mono">
          Passive Email TLS Forensics
        </span>
      </div>
    </div>
  );
}

export const SekureBrand = AvalokBrand;

/**
 * Primary Action Button
 */
interface ButtonProps {
  label?: string;
  onClick?: () => void;
  className?: string;
  children?: React.ReactNode;
  icon?: React.ReactNode;
  full?: boolean;
}

export function AvalokButton({
  label = 'Analyze a PCAP',
  onClick,
  className = '',
  children,
  icon,
  full = false,
}: ButtonProps) {
  return (
    <button
      onClick={onClick}
      className={`group inline-flex items-center justify-center gap-2 bg-[#48BB36] hover:bg-[#3ca32c] active:scale-[0.98] text-white font-semibold text-xs tracking-wide uppercase px-5 py-3 rounded-md shadow-lg shadow-[#48bb36]/20 transition-all duration-200 cursor-pointer ${
        full ? 'w-full' : ''
      } ${className}`}
    >
      <span>{children || label}</span>
      {icon ? (
        icon
      ) : (
        <ArrowRight className="w-3.5 h-3.5 transition-transform duration-200 group-hover:translate-x-1" />
      )}
    </button>
  );
}

export const SekureButton = AvalokButton;

export function AvalokOutlineButton({
  label = 'View Sample Analysis',
  onClick,
  className = '',
  children,
  icon,
  full = false,
}: ButtonProps) {
  return (
    <button
      onClick={onClick}
      className={`group inline-flex items-center justify-center gap-2 bg-white/5 hover:bg-white/10 active:scale-[0.98] text-white border border-white/15 font-semibold text-xs tracking-wide uppercase px-5 py-3 rounded-md transition-all duration-200 cursor-pointer ${
        full ? 'w-full' : ''
      } ${className}`}
    >
      <span>{children || label}</span>
      {icon}
    </button>
  );
}

export const SekureWhiteButton = AvalokOutlineButton;
export const AppleButton = AvalokButton;

export function SectionEyebrow({
  label,
  tag,
  className = '',
}: {
  label: string;
  tag?: string;
  className?: string;
}) {
  return (
    <div className={`inline-flex items-center gap-2 text-xs font-semibold tracking-wide ${className}`}>
      <span className="w-2 h-2 rounded-full bg-[#48BB36] shadow-[0_0_8px_rgba(72,187,54,0.8)]" />
      <span className="text-white/90 uppercase tracking-widest font-mono text-[11px]">{label}</span>
      {tag && (
        <span className="px-2 py-0.5 rounded border border-[#48BB36]/30 text-[#48BB36] bg-[#48BB36]/10 text-[10px] font-mono">
          {tag}
        </span>
      )}
    </div>
  );
}
