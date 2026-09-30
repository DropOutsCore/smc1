import React from 'react';
import { Navbar } from './Navbar';
import { AvalokLogoMark } from './AuraPrimitives';
import { Link } from 'react-router-dom';

interface LayoutProps {
  children: React.ReactNode;
}

export function Layout({ children }: LayoutProps) {
  return (
    <div className="min-h-screen bg-[#0d1117] text-white selection:bg-[#48BB36]/30 font-sans">
      <Navbar />
      <main className="pt-16 min-h-screen">
        {children}
      </main>
      <footer className="border-t border-white/10 py-10 px-6 bg-[#090d12] text-white/70">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-6">
          <div className="flex items-center gap-3">
            <AvalokLogoMark className="w-6 h-6 shrink-0" />
            <div>
              <div className="text-white font-bold text-sm tracking-wider uppercase font-mono">AVALOK</div>
              <div className="text-white/40 text-xs">Passive Email TLS Forensics & Cryptographic Risk Intelligence</div>
            </div>
          </div>
          <div className="flex items-center gap-6 text-xs text-white/60 font-mono">
            <Link to="/dashboard" className="hover:text-white transition-colors">Dashboard</Link>
            <Link to="/analyze" className="hover:text-white transition-colors">Analyze PCAP</Link>
            <Link to="/sessions" className="hover:text-white transition-colors">Sessions</Link>
            <Link to="/reports" className="hover:text-white transition-colors">Reports</Link>
            <Link to="/docs" className="hover:text-white transition-colors">Documentation</Link>
          </div>
          <div className="flex items-center gap-2 text-xs font-mono text-white/40">
            <span className="w-2 h-2 rounded-full bg-[#48BB36]" />
            <span>100% Passive · Offline</span>
          </div>
        </div>
        <div className="max-w-7xl mx-auto mt-6 pt-6 border-t border-white/5 flex flex-col sm:flex-row items-center justify-between text-xs text-white/40 font-mono">
          <p>&copy; {new Date().getFullYear()} AVALOK. All rights reserved.</p>
          <div className="mt-2 sm:mt-0">
            NIST SP 800-52 Rev. 2 · RFC 8996 · RFC 3207
          </div>
        </div>
      </footer>
    </div>
  );
}
