import React from 'react';
import { Navbar } from './Navbar';
import { LogoMark } from './AuraPrimitives';
import { Link } from 'react-router-dom';

interface LayoutProps {
  children: React.ReactNode;
}

export function Layout({ children }: LayoutProps) {
  return (
    <div className="min-h-screen bg-[#0c0c0c] text-white selection:bg-[#3D81E3]/30">
      <Navbar />
      <main className="pt-14 min-h-screen">
        {children}
      </main>
      <footer className="border-t border-white/10 py-8 px-6 bg-black/40 backdrop-blur-md">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <LogoMark className="w-5 h-5 text-white" />
            <div>
              <div className="text-white font-semibold text-sm tracking-wider uppercase font-mono">AVALOK Forensics</div>
              <div className="text-white/40 text-xs">Passive Email TLS Forensics & Cryptographic Threat Intelligence</div>
            </div>
          </div>
          <div className="flex items-center gap-6 text-xs text-white/50">
            <Link to="/" className="hover:text-white transition-colors">Landing</Link>
            <Link to="/dashboard" className="hover:text-white transition-colors">Dashboard</Link>
            <Link to="/analyze" className="hover:text-white transition-colors">Analyze</Link>
            <Link to="/sessions" className="hover:text-white transition-colors">Sessions</Link>
            <Link to="/reports" className="hover:text-white transition-colors">Reports</Link>
          </div>
          <p className="text-white/40 text-xs font-mono">
            &copy; 2026 Aura Technologies Inc.
          </p>
        </div>
      </footer>
    </div>
  );
}
