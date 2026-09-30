import { useState } from 'react';
import { Link, NavLink, useNavigate, useLocation } from 'react-router-dom';
import { Menu, X, ArrowRight, Layers, LayoutGrid } from 'lucide-react';
import { cn } from '../lib/utils';
import { AvalokLogoMark } from './AuraPrimitives';

const defaultNavItems = [
  { to: '/dashboard', label: 'Dashboard' },
  { to: '/analyze', label: 'Analyze PCAP' },
  { to: '/sessions', label: 'Sessions' },
  { to: '/reports', label: 'Reports' },
  { to: '/docs', label: 'Documentation' },
];

export interface SectionItem {
  id: string;
  label: string;
}

interface NavbarProps {
  sections?: SectionItem[];
  activeSection?: string;
  onSelectSection?: (id: string) => void;
}

export function Navbar({ sections, activeSection, onSelectSection }: NavbarProps) {
  const navigate = useNavigate();
  const location = useLocation();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [consoleMenuOpen, setConsoleMenuOpen] = useState(false);

  const isLanding = location.pathname === '/';

  return (
    <header className="fixed top-3 sm:top-4 left-1/2 -translate-x-1/2 z-50 w-[95%] max-w-6xl">
      <div className="rounded-full border border-white/15 bg-[#12161f]/85 backdrop-blur-2xl px-4 sm:px-6 py-2.5 shadow-2xl shadow-black/80 flex items-center justify-between gap-3">
        
        {/* Brand: AVALOK */}
        <Link to="/" className="flex items-center gap-2.5 shrink-0 group">
          <AvalokLogoMark className="w-7 h-7 transition-transform group-hover:scale-105" />
          <div className="flex flex-col text-left">
            <span className="text-white font-extrabold text-sm tracking-wider uppercase font-mono group-hover:text-[#48BB36] transition-colors leading-none">
              AVALOK
            </span>
            <span className="text-[9px] font-mono tracking-widest text-white/50 uppercase mt-0.5 hidden xs:inline">
              Passive Wire Forensics
            </span>
          </div>
        </Link>

        {/* Center: Landing Page Section Navigation OR App Feature Links */}
        {isLanding && sections && onSelectSection ? (
          <nav className="hidden lg:flex items-center gap-1">
            {sections.map((sec) => {
              const isActive = activeSection === sec.id;
              return (
                <button
                  key={sec.id}
                  onClick={() => onSelectSection(sec.id)}
                  className={cn(
                    'px-3 py-1.5 rounded-full text-xs font-mono font-medium transition-all cursor-pointer',
                    isActive
                      ? 'text-white bg-white/15 border border-white/20 shadow-sm'
                      : 'text-white/60 hover:text-white hover:bg-white/5'
                  )}
                >
                  {sec.label}
                </button>
              );
            })}
          </nav>
        ) : (
          <nav className="hidden md:flex items-center gap-1">
            {defaultNavItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  cn(
                    'px-3.5 py-1.5 rounded-full text-xs font-mono font-medium transition-all',
                    isActive
                      ? 'text-white bg-white/15 border border-white/20 shadow-sm'
                      : 'text-white/60 hover:text-white hover:bg-white/5'
                  )
                }
              >
                {item.label}
              </NavLink>
            ))}
          </nav>
        )}

        {/* Right Action: 100% Passive status badge + Console Toggle + Analyze PCAP CTA */}
        <div className="hidden sm:flex items-center gap-2.5 shrink-0">
          <div className="hidden xl:flex items-center gap-2 px-3 py-1 rounded-full bg-white/[0.04] border border-white/10 text-[11px] font-mono text-white/70">
            <span className="w-1.5 h-1.5 rounded-full bg-[#48BB36] shadow-[0_0_8px_rgba(72,187,54,0.8)]" />
            <span>100% Passive</span>
          </div>

          {/* Quick App Console Dropdown on Landing */}
          {isLanding && (
            <div className="relative">
              <button
                onClick={() => setConsoleMenuOpen(!consoleMenuOpen)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-mono text-white/70 hover:text-white hover:bg-white/5 border border-white/10 transition-colors cursor-pointer"
                title="System Consoles"
              >
                <LayoutGrid className="w-3.5 h-3.5 text-[#48BB36]" />
                <span>Console</span>
              </button>

              {consoleMenuOpen && (
                <div
                  className="absolute right-0 top-10 w-44 rounded-xl bg-[#12161f] border border-white/15 shadow-2xl p-2 z-50 flex flex-col gap-1 backdrop-blur-xl"
                  onMouseLeave={() => setConsoleMenuOpen(false)}
                >
                  <Link
                    to="/dashboard"
                    onClick={() => setConsoleMenuOpen(false)}
                    className="px-3 py-1.5 rounded-lg text-xs font-mono text-white/80 hover:text-white hover:bg-white/5"
                  >
                    Dashboard
                  </Link>
                  <Link
                    to="/sessions"
                    onClick={() => setConsoleMenuOpen(false)}
                    className="px-3 py-1.5 rounded-lg text-xs font-mono text-white/80 hover:text-white hover:bg-white/5"
                  >
                    Sessions
                  </Link>
                  <Link
                    to="/reports"
                    onClick={() => setConsoleMenuOpen(false)}
                    className="px-3 py-1.5 rounded-lg text-xs font-mono text-white/80 hover:text-white hover:bg-white/5"
                  >
                    Reports
                  </Link>
                  <Link
                    to="/docs"
                    onClick={() => setConsoleMenuOpen(false)}
                    className="px-3 py-1.5 rounded-lg text-xs font-mono text-white/80 hover:text-white hover:bg-white/5"
                  >
                    Documentation
                  </Link>
                </div>
              )}
            </div>
          )}

          <button
            onClick={() => navigate('/analyze')}
            className="inline-flex items-center gap-1.5 bg-[#48BB36] hover:bg-[#3ca32c] text-white text-xs font-mono font-semibold uppercase px-4 py-1.5 rounded-full shadow-md shadow-[#48bb36]/20 transition-all cursor-pointer"
          >
            <span>Analyze PCAP</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Mobile Menu Button */}
        <div className="flex lg:hidden items-center gap-2">
          <button
            onClick={() => navigate('/analyze')}
            className="bg-[#48BB36] text-white text-xs font-mono font-semibold px-3 py-1.5 rounded-full sm:hidden"
          >
            Analyze
          </button>
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="w-8 h-8 rounded-full border border-white/15 bg-white/5 flex items-center justify-center text-white cursor-pointer"
            aria-label="Toggle Navigation"
          >
            {mobileMenuOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Mobile Drawer Menu */}
      {mobileMenuOpen && (
        <div className="mt-2 rounded-2xl border border-white/15 bg-[#12161f]/98 backdrop-blur-2xl p-5 shadow-2xl lg:hidden flex flex-col gap-3">
          {isLanding && sections && onSelectSection ? (
            <div className="space-y-1 pb-3 border-b border-white/10">
              <span className="text-[10px] font-mono uppercase text-white/40 px-2 font-bold tracking-wider">
                Landing Sections
              </span>
              {sections.map((sec) => (
                <button
                  key={sec.id}
                  onClick={() => {
                    onSelectSection(sec.id);
                    setMobileMenuOpen(false);
                  }}
                  className={cn(
                    'w-full text-left py-2 px-3 text-xs font-mono rounded-lg transition-colors cursor-pointer',
                    activeSection === sec.id
                      ? 'text-[#48BB36] bg-white/5 font-semibold'
                      : 'text-white/80 hover:text-white'
                  )}
                >
                  {sec.label}
                </button>
              ))}
            </div>
          ) : null}

          <div className="space-y-1">
            <span className="text-[10px] font-mono uppercase text-white/40 px-2 font-bold tracking-wider">
              System Consoles
            </span>
            {defaultNavItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                onClick={() => setMobileMenuOpen(false)}
                className={({ isActive }) =>
                  cn(
                    'py-2 px-3 text-xs font-mono rounded-lg flex items-center justify-between',
                    isActive ? 'text-[#48BB36] bg-white/5' : 'text-white/80 hover:text-white'
                  )
                }
              >
                <span>{item.label}</span>
              </NavLink>
            ))}
          </div>

          <div className="pt-2">
            <button
              onClick={() => {
                navigate('/analyze');
                setMobileMenuOpen(false);
              }}
              className="w-full bg-[#48BB36] hover:bg-[#3ca32c] text-white font-mono font-semibold text-xs uppercase py-2.5 rounded-lg text-center shadow-lg"
            >
              Analyze PCAP Ingest
            </button>
          </div>
        </div>
      )}
    </header>
  );
}
