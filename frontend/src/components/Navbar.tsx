import { Link, NavLink } from 'react-router-dom';
import { useHealth } from '../hooks';
import { Activity, FileText, BookOpen, Cpu, Shield, ArrowLeft } from 'lucide-react';
import { cn } from '../lib/utils';
import { LogoMark } from './AuraPrimitives';

const navLinks = [
  { to: '/dashboard', label: 'Dashboard', icon: Activity },
  { to: '/analyze', label: 'Analyze PCAP', icon: Cpu },
  { to: '/sessions', label: 'Sessions', icon: Shield },
  { to: '/reports', label: 'Reports', icon: FileText },
  { to: '/docs', label: 'Docs', icon: BookOpen },
];

export function Navbar() {
  const health = useHealth();

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 h-14 border-b border-white/10 bg-[#0c0c0c]/85 backdrop-blur-xl">
      <div className="max-w-7xl mx-auto h-full px-6 flex items-center justify-between">
        {/* Logo with Aura Mark */}
        <div className="flex items-center gap-4">
          <Link to="/" className="flex items-center gap-2.5 group">
            <LogoMark className="w-6 h-6 transition-transform group-hover:scale-105" />
            <div className="flex items-baseline gap-1.5">
              <span className="text-white font-bold text-base tracking-wider uppercase font-mono group-hover:text-cyan-400 transition-colors">
                AVALOK
              </span>
              <span className="text-[10px] font-mono uppercase tracking-widest text-white/40">
                Forensics
              </span>
            </div>
          </Link>

          <div className="h-4 w-px bg-white/10 hidden sm:block" />

          {/* Quick link to Landing Page */}
          <Link
            to="/"
            className="hidden sm:inline-flex items-center gap-1 text-[11px] text-white/40 hover:text-white transition-colors"
          >
            <ArrowLeft className="w-3 h-3" />
            <span>Landing</span>
          </Link>
        </div>

        {/* Nav links */}
        <ul className="hidden md:flex items-center gap-1">
          {navLinks.map(({ to, label, icon: Icon }) => (
            <li key={to}>
              <NavLink
                to={to}
                className={({ isActive }) =>
                  cn(
                    'flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-medium tracking-wide transition-all duration-150',
                    isActive
                      ? 'text-white bg-white/10 shadow-sm border border-white/10'
                      : 'text-white/60 hover:text-white hover:bg-white/5'
                  )
                }
              >
                <Icon className="w-3.5 h-3.5 text-white/50" />
                <span>{label}</span>
              </NavLink>
            </li>
          ))}
        </ul>

        {/* Status indicator */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-2.5 py-1 rounded-full bg-white/[0.03] border border-white/10 text-xs">
            <span
              className={cn(
                'w-2 h-2 rounded-full',
                health === 'online'
                  ? 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]'
                  : health === 'offline'
                  ? 'bg-rose-500'
                  : 'bg-amber-400 animate-pulse'
              )}
            />
            <span
              className={cn(
                'font-mono text-[11px]',
                health === 'online'
                  ? 'text-emerald-300'
                  : health === 'offline'
                  ? 'text-rose-400'
                  : 'text-amber-300'
              )}
            >
              {health === 'online' ? 'Engine Ready' : health === 'offline' ? 'Offline' : 'Connecting'}
            </span>
          </div>
        </div>
      </div>
    </nav>
  );
}
