import { cn } from '../lib/utils';

interface CardProps {
  children: React.ReactNode;
  className?: string;
  hover?: boolean;
  onClick?: () => void;
}

export function Card({ children, className, hover = false, onClick }: CardProps) {
  return (
    <div
      onClick={onClick}
      className={cn(
        'bg-[#111215]/80 border border-white/10 rounded-xl p-5 shadow-lg backdrop-blur-sm transition-all duration-200',
        hover && 'hover:border-white/20 hover:bg-[#16181d]/90 hover:shadow-xl',
        onClick && 'cursor-pointer',
        className
      )}
    >
      {children}
    </div>
  );
}

interface StatCardProps {
  label: string;
  value: string | number;
  sub?: string;
  valueColor?: string;
  icon?: React.ReactNode;
}

export function StatCard({ label, value, sub, valueColor = 'text-white', icon }: StatCardProps) {
  return (
    <Card className="flex flex-col gap-1">
      <div className="flex items-center justify-between">
        <span className="text-white/50 text-xs uppercase tracking-wider font-mono">{label}</span>
        {icon && <span className="text-white/40">{icon}</span>}
      </div>
      <span className={cn('text-3xl font-bold font-mono mt-1', valueColor)}>{value}</span>
      {sub && <span className="text-white/40 text-xs font-mono">{sub}</span>}
    </Card>
  );
}

interface SectionHeaderProps {
  title: string;
  sub?: string;
  badge?: React.ReactNode;
  action?: React.ReactNode;
}

export function SectionHeader({ title, sub, badge, action }: SectionHeaderProps) {
  return (
    <div className="flex items-start justify-between mb-6">
      <div>
        <div className="flex items-center gap-3">
          <h2 className="text-white text-sm font-semibold tracking-wider uppercase font-mono">
            {title}
          </h2>
          {badge}
        </div>
        {sub && <p className="text-white/50 text-xs mt-1">{sub}</p>}
      </div>
      {action}
    </div>
  );
}

export function Divider({ className }: { className?: string }) {
  return <div className={cn('border-t border-white/10', className)} />;
}

export function Label({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <span className={cn('text-white/50 text-xs uppercase tracking-wider font-mono', className)}>
      {children}
    </span>
  );
}

export function Value({ children, className, mono = true }: { children: React.ReactNode; className?: string; mono?: boolean }) {
  return (
    <span className={cn('text-white text-sm', mono && 'font-mono', className)}>
      {children ?? '—'}
    </span>
  );
}

export function KeyValue({ label, value, valueClassName }: { label: string; value: React.ReactNode; valueClassName?: string }) {
  return (
    <div className="flex flex-col gap-1">
      <Label>{label}</Label>
      <Value className={valueClassName}>{value}</Value>
    </div>
  );
}

interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description?: string;
  action?: React.ReactNode;
}

export function EmptyState({ icon, title, description, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center py-20 gap-4 text-center">
      {icon && <div className="text-white/20 mb-2">{icon}</div>}
      <h3 className="text-white/80 font-mono text-sm uppercase tracking-widest">{title}</h3>
      {description && <p className="text-white/40 text-sm max-w-sm">{description}</p>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}

interface ErrorBannerProps {
  title: string;
  message: string;
  onRetry?: () => void;
  className?: string;
}

export function ErrorBanner({ title, message, onRetry, className }: ErrorBannerProps) {
  return (
    <div className={cn('bg-[#FF5C5C]/10 border border-[#FF5C5C]/30 rounded-xl p-5', className)}>
      <p className="text-[#FF5C5C] font-mono text-sm font-semibold uppercase tracking-wider mb-1">{title}</p>
      <p className="text-white/70 text-sm">{message}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="mt-3 text-xs font-mono text-[#FF5C5C] hover:text-white border border-[#FF5C5C]/30 rounded-lg px-3 py-1 transition-colors"
        >
          Retry
        </button>
      )}
    </div>
  );
}

export function Spinner({ size = 'md' }: { size?: 'sm' | 'md' | 'lg' }) {
  const sizeClass = size === 'sm' ? 'w-4 h-4' : size === 'lg' ? 'w-8 h-8' : 'w-6 h-6';
  return (
    <div className={cn('border-2 border-white/10 border-t-[#48BB36] rounded-full animate-spin', sizeClass)} />
  );
}
