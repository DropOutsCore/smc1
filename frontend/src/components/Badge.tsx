import { cn } from '../lib/utils';
import type { SeverityLevel, GradeLevel } from '../types';
import { getSeverityBg, getGradeColor, getGradeBg } from '../lib/utils';

interface BadgeProps {
  children: React.ReactNode;
  className?: string;
}

export function Badge({ children, className }: BadgeProps) {
  return (
    <span className={cn('inline-flex items-center px-2 py-0.5 rounded border text-xs font-mono font-semibold tracking-wider uppercase', className)}>
      {children}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: SeverityLevel | string }) {
  return (
    <Badge className={getSeverityBg(severity as SeverityLevel)}>
      {severity}
    </Badge>
  );
}

export function GradeBadge({ grade, size = 'md' }: { grade: GradeLevel | string; size?: 'sm' | 'md' | 'lg' }) {
  const sizeClasses = {
    sm: 'w-7 h-7 text-sm',
    md: 'w-10 h-10 text-xl',
    lg: 'w-14 h-14 text-2xl',
  };
  return (
    <span className={cn(
      'inline-flex items-center justify-center rounded border-2 font-bold font-mono',
      sizeClasses[size],
      getGradeColor(grade),
      getGradeBg(grade),
    )}>
      {grade}
    </span>
  );
}

export function PostureGradeBadge({
  grade,
  label,
  score,
  size = 'md',
  showLabel = true,
}: {
  grade: GradeLevel | string;
  label?: string;
  score?: number;
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
}) {
  const lbl = label || (grade === 'A+' ? 'Excellent' : grade === 'A' ? 'Strong' : grade === 'B' ? 'Good' : grade === 'C' ? 'Moderate' : grade === 'D' ? 'Weak' : grade === 'E' ? 'Poor' : 'Critical');
  return (
    <div className="inline-flex items-center gap-2.5">
      <GradeBadge grade={grade} size={size} />
      {showLabel && (
        <div className="flex flex-col">
          <div className="flex items-center gap-1.5">
            <span className={cn('font-mono font-bold leading-tight', size === 'lg' ? 'text-lg' : size === 'sm' ? 'text-xs' : 'text-sm', getGradeColor(grade))}>
              {grade} — {lbl}
            </span>
          </div>
          <span className="text-[10px] font-mono text-[#7F948B]">
            Security Posture{score !== undefined ? ` • ${score}/100` : ''}
          </span>
        </div>
      )}
    </div>
  );
}

export function GradePill({ grade, score, label }: { grade: string; score: number; label?: string }) {
  return (
    <div className={cn(
      'inline-flex items-center gap-2.5 px-3 py-1.5 rounded border',
      getGradeBg(grade),
    )}>
      <span className={cn('text-2xl font-bold font-mono', getGradeColor(grade))}>{grade}</span>
      <div className="flex flex-col text-left">
        {label && <span className={cn('text-[11px] font-bold font-mono uppercase tracking-wider', getGradeColor(grade))}>{label}</span>}
        <span className="text-xs text-[#B8C8C0] font-mono">{score}/100</span>
      </div>
    </div>
  );
}
