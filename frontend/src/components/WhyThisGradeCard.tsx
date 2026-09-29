import { useState } from 'react';
import type { WhyThisGrade, GradeLadderStep, DeterminingFactor } from '../types';
import { cn, getGradeColor, getGradeBg, getGradeLabel } from '../lib/utils';
import { SeverityBadge } from './Badge';
import { ChevronDown, ChevronUp, ArrowUpRight, CheckCircle2 } from 'lucide-react';

interface WhyThisGradeCardProps {
  why: WhyThisGrade;
  hostName?: string;
  defaultOpen?: boolean;
}

export function WhyThisGradeCard({ why, hostName, defaultOpen = true }: WhyThisGradeCardProps) {
  const [open, setOpen] = useState(defaultOpen);
  const grade = why.grade;
  const label = why.label || getGradeLabel(grade);
  const ladder: GradeLadderStep[] = why.grade_ladder || [];
  const factors: DeterminingFactor[] = why.determining_factors || [];
  const nextTarget = why.next_grade_target;
  const scoreVal = why.score !== undefined ? why.score : (why as any).risk_score ?? 0;
  const bracketVal = why.threshold_bracket || (why as any).score_bracket || `Score: ${scoreVal}`;

  return (
    <div className="bg-[#111215]/90 border border-white/10 rounded-xl overflow-hidden my-4 shadow-xl">
      {/* Header bar */}
      <div className="p-4 bg-[#16181d]/90 border-b border-white/10 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div
            className={cn(
              'w-12 h-12 rounded-xl border flex items-center justify-center font-mono font-bold text-2xl shadow-inner',
              getGradeColor(grade),
              getGradeBg(grade)
            )}
          >
            {grade}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className={cn('text-base font-mono font-bold', getGradeColor(grade))}>
                Security Posture: {grade} ({label})
              </span>
              {hostName && (
                <span className="text-xs font-mono text-white/90 bg-white/5 px-2 py-0.5 rounded-md border border-white/10">
                  {hostName}
                </span>
              )}
            </div>
            <p className="text-xs font-mono text-white/50 mt-0.5">
              Risk Score: <strong className="text-white">{scoreVal}/100</strong> • {bracketVal}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 self-end md:self-auto">
          <div className="text-right hidden sm:block">
            <span className="text-[10px] font-mono text-white/40 block uppercase tracking-wider">Evaluation Mode</span>
            <span className="text-xs font-mono text-cyan-400">Deterministic Rule Engine</span>
          </div>
          <button
            onClick={() => setOpen(v => !v)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono bg-white/10 hover:bg-white/15 text-white border border-white/10 transition-colors cursor-pointer"
          >
            <span>{open ? 'Hide Breakdown' : 'Why this grade?'}</span>
            {open ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </button>
        </div>
      </div>

      {open && (
        <div className="p-4 space-y-5">
          {/* Summary Quote */}
          {why.summary && (
            <div className="bg-white/[0.02] border-l-4 border-cyan-400 p-3 rounded-r text-xs font-mono text-white/80 leading-relaxed">
              <span className="text-cyan-400 font-bold">Posture Assessment: </span>
              {why.summary}
            </div>
          )}

          {/* Visual 7-Tier Grade Ladder */}
          {ladder.length > 0 && (
            <div>
              <div className="flex items-center justify-between text-[11px] font-mono text-white/50 mb-2 uppercase tracking-wider">
                <span>Deterministic Grade Ladder (SSL Labs Style)</span>
                <span>Active Tier: {grade} ({label})</span>
              </div>
              <div className="grid grid-cols-7 gap-1.5 sm:gap-2">
                {ladder.map((step: GradeLadderStep) => {
                  const isCurrent = step.active || step.grade === grade;
                  const stepGradeColor = getGradeColor(step.grade);
                  return (
                    <div
                      key={step.grade}
                      className={cn(
                        'flex flex-col items-center justify-center p-2 rounded-lg border text-center transition-all',
                        isCurrent
                          ? 'bg-white/10 border-cyan-400/60 ring-1 ring-cyan-400/30 shadow-[0_0_12px_rgba(0,210,255,0.2)]'
                          : 'bg-white/[0.02] border-white/5 opacity-60'
                      )}
                    >
                      <span className={cn('text-sm sm:text-base font-mono font-bold', isCurrent ? stepGradeColor : 'text-white/40')}>
                        {step.grade}
                      </span>
                      <span className={cn('text-[10px] font-mono hidden sm:inline truncate w-full', isCurrent ? 'text-white font-semibold' : 'text-white/40')}>
                        {step.label}
                      </span>
                      <span className="text-[9px] font-mono text-white/40 mt-0.5">
                        {step.range}
                      </span>
                      {isCurrent && (
                        <span className="mt-1 px-1 py-0.2 rounded text-[8px] font-mono font-bold bg-cyan-400 text-black uppercase">
                          Current
                        </span>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Determining Factors Table */}
          <div>
            <div className="flex items-center justify-between text-[11px] font-mono text-[#7F948B] mb-2 uppercase tracking-wider">
              <span>Why This Grade? — Root Finding Contributions</span>
              <span>{factors.length} Determining Factor(s)</span>
            </div>

            {factors.length > 0 ? (
              <div className="overflow-x-auto border border-white/10 rounded-lg bg-black/40">
                <table className="w-full text-left text-xs font-mono border-collapse">
                  <thead>
                    <tr className="border-b border-white/10 text-white/50 text-[10px] bg-white/[0.03]">
                      <th className="py-2.5 px-3">Finding Description</th>
                      <th className="py-2.5 px-3">Severity</th>
                      <th className="py-2.5 px-3">Risk Penalty</th>
                      <th className="py-2.5 px-3">Evidence Reference</th>
                      <th className="py-2.5 px-3">Impact & Rationale</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5 text-[11px]">
                    {factors.map((f: DeterminingFactor, i: number) => (
                      <tr key={i} className="hover:bg-white/[0.02]">
                        <td className="py-2.5 px-3 text-white font-medium">
                          {f.description || f.feature || f.rule_id}
                          <div className="text-[10px] text-white/40">{f.rule_id || f.finding_id}</div>
                        </td>
                        <td className="py-2.5 px-3 whitespace-nowrap">
                          <SeverityBadge severity={f.severity} />
                        </td>
                        <td className="py-2.5 px-3 text-[#FF5C5C] font-bold whitespace-nowrap">
                          +{f.score_contribution} pts
                        </td>
                        <td className="py-2.5 px-3 text-white/70 text-[10px] whitespace-nowrap">
                          {f.evidence_ref ? (
                            <span className="bg-white/10 px-1.5 py-0.5 rounded border border-white/10 text-cyan-300">
                              {f.evidence_ref}
                            </span>
                          ) : (
                            <span className="text-white/40">Wire Evidence</span>
                          )}
                        </td>
                        <td className="py-2.5 px-3 text-white/50 text-[10px] max-w-xs leading-relaxed">
                          {f.impact_on_grade || f.observed_value || 'Determines active posture grade'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="p-3 bg-white/[0.02] border border-cyan-400/20 rounded-lg text-xs font-mono text-cyan-300 flex items-center gap-2">
                <CheckCircle2 size={16} />
                <span>Zero adverse findings detected. Cryptographic posture qualifies for tier {grade} ({label}).</span>
              </div>
            )}
          </div>

          {/* Actionable Next Grade Target */}
          {nextTarget && (
            <div className="p-3.5 bg-white/[0.04] border border-white/10 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-start gap-2.5">
                <ArrowUpRight size={18} className="text-cyan-400 shrink-0 mt-0.5" />
                <div>
                  <div className="text-xs font-mono font-bold text-white flex items-center gap-1.5">
                    <span>Path to Grade {nextTarget.target_grade} ({nextTarget.target_label}):</span>
                    <span className="text-cyan-400">Reduce risk by {nextTarget.points_to_reduce} pt(s)</span>
                  </div>
                  <p className="text-[11px] font-mono text-white/50 mt-0.5">
                    {nextTarget.top_remediation_action}
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
