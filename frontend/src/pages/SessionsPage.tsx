import { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Layout } from '../components/Layout';
import { Card, SectionHeader, EmptyState, Spinner, ErrorBanner } from '../components/Card';
import { SeverityBadge, GradeBadge, PostureGradeBadge } from '../components/Badge';
import { WhyThisGradeCard } from '../components/WhyThisGradeCard';
import { getReports, getReport } from '../services/api';
import type { ForensicReport, Session, WhyThisGrade } from '../types';
import { cn, formatTlsVersion, getGradeColor, getGradeBg, getGradeLabel } from '../lib/utils';
import { Shield, ChevronRight, Eye, Lock, CheckCircle, XCircle, AlertTriangle, Minus, HelpCircle, ChevronDown, ChevronUp, Terminal } from 'lucide-react';

function SessionWhyThisScore({ session }: { session: Session }) {
  const [showTree, setShowTree] = useState(false);
  const [open, setOpen] = useState(true);
  const why = session.why_this_score;
  const ml = session.ml_anomaly_assessment || why?.ml_anomaly_assessment;

  if (!why && !ml) return null;
  const scoreVal = why?.risk_score ?? 0;
  const sevVal = why?.severity ?? 'clean';
  const factors = why?.contributing_factors ?? [];

  return (
    <div className="border border-white/10 bg-[#111215]/90 rounded-xl p-3.5 space-y-3 mb-5">
      <div className="flex items-center justify-between border-b border-white/10 pb-2">
        <div className="flex items-center gap-1.5">
          <HelpCircle size={14} className="text-[#48BB36]" />
          <span className="text-[#48BB36] font-mono text-xs font-bold uppercase tracking-wider">
            Why This Score? — Risk Reasoning
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] font-mono text-white bg-white/10 px-2 py-0.5 rounded border border-white/10">
            Score: <strong className="text-[#48BB36]">{scoreVal} / 100</strong> ({sevVal.toUpperCase()})
          </span>
          {why?.ascii_tree && (
            <button
              onClick={() => setShowTree(v => !v)}
              className="text-[10px] font-mono text-[#48BB36] underline hover:text-[#5fcf4c] transition-colors cursor-pointer"
            >
              {showTree ? 'Hide Tree' : 'View Tree'}
            </button>
          )}
          <button
            onClick={() => setOpen(v => !v)}
            className="text-[#7F948B] hover:text-[#F3F7F4] transition-colors"
          >
            {open ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
          </button>
        </div>
      </div>

      {open && (
        <>
          {showTree && why?.ascii_tree && (
            <pre className="bg-[#020F0C] p-2.5 rounded font-mono text-[11px] text-[#8BFF7A] overflow-x-auto border border-[rgba(139,255,122,0.15)] leading-relaxed">
              {why.ascii_tree}
            </pre>
          )}

          {factors.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono border-collapse">
                <thead>
                  <tr className="border-b border-[rgba(139,255,122,0.15)] text-[#7F948B] text-[10px]">
                    <th className="py-1 px-1.5">Feature</th>
                    <th className="py-1 px-1.5">Observed</th>
                    <th className="py-1 px-1.5">Impact</th>
                    <th className="py-1 px-1.5">Severity</th>
                    <th className="py-1 px-1.5">Evidence</th>
                    <th className="py-1 px-1.5">Rationale</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[rgba(139,255,122,0.06)] text-[10px]">
                  {factors.map((f, i) => (
                    <tr key={i} className="hover:bg-[rgba(139,255,122,0.02)]">
                      <td className="py-1.5 px-1.5 text-[#F3F7F4] font-medium whitespace-nowrap">
                        {f.feature}
                        <div className="text-[9px] text-[#7F948B]">{f.rule_id}</div>
                      </td>
                      <td className="py-1.5 px-1.5 text-[#F5B942] whitespace-nowrap">{f.observed_value}</td>
                      <td className="py-1.5 px-1.5 text-[#FF5C5C] font-bold">+{f.score_contribution}</td>
                      <td className="py-1.5 px-1.5 uppercase font-semibold">{f.severity}</td>
                      <td className="py-1.5 px-1.5 text-[#B8C8C0] whitespace-nowrap">{f.evidence_reference}</td>
                      <td className="py-1.5 px-1.5 text-[#B8C8C0] leading-snug">{f.short_explanation}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-[#3DDC97] text-xs font-mono py-0.5">
              ✓ Clean cryptographic baseline: no adverse score contributions detected.
            </p>
          )}

          {ml && (
            <div className="mt-2 pt-2 border-t border-[rgba(139,255,122,0.1)] bg-[#0B2A20]/40 rounded p-2.5">
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] font-mono font-bold text-[#5DA9FF] uppercase tracking-wider flex items-center gap-1">
                  <span>🤖</span> ML Anomaly Assessment (Independent Layer)
                </span>
                <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-[#5DA9FF]/10 text-[#5DA9FF] border border-[#5DA9FF]/30">
                  {ml.ml_risk_label.toUpperCase()} ({Math.round(ml.ml_confidence * 100)}% conf)
                </span>
              </div>
              <p className="text-[10px] font-mono text-[#7F948B] leading-relaxed mb-1.5">
                {ml.score_isolation_note}
              </p>
              <div className="flex flex-wrap gap-1.5 text-[9px] font-mono text-white/80">
                <span className="bg-white/5 px-1.5 py-0.5 rounded border border-white/10">
                  Anomaly: <strong className={ml.is_model_anomaly ? 'text-[#FF5C5C]' : 'text-emerald-400'}>{ml.is_model_anomaly ? 'YES' : 'NO'}</strong>
                </span>
                <span className="bg-white/5 px-1.5 py-0.5 rounded border border-white/10">
                  Score: <strong className="text-white">{ml.anomaly_score.toFixed(3)}</strong>
                </span>
                <span className="bg-white/5 px-1.5 py-0.5 rounded border border-white/10">
                  Arch: <strong className="text-white">{ml.model_architecture}</strong>
                </span>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function TlsIcon({ version }: { version: string }) {
  const v = formatTlsVersion(version);
  const color = v.includes('1.3') ? '#8BFF7A' : v.includes('1.2') ? '#3DDC97' :
    v.includes('1.1') ? '#F5B942' : v.includes('1.0') ? '#F59342' :
    v.toLowerCase().includes('ssl') ? '#FF5C5C' : '#B8C8C0';
  return <span style={{ color }} className="font-mono text-xs">{v}</span>;
}

function BoolIndicator({ value, trueLabel, falseLabel }: { value: boolean; trueLabel?: string; falseLabel?: string }) {
  return value ? (
    <span className="flex items-center gap-1 text-[#8BFF7A] text-xs font-mono">
      <CheckCircle size={12} /> {trueLabel ?? 'Yes'}
    </span>
  ) : (
    <span className="flex items-center gap-1 text-[#FF5C5C] text-xs font-mono">
      <XCircle size={12} /> {falseLabel ?? 'No'}
    </span>
  );
}

export default function SessionsPage() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [report, setReport] = useState<ForensicReport | null>(null);
  const [selectedSession, setSelectedSession] = useState<Session | null>(null);
  const [filterProtocol, setFilterProtocol] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('');

  useEffect(() => {
    async function load() {
      try {
        const reps = await getReports();
        if (reps.length === 0) { setLoading(false); return; }
        const full = await getReport(reps[0].report_id);
        setReport(full);
      } catch (err: any) {
        setError(err?.message ?? 'Failed to load sessions');
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  if (loading) {
    return (
      <Layout>
        <div className="flex items-center justify-center min-h-[60vh] gap-3">
          <Spinner size="lg" />
          <span className="text-[#7F948B] font-mono text-sm">Loading sessions…</span>
        </div>
      </Layout>
    );
  }

  if (error) {
    return <Layout><div className="max-w-xl mx-auto px-6 py-16"><ErrorBanner title="Error" message={error} /></div></Layout>;
  }

  if (!report) {
    return (
      <Layout>
        <div className="max-w-screen-xl mx-auto px-6 py-16">
          <EmptyState
            icon={<Shield size={48} />}
            title="No Sessions"
            description="Analyze a PCAP file to see reconstructed email sessions."
            action={
              <button
                onClick={() => navigate('/analyze')}
                className="px-6 py-3 bg-[#48BB36] hover:bg-[#3ca32c] text-white font-bold text-xs uppercase tracking-wider rounded-md shadow-lg shadow-[#48bb36]/25 transition-all cursor-pointer"
              >
                Analyze PCAP
              </button>
            }
          />
        </div>
      </Layout>
    );
  }

  const allSessions = report.hosts.flatMap(h =>
    h.sessions.map(s => ({ ...s, _host: h.host, _grade: h.posture_grade }))
  );

  const protocols = [...new Set(allSessions.map(s => s.protocol))];
  const filtered = allSessions.filter(s => {
    if (filterProtocol && s.protocol !== filterProtocol) return false;
    if (filterSeverity && !s.findings.some(f => f.severity === filterSeverity)) return false;
    return true;
  });

  return (
    <Layout>
      <div className="max-w-screen-xl mx-auto px-6 py-10 fade-in">
        <div className="mb-6">
          <h1 className="text-white text-3xl font-extrabold tracking-tight">Session Explorer</h1>
          <p className="text-white/60 text-sm mt-1 font-mono">
            {allSessions.length} reconstructed sessions across {report.hosts.length} hosts
          </p>
        </div>

        {/* Filters */}
        <div className="flex gap-3 mb-6 flex-wrap">
          <select
            value={filterProtocol}
            onChange={e => setFilterProtocol(e.target.value)}
            className="bg-[#171c23] border border-white/10 text-white text-xs font-mono rounded-lg px-3 py-2 focus:outline-none focus:border-[#48BB36]"
          >
            <option value="">All Protocols</option>
            {protocols.map(p => <option key={p} value={p}>{p}</option>)}
          </select>
          <select
            value={filterSeverity}
            onChange={e => setFilterSeverity(e.target.value)}
            className="bg-[#171c23] border border-white/10 text-white text-xs font-mono rounded-lg px-3 py-2 focus:outline-none focus:border-[#48BB36]"
          >
            <option value="">All Severity</option>
            {['critical', 'high', 'medium', 'low'].map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <span className="ml-auto text-[#7F948B] text-xs font-mono self-center">
            {filtered.length} of {allSessions.length} sessions
          </span>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
          {/* Session list */}
          <div className="lg:col-span-2">
            <div className="space-y-2 max-h-[70vh] overflow-y-auto pr-1">
              {filtered.map((session) => {
                const hasCritical = session.findings.some(f => f.severity === 'critical');
                const hasHigh = session.findings.some(f => f.severity === 'high');
                const isSelected = selectedSession?.session_id === session.session_id;
                const hostForSess = report?.hosts.find(h => h.sessions.some(s => s.session_id === session.session_id));
                const sGrade = session.host_posture_grade || hostForSess?.posture_grade;
                const sLabel = session.host_posture_label || hostForSess?.posture_label || (sGrade ? getGradeLabel(sGrade) : undefined);

                return (
                  <div
                    key={session.session_id}
                    onClick={() => setSelectedSession(session)}
                    className={cn(
                      'bg-[#0B2A20] border rounded-lg p-4 cursor-pointer transition-all duration-150',
                      isSelected
                        ? 'border-[rgba(139,255,122,0.4)] bg-[rgba(139,255,122,0.04)]'
                        : 'border-[rgba(139,255,122,0.08)] hover:border-[rgba(139,255,122,0.2)]'
                    )}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span className={cn(
                          'text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border',
                          session.protocol.includes('SMTP') ? 'text-[#8BFF7A] border-[rgba(139,255,122,0.3)] bg-[rgba(139,255,122,0.08)]' :
                          session.protocol.includes('IMAP') ? 'text-[#3DDC97] border-[rgba(61,220,151,0.3)] bg-[rgba(61,220,151,0.08)]' :
                          'text-[#5DA9FF] border-[rgba(93,169,255,0.3)] bg-[rgba(93,169,255,0.08)]'
                        )}>
                          {session.protocol}
                        </span>
                        <TlsIcon version={session.tls_version} />
                        {sGrade && (
                          <span
                            className={cn('text-[9px] font-mono px-1.5 py-0.5 rounded border font-bold', getGradeBg(sGrade), getGradeColor(sGrade))}
                            title={`Host Security Posture: ${sGrade} (${sLabel})`}
                          >
                            {sGrade}
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-1.5">
                        {hasCritical && <span className="w-1.5 h-1.5 rounded-full bg-[#FF5C5C]" />}
                        {hasHigh && <span className="w-1.5 h-1.5 rounded-full bg-[#F5B942]" />}
                        {session.downgrade_suspected && <AlertTriangle size={12} className="text-[#FF5C5C]" />}
                        <ChevronRight size={12} className={cn('transition-colors', isSelected ? 'text-[#8BFF7A]' : 'text-[#3B5A4F]')} />
                      </div>
                    </div>
                    <p className="text-[#F3F7F4] text-xs font-mono">
                      {session.src_ip}:{session.src_port}
                    </p>
                    <p className="text-[#7F948B] text-[10px] font-mono">
                      → {session.dst_ip}:{session.dst_port}
                    </p>
                    <div className="flex items-center gap-3 mt-2">
                      <span className="text-[#7F948B] text-[10px] font-mono">{session.findings.length} findings</span>
                      {session.pfs && <span className="text-[10px] text-[#3DDC97] font-mono">PFS</span>}
                      {session.anomaly_detected && <span className="text-[10px] text-[#F5B942] font-mono">ANOMALY</span>}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Session detail */}
          <div className="lg:col-span-3">
            {!selectedSession ? (
              <Card className="h-full flex items-center justify-center min-h-[400px]">
                <EmptyState
                  icon={<Eye size={32} />}
                  title="Select a Session"
                  description="Click a session on the left to view forensic details."
                />
              </Card>
            ) : (() => {
              const selectedHost = report?.hosts.find(h => h.sessions.some(s => s.session_id === selectedSession.session_id));
              const selectedHostGrade = selectedSession.host_posture_grade || selectedHost?.posture_grade || 'F';
              const selectedHostLabel = selectedSession.host_posture_label || selectedHost?.posture_label || getGradeLabel(selectedHostGrade);
              const selectedHostWhyGrade: WhyThisGrade | undefined = selectedHost?.why_this_grade || (selectedHost?.why_this_score ? {
                grade: selectedHostGrade,
                label: selectedHostLabel,
                score: selectedHost.posture_score,
                threshold_bracket: `Score ${selectedHost.posture_score} / 100`,
                headline: `Security Posture: ${selectedHostGrade} (${selectedHostLabel})`,
                summary: `Host ${selectedHost.host} assigned posture grade ${selectedHostGrade} (${selectedHostLabel}) based on ${selectedHost.why_this_score.contributing_factors.length} adverse security finding(s).`,
                grade_ladder: [
                  { grade: 'A+', label: 'Excellent', range: '0', active: selectedHostGrade === 'A+' },
                  { grade: 'A', label: 'Strong', range: '1–5', active: selectedHostGrade === 'A' },
                  { grade: 'B', label: 'Good', range: '6–15', active: selectedHostGrade === 'B' },
                  { grade: 'C', label: 'Moderate', range: '16–30', active: selectedHostGrade === 'C' },
                  { grade: 'D', label: 'Weak', range: '31–50', active: selectedHostGrade === 'D' },
                  { grade: 'E', label: 'Poor', range: '51–75', active: selectedHostGrade === 'E' },
                  { grade: 'F', label: 'Critical', range: '76+', active: selectedHostGrade === 'F' },
                ],
                determining_factors: selectedHost.why_this_score.contributing_factors.map(f => ({
                  finding_id: f.rule_id,
                  rule_id: f.rule_id,
                  feature: f.feature,
                  description: f.feature,
                  severity: f.severity,
                  score_contribution: f.score_contribution,
                  evidence_ref: f.evidence_reference,
                  impact_on_grade: f.short_explanation,
                })),
              } : undefined);

              return (
              <Card className="slide-in-right">
                {/* Header */}
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 mb-6 pb-4 border-b border-[rgba(139,255,122,0.1)]">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-[#8BFF7A] font-mono text-xs uppercase tracking-wider font-semibold">
                        Session Detail
                      </span>
                      <span className="text-[#3B5A4F] text-[10px] font-mono">
                        {selectedSession.session_id.slice(0, 8).toUpperCase()}
                      </span>
                      {selectedHost && (
                        <span className="text-[#7F948B] text-[10px] font-mono">
                          • {selectedHost.host}
                        </span>
                      )}
                    </div>
                    <p className="text-[#F3F7F4] font-mono text-sm">
                      {selectedSession.src_ip}:{selectedSession.src_port} → {selectedSession.dst_ip}:{selectedSession.dst_port}
                    </p>
                  </div>
                  <PostureGradeBadge
                    grade={selectedHostGrade}
                    label={selectedHostLabel}
                    score={selectedHost?.posture_score}
                    size="md"
                  />
                </div>

                {/* TLS Summary */}
                <div className="grid grid-cols-2 gap-3 mb-5">
                  <div className="bg-[#0E3327] rounded p-3">
                    <p className="text-[#7F948B] text-[10px] font-mono uppercase tracking-wider mb-1">TLS Version</p>
                    <TlsIcon version={selectedSession.tls_version} />
                  </div>
                  <div className="bg-[#0E3327] rounded p-3">
                    <p className="text-[#7F948B] text-[10px] font-mono uppercase tracking-wider mb-1">Cipher Strength</p>
                    <span className={cn('text-xs font-mono font-semibold',
                      selectedSession.cipher_strength === 'strong' ? 'text-[#8BFF7A]' :
                      selectedSession.cipher_strength === 'adequate' ? 'text-[#3DDC97]' : 'text-[#FF5C5C]'
                    )}>
                      {selectedSession.cipher_strength || '—'}
                    </span>
                  </div>
                  <div className="bg-[#0E3327] rounded p-3">
                    <p className="text-[#7F948B] text-[10px] font-mono uppercase tracking-wider mb-1">PFS</p>
                    <BoolIndicator value={selectedSession.pfs} trueLabel="Enabled" falseLabel="Disabled" />
                  </div>
                  <div className="bg-[#0E3327] rounded p-3">
                    <p className="text-[#7F948B] text-[10px] font-mono uppercase tracking-wider mb-1">STARTTLS</p>
                    <BoolIndicator value={selectedSession.starttls_detected} />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3 mb-5">
                  <div className="bg-[#0E3327] rounded p-3 col-span-2">
                    <p className="text-[#7F948B] text-[10px] font-mono uppercase tracking-wider mb-1">Cipher Suite</p>
                    <p className="text-[#F3F7F4] text-xs font-mono break-all">{selectedSession.cipher_suite || '—'}</p>
                  </div>
                  {selectedSession.sni && (
                    <div className="bg-[#0E3327] rounded p-3 col-span-2">
                      <p className="text-[#7F948B] text-[10px] font-mono uppercase tracking-wider mb-1">SNI</p>
                      <p className="text-[#5DA9FF] text-xs font-mono">{selectedSession.sni}</p>
                    </div>
                  )}
                </div>

                {/* Alerts */}
                {selectedSession.downgrade_suspected && (
                  <div className="bg-[#FF5C5C]/8 border border-[#FF5C5C]/25 rounded p-3 mb-4 flex items-center gap-2">
                    <AlertTriangle size={14} className="text-[#FF5C5C] shrink-0" />
                    <span className="text-[#FF5C5C] text-xs font-mono">STARTTLS Downgrade Attack Suspected</span>
                  </div>
                )}
                {selectedSession.anomaly_detected && (
                  <div className="bg-[#F5B942]/8 border border-[#F5B942]/25 rounded p-3 mb-4 flex items-center gap-2">
                    <AlertTriangle size={14} className="text-[#F5B942] shrink-0" />
                    <span className="text-[#F5B942] text-xs font-mono">
                      ML Anomaly Detected (score: {selectedSession.anomaly_score?.toFixed(4)})
                    </span>
                  </div>
                )}

                {/* Certificate */}
                {selectedSession.certificate && (
                  <div className="bg-[#0E3327] border border-[rgba(139,255,122,0.08)] rounded p-4 mb-5">
                    <p className="text-[#7F948B] text-[10px] font-mono uppercase tracking-wider mb-3 flex items-center gap-1.5">
                      <Lock size={10} /> Certificate
                    </p>
                    <div className="grid grid-cols-2 gap-2 text-[10px]">
                      <div>
                        <p className="text-[#7F948B] font-mono">Subject</p>
                        <p className="text-[#F3F7F4] font-mono break-all">{selectedSession.certificate.subject}</p>
                      </div>
                      <div>
                        <p className="text-[#7F948B] font-mono">Key</p>
                        <p className="text-[#F3F7F4] font-mono">{selectedSession.certificate.key_algorithm} {selectedSession.certificate.key_length}b</p>
                      </div>
                      <div>
                        <p className="text-[#7F948B] font-mono">Expires</p>
                        <p className={cn('font-mono', selectedSession.certificate.is_expired ? 'text-[#FF5C5C]' : 'text-[#F3F7F4]')}>
                          {selectedSession.certificate.expires ? new Date(selectedSession.certificate.expires).toLocaleDateString() : '—'}
                          {selectedSession.certificate.is_expired && ' (EXPIRED)'}
                        </p>
                      </div>
                      <div>
                        <p className="text-[#7F948B] font-mono">Self-Signed</p>
                        <BoolIndicator
                          value={!selectedSession.certificate.is_self_signed}
                          trueLabel="No"
                          falseLabel="Yes"
                        />
                      </div>
                    </div>
                  </div>
                )}

                {/* Why This Score? Explainable AI & Risk Breakdown */}
                <SessionWhyThisScore session={selectedSession} />

                {/* Host Security Posture — Why This Grade? */}
                {selectedHostWhyGrade && (
                  <WhyThisGradeCard
                    why={selectedHostWhyGrade}
                    hostName={selectedHost?.host}
                    defaultOpen={false}
                  />
                )}

                {/* Findings */}
                {selectedSession.findings.length > 0 && (
                  <div>
                    <p className="text-[#7F948B] text-[10px] font-mono uppercase tracking-wider mb-3">
                      Findings ({selectedSession.findings.length})
                    </p>
                    <div className="space-y-2 max-h-[300px] overflow-y-auto">
                      {selectedSession.findings.map(finding => (
                        <div key={finding.finding_id} className="bg-[#020F0C] border border-[rgba(139,255,122,0.06)] rounded p-3">
                          <div className="flex items-center gap-2 mb-1.5">
                            <SeverityBadge severity={finding.severity} />
                            <span className="text-[#7F948B] text-[10px] font-mono">{finding.cwe}</span>
                          </div>
                          <p className="text-[#F3F7F4] text-xs">{finding.description}</p>
                          {finding.remediation && (
                            <p className="text-[#7F948B] text-[10px] font-mono mt-1.5">
                              → {finding.remediation}
                            </p>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </Card>
              );
            })()}
          </div>
        </div>
      </div>
    </Layout>
  );
}
