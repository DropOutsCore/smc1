import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Layout } from '../components/Layout';
import { Card, Spinner, ErrorBanner, KeyValue, Divider } from '../components/Card';
import { GradeBadge, SeverityBadge, PostureGradeBadge } from '../components/Badge';
import { WhyThisGradeCard } from '../components/WhyThisGradeCard';
import { getReport, downloadReportJson, downloadReportHtml, downloadReportPdf } from '../services/api';
import type { ForensicReport, HostReport, Session, Finding, WhyThisScore, MLAnomalyAssessment, WhyThisGrade } from '../types';
import { cn, formatDate, formatTlsVersion, shortId, getGradeLabel } from '../lib/utils';
import { ChevronDown, ChevronUp, Download, ArrowLeft, Shield, Lock, AlertTriangle, CheckCircle, XCircle, FileText, HelpCircle } from 'lucide-react';

function BoolBadge({ value, trueLabel = 'Yes', falseLabel = 'No' }: { value: boolean; trueLabel?: string; falseLabel?: string }) {
  return value ? (
    <span className="flex items-center gap-1 text-[#8BFF7A] text-xs font-mono"><CheckCircle size={11} />{trueLabel}</span>
  ) : (
    <span className="flex items-center gap-1 text-[#FF5C5C] text-xs font-mono"><XCircle size={11} />{falseLabel}</span>
  );
}

function FindingRow({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="border border-[rgba(139,255,122,0.07)] rounded">
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-[rgba(139,255,122,0.03)] transition-colors"
      >
        <SeverityBadge severity={finding.severity} />
        <span className="flex-1 text-[#F3F7F4] text-xs">{finding.description}</span>
        <span className="text-[#7F948B] text-[10px] font-mono">{finding.cwe}</span>
        {open ? <ChevronUp size={14} className="text-[#7F948B] shrink-0" /> : <ChevronDown size={14} className="text-[#7F948B] shrink-0" />}
      </button>
      {open && (
        <div className="px-4 pb-4 space-y-3 bg-[#020F0C] rounded-b">
          <Divider className="mb-3" />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <KeyValue label="Category" value={finding.category} />
            <KeyValue label="CWE" value={finding.cwe} />
            <KeyValue label="Reference" value={
              <span className="text-[#5DA9FF] font-mono text-xs">{finding.reference}</span>
            } />
            <KeyValue label="Evidence" value={
              <span className="font-mono text-xs">Packet #{finding.evidence_ref?.packet_number}</span>
            } />
          </div>
          <div>
            <p className="text-[#7F948B] text-[10px] font-mono uppercase tracking-wider mb-1">Remediation</p>
            <p className="text-[#B8C8C0] text-xs leading-relaxed">{finding.remediation}</p>
          </div>
          {finding.evidence_reference && (
            <div className="bg-[#111215]/90 border border-white/10 rounded-lg p-3 space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-cyan-400 text-[10px] font-mono font-semibold uppercase tracking-wider">
                  Forensic Provenance Chain
                </span>
                <span className="text-white/40 text-[10px] font-mono">
                  Offset: {finding.evidence_reference.byte_offset}
                </span>
              </div>
              <p className="text-white/80 text-[11px] font-mono break-all bg-black/50 p-2 rounded border border-white/10">
                {finding.evidence_reference.evidence_chain}
              </p>
              <p className="text-[10px] font-mono text-white/50">
                Observed on Wire: <strong className="text-white">{finding.evidence_reference.observed_value}</strong>
              </p>
            </div>
          )}
          {finding.contributing_factors.length > 0 && (
            <div>
              <p className="text-[#7F948B] text-[10px] font-mono uppercase tracking-wider mb-1">Contributing Factors</p>
              <ul className="space-y-0.5">
                {finding.contributing_factors.map((f, i) => (
                  <li key={i} className="text-[#B8C8C0] text-xs font-mono flex items-center gap-1.5">
                    <span className="text-[#3B5A4F]">•</span>{f}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {finding.ml_flagged && (
            <span className="inline-flex items-center gap-1 text-[10px] font-mono text-[#F5B942] bg-[#F5B942]/8 border border-[#F5B942]/20 px-2 py-0.5 rounded">
              ⚡ ML Flagged
            </span>
          )}
        </div>
      )}
    </div>
  );
}

function SessionSection({ session, index }: { session: Session; index: number }) {
  const [open, setOpen] = useState(index === 0);
  const tlsV = formatTlsVersion(session.tls_version);

  return (
    <div className="border border-[rgba(139,255,122,0.1)] rounded-lg">
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-center gap-4 px-5 py-4 text-left hover:bg-[rgba(139,255,122,0.02)] transition-colors"
      >
        <div className="flex items-center gap-2 flex-1">
          <span className={cn(
            'text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border',
            session.protocol === 'SMTP' ? 'text-[#8BFF7A] border-[rgba(139,255,122,0.3)]' :
            session.protocol === 'IMAP' ? 'text-[#3DDC97] border-[rgba(61,220,151,0.3)]' :
            'text-[#5DA9FF] border-[rgba(93,169,255,0.3)]'
          )}>{session.protocol}</span>
          <span className="text-[#F3F7F4] text-xs font-mono">
            {session.src_ip}:{session.src_port} → {session.dst_ip}:{session.dst_port}
          </span>
          <span className="text-[#7F948B] text-[10px] font-mono">{tlsV}</span>
          {session.host_posture_grade && (
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-md bg-white/10 border border-white/10 text-cyan-300">
              Posture: <strong>{session.host_posture_grade}</strong> ({session.host_posture_label || getGradeLabel(session.host_posture_grade)})
            </span>
          )}
        </div>
        <div className="flex items-center gap-3">
          {session.downgrade_suspected && (
            <span className="text-[10px] text-[#FF5C5C] font-mono flex items-center gap-1">
              <AlertTriangle size={10} /> DOWNGRADE
            </span>
          )}
          <span className="text-[#7F948B] text-[10px] font-mono">{session.findings.length} findings</span>
          {open ? <ChevronUp size={14} className="text-[#7F948B]" /> : <ChevronDown size={14} className="text-[#7F948B]" />}
        </div>
      </button>

      {open && (
        <div className="px-5 pb-5 border-t border-[rgba(139,255,122,0.06)]">
          {/* TLS properties */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 py-4">
            <KeyValue label="TLS Version" value={<span className={cn('font-mono text-xs',
              tlsV.includes('1.3') ? 'text-[#8BFF7A]' : tlsV.includes('1.2') ? 'text-[#3DDC97]' : 'text-[#F5B942]'
            )}>{tlsV}</span>} />
            <KeyValue label="PFS" value={<BoolBadge value={session.pfs} trueLabel="Enabled" falseLabel="Disabled" />} />
            <KeyValue label="STARTTLS" value={<BoolBadge value={session.starttls_detected} />} />
            <KeyValue label="Key Exchange" value={session.key_exchange || '—'} />
            <KeyValue label="Cipher Strength" value={
              <span className={cn('font-mono text-xs font-semibold',
                session.cipher_strength === 'strong' ? 'text-[#8BFF7A]' :
                session.cipher_strength === 'adequate' ? 'text-[#3DDC97]' : 'text-[#FF5C5C]'
              )}>{session.cipher_strength || '—'}</span>
            } />
            <KeyValue label="SNI" value={session.sni ?? <span className="text-[#7F948B]">None</span>} />
            <KeyValue label="ML Risk" value={
              <span className="font-mono text-xs">{session.ml_risk_label} ({(session.ml_confidence * 100).toFixed(0)}%)</span>
            } />
            <KeyValue label="Anomaly" value={<BoolBadge value={session.anomaly_detected} trueLabel="Detected" falseLabel="None" />} />
          </div>

          {/* Cipher suite */}
          <div className="bg-[#0E3327] rounded p-3 mb-4">
            <p className="text-[#7F948B] text-[10px] font-mono uppercase tracking-wider mb-1">Cipher Suite</p>
            <p className="text-[#F3F7F4] text-xs font-mono break-all">{session.cipher_suite || '—'}</p>
          </div>

          {/* Certificate */}
          {session.certificate ? (
            <div className="border border-[rgba(93,169,255,0.15)] bg-[rgba(93,169,255,0.04)] rounded p-4 mb-4">
              <p className="text-[#5DA9FF] text-[10px] font-mono uppercase tracking-wider mb-3 flex items-center gap-1.5">
                <Lock size={10} /> X.509 Certificate
              </p>
              <div className="grid grid-cols-2 gap-3">
                <KeyValue label="Subject" value={<span className="break-all text-xs">{session.certificate.subject}</span>} />
                <KeyValue label="Issuer" value={<span className="break-all text-xs">{session.certificate.issuer}</span>} />
                <KeyValue label="Key" value={`${session.certificate.key_algorithm} ${session.certificate.key_length}-bit`} />
                <KeyValue label="Sig Algo" value={session.certificate.signature_algorithm} />
                <KeyValue label="Expires" value={
                  <span className={cn(session.certificate.is_expired ? 'text-[#FF5C5C]' : 'text-[#F3F7F4]')}>
                    {session.certificate.expires ? new Date(session.certificate.expires).toLocaleDateString() : '—'}
                    {session.certificate.is_expired && ' (EXPIRED)'}
                    {!session.certificate.is_expired && session.certificate.days_until_expiry != null &&
                      ` (${session.certificate.days_until_expiry}d)`}
                  </span>
                } />
                <KeyValue label="Self-Signed" value={<BoolBadge value={!session.certificate.is_self_signed} trueLabel="No" falseLabel="Yes" />} />
                <KeyValue label="Hostname Match" value={
                  session.certificate.hostname_match == null
                    ? <span className="text-[#7F948B] font-mono text-xs">N/A</span>
                    : <BoolBadge value={session.certificate.hostname_match} />
                } />
                <KeyValue label="Key Strength" value={
                  <span className={cn('font-mono text-xs',
                    session.certificate.key_strength === 'strong' ? 'text-[#8BFF7A]' :
                    session.certificate.key_strength === 'adequate' ? 'text-[#3DDC97]' : 'text-[#FF5C5C]'
                  )}>{session.certificate.key_strength}</span>
                } />
              </div>
              {session.certificate.sans.length > 0 && (
                <div className="mt-3">
                  <p className="text-[#7F948B] text-[10px] font-mono uppercase tracking-wider mb-1">SANs</p>
                  <div className="flex flex-wrap gap-1">
                    {session.certificate.sans.map(san => (
                      <span key={san} className="text-[10px] font-mono text-[#5DA9FF] bg-[rgba(93,169,255,0.08)] px-1.5 py-0.5 rounded border border-[rgba(93,169,255,0.15)]">
                        {san}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="bg-[#F5B942]/5 border border-[#F5B942]/15 rounded p-3 mb-4 text-xs font-mono text-[#F5B942]">
              ⚠ No certificate captured
              {session.tls13_visibility_limited && ' — TLS 1.3 passive visibility limitation'}
            </div>
          )}

          {/* Downgrade warning */}
          {session.downgrade_suspected && (
            <div className="bg-[#FF5C5C]/8 border border-[#FF5C5C]/25 rounded p-3 mb-4 flex items-start gap-2">
              <AlertTriangle size={14} className="text-[#FF5C5C] shrink-0 mt-0.5" />
              <div>
                <p className="text-[#FF5C5C] font-mono text-xs font-semibold">STARTTLS Downgrade Attack Suspected</p>
                <p className="text-[#B8C8C0] text-xs mt-0.5">
                  The server may have refused STARTTLS, forcing the client to transmit without encryption.
                </p>
              </div>
            </div>
          )}

          {/* Why This Score? Explainable AI & Risk Breakdown */}
          {(session.why_this_score || session.ml_anomaly_assessment) && (
            <WhyThisScoreSection why={session.why_this_score} ml={session.ml_anomaly_assessment} />
          )}

          {/* Findings */}
          {session.findings.length > 0 && (
            <div className="space-y-2">
              <p className="text-[#7F948B] text-[10px] font-mono uppercase tracking-wider">
                Findings ({session.findings.length})
              </p>
              {session.findings.map(f => <FindingRow key={f.finding_id} finding={f} />)}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function WhyThisScoreSection({ why, ml, title = "Why This Score?" }: { why?: WhyThisScore; ml?: MLAnomalyAssessment; title?: string }) {
  const [showTree, setShowTree] = useState(false);
  const [open, setOpen] = useState(true);
  if (!why && !ml) return null;

  const scoreVal = why?.risk_score ?? why?.posture_score ?? 0;
  const sevVal = why?.severity ?? 'clean';

  return (
    <div className="border border-white/10 bg-[#111215]/90 rounded-xl p-4 space-y-3 mb-4">
      <div className="flex items-center justify-between border-b border-white/10 pb-2.5">
        <div className="flex items-center gap-2">
          <HelpCircle size={15} className="text-cyan-400" />
          <h4 className="text-cyan-300 font-mono text-xs font-bold uppercase tracking-wider">
            {title} — Transparent Risk Breakdown
          </h4>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] font-mono text-white bg-white/10 px-2.5 py-0.5 rounded border border-white/10">
            Score: <strong className="text-cyan-300">{scoreVal} / 100</strong> ({sevVal.toUpperCase()})
          </span>
          {why?.ascii_tree && (
            <button
              onClick={() => setShowTree(v => !v)}
              className="text-[10px] font-mono text-[#8BFF7A] underline hover:text-[#65E86A] transition-colors"
            >
              {showTree ? 'Hide Tree' : 'View Tree'}
            </button>
          )}
          <button
            onClick={() => setOpen(v => !v)}
            className="text-[#7F948B] hover:text-[#F3F7F4] transition-colors text-xs"
          >
            {open ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </button>
        </div>
      </div>

      {open && (
        <>
          {/* ASCII Decision Tree */}
          {showTree && why?.ascii_tree && (
            <pre className="bg-[#020F0C] p-3 rounded font-mono text-[11px] text-[#8BFF7A] overflow-x-auto border border-[rgba(139,255,122,0.15)] leading-relaxed">
              {why.ascii_tree}
            </pre>
          )}

          {/* Contributing Factors Table */}
          {why?.contributing_factors && why.contributing_factors.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono border-collapse">
                <thead>
                  <tr className="border-b border-[rgba(139,255,122,0.15)] text-[#7F948B] text-[10px]">
                    <th className="py-1 px-2">Finding / Feature</th>
                    <th className="py-1 px-2">Observed on Wire</th>
                    <th className="py-1 px-2">Impact</th>
                    <th className="py-1 px-2">Severity</th>
                    <th className="py-1 px-2">Evidence Ref</th>
                    <th className="py-1 px-2">Reason & Explanation</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[rgba(139,255,122,0.06)] text-[11px]">
                  {why.contributing_factors.map((f, i) => (
                    <tr key={i} className="hover:bg-[rgba(139,255,122,0.02)]">
                      <td className="py-2 px-2 text-[#F3F7F4] font-medium whitespace-nowrap">
                        {f.feature}
                        <div className="text-[10px] text-[#7F948B] font-normal">{f.rule_id}</div>
                      </td>
                      <td className="py-2 px-2 text-[#F5B942] whitespace-nowrap font-medium">{f.observed_value}</td>
                      <td className="py-2 px-2 text-[#FF5C5C] font-bold">+{f.score_contribution}</td>
                      <td className="py-2 px-2">
                        <span className="text-[10px] px-1.5 py-0.5 rounded font-mono font-semibold uppercase bg-black/40 border border-[rgba(139,255,122,0.15)] text-[#F3F7F4]">
                          {f.severity}
                        </span>
                      </td>
                      <td className="py-2 px-2 text-[#B8C8C0] text-[10px] whitespace-nowrap">{f.evidence_reference}</td>
                      <td className="py-2 px-2 text-[#B8C8C0] text-[11px] leading-relaxed max-w-sm">{f.short_explanation}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-[#3DDC97] text-xs font-mono py-1">
              ✓ Clean cryptographic baseline: no adverse risk contributions or policy violations detected.
            </p>
          )}

          {/* Separated ML Anomaly Assessment */}
          {ml && (
            <div className="mt-3 pt-3 border-t border-[rgba(139,255,122,0.1)] bg-[#0B2A20]/40 rounded p-3">
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-[10px] font-mono font-bold text-[#5DA9FF] uppercase tracking-wider flex items-center gap-1.5">
                  <span>🤖</span> ML Anomaly Assessment (Independent Statistical Model)
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#5DA9FF]/10 text-[#5DA9FF] border border-[#5DA9FF]/30">
                  {ml.ml_risk_label.toUpperCase()} ({Math.round(ml.ml_confidence * 100)}% confidence)
                </span>
              </div>
              <p className="text-[11px] font-mono text-[#7F948B] leading-relaxed mb-2">
                {ml.score_isolation_note}
              </p>
              <div className="flex flex-wrap gap-2 text-[10px] font-mono text-white/80">
                <span className="bg-white/5 px-2 py-0.5 rounded border border-white/10">
                  Anomaly Detected: <strong className={ml.is_model_anomaly ? 'text-[#FF5C5C]' : 'text-emerald-400'}>{ml.is_model_anomaly ? 'YES' : 'NO'}</strong>
                </span>
                <span className="bg-white/5 px-2 py-0.5 rounded border border-white/10">
                  Anomaly Score: <strong className="text-white">{ml.anomaly_score.toFixed(3)}</strong>
                </span>
                <span className="bg-white/5 px-2 py-0.5 rounded border border-white/10">
                  Model: <strong className="text-white">{ml.model_architecture}</strong>
                </span>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function HostSection({ host }: { host: HostReport }) {
  const whyGrade: WhyThisGrade | undefined = host.why_this_grade || (host.why_this_score ? {
    grade: host.posture_grade,
    label: host.posture_label || getGradeLabel(host.posture_grade),
    score: host.posture_score,
    threshold_bracket: `Score ${host.posture_score} / 100`,
    headline: `Security Posture: ${host.posture_grade} (${host.posture_label || getGradeLabel(host.posture_grade)})`,
    summary: `Assigned posture grade ${host.posture_grade} (${host.posture_label || getGradeLabel(host.posture_grade)}) based on ${host.why_this_score.contributing_factors.length} adverse security finding(s) with risk score ${host.posture_score}/100.`,
    grade_ladder: [
      { grade: 'A+', label: 'Excellent', range: '0', active: host.posture_grade === 'A+' },
      { grade: 'A', label: 'Strong', range: '1–5', active: host.posture_grade === 'A' },
      { grade: 'B', label: 'Good', range: '6–15', active: host.posture_grade === 'B' },
      { grade: 'C', label: 'Moderate', range: '16–30', active: host.posture_grade === 'C' },
      { grade: 'D', label: 'Weak', range: '31–50', active: host.posture_grade === 'D' },
      { grade: 'E', label: 'Poor', range: '51–75', active: host.posture_grade === 'E' },
      { grade: 'F', label: 'Critical', range: '76+', active: host.posture_grade === 'F' },
    ],
    determining_factors: host.why_this_score.contributing_factors.map(f => ({
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
    <div className="mb-10">
      <div className="flex flex-col sm:flex-row sm:items-center gap-4 mb-4 bg-[#0A261D] p-4 rounded-lg border border-[rgba(139,255,122,0.15)]">
        <PostureGradeBadge
          grade={host.posture_grade}
          label={host.posture_label || getGradeLabel(host.posture_grade)}
          score={host.posture_score}
          size="lg"
        />
        <div className="sm:ml-4">
          <h2 className="text-[#F3F7F4] font-mono text-base font-semibold">{host.host}</h2>
          <p className="text-[#7F948B] text-xs font-mono">
            Evaluated {host.sessions.length} sessions • {host.finding_summary.critical + host.finding_summary.high + host.finding_summary.medium + host.finding_summary.low} total findings
          </p>
          {host.grade_delta && <p className="text-[#8BFF7A] text-[10px] font-mono mt-0.5">{host.grade_delta}</p>}
        </div>
        <div className="sm:ml-auto flex gap-2 text-xs font-mono flex-wrap">
          {(host.finding_summary.critical ?? 0) > 0 && (
            <span className="text-[#FF5C5C] bg-[#FF5C5C]/10 border border-[#FF5C5C]/20 px-2 py-0.5 rounded font-semibold">{host.finding_summary.critical} Critical</span>
          )}
          {(host.finding_summary.high ?? 0) > 0 && (
            <span className="text-[#F5B942] bg-[#F5B942]/10 border border-[#F5B942]/20 px-2 py-0.5 rounded font-semibold">{host.finding_summary.high} High</span>
          )}
          {(host.finding_summary.medium ?? 0) > 0 && (
            <span className="text-[#5DA9FF] bg-[#5DA9FF]/10 border border-[#5DA9FF]/20 px-2 py-0.5 rounded">{host.finding_summary.medium} Med</span>
          )}
          {(host.finding_summary.low ?? 0) > 0 && (
            <span className="text-[#3DDC97] bg-[#3DDC97]/10 border border-[#3DDC97]/20 px-2 py-0.5 rounded">{host.finding_summary.low} Low</span>
          )}
        </div>
      </div>

      {/* Single Intuitive Posture Grade & "Why this grade?" */}
      {whyGrade && (
        <WhyThisGradeCard why={whyGrade} hostName={host.host} defaultOpen={true} />
      )}

      {/* Host-level Decision Tree Breakdown */}
      {host.why_this_score && (
        <WhyThisScoreSection why={host.why_this_score} title={`Decision Reasoning Tree (${host.host})`} />
      )}

      <div className="space-y-3">
        {host.sessions.map((s, i) => <SessionSection key={s.session_id} session={s} index={i} />)}
      </div>
    </div>
  );
}

export default function ReportDetailPage() {
  const { reportId } = useParams<{ reportId: string }>();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [report, setReport] = useState<ForensicReport | null>(null);
  const [error, setError] = useState('');
  const [downloading, setDownloading] = useState<'json' | 'html' | 'pdf' | null>(null);

  useEffect(() => {
    if (!reportId) return;
    async function load() {
      try {
        const r = await getReport(reportId!);
        setReport(r);
      } catch (err: any) {
        setError(err?.message ?? 'Failed to load report');
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [reportId]);

  async function handleDownloadJson() {
    if (!reportId) return;
    setDownloading('json');
    try {
      await downloadReportJson(reportId);
    } catch (err: any) {
      alert('Failed to download JSON report: ' + (err?.message ?? 'Unknown error'));
    } finally {
      setDownloading(null);
    }
  }

  async function handleDownloadHtml() {
    if (!reportId) return;
    setDownloading('html');
    try {
      await downloadReportHtml(reportId);
    } catch (err: any) {
      alert('Failed to download HTML report: ' + (err?.message ?? 'Unknown error'));
    } finally {
      setDownloading(null);
    }
  }

  async function handleDownloadPdf() {
    if (!reportId) return;
    setDownloading('pdf');
    try {
      await downloadReportPdf(reportId);
    } catch (err: any) {
      alert('Failed to download PDF report: ' + (err?.message ?? 'Unknown error'));
    } finally {
      setDownloading(null);
    }
  }

  if (loading) {
    return (
      <Layout>
        <div className="flex items-center justify-center min-h-[60vh] gap-3">
          <Spinner size="lg" />
          <span className="text-[#7F948B] font-mono text-sm">Loading report…</span>
        </div>
      </Layout>
    );
  }

  if (error || !report) {
    return (
      <Layout>
        <div className="max-w-xl mx-auto px-6 py-16">
          <ErrorBanner title="Report Not Found" message={error || 'Report could not be loaded.'} />
          <button onClick={() => navigate('/reports')} className="mt-4 text-sm font-mono text-[#7F948B] hover:text-[#8BFF7A] transition-colors">
            ← Back to Reports
          </button>
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="max-w-screen-xl mx-auto px-6 py-10 fade-in">
        {/* Header */}
        <div className="flex items-start justify-between mb-8">
          <div>
            <button onClick={() => navigate('/reports')} className="flex items-center gap-1.5 text-[#7F948B] text-xs font-mono hover:text-[#8BFF7A] transition-colors mb-3">
              <ArrowLeft size={12} /> Reports
            </button>
            <h1 className="text-[#F3F7F4] text-2xl font-bold">Forensic Report</h1>
            <p className="text-[#7F948B] text-sm font-mono mt-1">
              Report #{shortId(report.report_id)} — {formatDate(report.generated_at)}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handleDownloadPdf}
              disabled={downloading !== null}
              className="flex items-center gap-1.5 px-4 py-2 bg-white text-black font-semibold font-mono text-xs rounded-full hover:bg-white/90 transition-all disabled:opacity-40 shadow-md cursor-pointer"
              title="Download Formal Forensic PDF Report"
            >
              <Download size={13} /> {downloading === 'pdf' ? 'Generating PDF…' : 'PDF Report'}
            </button>
            <button
              onClick={handleDownloadHtml}
              disabled={downloading !== null}
              className="flex items-center gap-1.5 px-4 py-2 border border-white/20 text-white/80 text-xs font-mono rounded-full hover:text-white hover:bg-white/10 transition-all disabled:opacity-40 cursor-pointer"
              title="Download Interactive HTML Report"
            >
              <Download size={13} /> {downloading === 'html' ? 'Downloading…' : 'HTML'}
            </button>
            <button
              onClick={handleDownloadJson}
              disabled={downloading !== null}
              className="flex items-center gap-1.5 px-4 py-2 border border-[rgba(139,255,122,0.25)] text-[#B8C8C0] text-xs font-mono rounded hover:text-[#8BFF7A] hover:border-[rgba(139,255,122,0.5)] transition-all disabled:opacity-40"
              title="Download Raw JSON Report"
            >
              <Download size={13} /> {downloading === 'json' ? 'Downloading…' : 'JSON'}
            </button>
          </div>
        </div>

        {/* Forensic Evidence & Chain of Custody */}
        <Card className="mb-8 border border-[rgba(139,255,122,0.2)]">
          <div className="flex items-center justify-between mb-3 border-b border-[rgba(139,255,122,0.1)] pb-2.5">
            <div className="flex items-center gap-2">
              <Shield size={14} className="text-[#8BFF7A]" />
              <p className="text-[#8BFF7A] text-xs font-mono font-bold uppercase tracking-wider">
                Forensic Evidence & Chain of Custody
              </p>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#8BFF7A]/10 text-[#8BFF7A] border border-[#8BFF7A]/30">
              {report.forensic_evidence_and_chain_of_custody?.passive_offline_status ?? 'PASSIVE / OFFLINE (AIR-GAPPED)'}
            </span>
          </div>

          {/* Integrity Statement Banner */}
          <div className="bg-[#8BFF7A]/10 border border-[#8BFF7A]/30 rounded p-3 mb-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <CheckCircle size={15} className="text-[#8BFF7A] shrink-0" />
              <span className="text-[#F3F7F4] font-mono text-xs font-semibold">
                Integrity Statement: {report.forensic_evidence_and_chain_of_custody?.integrity_statement ?? 'No active network connections were made during analysis.'}
              </span>
            </div>
            <span className="text-[10px] font-mono text-[#8BFF7A] hidden sm:inline">
              ✓ Non-Invasive Read-Only Verification
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono mb-4">
            <KeyValue label="Report ID" value={report.report_id} />
            <KeyValue label="Analysis ID" value={report.analysis_id ?? (report.forensic_evidence_and_chain_of_custody?.analysis_id ?? report.report_id)} />
            <KeyValue label="Source PCAP" value={report.source_filename ?? (report.source_pcap_path ? report.source_pcap_path.split(/[/\\]/).pop() : 'capture.pcap')} />
            <KeyValue label="PCAP SHA-256" value={
              <span className="break-all text-[#7F948B]">{report.source_pcap_sha256}</span>
            } />
            <KeyValue label="Generated At" value={formatDate(report.generated_at)} />
            <KeyValue label="Analyzer Version" value={`SecureMailScope v${report.tool_version}`} />
          </div>

          {/* Packet-Level Evidence Mapping */}
          {report.forensic_evidence_and_chain_of_custody?.packet_level_evidence_mapping && report.forensic_evidence_and_chain_of_custody.packet_level_evidence_mapping.length > 0 && (
            <div className="mt-4 pt-3 border-t border-[rgba(139,255,122,0.1)]">
              <p className="text-[#7F948B] text-[10px] font-mono uppercase tracking-wider mb-2 font-semibold">
                Packet-Level Evidence Mapping ({report.forensic_evidence_and_chain_of_custody.packet_level_evidence_mapping.length} findings traced)
              </p>
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs font-mono">
                  <thead>
                    <tr className="border-b border-[rgba(139,255,122,0.15)] text-[#7F948B] text-[10px]">
                      <th className="py-1.5 px-2">Rule / ID</th>
                      <th className="py-1.5 px-2">Session Flow</th>
                      <th className="py-1.5 px-2">Pkt # / Offset</th>
                      <th className="py-1.5 px-2">Observed Wire Value</th>
                      <th className="py-1.5 px-2">Evidence Provenance Chain</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[rgba(139,255,122,0.06)] text-[11px]">
                    {report.forensic_evidence_and_chain_of_custody.packet_level_evidence_mapping.map((ev, i) => (
                      <tr key={i} className="hover:bg-[rgba(139,255,122,0.02)]">
                        <td className="py-2 px-2 text-[#8BFF7A] font-semibold whitespace-nowrap">
                          {ev.detection_rule} <span className="text-[#7F948B] font-normal text-[10px]">#{shortId(ev.finding_id)}</span>
                        </td>
                        <td className="py-2 px-2 text-[#B8C8C0] whitespace-nowrap">{ev.session_flow}</td>
                        <td className="py-2 px-2 text-[#F3F7F4] whitespace-nowrap">
                          Pkt #{ev.packet_number} (Off {ev.byte_offset})
                        </td>
                        <td className="py-2 px-2 text-[#F5B942]">{ev.observed_value}</td>
                        <td className="py-2 px-2 text-[#7F948B] text-[10px] break-all max-w-xs">{ev.evidence_chain}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </Card>

        {/* TLS 1.3 visibility note */}
        {report.tls13_visibility_note && (
          <div className="bg-[#5DA9FF]/5 border border-[#5DA9FF]/15 rounded p-4 mb-8 text-xs text-[#B8C8C0] font-mono leading-relaxed">
            <span className="text-[#5DA9FF] font-semibold">ℹ TLS 1.3 Passive Visibility Note: </span>
            {report.tls13_visibility_note}
          </div>
        )}

        {/* Host sections */}
        {report.hosts.map(host => <HostSection key={host.host} host={host} />)}
      </div>
    </Layout>
  );
}
