import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Layout } from '../components/Layout';
import { StatCard, Card, SectionHeader, EmptyState, Spinner } from '../components/Card';
import { GradeBadge, SeverityBadge, PostureGradeBadge } from '../components/Badge';
import { WhyThisGradeCard } from '../components/WhyThisGradeCard';
import { NetworkTopology } from '../components/NetworkTopology';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, PieChart, Pie, Legend,
} from 'recharts';
import { getReports, getReport } from '../services/api';
import type { ForensicReport, ReportSummary, HostReport, WhyThisGrade } from '../types';
import { cn, formatDate, formatTlsVersion, pcapBasename, shortId, getGradeLabel } from '../lib/utils';
import { Activity, FileText, Shield, AlertTriangle, HelpCircle, Terminal, Award } from 'lucide-react';

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#FF5C5C',
  high: '#F5B942',
  medium: '#5DA9FF',
  low: '#3DDC97',
  informational: '#B8C8C0',
};

const TLS_COLORS: Record<string, string> = {
  'TLS 1.3': '#8BFF7A',
  'TLS 1.2': '#3DDC97',
  'TLS 1.1': '#F5B942',
  'TLS 1.0': '#F59342',
  SSLv3: '#FF5C5C',
  Unknown: '#7F948B',
  Plaintext: '#B8C8C0',
};

function WhyThisScoreDashboard({ hosts, reportId }: { hosts: HostReport[]; reportId: string }) {
  const [selectedHostIndex, setSelectedHostIndex] = useState(0);
  const [showTree, setShowTree] = useState(false);
  const navigate = useNavigate();

  if (!hosts || hosts.length === 0) return null;
  const currentHost = hosts[selectedHostIndex] || hosts[0];
  const why = currentHost.why_this_score;
  const factors = why?.contributing_factors || [];

  const sessionWithML = currentHost.sessions.find(s => s.ml_anomaly_assessment || s.why_this_score?.ml_anomaly_assessment);
  const ml = sessionWithML?.ml_anomaly_assessment || sessionWithML?.why_this_score?.ml_anomaly_assessment;

  const whyGrade: WhyThisGrade = currentHost.why_this_grade || {
    grade: currentHost.posture_grade,
    label: currentHost.posture_label || getGradeLabel(currentHost.posture_grade),
    score: currentHost.posture_score,
    threshold_bracket: `Score ${currentHost.posture_score} / 100`,
    headline: `Security Posture: ${currentHost.posture_grade} (${currentHost.posture_label || getGradeLabel(currentHost.posture_grade)})`,
    summary: `Assigned posture grade ${currentHost.posture_grade} (${currentHost.posture_label || getGradeLabel(currentHost.posture_grade)}) based on ${factors.length} adverse security finding(s) with risk score ${currentHost.posture_score}/100.`,
    grade_ladder: [
      { grade: 'A+', label: 'Excellent', range: '0', active: currentHost.posture_grade === 'A+' },
      { grade: 'A', label: 'Strong', range: '1–5', active: currentHost.posture_grade === 'A' },
      { grade: 'B', label: 'Good', range: '6–15', active: currentHost.posture_grade === 'B' },
      { grade: 'C', label: 'Moderate', range: '16–30', active: currentHost.posture_grade === 'C' },
      { grade: 'D', label: 'Weak', range: '31–50', active: currentHost.posture_grade === 'D' },
      { grade: 'E', label: 'Poor', range: '51–75', active: currentHost.posture_grade === 'E' },
      { grade: 'F', label: 'Critical', range: '76+', active: currentHost.posture_grade === 'F' },
    ],
    determining_factors: factors.map((f) => ({
      finding_id: f.rule_id,
      rule_id: f.rule_id,
      feature: f.feature,
      description: f.feature,
      severity: f.severity,
      score_contribution: f.score_contribution,
      evidence_ref: f.evidence_reference,
      impact_on_grade: f.short_explanation,
    })),
  };

  return (
    <Card className="mb-6 border border-white/10 bg-[#111215]/90">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 mb-4 border-b border-white/10 gap-3">
        <div className="flex items-center gap-2">
          <HelpCircle size={18} className="text-[#8BFF7A]" />
          <div>
            <h3 className="text-[#F3F7F4] font-mono text-sm font-bold uppercase tracking-wider">
              Single Intuitive Posture Grade & Explainable Risk
            </h3>
            <p className="text-[#7F948B] text-xs font-mono">
              Deterministic A+–F security posture with "Why this grade?" root-cause evidence.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowTree(v => !v)}
            className="flex items-center gap-1.5 text-xs font-mono text-cyan-300 bg-white/10 px-3 py-1.5 rounded-lg border border-white/10 hover:bg-white/15 transition-colors cursor-pointer"
          >
            <Terminal size={13} />
            <span>{showTree ? 'Hide Decision Tree' : 'View Decision Tree'}</span>
          </button>
          <button
            onClick={() => navigate(`/reports/${reportId}`)}
            className="text-xs font-mono text-[#7F948B] hover:text-[#8BFF7A] px-2 py-1 transition-colors"
          >
            Forensic Report →
          </button>
        </div>
      </div>

      {hosts.length > 1 && (
        <div className="flex gap-2 mb-4 overflow-x-auto pb-1">
          {hosts.map((h, idx) => (
            <button
              key={h.host}
              onClick={() => setSelectedHostIndex(idx)}
              className={cn(
                "px-3 py-1.5 rounded text-xs font-mono transition-colors border",
                selectedHostIndex === idx
                  ? "bg-[#0E3327] text-[#8BFF7A] border-[#8BFF7A]/40 font-bold"
                  : "bg-[#020F0C] text-[#7F948B] border-[rgba(139,255,122,0.08)] hover:text-[#F3F7F4]"
              )}
            >
              {h.host} (Grade {h.posture_grade} • {h.posture_label || getGradeLabel(h.posture_grade)})
            </button>
          ))}
        </div>
      )}

      {/* Single Intuitive Posture Grade Component with "Why this grade?" Ladder */}
      <WhyThisGradeCard why={whyGrade} hostName={currentHost.host} defaultOpen={true} />

      {showTree && why?.ascii_tree && (
        <div className="mb-4">
          <div className="flex items-center justify-between text-[11px] font-mono text-[#7F948B] mb-1.5">
            <span>DECISION REASONING TREE</span>
            <span>Deterministic Scoring Tree</span>
          </div>
          <pre className="bg-[#020F0C] p-3 rounded font-mono text-xs text-[#8BFF7A] overflow-x-auto border border-[rgba(139,255,122,0.15)] leading-relaxed">
            {why.ascii_tree}
          </pre>
        </div>
      )}

      {factors.length > 0 ? (
        <div className="overflow-x-auto mb-4">
          <table className="w-full text-left text-xs font-mono border-collapse">
            <thead>
              <tr className="border-b border-[rgba(139,255,122,0.15)] text-[#7F948B] text-[10px]">
                <th className="py-2 px-2.5">Contributing Feature</th>
                <th className="py-2 px-2.5">Observed Value</th>
                <th className="py-2 px-2.5">Impact</th>
                <th className="py-2 px-2.5">Severity</th>
                <th className="py-2 px-2.5">Evidence Reference</th>
                <th className="py-2 px-2.5">Explanation & Standard</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[rgba(139,255,122,0.06)] text-[11px]">
              {factors.map((f, i) => (
                <tr key={i} className="hover:bg-[rgba(139,255,122,0.02)]">
                  <td className="py-2.5 px-2.5 text-[#F3F7F4] font-medium whitespace-nowrap">
                    {f.feature}
                    <div className="text-[10px] text-[#7F948B] font-normal">{f.rule_id}</div>
                  </td>
                  <td className="py-2.5 px-2.5 text-[#F5B942] whitespace-nowrap font-medium">{f.observed_value}</td>
                  <td className="py-2.5 px-2.5 text-[#FF5C5C] font-bold">+{f.score_contribution}</td>
                  <td className="py-2.5 px-2.5">
                    <span className="text-[10px] px-1.5 py-0.5 rounded font-mono font-semibold uppercase bg-black/40 border border-[rgba(139,255,122,0.15)] text-[#F3F7F4]">
                      {f.severity}
                    </span>
                  </td>
                  <td className="py-2.5 px-2.5 text-[#B8C8C0] text-[10px] whitespace-nowrap">{f.evidence_reference}</td>
                  <td className="py-2.5 px-2.5 text-[#B8C8C0] text-[11px] leading-relaxed max-w-sm">{f.short_explanation}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="bg-[#020F0C] border border-[#8BFF7A]/20 rounded p-3 mb-4 text-xs font-mono text-[#3DDC97]">
          ✓ Clean Cryptographic Posture: No adverse security findings or policy violations detected for this host.
        </div>
      )}

      {ml && (
        <div className="pt-3 border-t border-[rgba(139,255,122,0.1)] bg-[#0B2A20]/40 rounded p-3">
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-[11px] font-mono font-bold text-[#5DA9FF] uppercase tracking-wider flex items-center gap-1.5">
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
            <span className="bg-white/5 px-2 py-0.5 rounded-md border border-white/10">
              Anomaly Detected: <strong className={ml.is_model_anomaly ? 'text-[#FF5C5C]' : 'text-emerald-400'}>{ml.is_model_anomaly ? 'YES' : 'NO'}</strong>
            </span>
            <span className="bg-white/5 px-2 py-0.5 rounded-md border border-white/10">
              Anomaly Score: <strong className="text-white">{ml.anomaly_score.toFixed(3)}</strong>
            </span>
            <span className="bg-white/5 px-2 py-0.5 rounded-md border border-white/10">
              Architecture: <strong className="text-white">{ml.model_architecture}</strong>
            </span>
          </div>
        </div>
      )}
    </Card>
  );
}

export default function DashboardPage() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [latestReport, setLatestReport] = useState<ForensicReport | null>(null);

  useEffect(() => {
    async function load() {
      try {
        const reps = await getReports();
        setReports(reps);
        if (reps.length > 0) {
          for (const rep of reps) {
            try {
              const full = await getReport(rep.report_id);
              if (full && full.hosts && full.hosts.length > 0) {
                setLatestReport(full);
                break;
              }
            } catch (err) {
              console.warn(`Could not load report ${rep.report_id}:`, err);
            }
          }
        }
      } catch (err) {
        console.error(err);
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
          <span className="text-[#7F948B] font-mono text-sm">Loading dashboard…</span>
        </div>
      </Layout>
    );
  }

  if (!latestReport) {
    return (
      <Layout>
        <div className="max-w-screen-xl mx-auto px-6 py-16">
          <EmptyState
            icon={<Activity size={48} />}
            title="No Analysis Data"
            description="Upload a PCAP file to generate your first forensic report and populate the dashboard."
            action={
              <button
                onClick={() => navigate('/analyze')}
                className="px-6 py-2.5 bg-white text-black font-semibold text-sm rounded-full hover:bg-white/90 transition-all cursor-pointer shadow-lg"
              >
                Analyze PCAP
              </button>
            }
          />
        </div>
      </Layout>
    );
  }

  // Aggregate stats across all sessions
  const allSessions = latestReport.hosts.flatMap(h => h.sessions);
  const allFindings = allSessions.flatMap(s => s.findings);

  const criticalCount = allFindings.filter(f => f.severity === 'critical').length;
  const highCount = allFindings.filter(f => f.severity === 'high').length;
  const mediumCount = allFindings.filter(f => f.severity === 'medium').length;
  const lowCount = allFindings.filter(f => f.severity === 'low').length;

  const tlsSessions = allSessions.filter(s => s.tls_version && s.tls_version !== 'unknown' && !s.downgrade_suspected);
  const plaintextSessions = allSessions.filter(s => s.downgrade_suspected || (!s.starttls_detected && !s.is_implicit_tls));
  const pfsCount = allSessions.filter(s => s.pfs).length;
  const certIssues = allSessions.filter(
    s => s.certificate && (s.certificate.is_expired || s.certificate.is_self_signed || s.certificate.hostname_match === false)
  ).length;

  // Protocol distribution
  const protocolCounts: Record<string, number> = {};
  allSessions.forEach(s => { protocolCounts[s.protocol] = (protocolCounts[s.protocol] ?? 0) + 1; });
  const protocolData = Object.entries(protocolCounts).map(([name, value]) => ({ name, value }));

  // TLS version distribution
  const tlsCounts: Record<string, number> = {};
  allSessions.forEach(s => {
    const v = s.downgrade_suspected ? 'Plaintext' : formatTlsVersion(s.tls_version);
    tlsCounts[v] = (tlsCounts[v] ?? 0) + 1;
  });
  const tlsData = Object.entries(tlsCounts).map(([name, value]) => ({ name, value }));

  // Findings distribution
  const findingsData = [
    { name: 'Critical', value: criticalCount, color: '#FF5C5C' },
    { name: 'High', value: highCount, color: '#F5B942' },
    { name: 'Medium', value: mediumCount, color: '#5DA9FF' },
    { name: 'Low', value: lowCount, color: '#3DDC97' },
  ].filter(d => d.value > 0);

  const customTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-[#0E3327] border border-[rgba(139,255,122,0.2)] rounded p-2 text-xs font-mono">
          <p className="text-[#F3F7F4]">{label ?? payload[0].name}: {payload[0].value}</p>
        </div>
      );
    }
    return null;
  };

  return (
    <Layout>
      <div className="max-w-screen-xl mx-auto px-6 py-10 fade-in">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-2 text-[#7F948B] text-xs font-mono mb-1">
            <span>Latest Scan</span>
            <span className="text-[rgba(139,255,122,0.4)]">•</span>
            <span>{formatDate(latestReport.generated_at)}</span>
          </div>
          <h1 className="text-[#F3F7F4] text-2xl font-bold">Security Posture Overview</h1>
          <p className="text-[#7F948B] text-sm font-mono mt-1">
            {pcapBasename(latestReport.source_pcap_path)}
          </p>
        </div>

        {/* Primary stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <StatCard label="Sessions Analyzed" value={allSessions.length} icon={<Activity size={16} />} />
          <StatCard label="Hosts Analyzed" value={latestReport.hosts.length} icon={<Shield size={16} />} />
          <StatCard
            label="Critical Findings"
            value={criticalCount}
            valueColor={criticalCount > 0 ? 'text-[#FF5C5C]' : 'text-[#8BFF7A]'}
            icon={<AlertTriangle size={16} />}
          />
          <StatCard
            label="High Findings"
            value={highCount}
            valueColor={highCount > 0 ? 'text-[#F5B942]' : 'text-[#8BFF7A]'}
          />
        </div>

        {/* Secondary stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-10">
          <StatCard label="TLS Sessions" value={tlsSessions.length} valueColor="text-[#8BFF7A]" />
          <StatCard
            label="Plaintext Sessions"
            value={plaintextSessions.length}
            valueColor={plaintextSessions.length > 0 ? 'text-[#FF5C5C]' : 'text-[#8BFF7A]'}
          />
          <StatCard
            label="Certificate Issues"
            value={certIssues}
            valueColor={certIssues > 0 ? 'text-[#F5B942]' : 'text-[#8BFF7A]'}
          />
          <StatCard
            label="PFS Enabled"
            value={`${pfsCount}/${allSessions.length}`}
            valueColor={pfsCount === allSessions.length ? 'text-[#8BFF7A]' : 'text-[#F5B942]'}
          />
        </div>

        {/* Visual Network & Session Topology Entry Point */}
        <NetworkTopology
          hosts={latestReport.hosts}
          sourcePcapName={pcapBasename(latestReport.source_pcap_path)}
        />

        {/* Host grades */}
        <Card className="mb-6">
          <SectionHeader
            title="Host Posture Grades"
            action={
              <button onClick={() => navigate('/reports')} className="text-xs text-[#7F948B] font-mono hover:text-[#8BFF7A] transition-colors">
                View Full Report →
              </button>
            }
          />
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {latestReport.hosts.map(host => (
              <div
                key={host.host}
                className="bg-[#0E3327] border border-[rgba(139,255,122,0.08)] rounded p-4 card-hover cursor-pointer"
                onClick={() => navigate('/sessions')}
              >
                <div className="flex items-start justify-between mb-3">
                  <PostureGradeBadge
                    grade={host.posture_grade}
                    label={host.posture_label || getGradeLabel(host.posture_grade)}
                    size="sm"
                  />
                  <div className="text-right">
                    <span className="text-[#7F948B] text-[10px] font-mono block">Risk Score</span>
                    <span className="text-[#F3F7F4] text-xs font-mono font-bold">{host.posture_score}/100</span>
                  </div>
                </div>
                <p className="text-[#F3F7F4] text-xs font-mono break-all font-semibold">{host.host}</p>
                {host.grade_delta && (
                  <p className="text-[#7F948B] text-[10px] font-mono mt-1">{host.grade_delta}</p>
                )}
                <div className="flex gap-2 mt-3 flex-wrap">
                  {(host.finding_summary.critical ?? 0) > 0 && (
                    <span className="text-[10px] font-mono text-[#FF5C5C]">{host.finding_summary.critical}C</span>
                  )}
                  {(host.finding_summary.high ?? 0) > 0 && (
                    <span className="text-[10px] font-mono text-[#F5B942]">{host.finding_summary.high}H</span>
                  )}
                  {(host.finding_summary.medium ?? 0) > 0 && (
                    <span className="text-[10px] font-mono text-[#5DA9FF]">{host.finding_summary.medium}M</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </Card>

        {/* Why This Score? Explainable AI & Risk Breakdown */}
        <WhyThisScoreDashboard hosts={latestReport.hosts} reportId={latestReport.report_id} />

        {/* Charts row */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
          {/* Protocol distribution */}
          <Card>
            <SectionHeader title="Protocol Distribution" />
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={protocolData} margin={{ left: -20 }}>
                <XAxis dataKey="name" tick={{ fill: '#7F948B', fontSize: 11, fontFamily: 'monospace' }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: '#7F948B', fontSize: 11, fontFamily: 'monospace' }} axisLine={false} tickLine={false} />
                <Tooltip content={customTooltip} />
                <Bar dataKey="value" radius={[3, 3, 0, 0]}>
                  {protocolData.map((entry, i) => (
                    <Cell key={i} fill="#8BFF7A" fillOpacity={0.7 - i * 0.15} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </Card>

          {/* TLS distribution */}
          <Card>
            <SectionHeader title="TLS Distribution" />
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={tlsData} margin={{ left: -20 }}>
                <XAxis dataKey="name" tick={{ fill: '#7F948B', fontSize: 9, fontFamily: 'monospace' }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: '#7F948B', fontSize: 11, fontFamily: 'monospace' }} axisLine={false} tickLine={false} />
                <Tooltip content={customTooltip} />
                <Bar dataKey="value" radius={[3, 3, 0, 0]}>
                  {tlsData.map((entry, i) => (
                    <Cell key={i} fill={TLS_COLORS[entry.name] ?? '#7F948B'} fillOpacity={0.8} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </Card>

          {/* Findings distribution */}
          <Card>
            <SectionHeader title="Findings Distribution" />
            {findingsData.length > 0 ? (
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie
                    data={findingsData}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={70}
                    dataKey="value"
                    paddingAngle={2}
                  >
                    {findingsData.map((entry, i) => (
                      <Cell key={i} fill={entry.color} fillOpacity={0.8} />
                    ))}
                  </Pie>
                  <Tooltip content={customTooltip} />
                  <Legend
                    formatter={(value) => <span className="text-[10px] text-[#B8C8C0] font-mono">{value}</span>}
                    iconSize={8}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[180px] flex items-center justify-center">
                <span className="text-[#3DDC97] font-mono text-sm">No Findings</span>
              </div>
            )}
          </Card>
        </div>

        {/* TLS 1.3 note */}
        {latestReport.tls13_visibility_note && (
          <div className="bg-[#5DA9FF]/5 border border-[#5DA9FF]/20 rounded p-4 text-xs text-[#B8C8C0] font-mono leading-relaxed">
            <span className="text-[#5DA9FF] font-semibold">ℹ TLS 1.3 Passive Visibility Limit: </span>
            {latestReport.tls13_visibility_note}
          </div>
        )}
      </div>
    </Layout>
  );
}
