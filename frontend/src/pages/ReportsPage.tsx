import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Layout } from '../components/Layout';
import { Card, EmptyState, Spinner, ErrorBanner } from '../components/Card';
import { GradeBadge } from '../components/Badge';
import { getReports, deleteReport, downloadReportPdf } from '../services/api';
import type { ReportSummary } from '../types';
import { cn, formatDate, formatBytes, pcapBasename, shortId } from '../lib/utils';
import { FileText, Trash2, Eye, Download, AlertTriangle } from 'lucide-react';

export default function ReportsPage() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [error, setError] = useState('');
  const [deleting, setDeleting] = useState<string | null>(null);
  const [downloadingPdf, setDownloadingPdf] = useState<string | null>(null);

  async function load() {
    try {
      setLoading(true);
      const r = await getReports();
      setReports(r);
    } catch (err: any) {
      setError(err?.message ?? 'Failed to load reports');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  async function handleDownloadPdf(reportId: string) {
    setDownloadingPdf(reportId);
    try {
      await downloadReportPdf(reportId);
    } catch (err: any) {
      alert('Failed to download PDF: ' + (err?.message ?? 'Unknown error'));
    } finally {
      setDownloadingPdf(null);
    }
  }

  async function handleDelete(reportId: string) {
    if (!confirm(`Delete report ${shortId(reportId)}?`)) return;
    setDeleting(reportId);
    try {
      await deleteReport(reportId);
      setReports(prev => prev.filter(r => r.report_id !== reportId));
    } catch (err: any) {
      alert('Failed to delete: ' + (err?.message ?? 'Unknown error'));
    } finally {
      setDeleting(null);
    }
  }

  if (loading) {
    return (
      <Layout>
        <div className="flex items-center justify-center min-h-[60vh] gap-3">
          <Spinner size="lg" />
          <span className="text-[#7F948B] font-mono text-sm">Loading reports…</span>
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="max-w-screen-xl mx-auto px-6 py-10 fade-in">
        <div className="flex items-end justify-between mb-8">
          <div>
            <h1 className="text-white text-3xl font-extrabold tracking-tight">Forensic Reports</h1>
            <p className="text-white/60 text-sm mt-1 font-mono">
              {reports.length} stored analysis report{reports.length !== 1 ? 's' : ''}
            </p>
          </div>
          <button
            onClick={() => navigate('/analyze')}
            className="flex items-center gap-2 px-5 py-2.5 bg-[#48BB36] hover:bg-[#3ca32c] text-white font-bold text-xs uppercase tracking-wider rounded-md shadow-lg shadow-[#48bb36]/25 transition-all cursor-pointer"
          >
            + Ingest New PCAP
          </button>
        </div>

        {error && <ErrorBanner title="Error" message={error} onRetry={load} className="mb-6" />}

        {reports.length === 0 ? (
          <EmptyState
            icon={<FileText size={48} />}
            title="No Reports"
            description="Analyze a PCAP file to generate your first forensic report."
            action={
              <button
                onClick={() => navigate('/analyze')}
                className="px-6 py-3 bg-[#48BB36] hover:bg-[#3ca32c] text-white font-bold text-xs uppercase tracking-wider rounded-md shadow-lg shadow-[#48bb36]/25 transition-all cursor-pointer"
              >
                Analyze PCAP
              </button>
            }
          />
        ) : (
          <div className="space-y-3">
            {reports.map(report => (
              <div
                key={report.report_id}
                className="bg-[#111215]/80 border border-white/10 rounded-xl p-5 hover:bg-[#16181d]/90 hover:border-white/20 transition-all shadow-md"
              >
                <div className="flex items-start gap-5">
                  {/* Grade */}
                  <GradeBadge grade={report.worst_grade} />

                  {/* Info */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3 mb-1">
                      <span className="text-[#F3F7F4] font-mono text-sm font-semibold truncate">
                        {pcapBasename(report.source_pcap_path) || 'Unknown Source'}
                      </span>
                      <span className="text-[#3B5A4F] text-[10px] font-mono shrink-0">
                        #{shortId(report.report_id)}
                      </span>
                    </div>
                    <p className="text-[#7F948B] text-xs font-mono mb-3">
                      {formatDate(report.generated_at)} — {report.host_count} host{report.host_count !== 1 ? 's' : ''}
                    </p>

                    {/* Severity summary */}
                    <div className="flex gap-4 flex-wrap">
                      {(report.severity_summary.critical ?? 0) > 0 && (
                        <div className="flex items-center gap-1.5">
                          <span className="w-1.5 h-1.5 rounded-full bg-[#FF5C5C]" />
                          <span className="text-[#FF5C5C] text-xs font-mono">{report.severity_summary.critical} Critical</span>
                        </div>
                      )}
                      {(report.severity_summary.high ?? 0) > 0 && (
                        <div className="flex items-center gap-1.5">
                          <span className="w-1.5 h-1.5 rounded-full bg-[#F5B942]" />
                          <span className="text-[#F5B942] text-xs font-mono">{report.severity_summary.high} High</span>
                        </div>
                      )}
                      {(report.severity_summary.medium ?? 0) > 0 && (
                        <div className="flex items-center gap-1.5">
                          <span className="w-1.5 h-1.5 rounded-full bg-[#5DA9FF]" />
                          <span className="text-[#5DA9FF] text-xs font-mono">{report.severity_summary.medium} Medium</span>
                        </div>
                      )}
                      {(report.severity_summary.low ?? 0) > 0 && (
                        <div className="flex items-center gap-1.5">
                          <span className="w-1.5 h-1.5 rounded-full bg-[#3DDC97]" />
                          <span className="text-[#3DDC97] text-xs font-mono">{report.severity_summary.low} Low</span>
                        </div>
                      )}
                      {report.finding_count === 0 && (
                        <span className="text-[#8BFF7A] text-xs font-mono">✓ No Findings</span>
                      )}
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      onClick={() => handleDownloadPdf(report.report_id)}
                      disabled={downloadingPdf === report.report_id}
                      className="flex items-center gap-1 px-2.5 py-1.5 border border-[#8BFF7A]/30 text-[#8BFF7A] text-xs font-mono rounded hover:bg-[#8BFF7A]/10 hover:border-[#8BFF7A] transition-all disabled:opacity-40"
                      title="Download PDF Forensic Report"
                    >
                      <Download size={12} /> {downloadingPdf === report.report_id ? 'PDF…' : 'PDF'}
                    </button>
                    <button
                      onClick={() => navigate(`/reports/${report.report_id}`)}
                      className="flex items-center gap-1.5 px-3 py-1.5 border border-[rgba(139,255,122,0.2)] text-[#B8C8C0] text-xs font-mono rounded hover:text-[#8BFF7A] hover:border-[rgba(139,255,122,0.5)] transition-all"
                      title="View Full Report"
                    >
                      <Eye size={13} /> View
                    </button>
                    <button
                      onClick={() => handleDelete(report.report_id)}
                      disabled={deleting === report.report_id}
                      className="flex items-center gap-1 p-1.5 border border-[rgba(255,92,92,0.2)] text-[#FF5C5C]/60 text-xs rounded hover:text-[#FF5C5C] hover:border-[rgba(255,92,92,0.5)] transition-all disabled:opacity-40"
                      title="Delete Report"
                    >
                      <Trash2 size={13} />
                    </button>
                  </div>
                </div>

                {/* SHA-256 chain of custody */}
                <div className="mt-4 pt-3 border-t border-[rgba(139,255,122,0.06)]">
                  <p className="text-[#3B5A4F] text-[10px] font-mono">
                    SHA-256: {report.source_pcap_sha256 || 'N/A'}
                  </p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </Layout>
  );
}
