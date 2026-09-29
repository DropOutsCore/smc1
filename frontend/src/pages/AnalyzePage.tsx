import { useState, useCallback, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useDropzone } from 'react-dropzone';
import { Layout } from '../components/Layout';
import { Card } from '../components/Card';
import { ErrorBanner, Spinner } from '../components/Card';
import { cn, formatBytes, shortHash } from '../lib/utils';
import { uploadPcap, getAnalysisStatus, getAnalysisResult } from '../services/api';
import type { ForensicReport } from '../types';
import { Upload, File, CheckCircle, XCircle, ChevronRight, Cpu, Terminal } from 'lucide-react';

const ANALYSIS_STAGES = [
  'Validating PCAP',
  'Computing SHA-256',
  'Parsing packets',
  'Reconstructing sessions',
  'Analyzing TLS handshakes',
  'Evaluating security rules',
  'Running ML assessment',
  'Calculating risk scores',
  'Generating report',
  'Complete',
];

type Phase = 'idle' | 'uploading' | 'analyzing' | 'complete' | 'error';

export default function AnalyzePage() {
  const navigate = useNavigate();
  const [phase, setPhase] = useState<Phase>('idle');
  const [file, setFile] = useState<File | null>(null);
  const [analysisId, setAnalysisId] = useState<string | null>(null);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [analysisProgress, setAnalysisProgress] = useState(0);
  const [currentStage, setCurrentStage] = useState('');
  const [completedStages, setCompletedStages] = useState<string[]>([]);
  const [error, setError] = useState('');
  const [report, setReport] = useState<ForensicReport | null>(null);
  const [log, setLog] = useState<string[]>([]);
  const logRef = useRef<HTMLDivElement>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  function addLog(msg: string) {
    setLog(prev => [...prev, `[${new Date().toTimeString().slice(0, 8)}] ${msg}`]);
  }

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [log]);

  // Clean up polling on unmount
  useEffect(() => () => { if (pollRef.current) clearInterval(pollRef.current); }, []);

  const startPolling = useCallback((id: string) => {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      try {
        const status = await getAnalysisStatus(id);
        setCurrentStage(status.stage);
        setAnalysisProgress(status.progress);

        // Update completed stages
        const idx = ANALYSIS_STAGES.indexOf(status.stage);
        if (idx > 0) {
          setCompletedStages(ANALYSIS_STAGES.slice(0, idx));
        }
        addLog(`[${status.progress}%] ${status.stage}`);

        if (status.status === 'complete') {
          clearInterval(pollRef.current!);
          addLog('Analysis complete — fetching results…');
          const result = await getAnalysisResult(id);
          setReport(result);
          setPhase('complete');
          addLog(`Report ID: ${result.report_id}`);
        } else if (status.status === 'error') {
          clearInterval(pollRef.current!);
          setError(status.error ?? 'Unknown analysis error');
          setPhase('error');
          addLog(`ERROR: ${status.error}`);
        }
      } catch (err: any) {
        clearInterval(pollRef.current!);
        setError(err?.message ?? 'Connection lost');
        setPhase('error');
      }
    }, 900);
  }, []);

  const onDrop = useCallback(async (accepted: File[]) => {
    if (!accepted.length) return;
    const f = accepted[0];
    setFile(f);
    setPhase('uploading');
    setError('');
    setLog([]);
    setCompletedStages([]);
    setReport(null);
    addLog(`File selected: ${f.name} (${formatBytes(f.size)})`);

    try {
      addLog('Uploading to AVALOK backend…');
      const res = await uploadPcap(f, (pct) => setUploadProgress(pct));
      addLog(`Upload complete — Analysis ID: ${res.analysis_id}`);
      addLog(`SHA-256: ${shortHash(res.file_sha256, 32)}`);
      setAnalysisId(res.analysis_id);
      setPhase('analyzing');
      startPolling(res.analysis_id);
    } catch (err: any) {
      setError(err?.response?.data?.detail ?? err?.message ?? 'Upload failed');
      setPhase('error');
      addLog(`UPLOAD ERROR: ${err?.message}`);
    }
  }, [startPolling]);

  const { getRootProps, getInputProps, isDragActive, fileRejections } = useDropzone({
    onDrop,
    accept: { 'application/octet-stream': ['.pcap', '.pcapng', '.cap'] },
    maxFiles: 1,
    disabled: phase === 'uploading' || phase === 'analyzing',
  });

  function reset() {
    if (pollRef.current) clearInterval(pollRef.current);
    setPhase('idle');
    setFile(null);
    setAnalysisId(null);
    setUploadProgress(0);
    setAnalysisProgress(0);
    setCurrentStage('');
    setCompletedStages([]);
    setError('');
    setReport(null);
    setLog([]);
  }

  return (
    <Layout>
      <div className="max-w-screen-xl mx-auto px-6 py-10 fade-in">
        <div className="mb-8">
          <div className="flex items-center gap-2 text-[#7F948B] text-xs font-mono mb-1">
            <Cpu size={12} />
            <span>Forensic Analysis Engine</span>
          </div>
          <h1 className="text-[#F3F7F4] text-2xl font-bold">Analyze PCAP</h1>
          <p className="text-[#7F948B] text-sm mt-1">
            Upload a PCAP network capture to start TLS forensic analysis.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
          {/* Upload / Progress Column */}
          <div className="lg:col-span-3 flex flex-col gap-5">
            {/* Drop zone */}
            {(phase === 'idle' || phase === 'error') && (
              <div
                {...getRootProps()}
                className={cn(
                  'upload-area border-2 border-dashed rounded-lg p-12 text-center cursor-pointer',
                  isDragActive
                    ? 'border-[rgba(139,255,122,0.6)] bg-[rgba(139,255,122,0.06)] upload-area-active'
                    : 'border-[rgba(139,255,122,0.2)] bg-[#0B2A20]/60 hover:border-[rgba(139,255,122,0.4)]'
                )}
              >
                <input {...getInputProps()} />
                <div className="flex flex-col items-center gap-4">
                  <div className={cn(
                    'w-16 h-16 rounded-full border-2 flex items-center justify-center transition-colors',
                    isDragActive ? 'border-[#8BFF7A] text-[#8BFF7A]' : 'border-[rgba(139,255,122,0.3)] text-[#7F948B]'
                  )}>
                    <Upload size={28} />
                  </div>
                  <div>
                    <p className="text-[#F3F7F4] font-mono text-sm font-semibold tracking-wide">
                      {isDragActive ? 'Drop PCAP here' : 'Drop PCAP or click to browse'}
                    </p>
                    <p className="text-[#7F948B] text-xs mt-1 font-mono">
                      Supported: .pcap, .pcapng, .cap
                    </p>
                  </div>
                  <div className="bg-[rgba(139,255,122,0.06)] border border-[rgba(139,255,122,0.15)] rounded px-4 py-2 text-xs font-mono text-[#7F948B] text-left w-full max-w-xs">
                    <div className="text-[#8BFF7A] font-semibold mb-1">Read-Only Passive Analysis</div>
                    The source file is never modified. A SHA-256 hash is taken for chain-of-custody verification.
                  </div>
                </div>
              </div>
            )}

            {/* Uploading state */}
            {phase === 'uploading' && file && (
              <Card>
                <div className="flex items-center gap-3 mb-4">
                  <File size={18} className="text-[#8BFF7A]" />
                  <div className="flex-1 min-w-0">
                    <p className="text-[#F3F7F4] text-sm font-mono truncate">{file.name}</p>
                    <p className="text-[#7F948B] text-xs font-mono">{formatBytes(file.size)}</p>
                  </div>
                </div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[#7F948B] text-xs font-mono">Uploading…</span>
                  <span className="text-[#8BFF7A] text-xs font-mono">{uploadProgress}%</span>
                </div>
                <div className="w-full h-1.5 bg-[#0E3327] rounded-full overflow-hidden">
                  <div
                    className="h-full bg-[#8BFF7A] rounded-full transition-all duration-300"
                    style={{ width: `${uploadProgress}%` }}
                  />
                </div>
              </Card>
            )}

            {/* Analyzing state */}
            {phase === 'analyzing' && file && (
              <Card>
                <div className="flex items-center gap-3 mb-5">
                  <Spinner />
                  <div>
                    <p className="text-[#F3F7F4] text-sm font-mono font-semibold">Analysis in Progress</p>
                    <p className="text-[#7F948B] text-xs font-mono">{file.name}</p>
                  </div>
                </div>

                {/* Overall progress bar */}
                <div className="mb-5">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[#7F948B] text-xs font-mono">{currentStage || 'Starting…'}</span>
                    <span className="text-[#8BFF7A] text-xs font-mono">{analysisProgress}%</span>
                  </div>
                  <div className="w-full h-1.5 bg-[#0E3327] rounded-full overflow-hidden">
                    <div
                      className="h-full bg-[#8BFF7A] rounded-full transition-all duration-500"
                      style={{ width: `${analysisProgress}%` }}
                    />
                  </div>
                </div>

                {/* Stage steps */}
                <div className="space-y-1.5">
                  {ANALYSIS_STAGES.filter(s => s !== 'Complete').map(stage => {
                    const done = completedStages.includes(stage);
                    const active = currentStage === stage;
                    return (
                      <div key={stage} className="flex items-center gap-2">
                        <div className={cn(
                          'w-1.5 h-1.5 rounded-full shrink-0',
                          done ? 'bg-[#8BFF7A]' : active ? 'bg-[#F3F7F4] animate-pulse' : 'bg-[#3B5A4F]'
                        )} />
                        <span className={cn(
                          'text-xs font-mono',
                          done ? 'text-[#8BFF7A]' : active ? 'text-[#F3F7F4]' : 'text-[#3B5A4F]'
                        )}>
                          {done && '✓ '}{stage}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </Card>
            )}

            {/* Error state */}
            {phase === 'error' && (
              <ErrorBanner
                title="Analysis Failed"
                message={error}
                onRetry={reset}
              />
            )}

            {/* Complete state */}
            {phase === 'complete' && report && (
              <Card className="border-[rgba(139,255,122,0.25)]">
                <div className="flex items-center gap-3 mb-4">
                  <CheckCircle size={22} className="text-[#8BFF7A]" />
                  <div>
                    <p className="text-[#8BFF7A] font-mono font-semibold text-sm">Analysis Complete</p>
                    <p className="text-[#7F948B] text-xs font-mono">Report ID: {report.report_id.slice(0, 8).toUpperCase()}</p>
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-3 mb-5">
                  {report.hosts.map(h => (
                    <div key={h.host} className="bg-[#0E3327] border border-[rgba(139,255,122,0.1)] rounded p-3 text-center">
                      <p className="text-[#7F948B] text-[10px] font-mono mb-1">{h.host}</p>
                      <p className={cn(
                        'text-2xl font-bold font-mono',
                        h.posture_grade === 'A' || h.posture_grade === 'B' ? 'text-[#8BFF7A]' :
                        h.posture_grade === 'C' ? 'text-[#F5B942]' : 'text-[#FF5C5C]'
                      )}>
                        {h.posture_grade}
                      </p>
                    </div>
                  ))}
                </div>

                <div className="flex gap-3 flex-wrap">
                  <button
                    onClick={() => navigate(`/reports/${report.report_id}`)}
                    className="flex items-center gap-2 px-5 py-2.5 bg-white text-black font-semibold text-sm rounded-full hover:bg-white/90 transition-all shadow-md cursor-pointer"
                  >
                    View Report <ChevronRight size={14} />
                  </button>
                  <button
                    onClick={reset}
                    className="px-5 py-2.5 border border-white/20 text-white/80 font-mono text-sm rounded-full hover:text-white hover:bg-white/5 transition-colors cursor-pointer"
                  >
                    Analyze Another
                  </button>
                </div>
              </Card>
            )}
          </div>

          {/* Log terminal column */}
          <div className="lg:col-span-2">
            <Card className="h-full min-h-[400px] flex flex-col">
              <div className="flex items-center gap-2 mb-3">
                <Terminal size={14} className="text-[#7F948B]" />
                <span className="text-[#7F948B] text-xs font-mono uppercase tracking-widest">Analysis Log</span>
                <span className="ml-auto text-[10px] font-mono text-[#3B5A4F]">{log.length} entries</span>
              </div>
              <div className="flex-1 bg-[#020F0C] rounded border border-[rgba(139,255,122,0.08)] p-3 overflow-y-auto font-mono text-xs leading-relaxed"
                ref={logRef}
                style={{ minHeight: 320 }}
              >
                {log.length === 0 ? (
                  <span className="text-[#3B5A4F]">Waiting for file upload…</span>
                ) : (
                  log.map((line, i) => (
                    <div key={i} className={cn(
                      'leading-5',
                      line.includes('ERROR') ? 'text-[#FF5C5C]' :
                      line.includes('complete') || line.includes('✓') ? 'text-[#8BFF7A]' :
                      line.includes('Report ID') || line.includes('SHA-256') ? 'text-[#5DA9FF]' :
                      'text-[#7F948B]'
                    )}>
                      {line}
                    </div>
                  ))
                )}
              </div>
            </Card>
          </div>
        </div>
      </div>
    </Layout>
  );
}
