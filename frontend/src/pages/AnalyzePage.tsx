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
      addLog('Uploading to Sekure Forensics Engine…');
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
          <div className="flex items-center gap-2 text-[#48BB36] text-xs font-semibold uppercase tracking-wider mb-1">
            <Cpu size={14} />
            <span>Sekure Forensic Analysis Engine</span>
          </div>
          <h1 className="text-white text-3xl font-extrabold tracking-tight">Analyze PCAP Capture</h1>
          <p className="text-white/60 text-sm mt-1">
            Upload a network capture file (SMTP, IMAP, POP3) for passive TLS forensic inspection and anomaly scoring.
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
                  'border-2 border-dashed rounded-xl p-12 text-center cursor-pointer transition-all duration-200',
                  isDragActive
                    ? 'border-[#48BB36] bg-[#48BB36]/10'
                    : 'border-white/15 bg-[#171c23] hover:border-[#48BB36]/50 hover:bg-[#1c222b]'
                )}
              >
                <input {...getInputProps()} />
                <div className="flex flex-col items-center gap-4">
                  <div className={cn(
                    'w-16 h-16 rounded-full border-2 flex items-center justify-center transition-colors',
                    isDragActive ? 'border-[#48BB36] text-[#48BB36]' : 'border-[#48BB36]/30 text-[#48BB36] bg-[#48BB36]/10'
                  )}>
                    <Upload size={28} />
                  </div>
                  <div>
                    <p className="text-white font-bold text-base tracking-wide">
                      {isDragActive ? 'Drop PCAP here' : 'Drop PCAP or click to browse'}
                    </p>
                    <p className="text-white/50 text-xs mt-1 font-mono">
                      Supported formats: .pcap, .pcapng, .cap
                    </p>
                  </div>
                  <div className="bg-[#48BB36]/10 border border-[#48BB36]/20 rounded-lg px-4 py-3 text-xs text-white/70 text-left w-full max-w-sm">
                    <div className="text-[#48BB36] font-bold mb-1">100% Read-Only Passive Ingest</div>
                    Zero packet modification. Cryptographic SHA-256 hash verified for tamper-proof chain of custody.
                  </div>
                </div>
              </div>
            )}

            {/* Uploading state */}
            {phase === 'uploading' && file && (
              <Card>
                <div className="flex items-center gap-3 mb-4">
                  <File size={18} className="text-[#48BB36]" />
                  <div className="flex-1 min-w-0">
                    <p className="text-white text-sm font-semibold truncate">{file.name}</p>
                    <p className="text-white/50 text-xs font-mono">{formatBytes(file.size)}</p>
                  </div>
                </div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-white/60 text-xs font-mono">Uploading…</span>
                  <span className="text-[#48BB36] text-xs font-mono font-bold">{uploadProgress}%</span>
                </div>
                <div className="w-full h-2 bg-white/10 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-[#48BB36] rounded-full transition-all duration-300"
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
                    <p className="text-white/60 text-xs font-mono">{file.name}</p>
                  </div>
                </div>

                {/* Overall progress bar */}
                <div className="mb-5">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-white/70 text-xs font-mono">{currentStage || 'Starting…'}</span>
                    <span className="text-[#48BB36] text-xs font-mono font-bold">{analysisProgress}%</span>
                  </div>
                  <div className="w-full h-2 bg-white/10 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-[#48BB36] rounded-full transition-all duration-500"
                      style={{ width: `${analysisProgress}%` }}
                    />
                  </div>
                </div>

                {/* Stage steps */}
                <div className="space-y-2">
                  {ANALYSIS_STAGES.filter(s => s !== 'Complete').map(stage => {
                    const done = completedStages.includes(stage);
                    const active = currentStage === stage;
                    return (
                      <div key={stage} className="flex items-center gap-2">
                        <div className={cn(
                          'w-2 h-2 rounded-full shrink-0',
                          done ? 'bg-[#48BB36]' : active ? 'bg-white animate-pulse' : 'bg-white/20'
                        )} />
                        <span className={cn(
                          'text-xs font-mono',
                          done ? 'text-[#48BB36]' : active ? 'text-white font-semibold' : 'text-white/40'
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
              <Card className="border-[#48BB36]/30">
                <div className="flex items-center gap-3 mb-4">
                  <CheckCircle size={24} className="text-[#48BB36]" />
                  <div>
                    <p className="text-[#48BB36] font-mono font-bold text-sm">Analysis Complete</p>
                    <p className="text-white/50 text-xs font-mono">Report ID: {report.report_id.slice(0, 8).toUpperCase()}</p>
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-3 mb-5">
                  {report.hosts.map(h => (
                    <div key={h.host} className="bg-white/5 border border-white/10 rounded-lg p-3 text-center">
                      <p className="text-white/60 text-[10px] font-mono mb-1 truncate">{h.host}</p>
                      <p className={cn(
                        'text-2xl font-bold font-mono',
                        h.posture_grade === 'A' || h.posture_grade === 'B' ? 'text-[#48BB36]' :
                        h.posture_grade === 'C' ? 'text-[#f59e0b]' : 'text-[#ef4444]'
                      )}>
                        {h.posture_grade}
                      </p>
                    </div>
                  ))}
                </div>

                <div className="flex gap-3 flex-wrap">
                  <button
                    onClick={() => navigate(`/reports/${report.report_id}`)}
                    className="flex items-center gap-2 px-6 py-3 bg-[#48BB36] hover:bg-[#3ca32c] text-white font-bold text-xs uppercase tracking-wider rounded-md shadow-lg shadow-[#48bb36]/25 transition-all cursor-pointer"
                  >
                    View Report <ChevronRight size={14} />
                  </button>
                  <button
                    onClick={reset}
                    className="px-5 py-3 border border-white/20 text-white/80 font-bold text-xs uppercase tracking-wider rounded-md hover:text-white hover:bg-white/5 transition-colors cursor-pointer"
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
                <Terminal size={14} className="text-white/60" />
                <span className="text-white/70 text-xs font-mono uppercase tracking-widest font-bold">Analysis Log</span>
                <span className="ml-auto text-[10px] font-mono text-white/40">{log.length} entries</span>
              </div>
              <div className="flex-1 bg-[#0b0e12] rounded-lg border border-white/10 p-3 overflow-y-auto font-mono text-xs leading-relaxed"
                ref={logRef}
                style={{ minHeight: 320 }}
              >
                {log.length === 0 ? (
                  <span className="text-white/30">Waiting for file upload…</span>
                ) : (
                  log.map((line, i) => (
                    <div key={i} className={cn(
                      'leading-5',
                      line.includes('ERROR') ? 'text-[#ef4444]' :
                      line.includes('complete') || line.includes('✓') ? 'text-[#48BB36]' :
                      line.includes('Report ID') || line.includes('SHA-256') ? 'text-white' :
                      'text-white/60'
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
