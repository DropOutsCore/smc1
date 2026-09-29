import { useState, useEffect, useRef } from 'react';
import { getHealth, getAnalysisStatus } from '../services/api';

export function useHealth() {
  const [status, setStatus] = useState<'online' | 'offline' | 'checking'>('checking');

  useEffect(() => {
    let cancelled = false;
    async function check() {
      try {
        await getHealth();
        if (!cancelled) setStatus('online');
      } catch {
        if (!cancelled) setStatus('offline');
      }
    }
    check();
    const interval = setInterval(check, 30_000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  return status;
}

export function usePollingAnalysis(
  analysisId: string | null,
  onComplete: (id: string) => void,
  onError: (msg: string) => void
) {
  const [stage, setStage] = useState('');
  const [progress, setProgress] = useState(0);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (!analysisId) return;

    timerRef.current = setInterval(async () => {
      try {
        const status = await getAnalysisStatus(analysisId);
        setStage(status.stage);
        setProgress(status.progress);
        if (status.status === 'complete') {
          clearInterval(timerRef.current!);
          onComplete(analysisId);
        } else if (status.status === 'error') {
          clearInterval(timerRef.current!);
          onError(status.error ?? 'Analysis failed');
        }
      } catch (err: unknown) {
        clearInterval(timerRef.current!);
        const message = err instanceof Error ? err.message : 'Connection lost';
        onError(message);
      }
    }, 800);

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [analysisId, onComplete, onError]);

  return { stage, progress };
}
