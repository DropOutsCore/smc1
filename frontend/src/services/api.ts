import axios from 'axios';
import type {
  AnalysisStatus,
  ForensicReport,
  HealthStatus,
  ReportSummary,
  UploadResponse,
} from '../types';

const BASE = '/api';

const api = axios.create({
  baseURL: BASE,
  timeout: 60_000,
});

// ── Health ──────────────────────────────────────────────────────────────────

export async function getHealth(): Promise<HealthStatus> {
  const { data } = await api.get<HealthStatus>('/health');
  return data;
}

// ── PCAP Upload ──────────────────────────────────────────────────────────────

export async function uploadPcap(
  file: File,
  onProgress?: (pct: number) => void
): Promise<UploadResponse> {
  const form = new FormData();
  form.append('file', file);
  const { data } = await api.post<UploadResponse>('/pcap/upload', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
    onUploadProgress: (e) => {
      if (onProgress && e.total) {
        onProgress(Math.round((e.loaded * 100) / e.total));
      }
    },
  });
  return data;
}

// ── Analysis polling ─────────────────────────────────────────────────────────

export async function getAnalysisStatus(id: string): Promise<AnalysisStatus> {
  const { data } = await api.get<AnalysisStatus>(`/analysis/${id}/status`);
  return data;
}

export async function getAnalysisResult(id: string): Promise<ForensicReport> {
  const { data } = await api.get<ForensicReport>(`/analysis/${id}/result`);
  return data;
}

// ── Reports ──────────────────────────────────────────────────────────────────

export async function getReports(): Promise<ReportSummary[]> {
  const { data } = await api.get<{ reports: ReportSummary[]; count: number }>('/reports');
  return data.reports;
}

export async function getReport(reportId: string): Promise<ForensicReport> {
  const { data } = await api.get<ForensicReport>(`/reports/${reportId}`);
  return data;
}

export async function downloadReportJson(reportId: string): Promise<void> {
  const res = await api.get(`/reports/${reportId}/download/json`, {
    responseType: 'blob',
  });
  const url = URL.createObjectURL(res.data);
  const a = document.createElement('a');
  a.href = url;
  a.download = `avalok_report_${reportId.slice(0, 8)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

export async function downloadReportHtml(reportId: string): Promise<void> {
  const res = await api.get(`/reports/${reportId}/download/html`, {
    responseType: 'blob',
  });
  const url = URL.createObjectURL(res.data);
  const a = document.createElement('a');
  a.href = url;
  a.download = `avalok_report_${reportId.slice(0, 8)}.html`;
  a.click();
  URL.revokeObjectURL(url);
}

export async function downloadReportPdf(reportId: string): Promise<void> {
  const res = await api.get(`/reports/${reportId}/download/pdf`, {
    responseType: 'blob',
  });
  const url = URL.createObjectURL(new Blob([res.data], { type: 'application/pdf' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = `avalok_report_${reportId.slice(0, 8)}.pdf`;
  a.click();
  URL.revokeObjectURL(url);
}

export async function deleteReport(reportId: string): Promise<void> {
  await api.delete(`/reports/${reportId}`);
}
