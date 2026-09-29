// AVALOK API Types — mirrors the backend JSON schema exactly

export interface CustodyMetadata {
  report_id: string;
  source_pcap_path: string;
  source_pcap_sha256: string;
  source_pcap_size_bytes: number;
  generated_at: string;
  analyst_host: string;
  analyst_platform: string;
  tool_version: string;
  report_sha256: string;
}

export interface Certificate {
  subject: string;
  issuer: string;
  key_algorithm: string;
  key_length: number;
  key_strength: string;
  signature_algorithm: string;
  expires: string;
  not_before?: string;
  days_until_expiry: number | null;
  is_expired: boolean;
  is_not_yet_valid?: boolean;
  expiring_within_30_days?: boolean;
  is_self_signed: boolean;
  hostname_match: boolean | null;
  sans: string[];
  trust_issues?: string[];
}

export interface EvidenceReference {
  pcap_sha256: string;
  session_id: string;
  session_flow: string;
  packet_number: number;
  byte_offset: number;
  observed_value: string;
  finding_id: string;
  detection_rule: string;
  evidence_chain: string;
}

export interface ForensicEvidenceAndCustody {
  source_pcap: string;
  source_filename: string;
  pcap_sha256: string;
  analysis_id: string;
  report_id: string;
  timestamp: string;
  analyzer_version: string;
  passive_offline_status: string;
  integrity_statement: string;
  packet_level_evidence_mapping: EvidenceReference[];
}

export interface ScoreFactor {
  feature: string;
  rule_id: string;
  finding_id?: string;
  observed_value: string;
  score_contribution: number;
  severity: string;
  evidence_reference: string;
  short_explanation: string;
}

export interface MLAnomalyAssessment {
  assessment_type: string;
  is_model_anomaly: boolean;
  ml_risk_label: string;
  ml_confidence: number;
  anomaly_score: number;
  model_architecture: string;
  score_isolation_note: string;
  model_features: string[];
}

export interface WhyThisScore {
  risk_score?: number;
  raw_score?: number;
  posture_score?: number;
  posture_grade?: string;
  severity: string;
  factor_count: number;
  contributing_factors: ScoreFactor[];
  ascii_tree: string;
  ml_anomaly_assessment?: MLAnomalyAssessment;
}

export interface GradeLadderStep {
  grade: string;
  label: string;
  range: string;
  active: boolean;
}

export interface DeterminingFactor {
  finding_id?: string;
  rule_id: string;
  feature?: string;
  severity: string;
  description: string;
  score_contribution: number;
  observed_value?: string;
  evidence_ref?: string;
  impact_on_grade?: string;
}

export interface WhyThisGrade {
  grade: string;
  label: string;
  score: number;
  headline?: string;
  summary: string;
  threshold_bracket: string;
  determining_factors: DeterminingFactor[];
  grade_ladder?: GradeLadderStep[];
  next_grade_target?: {
    target_grade: string;
    target_label: string;
    points_to_reduce: number;
    top_remediation_action: string;
  };
}

export interface Finding {
  id: string;
  finding_id: string;
  session_id?: string;
  host?: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  description: string;
  reference: string;
  cwe: string;
  contributing_factors: string[];
  evidence_ref: { packet_number: number; type?: string; byte_offset?: number };
  evidence_reference?: EvidenceReference;
  remediation: string;
  ml_flagged: boolean;
  anomaly_score?: number | null;
}

export interface Session {
  session_id: string;
  protocol: 'SMTP' | 'IMAP' | 'POP3' | string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  banner?: string;
  starttls_detected: boolean;
  downgrade_suspected: boolean;
  is_implicit_tls: boolean;
  tls_version: string;
  cipher_suite: string;
  cipher_strength: string;
  pfs: boolean;
  key_exchange: string;
  sni: string | null;
  alpn: string[];
  tls_anomalies: string[];
  tls13_visibility_limited: boolean;
  certificate: Certificate | null;
  ml_risk_label: string;
  ml_confidence: number;
  anomaly_detected: boolean;
  anomaly_score: number;
  packet_refs: number[];
  findings: Finding[];
  why_this_score?: WhyThisScore;
  ml_anomaly_assessment?: MLAnomalyAssessment;
  host_posture_grade?: string;
  host_posture_label?: string;
}

export interface FindingSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
}

export interface HostReport {
  host: string;
  posture_grade: GradeLevel;
  posture_label?: string;
  posture_score: number;
  grade_delta: string | null;
  finding_summary: FindingSummary;
  why_this_score?: WhyThisScore;
  why_this_grade?: WhyThisGrade;
  sessions: Session[];
}

export interface ForensicReport {
  report_id: string;
  analysis_id?: string;
  source_filename?: string;
  source_pcap_sha256: string;
  source_pcap_path: string;
  source_pcap_size_bytes?: number;
  generated_at: string;
  tool_version: string;
  analyst_host?: string;
  tls13_visibility_note: string;
  custody: CustodyMetadata;
  forensic_evidence_and_chain_of_custody?: ForensicEvidenceAndCustody;
  hosts: HostReport[];
}

export interface ReportSummary {
  report_id: string;
  source_pcap_path: string;
  source_pcap_sha256: string;
  generated_at: string;
  tool_version: string;
  worst_grade: string;
  host_count: number;
  finding_count: number;
  severity_summary: FindingSummary;
  json_path: string;
}

// Analysis job types
export interface AnalysisStatus {
  analysis_id: string;
  status: 'running' | 'complete' | 'error';
  stage: string;
  progress: number;
  filename: string;
  file_size: number;
  file_sha256: string;
  error: string | null;
}

export interface UploadResponse {
  analysis_id: string;
  filename: string;
  file_size: number;
  file_sha256: string;
  status: string;
}

export interface HealthStatus {
  status: string;
  service: string;
  version: string;
  analyzer: string;
}

// Derived / UI helper types
export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export type GradeLevel = 'A+' | 'A' | 'B' | 'C' | 'D' | 'E' | 'F' | string;
