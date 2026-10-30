// Mirrors backend/app/models.py

export type ScanStatus = "queued" | "running" | "enriching" | "completed" | "failed";
export type Severity = "critical" | "high" | "medium" | "low" | "none" | "unknown";

export interface Technique {
  id: string;
  name: string;
  flag: string;
  description: string;
  requires_privileges: boolean;
  available: boolean;
}

export interface TimingTemplate {
  level: number;
  name: string;
  description: string;
}

export interface PortPreset {
  id: string;
  name: string;
  description: string;
}

export interface Options {
  techniques: Technique[];
  timing_templates: TimingTemplate[];
  port_presets: PortPreset[];
  privileged: boolean;
  os_detection_available: boolean;
  allowed_targets: string[];
  ai_enabled: boolean;
  ai_provider: string | null;
  demo_mode: boolean;
}

export interface ScanRequest {
  target: string;
  technique: string;
  timing: number;
  port_preset: string;
  custom_ports?: string;
  service_detection: boolean;
  cve_detection: boolean;
  os_detection: boolean;
  skip_host_discovery: boolean;
  authorized: boolean;
}

export interface CommandPreview {
  target: string;
  resolved_ip: string;
  argv: string[];
  command: string;
  explanation: { flag: string; help: string }[];
}

export interface CVE {
  id: string;
  cvss: number | null;
  severity: Severity;
  source: string;
  is_exploit: boolean;
  epss: number | null;
  epss_percentile: number | null;
  in_kev: boolean;
  kev_date_added: string | null;
  kev_ransomware: boolean;
  description: string | null;
  cvss_vector: string | null;
  cvss_version: string | null;
  published: string | null;
  cwe: string[];
  references: string[];
  url: string | null;
}

export interface Port {
  port: number;
  protocol: string;
  state: string;
  reason: string | null;
  service: string | null;
  product: string | null;
  version: string | null;
  extrainfo: string | null;
  cpes: string[];
  cves: CVE[];
}

export interface Host {
  address: string;
  hostnames: string[];
  status: string;
  os_matches: { name: string; accuracy: number }[];
  ports: Port[];
}

export interface ScanResult {
  nmap_version: string | null;
  command: string | null;
  started_at: string | null;
  elapsed_seconds: number | null;
  summary: string | null;
  hosts: Host[];
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
}

export interface ScanJob {
  id: string;
  target: string;
  resolved_ip: string;
  options: Record<string, unknown>;
  command: string[];
  status: ScanStatus;
  progress: number;
  current_task: string | null;
  error: string | null;
  created_at: string;
  finished_at: string | null;
  result: ScanResult | null;
  severity_counts: SeverityCounts | null;
}

export interface ScanSummary {
  id: string;
  target: string;
  status: ScanStatus;
  created_at: string;
  open_ports: number;
  cve_count: number;
  severity_counts: SeverityCounts | null;
}

export interface ProgressEvent {
  status: ScanStatus;
  progress: number;
  current_task: string | null;
  error: string | null;
}

export interface Explanation {
  cve_id: string;
  summary: string;
  impact: string;
  who_is_affected: string;
  remediation: string[];
  risk_level: string;
  provider: string;
  model: string;
  cached: boolean;
}
