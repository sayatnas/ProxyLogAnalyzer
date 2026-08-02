// TypeScript mirror of the backend's JSON contract (see app.py upload()).

export interface LogEvent {
  timestamp: string;
  user: string;
  src_ip: string;
  domain: string;
  action: string;
  category: string;
  bytes_sent: number;
  bytes_received: number;
  status: number;
}

export interface Finding {
  detector: string;
  entity: string;
  mitre: string;
  confidence: number;
  reason: string;
  evidence: Record<string, unknown>;
  filter: Record<string, string | number>;
  entity_filter: Record<string, string | number>;
  first_seen: string;
  last_seen?: string;
}

export interface TimelineEvent {
  time: string;
  severity: "high" | "medium" | "low";
  detector: string;
  entity: string;
  description: string;
}

export interface Stats {
  total_records: number;
  skipped_lines: number;
  unique_users: number;
  unique_domains: number;
  unique_ips: number;
  blocked_count: number;
  time_range: { start: string; end: string };
}

export interface Lead {
  entity: string;
  observation?: string;
  why_suspicious: string;
  confidence?: number;
  filter?: Record<string, string>;
}

export interface Summary {
  assessment: "benign" | "suspicious" | "malicious" | "inconclusive";
  summary: string;
  correlations: string[];
  recommended_actions: string[];
  leads?: Lead[];
  generated_by: string;
  steps?: number;
  tokens?: number;
  trace?: TraceStep[];
}

export interface TraceStep {
  step?: number;
  tool: string;
  arguments: Record<string, unknown>;
  result: unknown;
  narration?: string | null;
}

export interface Investigation {
  assessment: string;
  steps: number;
  tokens?: number;
  generated_by: string;
  trace?: TraceStep[];
}

export interface AnalysisResult {
  upload_id: string;
  filename: string;
  analyzed_at: string;
  stats: Stats;
  timeline: TimelineEvent[];
  findings: Finding[];
  detectors: string[];
  charts: Charts;
}

export interface Charts {
  activity: {
    start: string;
    end: string;
    bucket_seconds: number;
    counts: number[];
  };
  bytes_by_host: { src_ip: string; bytes: number }[];
}
