// TypeScript mirror of the backend's JSON contract (see app.py upload()).
// If the backend response shape changes, this file must change with it.

export interface Finding {
  detector: string;
  entity: string;
  mitre: string;
  confidence: number;
  reason: string;
  evidence: Record<string, unknown>;
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

export interface AnalysisResult {
  upload_id: string;
  filename: string;
  analyzed_at: string;
  stats: Stats;
  timeline: TimelineEvent[];
  findings: Finding[];
}
