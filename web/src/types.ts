export interface JobRecord {
  job_id: number;
  run_id: number;
  run_attempt: number;
  repo_id: number;
  repo_full_name: string;
  repo_private: boolean;
  org_id?: number;
  labels: string[];
  status: string;
  agent_id?: string | null;
  executor?: string;
  queued_at: string;
  leased_at?: string | null;
  completed_at?: string | null;
  last_message?: string | null;
  updated_at: string;
  metadata?: Record<string, string>;
}

export interface ServiceStatus {
  queue_length: number;
  jobs_by_status: Record<string, number>;
}

export interface OrgStatusSummary {
  org_id: number;
  status_counts: Record<string, number>;
  last_activity: string | null;
  active_agents: string[];
  recent_failures: JobRecord[];
  metadata_top?: Array<{ value: string; count: number }>;
  metadata_outcomes?: Array<{ value: string | null; total: number; succeeded: number; failed: number }>;
  metadata_trend?: Array<{ window_start: string; window_end?: string; value: string | null; total: number; succeeded: number; failed: number }>;
}

export interface MetadataPresetBundle {
  key: string;
  summary: Array<{ value: string; count: number }>;
  outcomes: Array<{ value: string | null; total: number; succeeded: number; failed: number }>;
  trend: Array<{ window_start: string; window_end?: string; value?: string | null; total: number; succeeded: number; failed: number }>;
}

export interface CachePerformanceSummary {
  hit_ratio?: number | null;
  total_hits?: number | null;
  total_misses?: number | null;
  total_bytes?: number | null;
  max_storage_bytes?: number | null;
}

export interface ResourceHighlight {
  job_id: number;
  repo_full_name: string;
  status: string;
  completed_at?: string | null;
  value: number | null;
}

export interface PerformanceOverview {
  cache: {
    artifact?: CachePerformanceSummary;
    docker?: CachePerformanceSummary;
    artifact_hit_ratio_avg?: number | null;
  };
  resources: {
    top_cpu: ResourceHighlight[];
    top_memory: ResourceHighlight[];
  };
}

export interface AgentTokenRecord {
  agent_id: string;
  token_version: number;
  rotated_at: string;
  ttl_seconds: number;
}

export interface AgentTokenResponse {
  agent_id: string;
  token: string;
  expires_at: string;
  ttl_seconds: number;
  version: number;
}

export interface LogEntryView {
  job_id: number;
  timestamp: string;
  level: string;
  message: string;
}

export interface DashboardSettings {
  controlPlaneBase: string;
  loggingBase: string;
  adminToken: string;
  agentToken: string;
  agentTokenExpiresAt?: string;
  dashboardAgentId: string;
}
