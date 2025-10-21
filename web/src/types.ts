export interface JobRecord {
  job_id: number;
  run_id: number;
  run_attempt: number;
  repo_id: number;
  repo_full_name: string;
  repo_private: boolean;
  labels: string[];
  status: string;
  agent_id?: string | null;
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
