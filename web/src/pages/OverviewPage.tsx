import { useEffect, useMemo, useState } from "react";

import { useApi } from "../hooks/useApi";
import type { JobRecord, ServiceStatus } from "../types";
import { useSettings } from "../hooks/useSettings";

import "./OverviewPage.css";

export function OverviewPage() {
  const { controlGet, fetchMetricsText } = useApi();
  const { settings } = useSettings();
  const [jobs, setJobs] = useState<JobRecord[]>([]);
  const [status, setStatus] = useState<ServiceStatus | null>(null);
  const [metrics, setMetrics] = useState<string>("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const hasAgentToken = Boolean(settings.agentToken);

  const refresh = async () => {
    if (!hasAgentToken) {
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const [statusResponse, jobsResponse, metricsText] = await Promise.all([
        controlGet("/api/status"),
        controlGet("/api/jobs/recent?limit=100"),
        fetchMetricsText().catch(() => ""),
      ]);
      setStatus(statusResponse as ServiceStatus);
      setJobs(jobsResponse as JobRecord[]);
      setMetrics(metricsText);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hasAgentToken]);

  const jobCounts = useMemo(() => {
    if (!status) {
      return [] as Array<{ label: string; value: number }>;
    }
    return Object.entries(status.jobs_by_status || {})
      .sort((a, b) => b[1] - a[1])
      .map(([label, value]) => ({ label, value }));
  }, [status]);

  return (
    <div className="overview__container">
      <div className="overview__header">
        <div>
          <h1 className="overview__title">Control Plane Overview</h1>
          <p className="overview__subtitle">Real-time insight into job throughput and queue health.</p>
        </div>
        <button onClick={refresh} disabled={loading || !hasAgentToken}>
          {loading ? "Refreshing…" : "Refresh"}
        </button>
      </div>

      {error && <div className="overview__error">{error}</div>}

      <section className="overview__stats">
        <StatCard label="Queue Depth" value={status?.queue_length ?? 0} />
        <StatCard label="Active Jobs" value={status?.jobs_by_status?.running ?? 0} />
        <StatCard label="Succeeded" value={status?.jobs_by_status?.succeeded ?? 0} />
        <StatCard label="Failed" value={status?.jobs_by_status?.failed ?? 0} />
      </section>

      <section className="overview__section">
        <header className="overview__section-header">
          <h2>Job Activity</h2>
          <span>{jobs.length} recent jobs</span>
        </header>
        <div className="overview__table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Job ID</th>
                <th>Repository</th>
                <th>Status</th>
                <th>Agent</th>
                <th>Queued</th>
                <th>Last Message</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((job) => (
                <tr key={job.job_id}>
                  <td>#{job.job_id}</td>
                  <td>{job.repo_full_name}</td>
                  <td className={`status status--${job.status.toLowerCase()}`}>{job.status}</td>
                  <td>{job.agent_id ?? "–"}</td>
                  <td>{new Date(job.queued_at).toLocaleString()}</td>
                  <td className="overview__message">{job.last_message ?? ""}</td>
                </tr>
              ))}
              {jobs.length === 0 && (
                <tr>
                  <td colSpan={6} className="overview__empty">
                    No job data available. Ensure the dashboard agent token has access.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {jobCounts.length > 0 && (
        <section className="overview__section">
          <header className="overview__section-header">
            <h2>Status Breakdown</h2>
          </header>
          <ul className="overview__status-list">
            {jobCounts.map((item) => (
              <li key={item.label}>
                <span>{item.label}</span>
                <span>{item.value}</span>
              </li>
            ))}
          </ul>
        </section>
      )}

      {metrics && (
        <section className="overview__section">
          <header className="overview__section-header">
            <h2>Prometheus Metrics</h2>
            <span>Snippet from /metrics</span>
          </header>
          <pre className="overview__metrics" aria-label="Prometheus metrics sample">
            {metrics.split("\n").slice(0, 30).join("\n")}
            {metrics.split("\n").length > 30 ? "\n…" : ""}
          </pre>
        </section>
      )}
    </div>
  );
}

function StatCard({ label, value }: { label: string; value: number }) {
  return (
    <div className="overview__stat-card">
      <span className="overview__stat-label">{label}</span>
      <span className="overview__stat-value">{value}</span>
    </div>
  );
}
