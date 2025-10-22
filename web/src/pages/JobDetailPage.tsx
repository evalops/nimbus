import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { useApi } from "../hooks/useApi";
import type { JobRecord, LogEntryView } from "../types";

import "./JobDetailPage.css";

function parseNumeric(value: string | number | undefined): number | null {
  if (value === undefined) {
    return null;
  }
  const numeric = typeof value === "number" ? value : Number(value);
  return Number.isFinite(numeric) ? numeric : null;
}

function formatBytes(value: number | null): string {
  if (value === null) {
    return "n/a";
  }
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = value;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  const precision = size >= 10 ? 0 : 1;
  return `${size.toFixed(precision)} ${units[unitIndex]}`;
}

function formatSeconds(value: number | null): string {
  if (value === null) {
    return "n/a";
  }
  if (value >= 3600) {
    return `${(value / 3600).toFixed(1)} h`;
  }
  if (value >= 60) {
    return `${(value / 60).toFixed(1)} m`;
  }
  return `${value.toFixed(2)} s`;
}

export function JobDetailPage() {
  const { jobId } = useParams<{ jobId: string }>();
  const { controlGet, loggingGet } = useApi();
  const [job, setJob] = useState<JobRecord | null>(null);
  const [logs, setLogs] = useState<LogEntryView[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadDetails = useCallback(async () => {
    if (!jobId) {
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const jobResponse = (await controlGet(`/api/jobs/${jobId}`)) as JobRecord;
      setJob(jobResponse);
      try {
        const recentLogs = (await loggingGet(`/logs/query?job_id=${jobId}&limit=50`)) as LogEntryView[];
        setLogs(recentLogs);
      } catch (logError) {
        console.warn("Failed to load logs", logError);
        setLogs([]);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [controlGet, loggingGet, jobId]);

  useEffect(() => {
    void loadDetails();
  }, [loadDetails]);

  const resourceMetrics = useMemo(() => {
    if (!job) {
      return [];
    }
    const metadata = job.metadata || {};
    const cpuSeconds = parseNumeric(metadata["resource.cpu_seconds"]);
    const durationSeconds = parseNumeric(metadata["resource.duration_seconds"]);
    const maxMemory = parseNumeric(metadata["resource.max_memory_bytes"] ?? metadata["resource.memory_bytes"]);
    const ioRead = parseNumeric(metadata["resource.io_read_bytes"]);
    const ioWrite = parseNumeric(metadata["resource.io_write_bytes"]);
    return [
      { label: "CPU Time", value: formatSeconds(cpuSeconds) },
      { label: "Duration", value: formatSeconds(durationSeconds) },
      { label: "Peak Memory", value: formatBytes(maxMemory) },
      { label: "IO Read", value: formatBytes(ioRead) },
      { label: "IO Write", value: formatBytes(ioWrite) },
    ].filter((item) => item.value !== "n/a");
  }, [job]);

  const cacheMetrics = useMemo(() => {
    if (!job) {
      return [];
    }
    const metadata = job.metadata || {};
    const artifactRatio = parseNumeric(metadata["cache.artifact.hit_ratio"]);
    const artifactHits = parseNumeric(metadata["cache.artifact.total_hits"]);
    const artifactMisses = parseNumeric(metadata["cache.artifact.total_misses"]);
    const dockerRatio = parseNumeric(metadata["cache.docker.hit_ratio"]);
    return [
      artifactRatio !== null ? { label: "Artifact Hit Ratio", value: `${(artifactRatio * 100).toFixed(1)}%` } : null,
      artifactHits !== null ? { label: "Artifact Hits", value: artifactHits.toLocaleString() } : null,
      artifactMisses !== null ? { label: "Artifact Misses", value: artifactMisses.toLocaleString() } : null,
      dockerRatio !== null ? { label: "Docker Hit Ratio", value: `${(dockerRatio * 100).toFixed(1)}%` } : null,
    ].filter(Boolean) as Array<{ label: string; value: string }>;
  }, [job]);

  const resourceTimeline = useMemo(() => {
    if (!job) {
      return [] as Array<{ ts: string; cpu_seconds?: number; memory_bytes?: number }>;
    }
    const raw = job.metadata?.["resource.timeline"];
    if (!raw) {
      return [];
    }
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        return parsed
          .map((entry) => ({
            ts: typeof entry.ts === "string" ? entry.ts : String(entry.ts ?? ""),
            cpu_seconds: typeof entry.cpu_seconds === "number" ? entry.cpu_seconds : parseNumeric(entry.cpu_seconds),
            memory_bytes: typeof entry.memory_bytes === "number" ? entry.memory_bytes : parseNumeric(entry.memory_bytes),
          }))
          .filter((entry) => entry.ts);
      }
    } catch (error) {
      console.warn("Failed to parse resource timeline", error);
    }
    return [];
  }, [job]);

  if (!jobId) {
    return (
      <div className="job-detail__container">
        <p className="job-detail__error">Job ID is missing from the URL.</p>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="job-detail__container">
        <p>Loading job details…</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="job-detail__container">
        <p className="job-detail__error">{error}</p>
        <button type="button" onClick={loadDetails}>
          Retry
        </button>
      </div>
    );
  }

  if (!job) {
    return (
      <div className="job-detail__container">
        <p className="job-detail__error">Job not found.</p>
      </div>
    );
  }

  return (
    <div className="job-detail__container">
      <header className="job-detail__header">
        <div>
          <h1>
            Job #{job.job_id} &mdash; {job.repo_full_name}
          </h1>
          <p>
            Status: <span className={`job-detail__status job-detail__status--${job.status.toLowerCase()}`}>{job.status}</span>
          </p>
        </div>
        <Link className="job-detail__back" to="/">
          ← Back to overview
        </Link>
      </header>

      <section className="job-detail__section">
        <h2>Execution Summary</h2>
        <div className="job-detail__summary-grid">
          <div>
            <span className="job-detail__summary-label">Executor</span>
            <span>{job.executor}</span>
          </div>
          <div>
            <span className="job-detail__summary-label">Agent</span>
            <span>{job.agent_id ?? "n/a"}</span>
          </div>
          <div>
            <span className="job-detail__summary-label">Run Attempt</span>
            <span>{job.run_attempt}</span>
          </div>
          <div>
            <span className="job-detail__summary-label">Queued At</span>
            <span>{job.queued_at ? new Date(job.queued_at).toLocaleString() : "n/a"}</span>
          </div>
          <div>
            <span className="job-detail__summary-label">Completed At</span>
            <span>{job.completed_at ? new Date(job.completed_at).toLocaleString() : "n/a"}</span>
          </div>
        </div>
      </section>

      {resourceMetrics.length > 0 && (
        <section className="job-detail__section">
          <h2>Resource Utilization</h2>
          <div className="job-detail__metric-grid">
            {resourceMetrics.map((metric) => (
              <article key={metric.label} className="job-detail__metric-card">
                <span className="job-detail__metric-label">{metric.label}</span>
                <span className="job-detail__metric-value">{metric.value}</span>
              </article>
            ))}
          </div>
        </section>
      )}

      {resourceTimeline.length > 0 && (
        <section className="job-detail__section">
          <h2>Resource Timeline</h2>
          <div className="job-detail__timeline">
            <table>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>CPU Seconds</th>
                  <th>Memory</th>
                </tr>
              </thead>
              <tbody>
                {resourceTimeline.map((entry) => (
                  <tr key={entry.ts}>
                    <td>{new Date(entry.ts).toLocaleTimeString()}</td>
                    <td>{entry.cpu_seconds !== undefined ? entry.cpu_seconds.toFixed(3) : "-"}</td>
                    <td>{entry.memory_bytes !== undefined ? formatBytes(entry.memory_bytes) : "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {cacheMetrics.length > 0 && (
        <section className="job-detail__section">
          <h2>Cache Performance</h2>
          <div className="job-detail__metric-grid">
            {cacheMetrics.map((metric) => (
              <article key={metric.label} className="job-detail__metric-card">
                <span className="job-detail__metric-label">{metric.label}</span>
                <span className="job-detail__metric-value">{metric.value}</span>
              </article>
            ))}
          </div>
        </section>
      )}

      <section className="job-detail__section">
        <h2>Metadata</h2>
        {Object.keys(job.metadata || {}).length === 0 ? (
          <p className="job-detail__empty">No metadata recorded for this job.</p>
        ) : (
          <table className="job-detail__metadata-table">
            <thead>
              <tr>
                <th>Key</th>
                <th>Value</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(job.metadata || {}).map(([key, value]) => (
                <tr key={key}>
                  <td>{key}</td>
                  <td>{String(value)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="job-detail__section">
        <header className="job-detail__logs-header">
          <h2>Recent Logs</h2>
          <Link to={`/logs?job_id=${job.job_id}`} className="job-detail__logs-link">
            Open in Log Explorer →
          </Link>
        </header>
        {logs.length === 0 ? (
          <p className="job-detail__empty">No logs captured for this job.</p>
        ) : (
          <ul className="job-detail__logs">
            {logs.map((entry, index) => (
              <li key={`${entry.timestamp}-${index}`} className={`job-detail__log job-detail__log--${entry.level.toLowerCase()}`}>
                <span className="job-detail__log-time">{new Date(entry.timestamp).toLocaleString()}</span>
                <span className="job-detail__log-level">{entry.level}</span>
                <span className="job-detail__log-message">{entry.message}</span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
