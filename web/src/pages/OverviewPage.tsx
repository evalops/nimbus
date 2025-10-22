import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";

import { useApi } from "../hooks/useApi";
import type { JobRecord, ServiceStatus, MetadataPresetBundle } from "../types";
import { useSettings } from "../hooks/useSettings";

import "./OverviewPage.css";

type MetadataBucket = {
  value: string;
  count: number;
};

type MetadataOutcome = {
  value: string | null;
  total: number;
  succeeded: number;
  failed: number;
};

export function OverviewPage() {
  const { controlGet, fetchMetricsText } = useApi();
  const { settings } = useSettings();
  const [jobs, setJobs] = useState<JobRecord[]>([]);
  const [status, setStatus] = useState<ServiceStatus | null>(null);
  const [metrics, setMetrics] = useState<string>("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [metadataKey, setMetadataKey] = useState("");
  const [metadataValue, setMetadataValue] = useState("");
  const [metadataOrg, setMetadataOrg] = useState<string>("");
  const [appliedMetadataKey, setAppliedMetadataKey] = useState("");
  const [appliedMetadataValue, setAppliedMetadataValue] = useState("");
  const [appliedMetadataOrg, setAppliedMetadataOrg] = useState<string>("");
  const [metadataSummary, setMetadataSummary] = useState<MetadataBucket[]>([]);
  const [metadataOutcomes, setMetadataOutcomes] = useState<MetadataOutcome[]>([]);
  const [metadataTrend, setMetadataTrend] = useState<Array<{ window_start: string; total: number; succeeded: number; value?: string | null }>>([]);
  const [metadataPresets, setMetadataPresets] = useState<MetadataPresetBundle[]>([]);
  const [metadataHours, setMetadataHours] = useState(24);

  const hasAgentToken = Boolean(settings.agentToken);

  const orgOptions = useMemo(() => {
    const ids = new Set<number>();
    jobs.forEach((job) => {
      if (typeof job.org_id === "number") {
        ids.add(job.org_id);
      }
    });
    return Array.from(ids).sort((a, b) => a - b);
  }, [jobs]);

  const outcomeMap = useMemo(() => {
    const map: Record<string, MetadataOutcome> = {};
    metadataOutcomes.forEach((entry) => {
      const key = entry.value ?? "";
      map[key] = entry;
    });
    return map;
  }, [metadataOutcomes]);

  const refresh = useCallback(async () => {
    if (!hasAgentToken) {
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams({ limit: "100" });
      if (appliedMetadataKey) {
        params.set("meta_key", appliedMetadataKey);
      }
      if (appliedMetadataValue) {
        params.set("meta_value", appliedMetadataValue);
      }
      if (appliedMetadataOrg) {
        params.set("org_id", appliedMetadataOrg);
      }
      const query = params.toString();
      const [statusResponse, jobsResponse, metricsText] = await Promise.all([
        controlGet("/api/status"),
        controlGet(`/api/jobs/recent?${query}`),
        fetchMetricsText().catch(() => ""),
      ]);
      setStatus(statusResponse as ServiceStatus);
      setJobs(jobsResponse as JobRecord[]);
      setMetrics(metricsText);

      if (appliedMetadataKey) {
        const summaryParams = new URLSearchParams({ key: appliedMetadataKey, limit: "10" });
        const outcomeParams = new URLSearchParams({ key: appliedMetadataKey, limit: "10" });
        if (appliedMetadataValue) {
          summaryParams.set("meta_value", appliedMetadataValue);
        }
        if (appliedMetadataOrg) {
          summaryParams.set("org_id", appliedMetadataOrg);
          outcomeParams.set("org_id", appliedMetadataOrg);
        }
        if (metadataHours > 0) {
          summaryParams.set("hours_back", metadataHours.toString());
          outcomeParams.set("hours_back", metadataHours.toString());
        }
        try {
          const summaryResponse = await controlGet(`/api/jobs/metadata/summary?${summaryParams.toString()}`);
          setMetadataSummary(summaryResponse as MetadataBucket[]);
        } catch (summaryError) {
          console.warn("Failed to load metadata summary", summaryError);
          setMetadataSummary([]);
        }
        try {
          const outcomeResponse = await controlGet(`/api/jobs/metadata/outcomes?${outcomeParams.toString()}`);
          setMetadataOutcomes(outcomeResponse as MetadataOutcome[]);
        } catch (outcomeError) {
          console.warn("Failed to load metadata outcomes", outcomeError);
          setMetadataOutcomes([]);
        }
        try {
          const trendParams = new URLSearchParams({ key: appliedMetadataKey, bucket_hours: Math.max(1, Math.min(metadataHours || 1, 168)).toString() });
          if (metadataHours > 0) {
            trendParams.set("hours_back", metadataHours.toString());
          }
          if (appliedMetadataOrg) {
            trendParams.set("org_id", appliedMetadataOrg);
          }
          const trendResponse = await controlGet(`/api/jobs/metadata/trends?${trendParams.toString()}`);
          setMetadataTrend(trendResponse as Array<{ window_start: string; total: number; succeeded: number; value?: string | null }>);
        } catch (trendError) {
          console.warn("Failed to load metadata trend", trendError);
          setMetadataTrend([]);
        }
        setMetadataPresets([]);
      } else {
        setMetadataSummary([]);
        setMetadataOutcomes([]);
        setMetadataTrend([]);
        try {
          const presetParams = new URLSearchParams({ limit: "5", bucket_hours: Math.max(1, Math.min(metadataHours || 24, 168)).toString() });
          if (metadataHours > 0) {
            presetParams.set("hours_back", metadataHours.toString());
          }
          if (metadataOrg) {
            presetParams.set("org_id", metadataOrg);
          }
          const presetResponse = await controlGet(`/api/jobs/metadata/presets?${presetParams.toString()}`);
          setMetadataPresets(presetResponse as MetadataPresetBundle[]);
        } catch (presetError) {
          console.warn("Failed to load metadata presets", presetError);
          setMetadataPresets([]);
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [appliedMetadataKey, appliedMetadataValue, appliedMetadataOrg, metadataHours, controlGet, fetchMetricsText, hasAgentToken]);

  useEffect(() => {
    if (hasAgentToken) {
      void refresh();
    }
  }, [hasAgentToken, refresh]);

  const handleApplyFilters = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setAppliedMetadataKey(metadataKey.trim());
    setAppliedMetadataValue(metadataValue.trim());
    setAppliedMetadataOrg(metadataOrg.trim());
  };

  const handleClearFilters = () => {
    setMetadataKey("");
    setMetadataValue("");
    setMetadataOrg("");
    setAppliedMetadataKey("");
    setAppliedMetadataValue("");
    setAppliedMetadataOrg("");
    setMetadataSummary([]);
    setMetadataOutcomes([]);
    setMetadataHours(24);
  };

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
        <form className="overview__filters" onSubmit={handleApplyFilters}>
          <div className="overview__filter-field">
            <label htmlFor="metadata-key">Metadata key</label>
            <input
              id="metadata-key"
              type="text"
              placeholder="e.g. lr"
              value={metadataKey}
              onChange={(event) => setMetadataKey(event.target.value)}
            />
          </div>
          <div className="overview__filter-field">
            <label htmlFor="metadata-value">Metadata value</label>
            <input
              id="metadata-value"
              type="text"
              placeholder="optional"
              value={metadataValue}
              onChange={(event) => setMetadataValue(event.target.value)}
            />
          </div>
          <div className="overview__filter-field">
            <label htmlFor="metadata-org">Organization</label>
            <select
              id="metadata-org"
              value={metadataOrg}
              onChange={(event) => setMetadataOrg(event.target.value)}
            >
              <option value="">All orgs</option>
              {orgOptions.map((orgId) => (
                <option key={orgId} value={String(orgId)}>
                  org-{orgId}
                </option>
              ))}
            </select>
          </div>
          <div className="overview__filter-field">
            <label htmlFor="metadata-hours">Window (hours)</label>
            <select
              id="metadata-hours"
              value={metadataHours}
              onChange={(event) => setMetadataHours(Number(event.target.value))}
            >
              <option value={6}>6 hours</option>
              <option value={12}>12 hours</option>
              <option value={24}>24 hours</option>
              <option value={72}>72 hours</option>
              <option value={168}>7 days</option>
              <option value={0}>All time</option>
            </select>
          </div>
          <div className="overview__filter-actions">
            <button type="submit" disabled={loading}>
              Apply
            </button>
            <button
              type="button"
              onClick={handleClearFilters}
              disabled={
                loading || (!metadataKey && !metadataValue && !metadataOrg && !appliedMetadataKey && !appliedMetadataValue && !appliedMetadataOrg)
              }
            >
              Clear
            </button>
          </div>
          {(appliedMetadataKey || appliedMetadataValue || appliedMetadataOrg || metadataHours !== 24) && (
            <div className="overview__filter-active">
              Active filter: {appliedMetadataKey || "any"}
              {appliedMetadataValue ? `=${appliedMetadataValue}` : " (any value)"}
              {appliedMetadataOrg ? ` | org=${appliedMetadataOrg}` : " | all orgs"}
              {metadataHours > 0 ? ` | last ${metadataHours}h` : " | full history"}
            </div>
          )}
        </form>
        <div className="overview__table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Job ID</th>
                <th>Repository</th>
                <th>Status</th>
                <th>Metadata</th>
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
                  <td className="overview__metadata">
                    {job.metadata && Object.keys(job.metadata).length > 0
                      ? Object.entries(job.metadata)
                          .map(([key, value]) => `${key}=${value}`)
                          .join(", ")
                      : "–"}
                  </td>
                  <td>{job.agent_id ?? "–"}</td>
                  <td>{new Date(job.queued_at).toLocaleString()}</td>
                  <td className="overview__message">{job.last_message ?? ""}</td>
                </tr>
              ))}
              {jobs.length === 0 && (
                <tr>
                  <td colSpan={7} className="overview__empty">
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

      {appliedMetadataKey && (
        <section className="overview__section">
          <header className="overview__section-header">
            <h2>Metadata Distribution</h2>
            <span>
              Key: {appliedMetadataKey}
              {appliedMetadataValue ? ` (${appliedMetadataValue})` : ""}
            </span>
          </header>
          {metadataSummary.length > 0 ? (
            <MetadataChart data={metadataSummary} outcomes={outcomeMap} trend={metadataTrend} />
          ) : (
            <p className="overview__empty">No metadata recorded for this key.</p>
          )}
          {metadataOutcomes.length > 0 && (
            <div className="overview__metadata-note">Success metrics calculated from recent job outcomes.</div>
          )}
        </section>
      )}

      {!appliedMetadataKey && metadataPresets.length > 0 && (
        <section className="overview__section">
          <header className="overview__section-header">
            <h2>Metadata Presets</h2>
            <span>{metadataPresets.length} bundle{metadataPresets.length === 1 ? "" : "s"} loaded</span>
          </header>
          <div className="overview__presets">
            {metadataPresets.map((preset, index) => (
              <PresetCard key={preset.key || `preset-${index}`} preset={preset} />
            ))}
          </div>
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

function MetadataChart({
  data,
  outcomes,
  trend = [],
}: {
  data: MetadataBucket[];
  outcomes: Record<string, MetadataOutcome>;
  trend?: Array<{ window_start: string; total: number; succeeded: number; value?: string | null }>;
}) {
  const maxCount = Math.max(...data.map((bucket) => Number(bucket.count) || 0), 1);
  const trendMap = new Map<string, Array<{ window_start: string; total: number; succeeded: number }>>();
  trend.forEach((entry) => {
    const key = entry.value ?? "";
    const list = trendMap.get(key) || [];
    list.push({ window_start: entry.window_start, total: entry.total, succeeded: entry.succeeded });
    trendMap.set(key, list);
  });

  return (
    <ul className="overview__metadata-list">
      {data.map((bucket) => {
        const width = Math.max(4, (Number(bucket.count) / maxCount) * 100);
        const outcome = outcomes[bucket.value] || outcomes[""];
        const total = outcome?.total ?? bucket.count;
        const succeeded = outcome?.succeeded ?? 0;
        const failed = outcome?.failed ?? 0;
        const successRate = total ? (succeeded / total) * 100 : 0;
        const valueKey = bucket.value ?? "";
        const sparklinePoints = trendMap.get(valueKey) || [];
        return (
          <li key={`${bucket.value}-${bucket.count}`}>
            <div className="overview__metadata-label">
              {bucket.value || "(empty)"}
              <span className="overview__metadata-label-count">{bucket.count} runs</span>
            </div>
            <div className="overview__metadata-bar">
              <span className="overview__metadata-bar-fill" style={{ width: `${width}%` }} />
              <span className="overview__metadata-count">{bucket.count}</span>
            </div>
            {total > 0 && (
              <div className="overview__metadata-outcomes">
                <span className="overview__metadata-success">{successRate.toFixed(1)}% success</span>
                <span className="overview__metadata-breakdown">✔ {succeeded} · ✖ {failed}</span>
              </div>
            )}
            {sparklinePoints.length > 0 && <MetadataSparkline points={sparklinePoints} />}
          </li>
        );
      })}
    </ul>
  );
}

function PresetCard({ preset }: { preset: MetadataPresetBundle }) {
  const summary = (preset.summary ?? []).slice(0, 3);
  const outcomes = preset.outcomes ?? [];
  const trend = preset.trend ?? [];
  const totalSucceeded = outcomes.reduce((acc, row) => acc + (row.succeeded ?? 0), 0);
  const totalFailed = outcomes.reduce((acc, row) => acc + (row.failed ?? 0), 0);
  const totalCount = outcomes.reduce((acc, row) => acc + (row.total ?? 0), 0);
  const successRate = totalCount ? (totalSucceeded / totalCount) * 100 : null;
  const maxTrend = Math.max(...trend.map((point) => point.total ?? 0), 0) || 1;

  return (
    <article className="overview__preset-card">
      <div>
        <h3 className="overview__preset-title">{preset.key ?? "(unknown preset)"}</h3>
        {summary.length > 0 && (
          <ul className="overview__preset-summary">
            {summary.map((row, index) => (
              <li key={`${row.value ?? "(empty)"}-${index}`}>
                <span>{row.value ?? "(empty)"}</span>
                <span className="overview__metadata-label-count">{row.count} runs</span>
              </li>
            ))}
          </ul>
        )}
      </div>
      {successRate !== null && (
        <div className="overview__metadata-outcomes">
          <span className="overview__metadata-success">{successRate.toFixed(1)}% success</span>
          <span className="overview__metadata-breakdown">✔ {totalSucceeded} / ✖ {totalFailed}</span>
        </div>
      )}
      {trend.length > 0 && (
        <div className="overview__sparkline" aria-label="Preset trend">
          {trend.map((point, index) => {
            const value = point.total ?? 0;
            const heightPercent = Math.max(8, Math.round((value / maxTrend) * 100));
            return (
              <span
                key={`${point.window_start}-${index}`}
                style={{ height: `${heightPercent}%` }}
                title={`${point.window_start}: ${value} jobs`}
              />
            );
          })}
        </div>
      )}
    </article>
  );
}

function MetadataSparkline({ points }: { points: Array<{ window_start: string; total: number; succeeded: number }> }) {
  if (points.length === 0) {
    return null;
  }
  const ratios = points.map((point) => {
    const total = point.total || 0;
    return total ? (point.succeeded / total) * 100 : 0;
  });
  const max = Math.max(...ratios, 100);
  return (
    <div className="overview__sparkline">
      {ratios.map((ratio, index) => (
        <span
          key={`${points[index].window_start}-${index}`}
          style={{ height: `${Math.max(6, (ratio / max) * 100)}%` }}
          title={`${ratio.toFixed(1)}% success`}
        />
      ))}
    </div>
  );
}
