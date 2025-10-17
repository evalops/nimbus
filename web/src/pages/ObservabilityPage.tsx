import { useEffect, useState } from "react";

import { useApi } from "../hooks/useApi";
import type { OrgStatusSummary } from "../types";
import { useSettings } from "../hooks/useSettings";
import { useObservabilityMetrics } from "../hooks/useObservability";

import "./ObservabilityPage.css";

export function ObservabilityPage() {
  const { observabilityGet } = useApi();
  const { settings } = useSettings();
  const [orgs, setOrgs] = useState<OrgStatusSummary[]>([]);
  const [hoursBack, setHoursBack] = useState<number>(24);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const hasAdminToken = Boolean(settings.adminToken);
  const { failureLeaders, agentActivity, failureMap } = useObservabilityMetrics(orgs);

  const load = async () => {
    if (!hasAdminToken) {
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      params.set("limit", "50");
      if (hoursBack > 0) {
        params.set("hours_back", String(hoursBack));
      }
      const response = await observabilityGet(`/api/observability/orgs?${params.toString()}`);
      setOrgs(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hoursBack, hasAdminToken]);

  return (
    <div className="observability__container">
      <header className="observability__header">
        <div>
          <h1>Tenant Observability</h1>
          <p>Spot failing tenants, idle orgs, and agents that need attention.</p>
        </div>
        <div className="observability__controls">
          <label>
            Lookback hours
            <input
              type="number"
              min={1}
              max={168}
              value={hoursBack}
              onChange={(event) => setHoursBack(Number(event.target.value))}
            />
          </label>
          <button onClick={load} disabled={loading || !hasAdminToken}>
            {loading ? "Loading…" : "Refresh"}
          </button>
        </div>
      </header>

      {!hasAdminToken && (
        <div className="observability__banner" role="alert">
          Admin token required. Provide an admin bearer token in Settings to view tenant insights.
        </div>
      )}

      {error && <div className="observability__error">{error}</div>}

      <section className="observability__grid">
        <article className="observability__card">
          <h2>Top Failure Rates</h2>
          {failureLeaders.length === 0 ? (
            <p className="observability__empty">No failure data recorded yet.</p>
          ) : (
            <ol>
              {failureLeaders.map((item) => (
                <li key={item.orgId}>
                  <strong>Org {item.orgId}</strong>
                  <span>{(item.rate * 100).toFixed(1)}%</span>
                </li>
              ))}
            </ol>
          )}
        </article>

        <article className="observability__card">
          <h2>Most Active Agents</h2>
          {agentActivity.length === 0 ? (
            <p className="observability__empty">No agents recorded in the selected window.</p>
          ) : (
            <ol>
              {agentActivity.map((item) => (
                <li key={item.orgId}>
                  <strong>Org {item.orgId}</strong>
                  <span>{item.count} agents</span>
                </li>
              ))}
            </ol>
          )}
        </article>
      </section>

      <section className="observability__section">
        <header>
          <h2>Organization Details</h2>
          <span>{orgs.length} organizations observed</span>
        </header>

        <div className="observability__table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Org ID</th>
                <th>Last Activity</th>
                <th>Active Agents</th>
                <th>Queued</th>
                <th>Running</th>
                <th>Succeeded</th>
                <th>Failed</th>
                <th>Cancelled</th>
              </tr>
            </thead>
            <tbody>
              {orgs.map((org) => {
                const counts = org.status_counts || {};
                return (
                  <tr key={org.org_id}>
                    <td>{org.org_id}</td>
                    <td>{org.last_activity ? new Date(org.last_activity).toLocaleString() : "None"}</td>
                    <td>{org.active_agents.length}</td>
                    <td>{counts.queued ?? 0}</td>
                    <td>{counts.running ?? 0}</td>
                    <td>{counts.succeeded ?? 0}</td>
                    <td>{counts.failed ?? 0}</td>
                    <td>{counts.cancelled ?? 0}</td>
                  </tr>
                );
              })}
              {orgs.length === 0 && (
                <tr>
                  <td className="observability__empty" colSpan={8}>
                    No data in the selected window.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="observability__section">
        <header>
          <h2>Recent Failures</h2>
        </header>
        {orgs.every((org) => org.recent_failures.length === 0) ? (
          <p className="observability__empty">No failed jobs recorded.</p>
        ) : (
          <div className="observability__failures">
            {orgs.map((org) => (
              <div key={org.org_id} className="observability__failures-card">
                <h3>Org {org.org_id}</h3>
                {org.recent_failures.length === 0 ? (
                  <p>No recent failures</p>
                ) : (
                  <ul>
                    {(failureMap.get(org.org_id) ?? []).map((job) => (
                      <li key={`${org.org_id}-${job.jobId}`}>
                        <span>#{job.jobId}</span>
                        <span>{job.repo}</span>
                        <span>{new Date(job.updatedAt).toLocaleString()}</span>
                        <span>{job.message}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
