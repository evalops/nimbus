import { useEffect, useMemo, useState } from "react";

import { useSettings } from "../hooks/useSettings";

import "./AnalyticsPage.css";

type AnalyticsBucket = {
  date: string;
  counts: Record<string, number>;
  total: number;
};

export function AnalyticsPage() {
  const { settings } = useSettings();
  const [buckets, setBuckets] = useState<AnalyticsBucket[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function fetchAnalytics() {
      if (!settings.controlPlaneBase || !settings.adminToken) {
        return;
      }
      setLoading(true);
      setError(null);
      try {
        const response = await fetch(`${settings.controlPlaneBase}/api/analytics/jobs?days=14`, {
          headers: {
            Authorization: `Bearer ${settings.adminToken}`,
          },
        });
        if (!response.ok) {
          throw new Error(`Request failed: ${response.status}`);
        }
        const payload = (await response.json()) as AnalyticsBucket[];
        setBuckets(payload);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Unknown error");
      } finally {
        setLoading(false);
      }
    }

    fetchAnalytics();
  }, [settings.controlPlaneBase, settings.adminToken]);

  const statusKeys = useMemo(() => {
    const keys = new Set<string>();
    for (const bucket of buckets) {
      Object.keys(bucket.counts).forEach((key) => keys.add(key));
    }
    return Array.from(keys).sort();
  }, [buckets]);

  if (!settings.controlPlaneBase || !settings.adminToken) {
    return (
      <div className="analytics-page">
        <h1>Job Analytics</h1>
        <p className="analytics-page__empty">Configure control plane URL and admin token in Settings to view analytics.</p>
      </div>
    );
  }

  return (
    <div className="analytics-page">
      <div className="analytics-page__header">
        <div>
          <h1>Job Analytics</h1>
          <p className="analytics-page__subtitle">Fourteen-day rolling summary of job outcomes across Nimbus.</p>
        </div>
        {loading && <span className="analytics-page__badge">Loading…</span>}
        {error && <span className="analytics-page__error">{error}</span>}
      </div>

      {buckets.length === 0 ? (
        <p className="analytics-page__empty">No job activity captured in the selected window.</p>
      ) : (
        <div className="analytics-page__table-wrapper">
          <table className="analytics-page__table">
            <thead>
              <tr>
                <th>Date</th>
                <th>Total</th>
                {statusKeys.map((status) => (
                  <th key={status}>{status}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {buckets.map((bucket) => (
                <tr key={bucket.date}>
                  <td>{bucket.date}</td>
                  <td>{bucket.total}</td>
                  {statusKeys.map((status) => (
                    <td key={status}>{bucket.counts[status] ?? 0}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
