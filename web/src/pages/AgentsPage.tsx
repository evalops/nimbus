import { useEffect, useState } from "react";

import { useApi } from "../hooks/useApi";
import type { AgentTokenRecord } from "../types";

import "./AgentsPage.css";

export function AgentsPage() {
  const { adminRequest } = useApi();
  const [records, setRecords] = useState<AgentTokenRecord[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const refresh = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = (await adminRequest("/api/agents", { method: "GET" })) as AgentTokenRecord[];
      setRecords(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="agents__container">
      <header className="agents__header">
        <div>
          <h1>Agent Credentials</h1>
          <p>Monitor active agents and token rotation activity.</p>
        </div>
        <button onClick={refresh} disabled={loading}>
          {loading ? "Refreshing…" : "Refresh"}
        </button>
      </header>

      {error && <div className="agents__error">{error}</div>}

      <div className="agents__table-wrapper">
        <table>
          <thead>
            <tr>
              <th>Agent ID</th>
              <th>Token Version</th>
              <th>TTL (seconds)</th>
              <th>Last Rotated</th>
            </tr>
          </thead>
          <tbody>
            {records.map((record) => (
              <tr key={record.agent_id}>
                <td>{record.agent_id}</td>
                <td>{record.token_version}</td>
                <td>{record.ttl_seconds}</td>
                <td>{new Date(record.rotated_at).toLocaleString()}</td>
              </tr>
            ))}
            {records.length === 0 && (
              <tr>
                <td colSpan={4} className="agents__empty">
                  No agent credential data available. Provide an admin token to view records.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
