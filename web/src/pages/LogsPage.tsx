import { useState, type FormEvent } from "react";

import { useApi } from "../hooks/useApi";
import type { LogEntryView } from "../types";

import "./LogsPage.css";

export function LogsPage() {
  const { loggingGet } = useApi();
  const [jobId, setJobId] = useState<string>("");
  const [contains, setContains] = useState<string>("");
  const [limit, setLimit] = useState<number>(50);
  const [entries, setEntries] = useState<LogEntryView[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const runQuery = async (event?: FormEvent) => {
    event?.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      if (jobId.trim()) {
        params.set("job_id", jobId.trim());
      }
      if (contains.trim()) {
        params.set("contains", contains.trim());
      }
      params.set("limit", String(limit));
      const response = (await loggingGet(`/logs/query?${params.toString()}`)) as LogEntryView[];
      setEntries(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="logs__container">
      <header className="logs__header">
        <div>
          <h1>Log Explorer</h1>
          <p>Query pipeline logs with rich filtering.</p>
        </div>
      </header>

      <form className="logs__form" onSubmit={runQuery}>
        <label>
          Job ID
          <input
            type="number"
            min="0"
            value={jobId}
            onChange={(event) => setJobId(event.target.value)}
            placeholder="e.g. 101"
          />
        </label>
        <label>
          Contains text
          <input
            type="text"
            value={contains}
            onChange={(event) => setContains(event.target.value)}
            placeholder="error, runner, cache"
          />
        </label>
        <label>
          Limit
          <input
            type="number"
            min="1"
            max="500"
            value={limit}
            onChange={(event) => setLimit(Number(event.target.value))}
          />
        </label>
        <button type="submit" disabled={loading}>
          {loading ? "Searching…" : "Search"}
        </button>
      </form>

      {error && <div className="logs__error">{error}</div>}

      <div className="logs__results" role="region" aria-live="polite">
        {entries.length === 0 && !loading ? (
          <p className="logs__empty">No log entries match the current filters.</p>
        ) : (
          <ul className="logs__list">
            {entries.map((entry, index) => (
              <li key={`${entry.job_id}-${index}`} className={`logs__item logs__item--${entry.level.toLowerCase()}`}>
                <span className="logs__timestamp">{new Date(entry.timestamp).toLocaleString()}</span>
                <span className="logs__level">{entry.level}</span>
                <span className="logs__message">{entry.message}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
