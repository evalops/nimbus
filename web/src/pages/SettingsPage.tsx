import { useState, type FormEvent } from "react";

import { useApi } from "../hooks/useApi";
import { useSettings } from "../hooks/useSettings";
import type { AgentTokenResponse } from "../types";

import "./SettingsPage.css";

export function SettingsPage() {
  const { settings, updateSettings, clearTokens } = useSettings();
  const { mintAgentToken } = useApi();

  const [controlPlaneBase, setControlPlaneBase] = useState(settings.controlPlaneBase);
  const [loggingBase, setLoggingBase] = useState(settings.loggingBase);
  const [adminToken, setAdminToken] = useState(settings.adminToken);
  const [agentId, setAgentId] = useState(settings.dashboardAgentId);
  const [ttlSeconds, setTtlSeconds] = useState<number>(3600);
  const [mintResult, setMintResult] = useState<AgentTokenResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSave = (event: FormEvent) => {
    event.preventDefault();
    updateSettings({
      controlPlaneBase: controlPlaneBase.trim(),
      loggingBase: loggingBase.trim(),
      adminToken: adminToken.trim(),
      dashboardAgentId: agentId.trim() || "dashboard-viewer",
    });
    setSuccessMessage("Settings saved");
    setError(null);
  };

  const handleMint = async () => {
    setLoading(true);
    setError(null);
    setSuccessMessage(null);
    try {
      const response = await mintAgentToken(agentId.trim() || "dashboard-viewer", ttlSeconds);
      setMintResult(response);
      setSuccessMessage(`Minted dashboard token v${response.version} expiring at ${new Date(response.expires_at).toLocaleString()}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="settings__container">
      <h1>Dashboard Settings</h1>
      <p>Configure service endpoints and rotate scoped tokens for read access.</p>

      <form className="settings__form" onSubmit={handleSave}>
        <div>
          <label htmlFor="control-plane-base">Control plane base URL</label>
          <input
            id="control-plane-base"
            type="url"
            placeholder="https://nimbus.example.com"
            value={controlPlaneBase}
            onChange={(event) => setControlPlaneBase(event.target.value)}
            required
          />
        </div>

        <div>
          <label htmlFor="logging-base">Logging service base URL (optional)</label>
          <input
            id="logging-base"
            type="url"
            placeholder="https://logging.example.com"
            value={loggingBase}
            onChange={(event) => setLoggingBase(event.target.value)}
          />
        </div>

        <div>
          <label htmlFor="admin-token">Admin bearer token</label>
          <textarea
            id="admin-token"
            value={adminToken}
            onChange={(event) => setAdminToken(event.target.value)}
            placeholder="Paste admin JWT here"
            rows={3}
          />
        </div>

        <div className="settings__actions">
          <button type="submit">Save Settings</button>
          <button type="button" onClick={clearTokens} className="settings__clear">
            Clear Tokens
          </button>
        </div>
      </form>

      <section className="settings__section">
        <header>
          <h2>Dashboard Agent Token</h2>
          <p>Issue a dedicated agent token for read-only dashboard operations.</p>
        </header>

        <div className="settings__token-form">
          <label>
            Agent identifier
            <input
              type="text"
              value={agentId}
              onChange={(event) => setAgentId(event.target.value)}
              placeholder="dashboard-viewer"
            />
          </label>
          <label>
            TTL (seconds)
            <input
              type="number"
              min={300}
              max={86400}
              step={300}
              value={ttlSeconds}
              onChange={(event) => setTtlSeconds(Number(event.target.value))}
            />
          </label>
          <button type="button" onClick={handleMint} disabled={loading}>
            {loading ? "Minting…" : "Mint token"}
          </button>
        </div>

        {mintResult && (
          <div className="settings__token-details">
            <h3>Latest Token</h3>
            <code>{mintResult.token}</code>
          </div>
        )}

        <dl className="settings__summary">
          <div>
            <dt>Agent token expires</dt>
            <dd>{settings.agentTokenExpiresAt ? new Date(settings.agentTokenExpiresAt).toLocaleString() : "Unknown"}</dd>
          </div>
          <div>
            <dt>Agent token present</dt>
            <dd>{settings.agentToken ? "Yes" : "No"}</dd>
          </div>
        </dl>
      </section>

      {successMessage && <div className="settings__success">{successMessage}</div>}
      {error && <div className="settings__error">{error}</div>}
    </div>
  );
}
