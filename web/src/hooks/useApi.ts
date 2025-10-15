import { useCallback } from "react";

import type { AgentTokenResponse } from "../types";
import { useSettings } from "../context/SettingsContext";

function buildUrl(base: string, path: string): string {
  const normalizedBase = base.endsWith("/") ? base : `${base}/`;
  if (path.startsWith("http")) {
    return path;
  }
  return new URL(path.replace(/^\//, ""), normalizedBase).toString();
}

function ensureBase(base: string | undefined, label: string): string {
  if (!base) {
    throw new Error(`${label} is not configured in Settings`);
  }
  return base;
}

export function useApi() {
  const { settings, updateSettings } = useSettings();

  const controlRequest = useCallback(
    async (path: string, init: RequestInit = {}, expectJson: boolean = true) => {
      const base = ensureBase(settings.controlPlaneBase, "Control plane base URL");
      if (!settings.agentToken) {
        throw new Error("Dashboard agent token is not available. Mint one from Settings.");
      }
      const url = buildUrl(base, path);
      const headers = new Headers(init.headers);
      headers.set("Authorization", `Bearer ${settings.agentToken}`);
      if (init.body && !headers.has("Content-Type")) {
        headers.set("Content-Type", "application/json");
      }
      const response = await fetch(url, { ...init, headers });
      if (!response.ok) {
        const message = await response.text();
        throw new Error(message || `Request failed with status ${response.status}`);
      }
      if (!expectJson || response.status === 204) {
        return null;
      }
      return response.json();
    },
    [settings.agentToken, settings.controlPlaneBase],
  );

  const controlGet = useCallback(
    async (path: string) => {
      return controlRequest(path, { method: "GET" });
    },
    [controlRequest],
  );

  const adminRequest = useCallback(
    async (path: string, init: RequestInit = {}) => {
      const base = ensureBase(settings.controlPlaneBase, "Control plane base URL");
      if (!settings.adminToken) {
        throw new Error("Admin token is required for this action.");
      }
      const url = buildUrl(base, path);
      const headers = new Headers(init.headers);
      headers.set("Authorization", `Bearer ${settings.adminToken}`);
      if (init.body && !headers.has("Content-Type")) {
        headers.set("Content-Type", "application/json");
      }
      const response = await fetch(url, { ...init, headers });
      if (!response.ok) {
        const message = await response.text();
        throw new Error(message || `Request failed with status ${response.status}`);
      }
      if (response.status === 204) {
        return null;
      }
      return response.json();
    },
    [settings.adminToken, settings.controlPlaneBase],
  );

  const loggingGet = useCallback(
    async (path: string) => {
      const base = settings.loggingBase || settings.controlPlaneBase;
      const loggingBase = ensureBase(base, "Logging service base URL");
      const url = buildUrl(loggingBase, path);
      const response = await fetch(url);
      if (!response.ok) {
        const message = await response.text();
        throw new Error(message || `Logging request failed with status ${response.status}`);
      }
      return response.json();
    },
    [settings.controlPlaneBase, settings.loggingBase],
  );

  const fetchMetricsText = useCallback(
    async (path: string = "/metrics") => {
      const base = ensureBase(settings.controlPlaneBase, "Control plane base URL");
      const url = buildUrl(base, path);
      const response = await fetch(url);
      if (!response.ok) {
        const message = await response.text();
        throw new Error(message || `Metrics request failed with status ${response.status}`);
      }
      return response.text();
    },
    [settings.controlPlaneBase],
  );

  const mintAgentToken = useCallback(
    async (agentId: string, ttlSeconds: number): Promise<AgentTokenResponse> => {
      const payload = JSON.stringify({ agent_id: agentId, ttl_seconds: ttlSeconds });
      const response: AgentTokenResponse = await adminRequest("/api/agents/token", {
        method: "POST",
        body: payload,
      });
      updateSettings({ agentToken: response.token, agentTokenExpiresAt: response.expires_at });
      return response;
    },
    [adminRequest, updateSettings],
  );

  return {
    controlGet,
    controlRequest,
    adminRequest,
    loggingGet,
    fetchMetricsText,
    mintAgentToken,
  };
}
