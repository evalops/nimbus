import type { DashboardSettings } from "../types";

const STORAGE_KEY = "nimbus-dashboard-settings";

export const DEFAULT_SETTINGS: DashboardSettings = {
  controlPlaneBase: "",
  loggingBase: "",
  adminToken: "",
  agentToken: "",
  dashboardAgentId: "dashboard-viewer",
};

export function loadSettings(): DashboardSettings {
  if (typeof localStorage === "undefined") {
    return { ...DEFAULT_SETTINGS };
  }

  const stored = localStorage.getItem(STORAGE_KEY);
  if (!stored) {
    return { ...DEFAULT_SETTINGS };
  }

  try {
    const parsed = JSON.parse(stored) as DashboardSettings;
    return {
      controlPlaneBase: parsed.controlPlaneBase ?? "",
      loggingBase: parsed.loggingBase ?? "",
      adminToken: parsed.adminToken ?? "",
      agentToken: parsed.agentToken ?? "",
      agentTokenExpiresAt: parsed.agentTokenExpiresAt,
      dashboardAgentId: parsed.dashboardAgentId ?? "dashboard-viewer",
    };
  } catch (error) {
    console.error("Failed to parse settings", error);
    return { ...DEFAULT_SETTINGS };
  }
}

export function persistSettings(settings: DashboardSettings): void {
  if (typeof localStorage === "undefined") {
    return;
  }
  localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
}

export function clearSettings(): DashboardSettings {
  const cleared = { ...DEFAULT_SETTINGS };
  persistSettings(cleared);
  return cleared;
}
