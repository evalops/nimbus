import type { DashboardSettings } from "./types";

const DEFAULT_SETTINGS: DashboardSettings = {
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

  const stored = localStorage.getItem("nimbus-dashboard-settings");
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

export function persistSettings(value: DashboardSettings): void {
  if (typeof localStorage === "undefined") {
    return;
  }

  localStorage.setItem("nimbus-dashboard-settings", JSON.stringify(value));
}

export function clearSettings(): DashboardSettings {
  persistSettings({ ...DEFAULT_SETTINGS });
  return { ...DEFAULT_SETTINGS };
}

export function resetSettings() {
  return clearSettings();
}
