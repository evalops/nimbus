import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

import type { DashboardSettings } from "../types";

const STORAGE_KEY = "nimbus-dashboard-settings-v1";

const defaultSettings: DashboardSettings = {
  controlPlaneBase: "",
  loggingBase: "",
  adminToken: "",
  agentToken: "",
  dashboardAgentId: "dashboard-viewer",
};

type SettingsContextValue = {
  settings: DashboardSettings;
  updateSettings: (next: Partial<DashboardSettings>) => void;
  clearTokens: () => void;
};

const SettingsContext = createContext<SettingsContextValue | undefined>(undefined);

type PersistedSettings = Omit<DashboardSettings, "adminToken" | "agentToken">;

function loadSettings(storage: Storage | null): PersistedSettings {
  try {
    if (!storage) {
      return {
        controlPlaneBase: "",
        loggingBase: "",
        dashboardAgentId: "dashboard-viewer",
        agentTokenExpiresAt: undefined,
      };
    }
    const raw = storage.getItem(STORAGE_KEY);
    if (!raw) {
      return {
        controlPlaneBase: "",
        loggingBase: "",
        dashboardAgentId: "dashboard-viewer",
        agentTokenExpiresAt: undefined,
      };
    }
    const parsed = JSON.parse(raw) as Partial<PersistedSettings>;
    return {
      controlPlaneBase: parsed.controlPlaneBase ?? "",
      loggingBase: parsed.loggingBase ?? "",
      dashboardAgentId: parsed.dashboardAgentId ?? "dashboard-viewer",
      agentTokenExpiresAt: parsed.agentTokenExpiresAt,
    };
  } catch (error) {
    console.warn("Failed to parse stored settings", error);
    return {
      controlPlaneBase: "",
      loggingBase: "",
      dashboardAgentId: "dashboard-viewer",
      agentTokenExpiresAt: undefined,
    };
  }
}

export function SettingsProvider({ children }: { children: ReactNode }) {
  const [settings, setSettings] = useState<DashboardSettings>(() => {
    if (typeof window === "undefined") {
      return defaultSettings;
    }
    const storage = window.sessionStorage ?? null;
    const persisted = loadSettings(storage);
    return { ...defaultSettings, ...persisted };
  });

  useEffect(() => {
    try {
      if (typeof window === "undefined") {
        return;
      }
      const { adminToken: _admin, agentToken: _agent, ...persistable } = settings;
      window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(persistable));
    } catch (error) {
      console.warn("Failed to persist settings", error);
    }
  }, [settings]);

  const value = useMemo<SettingsContextValue>(() => {
    const updateSettings = (next: Partial<DashboardSettings>) => {
      setSettings((prev) => ({ ...prev, ...next }));
    };

    const clearTokens = () => {
      setSettings((prev) => ({
        ...prev,
        adminToken: "",
        agentToken: "",
        agentTokenExpiresAt: undefined,
      }));
    };

    return { settings, updateSettings, clearTokens };
  }, [settings]);

  return <SettingsContext.Provider value={value}>{children}</SettingsContext.Provider>;
}

export function useSettings(): SettingsContextValue {
  const ctx = useContext(SettingsContext);
  if (!ctx) {
    throw new Error("useSettings must be used within a SettingsProvider");
  }
  return ctx;
}
