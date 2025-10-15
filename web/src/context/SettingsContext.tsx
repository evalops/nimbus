import { createContext, useContext, useMemo, useState, type ReactNode } from "react";

import type { DashboardSettings } from "../types";

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

export function SettingsProvider({ children }: { children: ReactNode }) {
  const [settings, setSettings] = useState<DashboardSettings>(defaultSettings);

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
