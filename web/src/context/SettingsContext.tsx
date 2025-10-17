import { useMemo, useState, type ReactNode } from "react";

import type { DashboardSettings } from "../types";
import { clearSettings, loadSettings, persistSettings } from "../utils/settings";
import { SettingsContext, type SettingsContextValue } from "./settingsContext";

export function SettingsProvider({ children }: { children: ReactNode }) {
  const [settings, setSettings] = useState<DashboardSettings>(() => loadSettings());

  const value = useMemo<SettingsContextValue>(() => {
    const updateSettings = (next: Partial<DashboardSettings>) => {
      setSettings((prev) => {
        const updated = { ...prev, ...next };
        persistSettings(updated);
        return updated;
      });
    };

    const clearTokens = () => {
      const cleared = clearSettings();
      setSettings(cleared);
    };

    return { settings, updateSettings, clearTokens };
  }, [settings]);

  return <SettingsContext.Provider value={value}>{children}</SettingsContext.Provider>;
}

