import { createContext } from "react";

import type { DashboardSettings } from "../types";

export type SettingsContextValue = {
  settings: DashboardSettings;
  updateSettings: (next: Partial<DashboardSettings>) => void;
  clearTokens: () => void;
};

export const SettingsContext = createContext<SettingsContextValue | undefined>(undefined);
