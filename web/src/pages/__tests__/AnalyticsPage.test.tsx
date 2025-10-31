import { afterEach, describe, expect, it, vi } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { MemoryRouter } from 'react-router-dom';
import { render, screen, waitFor } from '@testing-library/react';

import { AnalyticsPage } from '../AnalyticsPage';
import { SettingsContext } from '../../context/settingsContext';
import type { DashboardSettings } from '../../types';

function renderWithSettings(settings: DashboardSettings) {
  const updateSettings = vi.fn();
  const clearTokens = vi.fn();

  return render(
    <SettingsContext.Provider value={{ settings, updateSettings, clearTokens }}>
      <MemoryRouter>
        <AnalyticsPage />
      </MemoryRouter>
    </SettingsContext.Provider>
  );
}

const baseSettings: DashboardSettings = {
  controlPlaneBase: '',
  loggingBase: '',
  adminToken: '',
  agentToken: '',
  dashboardAgentId: 'dashboard-agent',
};

afterEach(() => {
  vi.restoreAllMocks();
});

describe('AnalyticsPage', () => {
  it('prompts for configuration when tokens missing', () => {
    renderWithSettings(baseSettings);

    expect(
      screen.getByText(/Configure control plane URL and admin token in Settings to view analytics/i)
    ).toBeInTheDocument();
  });

  it('renders analytics table when data loads', async () => {
    const payload = [
      { date: '2024-01-01', total: 3, counts: { succeeded: 2, failed: 1 } },
      { date: '2024-01-02', total: 1, counts: { succeeded: 1 } },
    ];

    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(payload), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    );

    renderWithSettings({
      ...baseSettings,
      controlPlaneBase: 'https://cp.test',
      adminToken: 'token',
    });

    await waitFor(() => {
      expect(screen.getByText('2024-01-01')).toBeInTheDocument();
    });
    expect(screen.getByText('3')).toBeInTheDocument();
    expect(screen.getByText('2024-01-02')).toBeInTheDocument();
  });
});
