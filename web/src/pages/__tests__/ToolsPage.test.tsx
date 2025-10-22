import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

import '@testing-library/jest-dom/vitest';

import { ToolsPage } from '../ToolsPage';

const mockControlGet = vi.fn().mockResolvedValue({
  window_hours: 24,
  inputs: {
    runs_per_day: 100,
    avg_runtime_mins: 10,
    gh_minute_cost: 0.008,
    nimbus_minute_cost: 0.0025,
    hardware_cost_per_hour: 4,
    gh_queue_latency_mins: 5,
    nimbus_queue_latency_mins: 1,
  },
  results: {
    gh_monthly_cost: 240,
    nimbus_monthly_cost: 180,
    annual_savings: 720,
    time_saved_per_eval_mins: 4,
  },
});

vi.mock('../../hooks/useApi', () => ({
  useApi: () => ({ controlGet: mockControlGet }),
}));

beforeEach(() => {
  mockControlGet.mockClear();
});

describe('ToolsPage', () => {
  it('renders ROI default results', async () => {
    render(
      <MemoryRouter>
        <ToolsPage />
      </MemoryRouter>
    );

    expect(screen.getByText('Tools & ROI')).toBeInTheDocument();
    expect(screen.getByText(/GitHub Actions monthly cost/i)).toBeInTheDocument();
    expect(await screen.findByText(/Observed \(last 24h\)/i)).toBeInTheDocument();
    expect(screen.getByRole('img', { name: /Monthly cost comparison/i })).toBeInTheDocument();
    expect(screen.getByText(/Download CSV/i)).toBeInTheDocument();
    expect(screen.getByText(/terraform autoscaling snippet/i)).toBeInTheDocument();
    expect(screen.getByText(/agent_desired_capacity/)).toBeInTheDocument();
  });

  it('updates calculations when inputs change', () => {
    render(
      <MemoryRouter>
        <ToolsPage />
      </MemoryRouter>
    );

    const runsInput = screen.getAllByLabelText('Runs per day')[0];
    fireEvent.change(runsInput, { target: { value: '50' } });
    expect(screen.getByText('$144.00', { exact: false })).toBeInTheDocument();
  });

  it('adopts observed snapshot when requested', async () => {
    render(
      <MemoryRouter>
        <ToolsPage />
      </MemoryRouter>
    );

    await screen.findAllByText(/Observed \(last 24h\)/i);
    const adoptButton = screen.getAllByRole('button', { name: /Use these inputs/i })[0];
    fireEvent.click(adoptButton);

    const runsInput = screen.getAllByLabelText('Runs per day')[0] as HTMLInputElement;
    expect(runsInput.value).toBe('100');
  });
});
