import { describe, expect, it } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

import '@testing-library/jest-dom/vitest';

import { ToolsPage } from '../ToolsPage';

describe('ToolsPage', () => {
  it('renders ROI default results', () => {
    render(
      <MemoryRouter>
        <ToolsPage />
      </MemoryRouter>
    );

    expect(screen.getByText('Tools & ROI')).toBeInTheDocument();
    expect(screen.getByText(/GitHub Actions monthly cost/i)).toBeInTheDocument();
    expect(screen.getByRole('img', { name: /Monthly cost comparison/i })).toBeInTheDocument();
    expect(screen.getByText(/Download CSV/i)).toBeInTheDocument();
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
});
