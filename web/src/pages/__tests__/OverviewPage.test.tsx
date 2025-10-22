import { describe, expect, it } from 'vitest';
import '@testing-library/jest-dom/vitest';
import { MemoryRouter } from 'react-router-dom';
import { render, screen } from '@testing-library/react';

import { CacheCard, ResourceTable } from '../OverviewPage';
import type { CachePerformanceSummary, ResourceHighlight } from '../../types';

describe('CacheCard', () => {
  it('renders cache metrics', () => {
    const summary: CachePerformanceSummary = {
      hit_ratio: 0.82,
      total_hits: 120,
      total_misses: 30,
      total_bytes: 1024,
    };

    render(
      <MemoryRouter>
        <CacheCard title="Artifact Cache" summary={summary} />
      </MemoryRouter>
    );

    expect(screen.getByText('Artifact Cache')).toBeInTheDocument();
    expect(screen.getByText('82.0%')).toBeInTheDocument();
    expect(screen.getByText('120')).toBeInTheDocument();
    expect(screen.getByText((content) => content.includes('Hits (80%)'))).toBeInTheDocument();
  });

  it('shows empty state when summary missing', () => {
    render(
      <MemoryRouter>
        <CacheCard title="Docker Cache" summary={undefined} />
      </MemoryRouter>
    );

    expect(screen.getByText('No cache data available.')).toBeInTheDocument();
  });
});

describe('ResourceTable', () => {
  it('renders resource highlights', () => {
    const highlights: ResourceHighlight[] = [
      {
        job_id: 7,
        repo_full_name: 'acme/repo',
        status: 'succeeded',
        value: 12.5,
      },
    ];

    render(
      <MemoryRouter>
        <ResourceTable title="Top CPU" unit="seconds" highlights={highlights} />
      </MemoryRouter>
    );

    expect(screen.getByText('#7')).toBeInTheDocument();
    expect(screen.getByText('acme/repo')).toBeInTheDocument();
    expect(screen.getByText('12.50 s')).toBeInTheDocument();
  });

  it('shows empty state when highlights missing', () => {
    render(
      <MemoryRouter>
        <ResourceTable title="Top Memory" unit="bytes" highlights={[]} />
      </MemoryRouter>
    );

    expect(screen.getByText('No recent jobs recorded.')).toBeInTheDocument();
  });
});
