import { useMemo } from "react";

import type { OrgStatusSummary } from "../types";

export function useObservabilityMetrics(orgs: OrgStatusSummary[]) {
  return useMemo(() => {
    const failureLeaders = [...orgs]
      .map((org) => {
        const statusCounts = org.status_counts || {};
        const failureTotal = (statusCounts.failed ?? 0) + (statusCounts.cancelled ?? 0);
        const total = Object.values(statusCounts).reduce((acc, value) => acc + value, 0);
        const rate = total > 0 ? failureTotal / total : 0;
        return {
          orgId: org.org_id,
          rate,
        };
      })
      .sort((a, b) => b.rate - a.rate)
      .slice(0, 5);

    const agentActivity = [...orgs]
      .map((org) => ({ orgId: org.org_id, count: org.active_agents.length }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    const failureMap = new Map<number, Array<{ jobId: number; repo: string; updatedAt: string; message: string }>>();
    for (const org of orgs) {
      const entries = org.recent_failures.map((job) => ({
        jobId: job.job_id,
        repo: job.repo_full_name,
        updatedAt: job.updated_at,
        message: job.last_message ?? "",
      }));
      failureMap.set(org.org_id, entries);
    }

    return {
      failureLeaders,
      agentActivity,
      failureMap,
    };
  }, [orgs]);
}
