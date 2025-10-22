#!/usr/bin/env python3
"""Generate a Grafana dashboard JSON for tracking Nimbus spot fleet metrics."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


DASHBOARD_TEMPLATE = {
    "title": "Nimbus Spot Fleet",
    "style": "dark",
    "refresh": "30s",
    "panels": [
        {
            "type": "timeseries",
            "title": "Daily Spot Fleet Cost",
            "targets": [
                {
                    "expr": "sum(increase(nimbus_spot_fleet_cost_daily[24h]))",
                    "legendFormat": "{{fleet}}",
                }
            ],
        },
        {
            "type": "timeseries",
            "title": "Active Spot Agents",
            "targets": [
                {
                    "expr": "sum(nimbus_hosts_active{role=\"spot\"})",
                    "legendFormat": "active agents",
                }
            ],
        },
    ],
}


def build_dashboard(title: str) -> dict:
    dashboard = dict(DASHBOARD_TEMPLATE)
    dashboard["title"] = title
    return dashboard


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Grafana dashboard JSON for Nimbus spot fleets")
    parser.add_argument("--title", default="Nimbus Spot Fleet", help="Dashboard title")
    parser.add_argument("--output", default="spot_fleet_dashboard.json", help="Output JSON path")
    args = parser.parse_args()

    dashboard = build_dashboard(args.title)
    Path(args.output).write_text(json.dumps(dashboard, indent=2), encoding="utf-8")
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
