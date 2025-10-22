#!/usr/bin/env python3
"""Nimbus vs GitHub Actions ROI calculator."""

from __future__ import annotations

import argparse
import csv
import math
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class WorkloadInputs:
    runs_per_day: float
    avg_runtime_mins: float
    gh_minute_cost: float
    nimbus_minute_cost: float
    hardware_cost_per_hour: float
    gh_queue_latency_mins: float
    nimbus_queue_latency_mins: float


@dataclass
class RoiResult:
    gh_monthly_cost: float
    nimbus_monthly_cost: float
    annual_savings: float
    time_saved_per_eval_mins: float
    breakeven_runs_per_day: Optional[float]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Nimbus ROI calculator")
    parser.add_argument("--config", type=Path, help="YAML file with defaults", default=None)
    parser.add_argument("--runs-per-day", type=float, help="Evaluations per day")
    parser.add_argument("--avg-runtime-mins", type=float, help="Average eval runtime in minutes")
    parser.add_argument("--gh-minute-cost", type=float, help="GitHub Actions cost per compute minute", default=0.008)
    parser.add_argument("--nimbus-minute-cost", type=float, help="Nimbus compute cost per minute", default=0.0025)
    parser.add_argument("--hardware-cost-per-hour", type=float, help="Self-hosted hardware $/hour", default=4.0)
    parser.add_argument("--gh-queue-latency-mins", type=float, default=5, help="Average GH Actions queue latency per eval")
    parser.add_argument("--nimbus-queue-latency-mins", type=float, default=1, help="Average Nimbus queue latency")
    parser.add_argument("--csv", type=Path, help="Optional CSV output destination")
    return parser.parse_args()


def load_config(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def build_inputs(args: argparse.Namespace) -> WorkloadInputs:
    data = {}
    if args.config:
        data.update(load_config(args.config))

    def pick(key: str, fallback):
        cli_value = getattr(args, key)
        return cli_value if cli_value is not None else data.get(key, fallback)

    return WorkloadInputs(
        runs_per_day=pick("runs_per_day", args.runs_per_day),
        avg_runtime_mins=pick("avg_runtime_mins", args.avg_runtime_mins),
        gh_minute_cost=pick("gh_minute_cost", args.gh_minute_cost),
        nimbus_minute_cost=pick("nimbus_minute_cost", args.nimbus_minute_cost),
        hardware_cost_per_hour=pick("hardware_cost_per_hour", args.hardware_cost_per_hour),
        gh_queue_latency_mins=pick("gh_queue_latency_mins", args.gh_queue_latency_mins),
        nimbus_queue_latency_mins=pick("nimbus_queue_latency_mins", args.nimbus_queue_latency_mins),
    )


def calculate(inputs: WorkloadInputs) -> RoiResult:
    minutes_per_day = inputs.runs_per_day * inputs.avg_runtime_mins
    gh_daily_cost = minutes_per_day * inputs.gh_minute_cost
    gh_monthly_cost = gh_daily_cost * 30

    nimbus_compute_daily = minutes_per_day * inputs.nimbus_minute_cost
    nimbus_hardware_daily = (minutes_per_day / 60) * inputs.hardware_cost_per_hour
    nimbus_monthly_cost = (nimbus_compute_daily + nimbus_hardware_daily) * 30

    annual_savings = (gh_monthly_cost - nimbus_monthly_cost) * 12

    time_saved_per_eval = max(inputs.gh_queue_latency_mins - inputs.nimbus_queue_latency_mins, 0)

    gh_per_eval = inputs.avg_runtime_mins * inputs.gh_minute_cost
    nimbus_per_eval = inputs.avg_runtime_mins * inputs.nimbus_minute_cost + (
        inputs.avg_runtime_mins / 60 * inputs.hardware_cost_per_hour
    )
    if gh_per_eval == nimbus_per_eval:
        breakeven = None
    elif nimbus_per_eval > gh_per_eval:
        breakeven = math.inf
    else:
        breakeven = 0

    return RoiResult(
        gh_monthly_cost=gh_monthly_cost,
        nimbus_monthly_cost=nimbus_monthly_cost,
        annual_savings=annual_savings,
        time_saved_per_eval_mins=time_saved_per_eval,
        breakeven_runs_per_day=breakeven,
    )


def emit_console(result: RoiResult) -> None:
    print("=== Nimbus ROI Summary ===")
    print(f"GitHub Actions monthly cost    : ${result.gh_monthly_cost:,.2f}")
    print(f"Nimbus monthly cost            : ${result.nimbus_monthly_cost:,.2f}")
    delta = result.gh_monthly_cost - result.nimbus_monthly_cost
    print(f"Monthly savings                : ${delta:,.2f}")
    print(f"Annual savings                 : ${result.annual_savings:,.2f}")
    print(f"Time saved per eval            : {result.time_saved_per_eval_mins:.1f} minutes")
    if result.breakeven_runs_per_day is None:
        print("Breakeven                       : equal cost per eval")
    elif math.isinf(result.breakeven_runs_per_day):
        print("Breakeven                       : Nimbus more expensive per eval (adjust inputs)")
    else:
        print(f"Breakeven runs/day              : {result.breakeven_runs_per_day:.1f}")


def emit_csv(path: Path, inputs: WorkloadInputs, result: RoiResult) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["metric", "value"])
        writer.writerow(["runs_per_day", inputs.runs_per_day])
        writer.writerow(["avg_runtime_mins", inputs.avg_runtime_mins])
        writer.writerow(["gh_monthly_cost", result.gh_monthly_cost])
        writer.writerow(["nimbus_monthly_cost", result.nimbus_monthly_cost])
        writer.writerow(["annual_savings", result.annual_savings])
        writer.writerow(["time_saved_per_eval_mins", result.time_saved_per_eval_mins])
        writer.writerow(["breakeven_runs_per_day", result.breakeven_runs_per_day])


def main() -> None:
    args = parse_args()
    inputs = build_inputs(args)
    result = calculate(inputs)
    emit_console(result)
    if args.csv:
        emit_csv(args.csv, inputs, result)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:  # pragma: no cover
        sys.exit(1)
