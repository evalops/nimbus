"""Metrics utilities for exposing Prometheus-formatted data."""

from __future__ import annotations

import time
from typing import Callable, Dict


class Counter:
    def __init__(self, name: str, description: str = "") -> None:
        self.name = name
        self.description = description
        self._value = 0.0

    def inc(self, amount: float = 1.0) -> None:
        self._value += amount

    def render(self) -> str:
        return f"# HELP {self.name} {self.description}\n# TYPE {self.name} counter\n{self.name} {self._value}\n"


class Gauge:
    def __init__(self, name: str, description: str = "", supplier: Callable[[], float] | None = None) -> None:
        self.name = name
        self.description = description
        self._value = 0.0
        self._supplier = supplier

    def set(self, value: float) -> None:
        self._value = value

    def render(self) -> str:
        value = self._supplier() if self._supplier else self._value
        return f"# HELP {self.name} {self.description}\n# TYPE {self.name} gauge\n{self.name} {value}\n"


class Histogram:
    def __init__(self, name: str, buckets: list[float], description: str = "") -> None:
        self.name = name
        self.description = description
        self._buckets = sorted(buckets)
        self._counts = {b: 0 for b in self._buckets}
        self._sum = 0.0
        self._count = 0

    def observe(self, value: float) -> None:
        self._count += 1
        self._sum += value
        for bucket in self._buckets:
            if value <= bucket:
                self._counts[bucket] += 1
        # +Inf bucket
        self._counts.setdefault(float("inf"), 0)
        self._counts[float("inf")] += 1

    def render(self) -> str:
        lines = [f"# HELP {self.name} {self.description}", f"# TYPE {self.name} histogram"]
        cumulative = 0
        for bucket in self._buckets + [float("inf")]:
            cumulative = self._counts.get(bucket, cumulative)
            bucket_label = bucket if bucket != float("inf") else "+Inf"
            lines.append(f'{self.name}_bucket{{le="{bucket_label}"}} {cumulative}')
        lines.append(f"{self.name}_sum {self._sum}")
        lines.append(f"{self.name}_count {self._count}")
        return "\n".join(lines) + "\n"


class MetricsRegistry:
    def __init__(self) -> None:
        self._metrics: Dict[str, object] = {}

    def register(self, metric: object) -> object:
        self._metrics[getattr(metric, "name")] = metric
        return metric

    def render(self) -> str:
        return "\n".join(metric.render() for metric in self._metrics.values()) + "\n"


GLOBAL_REGISTRY = MetricsRegistry()
