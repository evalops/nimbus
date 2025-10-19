"""Runner execution framework for Nimbus.

This package provides the abstraction layer that separates how work is executed
(Firecracker, Docker, GPU, etc.) from how work is scheduled (control-plane leases).
"""

from .base import Executor, RunResult
from .firecracker import FirecrackerExecutor

# Registry of all available executors
EXECUTORS = {
    "firecracker": FirecrackerExecutor(),
}

__all__ = ["Executor", "RunResult", "EXECUTORS", "FirecrackerExecutor"]
