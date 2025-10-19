"""Runner execution framework for Nimbus.

This package provides the abstraction layer that separates how work is executed
(Firecracker, Docker, GPU, etc.) from how work is scheduled (control-plane leases).
"""

from .base import Executor, RunResult
from .firecracker import FirecrackerExecutor
from .docker import DockerExecutor

# Optional GPU executor (only if nvidia-docker is available)
try:
    from .gpu import GPUExecutor
    _gpu_executor = GPUExecutor()
except (ImportError, RuntimeError):
    _gpu_executor = None

# Registry of all available executors
EXECUTORS = {
    "firecracker": FirecrackerExecutor(),
    "docker": DockerExecutor(),
}

if _gpu_executor:
    EXECUTORS["gpu"] = _gpu_executor

__all__ = ["Executor", "RunResult", "EXECUTORS", "FirecrackerExecutor", "DockerExecutor"]
if _gpu_executor:
    __all__.append("GPUExecutor")
