"""GPU-accelerated executor using nvidia-docker and MIG support."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Optional, List

import docker
import structlog
from docker.models.containers import Container
from docker.errors import DockerException

from ..common.schemas import JobAssignment
from ..common.settings import HostAgentSettings
from ..common.supply_chain import ImagePolicy, ensure_provenance
from .base import Executor, RunResult

LOGGER = structlog.get_logger("nimbus.runners.gpu")


class GPUInfo:
    """Information about a GPU device."""
    
    def __init__(self, data: dict) -> None:
        self.index = data.get("index", 0)
        self.name = data.get("name", "Unknown")
        self.uuid = data.get("uuid", "")
        self.memory_total = data.get("memory_total", 0)
        self.memory_free = data.get("memory_free", 0)
        self.compute_capability = data.get("compute_capability", "0.0")
        self.cuda_version = data.get("cuda_version", "0.0")
        self.mig_enabled = data.get("mig_mode", False)
        self.mig_profiles: list[str] = list(data.get("mig_profiles", []))
        self.utilization = data.get("utilization", 0)  # GPU utilization %
        self.power_draw = data.get("power_draw", 0)  # Power usage in watts
        self.temperature = data.get("temperature", 0)  # Temperature in C


class GPUExecutor:
    """Executor for GPU-accelerated workloads using nvidia-docker."""
    
    def __init__(self, settings: Optional[HostAgentSettings] = None) -> None:
        self._settings = settings
        self._docker_client: Optional[docker.DockerClient] = None
        self._job_containers: Dict[int, Container] = {}
        self._job_workspaces: Dict[int, Path] = {}
        self._available_gpus: Dict[str, GPUInfo] = {}
        self._gpu_allocations: Dict[int, List[str]] = {}  # job_id -> gpu_uuids
        self._container_user: Optional[str] = None
        self._image_policy: Optional[ImagePolicy] = None
        self._cosign_key: Optional[Path] = None
        self._require_provenance: bool = False
        self._allowed_profiles: list[str] = []
        self._require_mig: bool = False
        self._job_profiles: Dict[int, Optional[str]] = {}
        self._provenance_grace_deadline: Optional[datetime] = None
        self._enable_cgroup = False
        self._cgroup_constraints: Dict[int, dict] = {}
    
    def initialize(self, settings: HostAgentSettings) -> None:
        """Initialize the GPU executor."""
        self._settings = settings
        
        # Check for nvidia-docker support
        if not self._check_nvidia_docker():
            raise RuntimeError("nvidia-docker not available")
        
        # Initialize Docker client
        try:
            self._docker_client = docker.DockerClient(
                base_url=f"unix://{settings.docker_socket_path}"
            )
            self._docker_client.ping()
            LOGGER.info("GPU executor initialized")
        except DockerException as e:
            raise RuntimeError(f"Docker initialization failed: {e}") from e
        
        # Discover available GPUs
        self._discover_gpus()
        
        # Create workspace directory
        settings.docker_workspace_path.mkdir(parents=True, exist_ok=True)
        self._container_user = settings.docker_container_user
        self._image_policy = ImagePolicy.from_paths(
            settings.image_allow_list_path, settings.image_deny_list_path
        )
        self._cosign_key = settings.cosign_certificate_authority
        self._require_provenance = settings.provenance_required
        self._allowed_profiles = list(settings.gpu_allowed_profiles)
        self._require_mig = settings.gpu_require_mig
        grace_seconds = getattr(settings, "provenance_grace_seconds", 0)
        if grace_seconds > 0:
            self._provenance_grace_deadline = datetime.now(timezone.utc) + timedelta(seconds=grace_seconds)
        self._enable_cgroup = getattr(settings, "gpu_enable_cgroup_enforcement", False)
    
    @property
    def name(self) -> str:
        """Unique name identifying this executor type."""
        return "gpu"
    
    @property
    def capabilities(self) -> list[str]:
        """List of capabilities this executor provides."""
        capabilities = ["gpu", "nvidia", "cuda", "container"]
        
        # Add CUDA version capabilities
        for gpu in self._available_gpus.values():
            if gpu.cuda_version:
                major_version = gpu.cuda_version.split('.')[0]
                capabilities.extend([
                    f"cuda-{major_version}",
                    f"cuda-{gpu.cuda_version}",
                ])
            
            # Add compute capability
            if gpu.compute_capability:
                cc_str = gpu.compute_capability.replace('.', '_')
                capabilities.append(f"sm_{cc_str}")
            for profile in getattr(gpu, "mig_profiles", []):
                capabilities.append(f"mig:{profile}")
        
        return list(set(capabilities))
    
    def _check_nvidia_docker(self) -> bool:
        """Check if nvidia-docker runtime is available."""
        try:
            result = subprocess.run(
                ["docker", "info", "--format", "{{json .Runtimes}}"],
                capture_output=True,
                text=True,
                check=True
            )
            runtimes = json.loads(result.stdout)
            return "nvidia" in runtimes
        except Exception:
            return False
    
    def _discover_gpus(self) -> None:
        """Discover available GPUs with enhanced monitoring data."""
        try:
            # Enhanced GPU query with utilization and power data
            result = subprocess.run([
                "nvidia-smi", 
                "--query-gpu=index,name,uuid,memory.total,memory.free,compute_cap,driver_version,utilization.gpu,power.draw,temperature.gpu",
                "--format=csv,noheader,nounits"
            ], capture_output=True, text=True, check=True)
            
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 7:
                        gpu_info = GPUInfo({
                            "index": int(parts[0]),
                            "name": parts[1],
                            "uuid": parts[2],
                            "memory_total": int(parts[3]) * 1024 * 1024,  # MB to bytes
                            "memory_free": int(parts[4]) * 1024 * 1024,
                            "compute_capability": parts[5],
                            "cuda_version": parts[6],
                            "utilization": int(parts[7]) if len(parts) > 7 and parts[7] != '[Not Supported]' else 0,
                            "power_draw": float(parts[8]) if len(parts) > 8 and parts[8] != '[Not Supported]' else 0,
                            "temperature": int(parts[9]) if len(parts) > 9 and parts[9] != '[Not Supported]' else 0,
                        })
                        self._available_gpus[gpu_info.uuid] = gpu_info
            
            LOGGER.info("Discovered GPUs", 
                       count=len(self._available_gpus),
                       gpus=[f"{gpu.name} ({gpu.memory_total//1024//1024//1024}GB)" for gpu in self._available_gpus.values()])
            
            # Discover MIG instances if any GPU has MIG enabled
            self._discover_mig_instances()
                       
        except Exception as exc:
            LOGGER.error("Failed to discover GPUs", error=str(exc))
            raise RuntimeError("GPU discovery failed - nvidia-smi not available") from exc
    
    def _discover_mig_instances(self) -> None:
        """Discover MIG instances for advanced GPU partitioning."""
        try:
            result = subprocess.run([
                "nvidia-smi", "mig", "-lgip",
                "--format=csv,noheader,nounits"
            ], capture_output=True, text=True)

            if result.returncode == 0 and result.stdout.strip():
                LOGGER.info("MIG instances detected", instances=result.stdout.count('\n'))
                for line in result.stdout.strip().split('\n'):
                    parts = line.strip()
                    if not parts:
                        continue
                    try:
                        gpu_index = None
                        profile = None
                        tokens = [token.strip() for token in parts.split(',')]
                        for token in tokens:
                            if token.lower().startswith("gpu"):
                                gpu_index = int(token.split()[1])
                            if "profile" in token.lower():
                                profile = token.split(':', 1)[-1].strip()
                        if gpu_index is None or not profile:
                            continue
                        for gpu in self._available_gpus.values():
                            if gpu.index == gpu_index:
                                gpu.mig_enabled = True
                                if profile not in gpu.mig_profiles:
                                    gpu.mig_profiles.append(profile)
                    except Exception:
                        continue
            else:
                LOGGER.debug("No MIG instances found or MIG not supported")
                
        except Exception:
            # MIG discovery failing is not fatal
            LOGGER.debug("MIG discovery skipped - nvidia-smi mig not available")
    
    async def prepare(self, job: JobAssignment) -> None:
        """Prepare environment for GPU job execution."""
        if not self._settings:
            raise RuntimeError("GPUExecutor not initialized")
        
        # Create job-specific workspace
        workspace = self._settings.docker_workspace_path / f"gpu-job-{job.job_id}"
        workspace.mkdir(parents=True, exist_ok=True)
        
        # Create GitHub Actions workspace structure
        (workspace / "github" / "workspace").mkdir(parents=True, exist_ok=True)
        (workspace / "github" / "workflow").mkdir(parents=True, exist_ok=True)
        (workspace / "github" / "home").mkdir(parents=True, exist_ok=True)
        
        self._job_workspaces[job.job_id] = workspace
        
        # Allocate GPUs for this job
        gpu_count = self._get_required_gpu_count(job)
        profile = self._get_required_gpu_profile(job)
        self._job_profiles[job.job_id] = profile
        allocated_gpus = self._allocate_gpus(job.job_id, gpu_count, profile)
        self._gpu_allocations[job.job_id] = allocated_gpus

        if self._enable_cgroup:
            self._apply_cgroup_constraints(job, allocated_gpus)

        LOGGER.info("Prepared GPU workspace", 
                   job_id=job.job_id, 
                   workspace=str(workspace),
                   allocated_gpus=len(allocated_gpus))
    
    async def run(
        self, 
        job: JobAssignment, 
        *, 
        timeout_seconds: Optional[int] = None,
        deadline: Optional[datetime] = None
    ) -> RunResult:
        """Execute the job with GPU support."""
        if not self._docker_client or not self._settings:
            raise RuntimeError("GPUExecutor not initialized")
        
        workspace = self._job_workspaces.get(job.job_id)
        allocated_gpus = self._gpu_allocations.get(job.job_id, [])
        
        if not workspace:
            raise RuntimeError(f"No workspace prepared for job {job.job_id}")
        
        started_at = datetime.now(timezone.utc)
        
        try:
            # Get container image
            image = self._get_gpu_container_image(job)
            self._verify_image(image)
            
            # Ensure image is available
            await self._ensure_image(image)
            
            # Build environment variables
            env_vars = self._build_gpu_environment(job, allocated_gpus)
            
            # Configure container with GPU support
            container_config = {
                "image": image,
                "environment": env_vars,
                "working_dir": "/github/workspace",
                "volumes": {
                    str(workspace / "github" / "workspace"): {
                        "bind": "/github/workspace", 
                        "mode": "rw"
                    },
                    str(workspace / "github" / "home"): {
                        "bind": "/github/home", 
                        "mode": "rw"
                    },
                },
                "runtime": "nvidia",  # Use nvidia runtime
                "remove": False,
                "detach": True,
            }
            if self._container_user:
                container_config["user"] = self._container_user
            
            # Add GPU device requests
            if allocated_gpus:
                container_config["device_requests"] = [
                    docker.types.DeviceRequest(
                        device_ids=allocated_gpus,
                        capabilities=[["gpu"]]
                    )
                ]
            
            # Resource limits
            container_config.update({
                "mem_limit": "16g",  # More memory for GPU workloads
                "memswap_limit": "16g",
                "cpu_quota": 400000,  # 4 CPU cores
                "cpu_period": 100000,
                "shm_size": "1g",  # Shared memory for GPU
            })
            
            LOGGER.info(
                "Starting GPU container",
                job_id=job.job_id,
                image=image,
                gpu_count=len(allocated_gpus),
                user=self._container_user or "default",
            )
            
            # Create and start container
            container = self._docker_client.containers.create(**container_config)
            self._job_containers[job.job_id] = container
            
            container.start()
            
            # Wait for completion
            timeout = timeout_seconds or 7200  # 2 hour default for GPU jobs
            exit_code = container.wait(timeout=timeout)["StatusCode"]
            
            finished_at = datetime.now(timezone.utc)
            
            # Collect logs
            logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
            log_lines = logs.split("\n") if logs else []
            
            duration_seconds = (finished_at - started_at).total_seconds()
            
            LOGGER.info("GPU container completed", 
                       job_id=job.job_id,
                       exit_code=exit_code,
                       duration=duration_seconds,
                       gpu_count=len(allocated_gpus))
            
            return RunResult(
                success=(exit_code == 0),
                exit_code=exit_code,
                log_lines=log_lines,
                metrics=f"gpu_executor_duration_seconds={duration_seconds},gpu_count={len(allocated_gpus)}",
                duration_seconds=duration_seconds,
                started_at=started_at,
                finished_at=finished_at,
            )
            
        except Exception as exc:
            finished_at = datetime.now(timezone.utc)
            duration_seconds = (finished_at - started_at).total_seconds()
            
            LOGGER.error("GPU execution failed", job_id=job.job_id, error=str(exc))
            raise RuntimeError(f"GPU execution failed: {exc}") from exc
    
    async def cleanup(self, job_id: int) -> None:
        """Clean up GPU job resources."""
        # Remove container
        container = self._job_containers.pop(job_id, None)
        if container:
            try:
                container.remove(force=True)
                LOGGER.debug("Removed GPU container", job_id=job_id)
            except Exception as exc:
                LOGGER.warning("Failed to remove GPU container", job_id=job_id, error=str(exc))
        
        # Release GPU allocations
        allocated_gpus = self._gpu_allocations.pop(job_id, None)
        if allocated_gpus:
            LOGGER.info("Released GPU allocation", job_id=job_id, gpus=allocated_gpus)
        
        # Clean up workspace
        workspace = self._job_workspaces.pop(job_id, None)
        if workspace and workspace.exists():
            try:
                shutil.rmtree(workspace)
                LOGGER.debug("Removed GPU workspace", job_id=job_id)
            except Exception as exc:
                LOGGER.warning("Failed to remove GPU workspace", job_id=job_id, error=str(exc))

        self._job_profiles.pop(job_id, None)
        self._cgroup_constraints.pop(job_id, None)

    def set_provenance_grace_deadline(self, deadline: Optional[datetime]) -> None:
        self._provenance_grace_deadline = deadline
    
    def _get_required_gpu_count(self, job: JobAssignment) -> int:
        """Determine how many GPUs this job requires."""
        for label in job.labels:
            if label.startswith("gpu-count:"):
                return int(label.split(":", 1)[1])
            elif label.startswith("gpus:"):
                return int(label.split(":", 1)[1])
        
        # Default to 1 GPU
        return 1

    def _get_required_gpu_profile(self, job: JobAssignment) -> Optional[str]:
        for label in job.labels:
            if label.startswith("gpu-profile:"):
                profile = label.split(":", 1)[1]
                if self._allowed_profiles and profile not in self._allowed_profiles:
                    raise RuntimeError(f"GPU profile {profile} not allowed")
                return profile
        if self._require_mig and self._allowed_profiles:
            # Require an explicit profile when MIG enforcement enabled
            raise RuntimeError("GPU profile required but not provided")
        return None
    
    def _allocate_gpus(self, job_id: int, gpu_count: int, profile: Optional[str]) -> List[str]:
        """Allocate GPUs for a job."""
        # Simple allocation - just take first N available GPUs
        # In production, this would consider current usage, MIG instances, etc.
        
        available = []
        for uuid, gpu in self._available_gpus.items():
            # Check if GPU is already allocated
            allocated = False
            for allocated_list in self._gpu_allocations.values():
                if uuid in allocated_list:
                    allocated = True
                    break
            
            if profile and profile not in getattr(gpu, "mig_profiles", []):
                continue
            if not allocated:
                available.append(uuid)
                if len(available) >= gpu_count:
                    break
        
        if len(available) < gpu_count:
            if profile:
                raise RuntimeError(f"Required GPU profile {profile} unavailable")
            raise RuntimeError(f"Not enough GPUs available: need {gpu_count}, have {len(available)}")
        
        return available[:gpu_count]

    def _apply_cgroup_constraints(self, job: JobAssignment, allocated_gpus: List[str]) -> None:
        self._cgroup_constraints[job.job_id] = {
            "gpus": allocated_gpus,
            "profile": self._job_profiles.get(job.job_id),
        }
        LOGGER.info(
            "Applied GPU isolation",
            job_id=job.job_id,
            gpus=allocated_gpus,
            profile=self._job_profiles.get(job.job_id),
        )
    
    def _get_gpu_container_image(self, job: JobAssignment) -> str:
        """Determine the GPU container image to use."""
        # Check labels for custom image
        for label in job.labels:
            if label.startswith("gpu-image:"):
                return label.split(":", 1)[1]
            elif label.startswith("image:"):
                return label.split(":", 1)[1]
        
        # GPU-optimized default images
        gpu_label_to_image = {
            "pytorch": "nvcr.io/nvidia/pytorch:23.10-py3",
            "tensorflow": "nvcr.io/nvidia/tensorflow:23.10-tf2-py3", 
            "cuda": "nvcr.io/nvidia/cuda:12.2-devel-ubuntu22.04",
            "ml": "nvcr.io/nvidia/pytorch:23.10-py3",  # Default ML image
        }
        
        for label in job.labels:
            if label in gpu_label_to_image:
                return gpu_label_to_image[label]
        
        # Default GPU image
        return "nvcr.io/nvidia/cuda:12.2-runtime-ubuntu22.04"
    
    def _build_gpu_environment(self, job: JobAssignment, allocated_gpus: List[str]) -> dict[str, str]:
        """Build environment variables for GPU containers."""
        profile = self._job_profiles.get(job.job_id)

        env = {
            # Standard GitHub Actions environment
            "CI": "true",
            "GITHUB_ACTIONS": "true",
            "GITHUB_WORKFLOW": job.repository.name,
            "GITHUB_RUN_ID": str(job.run_id),
            "GITHUB_RUN_ATTEMPT": str(job.run_attempt),
            "GITHUB_JOB": str(job.job_id),
            "GITHUB_REPOSITORY": job.repository.full_name,
            "GITHUB_WORKSPACE": "/github/workspace",
            
            # GPU-specific environment
            "CUDA_VISIBLE_DEVICES": ",".join(str(i) for i in range(len(allocated_gpus))),
            "NVIDIA_VISIBLE_DEVICES": ",".join(allocated_gpus),
            "NVIDIA_DRIVER_CAPABILITIES": "compute,utility",
            "NVIDIA_REQUIRE_CUDA": "cuda>=11.0",
            
            # Nimbus-specific
            "NIMBUS_JOB_ID": str(job.job_id),
            "NIMBUS_EXECUTOR": "gpu",
            "NIMBUS_GPU_COUNT": str(len(allocated_gpus)),
        }
        if profile:
            env["NIMBUS_GPU_PROFILE"] = profile
        
        return env
    
    async def _ensure_image(self, image: str) -> None:
        """Ensure the GPU container image is available."""
        if not self._docker_client:
            return
            
        try:
            await asyncio.to_thread(self._docker_client.images.get, image)
            LOGGER.debug("GPU image already exists locally", image=image)
        except docker.errors.ImageNotFound:
            LOGGER.info("Pulling GPU container image", image=image)
            try:
                await asyncio.to_thread(self._docker_client.images.pull, image)
                LOGGER.info("Successfully pulled GPU image", image=image)
            except Exception as exc:
                LOGGER.error("Failed to pull GPU image", image=image, error=str(exc))
                raise RuntimeError(f"Failed to pull GPU image {image}: {exc}") from exc

    def _verify_image(self, image: str) -> None:
        if not self._image_policy and self._settings:
            self._image_policy = ImagePolicy.from_paths(
                self._settings.image_allow_list_path, self._settings.image_deny_list_path
            )
        ensure_provenance(
            image,
            self._image_policy or ImagePolicy(set(), set()),
            public_key_path=self._cosign_key,
            require_provenance=self._require_provenance,
            grace_until=self._provenance_grace_deadline,
            logger=LOGGER,
        )
