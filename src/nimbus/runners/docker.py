"""Docker-based executor implementation."""

from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import docker
import structlog
from docker.models.containers import Container
from docker.errors import DockerException, APIError

from ..common.schemas import JobAssignment
from ..common.settings import HostAgentSettings
from ..common.networking import (
    MetadataEndpointDenylist,
    EgressPolicyPack,
    OfflineEgressEnforcer,
)
from .base import Executor, RunResult

LOGGER = structlog.get_logger("nimbus.runners.docker")


class DockerExecutor:
    """Executor that runs jobs in Docker containers."""
    
    def __init__(self, settings: Optional[HostAgentSettings] = None) -> None:
        self._settings = settings
        self._docker_client: Optional[docker.DockerClient] = None
        self._job_containers: dict[int, Container] = {}
        self._job_workspaces: dict[int, Path] = {}
        self._egress_enforcer: Optional[OfflineEgressEnforcer] = None
        self._container_user: Optional[str] = None
    
    def initialize(self, settings: HostAgentSettings) -> None:
        """Initialize the executor with settings."""
        self._settings = settings
        try:
            self._docker_client = docker.DockerClient(
                base_url=f"unix://{settings.docker_socket_path}"
            )
            # Test connection
            self._docker_client.ping()
            LOGGER.info("Docker client initialized", socket=settings.docker_socket_path)
        except (DockerException, Exception) as e:
            LOGGER.error("Failed to initialize Docker client", error=str(e))
            raise RuntimeError(f"Docker initialization failed: {e}") from e
        
        # Ensure Docker network exists
        self._ensure_network()
        
        # Create workspace directory
        settings.docker_workspace_path.mkdir(parents=True, exist_ok=True)
        self._container_user = settings.docker_container_user
        
        # Initialize egress enforcer (similar to HostAgent)
        metadata_denylist = MetadataEndpointDenylist(settings.metadata_endpoint_denylist)
        policy_pack = EgressPolicyPack.from_file(settings.egress_policy_pack)
        allowed_registries = list(settings.artifact_registry_allow_list)
        self._egress_enforcer = OfflineEgressEnforcer(
            offline_mode=settings.offline_mode,
            metadata_denylist=metadata_denylist,
            policy_pack=policy_pack,
            allowed_registries=allowed_registries,
        )
    
    @property
    def name(self) -> str:
        """Unique name identifying this executor type."""
        return "docker"
    
    @property
    def capabilities(self) -> list[str]:
        """List of capabilities this executor provides."""
        return ["docker", "container", "fast-start"]
    
    def _ensure_network(self) -> None:
        """Ensure the Docker network exists for job isolation."""
        if not self._docker_client:
            return
            
        try:
            network = self._docker_client.networks.get(self._settings.docker_network_name)
            LOGGER.debug("Using existing Docker network", name=self._settings.docker_network_name)
        except docker.errors.NotFound:
            LOGGER.info("Creating Docker network", name=self._settings.docker_network_name)
            network = self._docker_client.networks.create(
                name=self._settings.docker_network_name,
                driver="bridge",
                options={
                    "com.docker.network.bridge.enable_icc": "true",
                    "com.docker.network.bridge.enable_ip_masquerade": "true",
                },
            )
    
    async def prepare(self, job: JobAssignment) -> None:
        """Prepare environment for job execution (workspace setup)."""
        if not self._settings:
            raise RuntimeError("DockerExecutor not initialized")
        
        # Create job-specific workspace
        workspace = self._settings.docker_workspace_path / f"job-{job.job_id}"
        workspace.mkdir(parents=True, exist_ok=True)
        
        # Create standard GitHub Actions workspace structure
        (workspace / "github" / "workspace").mkdir(parents=True, exist_ok=True)
        (workspace / "github" / "workflow").mkdir(parents=True, exist_ok=True)
        (workspace / "github" / "home").mkdir(parents=True, exist_ok=True)
        
        self._job_workspaces[job.job_id] = workspace
        
        LOGGER.info("Prepared Docker workspace", job_id=job.job_id, workspace=str(workspace))
    
    async def run(
        self, 
        job: JobAssignment, 
        *, 
        timeout_seconds: Optional[int] = None,
        deadline: Optional[datetime] = None
    ) -> RunResult:
        """Execute the job and return the result."""
        if not self._docker_client or not self._settings:
            raise RuntimeError("DockerExecutor not initialized")
        
        workspace = self._job_workspaces.get(job.job_id)
        if not workspace:
            raise RuntimeError(f"No workspace prepared for job {job.job_id}")
        
        started_at = datetime.now(timezone.utc)
        
        try:
            # Determine container image
            image = self._get_container_image(job)
            
            # Pull image if not present locally (for better performance)
            await self._ensure_image(image)
            
            # Build environment variables
            env_vars = self._build_environment(job)
            
            # Configure container
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
                "network": self._settings.docker_network_name,
                "remove": False,  # We'll remove it ourselves for proper cleanup
                "detach": True,
            }
            if self._container_user:
                container_config["user"] = self._container_user
            
            # Add resource limits
            container_config.update({
                "mem_limit": "4g",
                "memswap_limit": "4g", 
                "cpu_quota": 200000,  # 2 CPU cores
                "cpu_period": 100000,
            })
            
            # Add security options
            container_config.update({
                "cap_drop": ["ALL"],  # Drop all capabilities
                "cap_add": ["CHOWN", "DAC_OVERRIDE", "SETGID", "SETUID"],  # Add minimal needed caps
                "security_opt": ["no-new-privileges:true"],
                "read_only": False,  # GitHub Actions needs write access
            })
            
            LOGGER.info(
                "Starting container",
                job_id=job.job_id,
                image=image,
                user=self._container_user or "default",
            )
            
            # Create and start container
            container = self._docker_client.containers.create(**container_config)
            self._job_containers[job.job_id] = container
            
            container.start()
            
            # Wait for completion with timeout
            timeout = timeout_seconds or 3600  # 1 hour default
            exit_code = container.wait(timeout=timeout)["StatusCode"]
            
            finished_at = datetime.now(timezone.utc)
            
            # Collect logs
            logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
            log_lines = logs.split("\n") if logs else []
            
            duration_seconds = (finished_at - started_at).total_seconds()
            
            LOGGER.info("Container completed", 
                       job_id=job.job_id, 
                       exit_code=exit_code, 
                       duration=duration_seconds)
            
            return RunResult(
                success=(exit_code == 0),
                exit_code=exit_code,
                log_lines=log_lines,
                metrics=f"docker_executor_duration_seconds={duration_seconds}",
                duration_seconds=duration_seconds,
                started_at=started_at,
                finished_at=finished_at,
            )
            
        except docker.errors.ContainerError as exc:
            finished_at = datetime.now(timezone.utc)
            duration_seconds = (finished_at - started_at).total_seconds()
            
            LOGGER.error("Container execution failed", job_id=job.job_id, error=str(exc))
            
            return RunResult(
                success=False,
                exit_code=exc.exit_status,
                log_lines=[str(exc)],
                metrics=f"docker_executor_duration_seconds={duration_seconds}",
                duration_seconds=duration_seconds,
                started_at=started_at,
                finished_at=finished_at,
            )
            
        except Exception as exc:
            finished_at = datetime.now(timezone.utc)
            duration_seconds = (finished_at - started_at).total_seconds()
            
            LOGGER.exception("Docker execution failed", job_id=job.job_id)
            
            # Try to get logs from container if it exists
            log_lines = [str(exc)]
            container = self._job_containers.get(job.job_id)
            if container:
                try:
                    logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
                    if logs:
                        log_lines = logs.split("\n")
                except Exception:
                    pass
            
            raise RuntimeError(f"Docker execution failed: {exc}") from exc
    
    async def _ensure_image(self, image: str) -> None:
        """Ensure the container image is available locally."""
        if not self._docker_client:
            return
            
        try:
            # Check if image exists locally
            await asyncio.to_thread(self._docker_client.images.get, image)
            LOGGER.debug("Image already exists locally", image=image)
        except docker.errors.ImageNotFound:
            LOGGER.info("Pulling container image", image=image)
            try:
                # Pull the image
                await asyncio.to_thread(self._docker_client.images.pull, image)
                LOGGER.info("Successfully pulled image", image=image)
            except Exception as exc:
                LOGGER.error("Failed to pull image", image=image, error=str(exc))
                raise RuntimeError(f"Failed to pull image {image}: {exc}") from exc
    
    async def prepare_warm_instance(self, instance_id: str) -> dict:
        """Prepare a warm Docker instance (primarily pre-pulled images)."""
        if not self._docker_client:
            raise RuntimeError("DockerExecutor not initialized")
        
        # For Docker, warm instances primarily mean pre-pulled common images
        common_images = [
            "ubuntu:22.04",
            "ubuntu:20.04", 
            "node:18-alpine",
            "python:3.11-slim",
            "golang:1.21-alpine"
        ]
        
        pulled_images = []
        for image in common_images:
            try:
                await self._ensure_image(image)
                pulled_images.append(image)
            except Exception as exc:
                LOGGER.warning("Failed to pre-pull image", image=image, error=str(exc))
        
        context = {
            "instance_id": instance_id,
            "pulled_images": pulled_images,
            "prepared_at": datetime.now(timezone.utc).isoformat(),
        }
        
        LOGGER.info("Prepared warm Docker instance", 
                   instance_id=instance_id,
                   pre_pulled_images=len(pulled_images))
        
        return context
    
    async def cleanup_warm_instance(self, instance_id: str, context: dict) -> None:
        """Clean up warm Docker instance (no-op since images can be shared)."""
        # For Docker warm instances, we don't need to clean up anything
        # Pre-pulled images can be shared across instances
        LOGGER.debug("Docker warm instance cleanup (no-op)", instance_id=instance_id)
    
    async def health_check_warm_instance(self, instance_id: str, context: dict) -> bool:
        """Health check for warm Docker instance."""
        if not self._docker_client:
            return False
        
        try:
            # Check that Docker daemon is still responsive
            self._docker_client.ping()
            
            # Verify some pre-pulled images are still available
            pulled_images = context.get("pulled_images", [])
            available_count = 0
            
            for image in pulled_images[:3]:  # Check first 3 images
                try:
                    self._docker_client.images.get(image)
                    available_count += 1
                except Exception:
                    pass
            
            # Consider healthy if Docker responds and at least 1 image available
            is_healthy = available_count > 0
            
            if not is_healthy:
                LOGGER.warning("Docker warm instance unhealthy", 
                              instance_id=instance_id,
                              available_images=available_count)
            
            return is_healthy
            
        except Exception as exc:
            LOGGER.warning("Docker health check failed", 
                          instance_id=instance_id,
                          error=str(exc))
            return False
    
    async def cleanup(self, job_id: int) -> None:
        """Clean up resources associated with a job."""
        # Remove container
        container = self._job_containers.pop(job_id, None)
        if container:
            try:
                container.remove(force=True)
                LOGGER.debug("Removed container", job_id=job_id)
            except Exception as exc:
                LOGGER.warning("Failed to remove container", job_id=job_id, error=str(exc))
        
        # Clean up workspace
        workspace = self._job_workspaces.pop(job_id, None)
        if workspace and workspace.exists():
            try:
                shutil.rmtree(workspace)
                LOGGER.debug("Removed workspace", job_id=job_id, workspace=str(workspace))
            except Exception as exc:
                LOGGER.warning("Failed to remove workspace", job_id=job_id, error=str(exc))
    
    def _get_container_image(self, job: JobAssignment) -> str:
        """Determine the container image to use for this job."""
        # Check job labels for custom image specification
        for label in job.labels:
            if label.startswith("image:"):
                image = label.split(":", 1)[1]
                LOGGER.info("Using custom image from label", job_id=job.job_id, image=image)
                return image
        
        # Map common labels to optimized images
        label_to_image = {
            "ubuntu-latest": "ubuntu:22.04",
            "ubuntu-22.04": "ubuntu:22.04", 
            "ubuntu-20.04": "ubuntu:20.04",
            "node": "node:18-alpine",
            "python": "python:3.11-slim",
            "golang": "golang:1.21-alpine",
        }
        
        for label in job.labels:
            if label in label_to_image:
                image = label_to_image[label]
                LOGGER.info("Using mapped image for label", job_id=job.job_id, label=label, image=image)
                return image
        
        # Use default image
        LOGGER.info("Using default image", job_id=job.job_id, image=self._settings.docker_default_image)
        return self._settings.docker_default_image
    
    def _build_environment(self, job: JobAssignment) -> dict[str, str]:
        """Build environment variables for the container."""
        env = {
            # GitHub Actions standard environment
            "CI": "true",
            "GITHUB_ACTIONS": "true",
            "GITHUB_WORKFLOW": job.repository.name,
            "GITHUB_RUN_ID": str(job.run_id),
            "GITHUB_RUN_ATTEMPT": str(job.run_attempt),
            "GITHUB_JOB": str(job.job_id),
            "GITHUB_REPOSITORY": job.repository.full_name,
            "GITHUB_REPOSITORY_ID": str(job.repository.id),
            "GITHUB_REPOSITORY_OWNER": job.repository.full_name.split("/")[0],
            "GITHUB_WORKSPACE": "/github/workspace",
            "GITHUB_HOME": "/github/home",
            "RUNNER_WORKSPACE": "/github/workspace",
            "RUNNER_TEMP": "/tmp",
            
            # Nimbus-specific
            "NIMBUS_JOB_ID": str(job.job_id),
            "NIMBUS_EXECUTOR": "docker",
            
            # Runner registration token
            "ACTIONS_RUNNER_TOKEN": job.runner_registration.token,
        }
        
        # Add cache token if available
        if job.cache_token:
            env["ACTIONS_CACHE_URL"] = f"http://cache-proxy:8080/cache/"
            env["ACTIONS_RUNTIME_TOKEN"] = job.cache_token.token
        
        return env
