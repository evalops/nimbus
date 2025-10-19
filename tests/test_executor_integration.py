"""Integration tests for the multi-executor job processing system."""

import pytest
import asyncio
import os
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, AsyncMock, patch, MagicMock

from src.nimbus.runners import EXECUTORS
from src.nimbus.runners.pool_manager import PoolManager, WarmInstance
from src.nimbus.runners.resource_manager import ResourceTracker
from src.nimbus.common.schemas import JobAssignment, GitHubRepository, RunnerRegistrationToken
from src.nimbus.common.settings import HostAgentSettings


@pytest.fixture
def mock_settings():
    """Create comprehensive mock settings."""
    settings = Mock(spec=HostAgentSettings)
    settings.enable_warm_pools = True
    settings.firecracker_min_warm = 1
    settings.firecracker_max_warm = 2
    settings.docker_min_warm = 0
    settings.docker_max_warm = 1
    settings.docker_socket_path = "/var/run/docker.sock"
    settings.docker_network_name = "nimbus-test"
    settings.docker_workspace_path = Path("/tmp/test-workspaces")
    settings.docker_default_image = "ubuntu:22.04"
    settings.metadata_endpoint_denylist = []
    settings.egress_policy_pack = None
    settings.offline_mode = False
    settings.artifact_registry_allow_list = []
    return settings


@pytest.fixture
def sample_jobs():
    """Create sample job assignments for different executors."""
    repo = GitHubRepository(
        id=123,
        name="test-repo",
        full_name="org/test-repo", 
        private=False,
        owner_id=456
    )
    
    token = RunnerRegistrationToken(
        token="test-token",
        expires_at=datetime.now(timezone.utc)
    )
    
    jobs = {
        "firecracker": JobAssignment(
            job_id=1001,
            run_id=2001,
            run_attempt=1,
            repository=repo,
            labels=["nimbus", "secure"],
            runner_registration=token,
            executor="firecracker"
        ),
        "docker": JobAssignment(
            job_id=1002,
            run_id=2002,
            run_attempt=1,
            repository=repo,
            labels=["nimbus", "docker", "fast"],
            runner_registration=token,
            executor="docker"
        ),
    }
    
    # Add GPU job if GPU executor is available
    if "gpu" in EXECUTORS:
        jobs["gpu"] = JobAssignment(
            job_id=1003,
            run_id=2003,
            run_attempt=1,
            repository=repo,
            labels=["nimbus", "gpu", "pytorch", "gpu-count:1"],
            runner_registration=token,
            executor="gpu"
        )
    
    return jobs


@pytest.mark.asyncio
async def test_executor_registry_functionality():
    """Test that all executors in the registry work correctly."""
    # Test that all executors have required properties
    for name, executor in EXECUTORS.items():
        assert executor.name == name
        assert isinstance(executor.capabilities, list)
        assert len(executor.capabilities) > 0
        
        # Test that all capabilities are strings
        for capability in executor.capabilities:
            assert isinstance(capability, str)
            assert len(capability) > 0


@pytest.mark.asyncio
async def test_executor_lifecycle_without_initialization(sample_jobs):
    """Test executor lifecycle methods handle uninitialized state."""
    for executor_name, executor in EXECUTORS.items():
        if executor_name not in sample_jobs:
            continue
            
        job = sample_jobs[executor_name]
        
        # Most executors should handle being called without initialization
        # by raising appropriate errors
        try:
            await executor.prepare(job)
            await executor.cleanup(job.job_id)
        except RuntimeError as e:
            # Expected for uninitialized executors
            assert "not initialized" in str(e).lower()


@pytest.mark.asyncio
@patch('src.nimbus.runners.docker.docker.DockerClient')
async def test_docker_executor_integration(mock_docker_client, mock_settings, sample_jobs):
    """Test Docker executor integration with mocked Docker."""
    if "docker" not in EXECUTORS or "docker" not in sample_jobs:
        pytest.skip("Docker executor not available")
    
    # Mock Docker client
    mock_client = Mock()
    mock_docker_client.return_value = mock_client
    mock_client.ping.return_value = True
    
    # Mock network operations - use proper Docker exception
    from docker.errors import NotFound
    mock_client.networks.get.side_effect = NotFound("Network not found")
    mock_client.networks.create.return_value = Mock()
    
    # Mock image operations
    mock_client.images.get.return_value = Mock()  # Image exists
    
    executor = EXECUTORS["docker"]
    job = sample_jobs["docker"]
    
    # Initialize executor
    with patch('src.nimbus.runners.docker.EgressPolicyPack'), \
         patch('src.nimbus.runners.docker.MetadataEndpointDenylist'):
        executor.initialize(mock_settings)
    
    # Test prepare
    with patch('pathlib.Path.mkdir'):
        await executor.prepare(job)
    
    assert job.job_id in executor._job_workspaces
    
    # Test cleanup
    await executor.cleanup(job.job_id)
    assert job.job_id not in executor._job_workspaces


@pytest.mark.skipif("gpu" not in EXECUTORS, reason="GPU executor not available")
@pytest.mark.asyncio
@patch('subprocess.run')
@patch('src.nimbus.runners.gpu.docker.DockerClient')
async def test_gpu_executor_integration(mock_docker_client, mock_run, mock_settings, sample_jobs):
    """Test GPU executor integration with mocked nvidia-docker."""
    # Mock nvidia-docker availability
    mock_run.return_value = Mock(
        returncode=0,
        stdout='{"nvidia": {"path": "/usr/bin/nvidia-container-runtime"}}'
    )
    
    # Mock nvidia-smi GPU discovery
    def run_side_effect(cmd, **kwargs):
        if "nvidia-smi" in cmd:
            return Mock(
                returncode=0,
                stdout="0, Tesla V100, GPU-12345, 32768, 30720, 7.0, 470.82"
            )
        return Mock(returncode=0, stdout='{"nvidia": {}}')
    
    mock_run.side_effect = run_side_effect
    
    # Mock Docker client
    mock_client = Mock()
    mock_docker_client.return_value = mock_client
    mock_client.ping.return_value = True
    
    executor = EXECUTORS["gpu"]
    job = sample_jobs["gpu"]
    
    # Initialize executor with proper workspace path type
    mock_settings.docker_workspace_path = Path("/tmp/test-gpu-workspaces")
    executor.initialize(mock_settings)
    
    # Test prepare
    with patch('pathlib.Path.mkdir'):
        await executor.prepare(job)
    
    assert job.job_id in executor._job_workspaces
    assert job.job_id in executor._gpu_allocations
    
    # Test cleanup
    await executor.cleanup(job.job_id)
    assert job.job_id not in executor._job_workspaces
    assert job.job_id not in executor._gpu_allocations


@pytest.mark.asyncio
async def test_pool_manager_integration(mock_settings):
    """Test pool manager integration with real executors."""
    # Create mock executors for testing
    mock_executors = {}
    for name in ["firecracker", "docker"]:
        if name in EXECUTORS:
            executor = Mock()
            executor.name = name
            executor.capabilities = [name, "test"]
            executor.prepare_warm_instance = AsyncMock(return_value={"context": "test"})
            executor.cleanup_warm_instance = AsyncMock()
            executor.health_check_warm_instance = AsyncMock(return_value=True)
            mock_executors[name] = executor
    
    pool_manager = PoolManager(mock_settings, mock_executors)
    
    # Test start/stop
    await pool_manager.start()
    assert pool_manager._running
    
    # Test pool configurations were set
    if "firecracker" in mock_executors:
        assert "firecracker" in pool_manager._pool_configs
        config = pool_manager._pool_configs["firecracker"] 
        assert config.min_warm == 1
        assert config.max_warm == 3
    
    if "docker" in mock_executors:
        assert "docker" in pool_manager._pool_configs
        config = pool_manager._pool_configs["docker"]
        assert config.min_warm == 0
        assert config.max_warm == 2
    
    await pool_manager.stop()
    assert not pool_manager._running


@pytest.mark.asyncio
async def test_resource_tracker_integration():
    """Test resource tracker integration."""
    tracker = ResourceTracker()
    
    # Test start/stop
    with patch.object(tracker._cgroup_manager, 'initialize') as mock_init:
        await tracker.start()
        mock_init.assert_called_once()
    
    assert tracker._running
    
    # Test job tracking
    with patch.object(tracker._cgroup_manager, 'create_job_cgroup') as mock_create, \
         patch.object(tracker._cgroup_manager, 'add_pid_to_job') as mock_add_pid:
        
        await tracker.start_job_tracking(123, "test", pid=9999)
    
    mock_create.assert_called_once()
    mock_add_pid.assert_called_once()
    
    # Test stop
    with patch.object(tracker._cgroup_manager, 'cleanup_job_cgroup') as mock_cleanup:
        await tracker.stop_job_tracking(123)
    
    mock_cleanup.assert_called_once()
    
    await tracker.stop()
    assert not tracker._running


@pytest.mark.asyncio
async def test_capability_based_job_matching():
    """Test that jobs are matched to executors based on capabilities."""
    test_cases = [
        ("firecracker", ["firecracker", "microvm", "isolated"]),
        ("docker", ["docker", "container", "fast-start"]),
    ]
    
    # Add GPU test case if available
    if "gpu" in EXECUTORS:
        test_cases.append(("gpu", ["gpu", "nvidia", "cuda", "container"]))
    
    for executor_name, expected_capabilities in test_cases:
        executor = EXECUTORS[executor_name]
        capabilities = executor.capabilities
        
        # Check that expected capabilities are present
        for expected_cap in expected_capabilities:
            assert expected_cap in capabilities, f"{expected_cap} not in {executor_name} capabilities"


@pytest.mark.asyncio
async def test_warm_instance_reservation_and_release(mock_settings):
    """Test warm instance reservation and release cycle."""
    # Create mock executor
    mock_executor = Mock()
    mock_executor.name = "test"
    mock_executor.capabilities = ["test"]
    mock_executor.prepare_warm_instance = AsyncMock(return_value={"ready": True})
    mock_executor.cleanup_warm_instance = AsyncMock()
    mock_executor.health_check_warm_instance = AsyncMock(return_value=True)
    
    executors = {"test": mock_executor}
    pool_manager = PoolManager(mock_settings, executors)
    
    await pool_manager.start()
    
    # Create a warm instance manually
    instance = WarmInstance(
        instance_id="test-1",
        executor_name="test",
        created_at=datetime.now(timezone.utc),
        is_healthy=True
    )
    pool_manager._pools["test"]["test-1"] = instance
    
    # Create mock job
    repo = GitHubRepository(id=1, name="test", full_name="test/test", private=False)
    token = RunnerRegistrationToken(token="test", expires_at=datetime.now(timezone.utc))
    job = JobAssignment(
        job_id=123,
        run_id=456,
        run_attempt=1,
        repository=repo,
        labels=["test"],
        runner_registration=token,
        executor="test"
    )
    
    # Test reservation
    reserved_instance = await pool_manager.get_warm_instance("test", job)
    assert reserved_instance is not None
    assert reserved_instance.reserved_for_job == 123
    
    # Test release
    await pool_manager.release_instance(reserved_instance, 123)
    assert reserved_instance.reserved_for_job is None
    
    await pool_manager.stop()


@pytest.mark.asyncio
async def test_executor_error_handling(mock_settings):
    """Test error handling across the executor system."""
    # Create failing executor
    failing_executor = Mock()
    failing_executor.name = "failing"
    failing_executor.capabilities = ["fail"]
    failing_executor.prepare = AsyncMock(side_effect=RuntimeError("Prepare failed"))
    failing_executor.run = AsyncMock(side_effect=RuntimeError("Run failed"))
    failing_executor.cleanup = AsyncMock(side_effect=RuntimeError("Cleanup failed"))
    failing_executor.prepare_warm_instance = AsyncMock(side_effect=RuntimeError("Warm prep failed"))
    failing_executor.cleanup_warm_instance = AsyncMock(side_effect=RuntimeError("Warm cleanup failed"))
    failing_executor.health_check_warm_instance = AsyncMock(side_effect=RuntimeError("Health check failed"))
    
    executors = {"failing": failing_executor}
    
    # Test pool manager handles executor errors
    pool_manager = PoolManager(mock_settings, executors)
    config = pool_manager._pool_configs["failing"] = Mock()
    config.executor_name = "failing"
    config.min_warm = 1
    config.max_warm = 2
    
    await pool_manager.start()
    
    # Test that creation failures are handled gracefully
    result = await pool_manager._create_warm_instance(config)
    assert result is None
    
    # Test that health check failures are handled
    instance = WarmInstance("fail-1", "failing", datetime.now(timezone.utc))
    health = await pool_manager._health_check_instance(instance)
    assert health is False
    
    # Test that cleanup failures are handled
    await pool_manager._destroy_instance(instance)  # Should not raise
    
    await pool_manager.stop()
    
    # Test resource tracker handles errors
    tracker = ResourceTracker()
    
    with patch.object(tracker._cgroup_manager, 'initialize', side_effect=RuntimeError("Init failed")):
        # Should not raise
        await tracker.start()
    
    await tracker.stop()


@pytest.mark.asyncio
async def test_concurrent_job_processing(mock_settings, sample_jobs):
    """Test concurrent job processing with multiple executors."""
    # Create mock executors
    mock_executors = {}
    for name in ["test1", "test2", "test3"]:
        executor = Mock()
        executor.name = name
        executor.capabilities = [name]
        executor.prepare = AsyncMock()
        executor.run = AsyncMock(return_value=Mock(success=True, exit_code=0))
        executor.cleanup = AsyncMock()
        mock_executors[name] = executor
    
    # Create jobs for each executor
    repo = GitHubRepository(id=1, name="test", full_name="test/test", private=False)
    token = RunnerRegistrationToken(token="test", expires_at=datetime.now(timezone.utc))
    
    jobs = []
    for i, executor_name in enumerate(mock_executors.keys()):
        job = JobAssignment(
            job_id=1000 + i,
            run_id=2000 + i,
            run_attempt=1,
            repository=repo,
            labels=[executor_name],
            runner_registration=token,
            executor=executor_name
        )
        jobs.append((job, mock_executors[executor_name]))
    
    # Process jobs concurrently
    async def process_job(job, executor):
        await executor.prepare(job)
        result = await executor.run(job)
        await executor.cleanup(job.job_id)
        return result
    
    # Run all jobs concurrently
    tasks = [process_job(job, executor) for job, executor in jobs]
    results = await asyncio.gather(*tasks)
    
    # Verify all jobs completed successfully
    assert len(results) == 3
    for result in results:
        assert result.success
        assert result.exit_code == 0
    
    # Verify all executors were called
    for job, executor in jobs:
        executor.prepare.assert_called_once_with(job)
        executor.run.assert_called_once()
        executor.cleanup.assert_called_once_with(job.job_id)


@pytest.mark.asyncio 
async def test_executor_metrics_integration():
    """Test that executor operations generate appropriate metrics."""
    # This would test Prometheus metrics integration
    # For now, we just verify the metrics objects exist and are callable
    
    from src.nimbus.runners.resource_manager import CGroupManager
    from src.nimbus.common.metrics import GLOBAL_REGISTRY
    
    cgroup_manager = CGroupManager()
    
    # Verify metrics are registered
    assert cgroup_manager._cpu_usage_gauge is not None
    assert cgroup_manager._memory_usage_gauge is not None
    assert cgroup_manager._io_read_counter is not None
    assert cgroup_manager._io_write_counter is not None
    
    # Verify metrics can be updated with labels (would normally require actual data)
    try:
        cgroup_manager._cpu_usage_gauge.set(1.5, labels=["123", "test"])
        cgroup_manager._memory_usage_gauge.set(1024000, labels=["123", "test"])
        # Test also works without labels
        cgroup_manager._cpu_usage_gauge.set(2.0)
        cgroup_manager._memory_usage_gauge.set(2048000)
    except Exception as e:
        pytest.fail(f"Metrics update failed: {e}")


def test_executor_configuration_validation(mock_settings):
    """Test that executor configurations are validated properly."""
    from src.nimbus.runners.pool_manager import PoolConfig
    
    # Test valid configuration
    config = PoolConfig(
        executor_name="test",
        min_warm=1,
        max_warm=5,
        max_idle_seconds=300,
        health_check_interval=60
    )
    
    assert config.executor_name == "test"
    assert config.min_warm < config.max_warm
    assert config.max_idle_seconds > 0
    assert config.health_check_interval > 0


@pytest.mark.integration 
@pytest.mark.skipif(not os.getenv("NIMBUS_INTEGRATION_TESTS"), 
                   reason="Integration tests not enabled")
@pytest.mark.asyncio
async def test_full_system_integration():
    """Full system integration test (requires NIMBUS_INTEGRATION_TESTS=1)."""
    # This would be a comprehensive test that exercises the full system
    # with real Docker daemon, real cgroups, etc.
    # Skipped by default to avoid requiring complex test environment
    
    pass
