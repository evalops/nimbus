"""Tests for the warm pool manager."""

import pytest
import asyncio
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, AsyncMock, patch

from src.nimbus.runners.pool_manager import PoolManager, PoolConfig, WarmInstance
from src.nimbus.runners.base import Executor
from src.nimbus.common.schemas import JobAssignment, GitHubRepository, RunnerRegistrationToken
from src.nimbus.common.settings import HostAgentSettings


@pytest.fixture
def mock_settings():
    """Create mock settings."""
    return Mock(spec=HostAgentSettings)


@pytest.fixture
def mock_executor():
    """Create a mock executor."""
    executor = Mock(spec=Executor)
    executor.name = "test"
    executor.capabilities = ["test", "mock"]
    executor.prepare_warm_instance = AsyncMock(return_value={"test": "context"})
    executor.cleanup_warm_instance = AsyncMock()
    executor.health_check_warm_instance = AsyncMock(return_value=True)
    return executor


@pytest.fixture
def mock_executors(mock_executor):
    """Create mock executors dict."""
    return {"test": mock_executor}


@pytest.fixture
def sample_job():
    """Create a sample job assignment."""
    repo = GitHubRepository(id=1, name="test", full_name="test/test", private=False)
    token = RunnerRegistrationToken(token="test", expires_at=datetime.now(timezone.utc))
    
    return JobAssignment(
        job_id=123,
        run_id=456,
        run_attempt=1,
        repository=repo,
        labels=["test"],
        runner_registration=token,
        executor="test"
    )


def test_pool_config_creation():
    """Test PoolConfig dataclass creation."""
    config = PoolConfig(
        executor_name="test",
        min_warm=2,
        max_warm=5,
        max_idle_seconds=300,
        health_check_interval=60
    )
    
    assert config.executor_name == "test"
    assert config.min_warm == 2
    assert config.max_warm == 5
    assert config.max_idle_seconds == 300
    assert config.health_check_interval == 60


def test_warm_instance_creation():
    """Test WarmInstance dataclass creation."""
    now = datetime.now(timezone.utc)
    
    instance = WarmInstance(
        instance_id="test-1",
        executor_name="test",
        created_at=now,
        context={"key": "value"}
    )
    
    assert instance.instance_id == "test-1"
    assert instance.executor_name == "test"
    assert instance.created_at == now
    assert instance.is_healthy is True
    assert instance.reserved_for_job is None
    assert instance.context == {"key": "value"}


def test_pool_manager_initialization(mock_settings, mock_executors):
    """Test PoolManager initialization."""
    manager = PoolManager(mock_settings, mock_executors)
    
    assert manager._settings == mock_settings
    assert manager._executors == mock_executors
    # Pool configs are only created for known executors (firecracker, docker)
    # Custom executors like "test" don't get default configs
    assert manager._running is False


def test_default_pool_configurations(mock_settings):
    """Test default pool configurations are set correctly."""
    # Mock executors for firecracker and docker
    executors = {
        "firecracker": Mock(name="firecracker"),
        "docker": Mock(name="docker"),
        "custom": Mock(name="custom")
    }
    
    manager = PoolManager(mock_settings, executors)
    
    # Check firecracker config
    assert "firecracker" in manager._pool_configs
    fc_config = manager._pool_configs["firecracker"]
    assert fc_config.min_warm == 1
    assert fc_config.max_warm == 3
    assert fc_config.max_idle_seconds == 600
    
    # Check docker config
    assert "docker" in manager._pool_configs
    docker_config = manager._pool_configs["docker"]
    assert docker_config.min_warm == 0
    assert docker_config.max_warm == 2
    assert docker_config.max_idle_seconds == 180
    
    # Custom executor should not have a default config
    assert "custom" not in manager._pool_configs


@pytest.mark.asyncio
async def test_pool_manager_start_stop(mock_settings, mock_executors):
    """Test pool manager start and stop."""
    manager = PoolManager(mock_settings, mock_executors)
    
    assert not manager._running
    
    # Start manager
    await manager.start()
    assert manager._running
    # No pool tasks since "test" executor doesn't have a default config
    
    # Stop manager
    await manager.stop()
    assert not manager._running
    assert len(manager._pool_tasks) == 0


@pytest.mark.asyncio
async def test_get_warm_instance_success(mock_settings, mock_executors, sample_job):
    """Test getting a warm instance successfully."""
    manager = PoolManager(mock_settings, mock_executors)
    
    # Create a warm instance
    instance = WarmInstance(
        instance_id="test-1",
        executor_name="test",
        created_at=datetime.now(timezone.utc),
        is_healthy=True
    )
    manager._pools["test"]["test-1"] = instance
    
    # Get warm instance
    result = await manager.get_warm_instance("test", sample_job)
    
    assert result == instance
    assert result.reserved_for_job == sample_job.job_id


@pytest.mark.asyncio
async def test_get_warm_instance_none_available(mock_settings, mock_executors, sample_job):
    """Test getting warm instance when none available."""
    manager = PoolManager(mock_settings, mock_executors)
    
    result = await manager.get_warm_instance("test", sample_job)
    assert result is None


@pytest.mark.asyncio
async def test_get_warm_instance_all_reserved(mock_settings, mock_executors, sample_job):
    """Test getting warm instance when all are reserved."""
    manager = PoolManager(mock_settings, mock_executors)
    
    # Create warm instance that's already reserved
    instance = WarmInstance(
        instance_id="test-1",
        executor_name="test", 
        created_at=datetime.now(timezone.utc),
        reserved_for_job=999  # Already reserved
    )
    manager._pools["test"]["test-1"] = instance
    
    result = await manager.get_warm_instance("test", sample_job)
    assert result is None


@pytest.mark.asyncio
async def test_get_warm_instance_unhealthy(mock_settings, mock_executors, sample_job):
    """Test getting warm instance when instance is unhealthy."""
    manager = PoolManager(mock_settings, mock_executors)
    
    # Create unhealthy instance
    instance = WarmInstance(
        instance_id="test-1",
        executor_name="test",
        created_at=datetime.now(timezone.utc),
        is_healthy=False
    )
    manager._pools["test"]["test-1"] = instance
    
    result = await manager.get_warm_instance("test", sample_job)
    assert result is None


@pytest.mark.asyncio
async def test_release_instance_success(mock_settings, mock_executors):
    """Test releasing an instance back to the pool."""
    manager = PoolManager(mock_settings, mock_executors)
    
    instance = WarmInstance(
        instance_id="test-1",
        executor_name="test",
        created_at=datetime.now(timezone.utc),
        reserved_for_job=123
    )
    
    await manager.release_instance(instance, 123)
    
    assert instance.reserved_for_job is None


@pytest.mark.asyncio
async def test_release_instance_job_mismatch(mock_settings, mock_executors):
    """Test releasing instance with job ID mismatch."""
    manager = PoolManager(mock_settings, mock_executors)
    
    instance = WarmInstance(
        instance_id="test-1", 
        executor_name="test",
        created_at=datetime.now(timezone.utc),
        reserved_for_job=123
    )
    
    # Should log warning but still release
    await manager.release_instance(instance, 456)  # Wrong job ID
    assert instance.reserved_for_job is None


@pytest.mark.asyncio
async def test_release_unhealthy_instance(mock_settings, mock_executors, mock_executor):
    """Test releasing an unhealthy instance destroys it."""
    manager = PoolManager(mock_settings, mock_executors)
    
    instance = WarmInstance(
        instance_id="test-1",
        executor_name="test", 
        created_at=datetime.now(timezone.utc),
        reserved_for_job=123,
        is_healthy=False
    )
    manager._pools["test"]["test-1"] = instance
    
    await manager.release_instance(instance, 123)
    
    # Instance should be destroyed (removed from pool)
    assert "test-1" not in manager._pools["test"]
    mock_executor.cleanup_warm_instance.assert_called_once()


@pytest.mark.asyncio
async def test_create_warm_instance_success(mock_settings, mock_executors, mock_executor):
    """Test creating a warm instance successfully."""
    manager = PoolManager(mock_settings, mock_executors)
    
    config = PoolConfig("test", min_warm=1, max_warm=3)
    
    result = await manager._create_warm_instance(config)
    
    assert result is not None
    assert result.executor_name == "test"
    assert result.instance_id.startswith("test-")
    
    # Verify executor was called
    mock_executor.prepare_warm_instance.assert_called_once()
    
    # Verify instance was added to pool
    assert result.instance_id in manager._pools["test"]


@pytest.mark.asyncio
async def test_create_warm_instance_executor_not_found(mock_settings, mock_executors):
    """Test creating warm instance when executor not found."""
    manager = PoolManager(mock_settings, mock_executors)
    
    config = PoolConfig("nonexistent", min_warm=1, max_warm=3)
    
    result = await manager._create_warm_instance(config)
    
    assert result is None


@pytest.mark.asyncio
async def test_create_warm_instance_prepare_fails(mock_settings, mock_executors, mock_executor):
    """Test creating warm instance when prepare fails."""
    manager = PoolManager(mock_settings, mock_executors)
    
    # Mock prepare to fail
    mock_executor.prepare_warm_instance.side_effect = Exception("Prepare failed")
    
    config = PoolConfig("test", min_warm=1, max_warm=3)
    
    result = await manager._create_warm_instance(config)
    
    assert result is None


@pytest.mark.asyncio
async def test_destroy_instance(mock_settings, mock_executors, mock_executor):
    """Test destroying a warm instance."""
    manager = PoolManager(mock_settings, mock_executors)
    
    # Create instance in pool
    instance = WarmInstance(
        instance_id="test-1",
        executor_name="test",
        created_at=datetime.now(timezone.utc),
        context={"test": "data"}
    )
    manager._pools["test"]["test-1"] = instance
    
    await manager._destroy_instance(instance)
    
    # Verify cleanup was called
    mock_executor.cleanup_warm_instance.assert_called_once_with("test-1", {"test": "data"})
    
    # Verify instance was removed from pool
    assert "test-1" not in manager._pools["test"]


@pytest.mark.asyncio
async def test_health_check_instance_success(mock_settings, mock_executors, mock_executor):
    """Test health checking a warm instance."""
    manager = PoolManager(mock_settings, mock_executors)
    
    instance = WarmInstance(
        instance_id="test-1",
        executor_name="test",
        created_at=datetime.now(timezone.utc)
    )
    
    result = await manager._health_check_instance(instance)
    
    assert result is True
    assert instance.last_health_check is not None
    mock_executor.health_check_warm_instance.assert_called_once()


@pytest.mark.asyncio
async def test_health_check_instance_reserved(mock_settings, mock_executors, mock_executor):
    """Test health check skips reserved instances."""
    manager = PoolManager(mock_settings, mock_executors)
    
    instance = WarmInstance(
        instance_id="test-1",
        executor_name="test",
        created_at=datetime.now(timezone.utc),
        reserved_for_job=123
    )
    
    result = await manager._health_check_instance(instance)
    
    assert result is True
    mock_executor.health_check_warm_instance.assert_not_called()


@pytest.mark.asyncio
async def test_health_check_instance_failure(mock_settings, mock_executors, mock_executor):
    """Test health check when instance is unhealthy."""
    manager = PoolManager(mock_settings, mock_executors)
    
    # Mock health check to fail
    mock_executor.health_check_warm_instance.return_value = False
    
    instance = WarmInstance(
        instance_id="test-1",
        executor_name="test",
        created_at=datetime.now(timezone.utc)
    )
    
    result = await manager._health_check_instance(instance)
    
    assert result is False


@pytest.mark.asyncio
async def test_health_check_no_executor_method(mock_settings, mock_executors, mock_executor):
    """Test health check when executor has no health check method."""
    manager = PoolManager(mock_settings, mock_executors)
    
    # Remove health check method
    delattr(mock_executor, 'health_check_warm_instance')
    
    instance = WarmInstance(
        instance_id="test-1",
        executor_name="test", 
        created_at=datetime.now(timezone.utc)
    )
    
    result = await manager._health_check_instance(instance)
    
    # Should default to healthy
    assert result is True
    assert instance.last_health_check is not None


@pytest.mark.asyncio
async def test_pool_maintenance_cycle_creates_instances(mock_settings, mock_executors, mock_executor):
    """Test pool maintenance creates instances when below minimum."""
    manager = PoolManager(mock_settings, mock_executors)
    
    config = PoolConfig("test", min_warm=2, max_warm=5)
    
    await manager._pool_maintenance_cycle(config)
    
    # Should create 2 instances to meet minimum
    assert len(manager._pools["test"]) == 2
    assert mock_executor.prepare_warm_instance.call_count == 2


@pytest.mark.asyncio
async def test_pool_maintenance_cycle_removes_idle_instances(mock_settings, mock_executors, mock_executor):
    """Test pool maintenance removes idle instances."""
    manager = PoolManager(mock_settings, mock_executors)
    
    # Create an old idle instance
    old_time = datetime.now(timezone.utc) - timedelta(seconds=400)
    instance = WarmInstance(
        instance_id="test-1",
        executor_name="test",
        created_at=old_time
    )
    manager._pools["test"]["test-1"] = instance
    
    config = PoolConfig("test", min_warm=0, max_warm=5, max_idle_seconds=300)
    
    await manager._pool_maintenance_cycle(config)
    
    # Instance should be removed
    assert "test-1" not in manager._pools["test"]
    mock_executor.cleanup_warm_instance.assert_called_once()


@pytest.mark.asyncio
async def test_pool_maintenance_cycle_removes_unhealthy_instances(mock_settings, mock_executors, mock_executor):
    """Test pool maintenance removes unhealthy instances."""
    manager = PoolManager(mock_settings, mock_executors)
    
    # Mock health check to fail
    mock_executor.health_check_warm_instance.return_value = False
    
    instance = WarmInstance(
        instance_id="test-1",
        executor_name="test",
        created_at=datetime.now(timezone.utc)
    )
    manager._pools["test"]["test-1"] = instance
    
    config = PoolConfig("test", min_warm=0, max_warm=5)
    
    await manager._pool_maintenance_cycle(config)
    
    # Unhealthy instance should be removed
    assert "test-1" not in manager._pools["test"]


@pytest.mark.asyncio
async def test_pool_maintenance_respects_max_limit(mock_settings, mock_executors, mock_executor):
    """Test pool maintenance respects maximum pool size."""
    manager = PoolManager(mock_settings, mock_executors)
    
    # Create instances up to max limit
    for i in range(3):
        instance = WarmInstance(
            instance_id=f"test-{i}",
            executor_name="test",
            created_at=datetime.now(timezone.utc)
        )
        manager._pools["test"][f"test-{i}"] = instance
    
    config = PoolConfig("test", min_warm=5, max_warm=3)  # min > max
    
    await manager._pool_maintenance_cycle(config)
    
    # Should not create more instances beyond max
    assert len(manager._pools["test"]) == 3
    mock_executor.prepare_warm_instance.assert_not_called()


def test_get_pool_stats(mock_settings, mock_executors):
    """Test getting pool statistics."""
    manager = PoolManager(mock_settings, mock_executors)
    
    # Create various instances
    healthy_available = WarmInstance("test-1", "test", datetime.now(timezone.utc))
    healthy_reserved = WarmInstance("test-2", "test", datetime.now(timezone.utc), reserved_for_job=123)
    unhealthy = WarmInstance("test-3", "test", datetime.now(timezone.utc), is_healthy=False)
    
    manager._pools["test"]["test-1"] = healthy_available
    manager._pools["test"]["test-2"] = healthy_reserved
    manager._pools["test"]["test-3"] = unhealthy
    
    stats = manager.get_pool_stats()
    
    assert "test" in stats
    test_stats = stats["test"]
    assert test_stats["total"] == 3
    assert test_stats["available"] == 1
    assert test_stats["reserved"] == 1
    assert test_stats["unhealthy"] == 1
    assert test_stats["config"]["min_warm"] == 0  # Default for non-standard executors
    assert test_stats["config"]["max_warm"] == 2


@pytest.mark.asyncio
async def test_pool_manager_handles_executor_errors_gracefully(mock_settings, mock_executors, mock_executor):
    """Test pool manager handles executor errors gracefully."""
    manager = PoolManager(mock_settings, mock_executors)
    
    # Mock all executor methods to fail
    mock_executor.prepare_warm_instance.side_effect = Exception("Prepare failed")
    mock_executor.cleanup_warm_instance.side_effect = Exception("Cleanup failed")
    mock_executor.health_check_warm_instance.side_effect = Exception("Health check failed")
    
    # These should not raise exceptions
    config = PoolConfig("test", min_warm=1, max_warm=3)
    
    result = await manager._create_warm_instance(config)
    assert result is None
    
    instance = WarmInstance("test-1", "test", datetime.now(timezone.utc))
    await manager._destroy_instance(instance)  # Should not raise
    
    health = await manager._health_check_instance(instance)
    assert health is False  # Should return False on error
