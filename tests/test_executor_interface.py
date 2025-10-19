"""Tests for the executor interface and registry system."""

import pytest
from datetime import datetime, timezone
from unittest.mock import Mock, AsyncMock

from src.nimbus.runners import EXECUTORS, Executor, RunResult
from src.nimbus.runners.base import Executor as ExecutorProtocol
from src.nimbus.common.schemas import JobAssignment, GitHubRepository, RunnerRegistrationToken
from src.nimbus.common.settings import HostAgentSettings


def test_executor_registry_contains_expected_executors():
    """Test that the executor registry contains the expected executors."""
    assert "firecracker" in EXECUTORS
    assert "docker" in EXECUTORS
    
    # GPU executor is optional based on nvidia-docker availability
    # So we just check it implements the interface if present
    if "gpu" in EXECUTORS:
        assert hasattr(EXECUTORS["gpu"], "name")
        assert hasattr(EXECUTORS["gpu"], "capabilities")


def test_all_executors_implement_protocol():
    """Test that all registered executors implement the Executor protocol."""
    for name, executor in EXECUTORS.items():
        # Check required properties
        assert hasattr(executor, "name")
        assert hasattr(executor, "capabilities")
        
        # Check required methods
        assert hasattr(executor, "prepare")
        assert hasattr(executor, "run") 
        assert hasattr(executor, "cleanup")
        
        # Check name matches registry key
        assert executor.name == name
        
        # Check capabilities is a list of strings
        capabilities = executor.capabilities
        assert isinstance(capabilities, list)
        assert all(isinstance(cap, str) for cap in capabilities)


def test_firecracker_executor_properties():
    """Test FirecrackerExecutor specific properties."""
    firecracker = EXECUTORS["firecracker"]
    
    assert firecracker.name == "firecracker"
    
    capabilities = firecracker.capabilities
    assert "firecracker" in capabilities
    assert "microvm" in capabilities
    assert "isolated" in capabilities


def test_docker_executor_properties():
    """Test DockerExecutor specific properties."""
    docker = EXECUTORS["docker"]
    
    assert docker.name == "docker"
    
    capabilities = docker.capabilities
    assert "docker" in capabilities
    assert "container" in capabilities
    assert "fast-start" in capabilities


@pytest.mark.skipif("gpu" not in EXECUTORS, reason="GPU executor not available")
def test_gpu_executor_properties():
    """Test GPUExecutor specific properties."""
    gpu = EXECUTORS["gpu"]
    
    assert gpu.name == "gpu"
    
    capabilities = gpu.capabilities
    assert "gpu" in capabilities
    assert "nvidia" in capabilities
    assert "cuda" in capabilities
    assert "container" in capabilities


def test_run_result_creation():
    """Test RunResult dataclass creation and validation."""
    now = datetime.now(timezone.utc)
    
    result = RunResult(
        success=True,
        exit_code=0,
        log_lines=["test line 1", "test line 2"],
        metrics="duration=1.5,memory=1024",
        duration_seconds=1.5,
        started_at=now,
        finished_at=now,
    )
    
    assert result.success is True
    assert result.exit_code == 0
    assert len(result.log_lines) == 2
    assert result.metrics == "duration=1.5,memory=1024"
    assert result.duration_seconds == 1.5
    assert result.started_at == now
    assert result.finished_at == now


def test_run_result_defaults():
    """Test RunResult with default values."""
    result = RunResult(success=False, exit_code=1)
    
    assert result.success is False
    assert result.exit_code == 1
    assert result.log_lines == []
    assert result.metrics is None
    assert result.duration_seconds is None
    assert result.started_at is None
    assert result.finished_at is None


class MockExecutor:
    """Mock executor for testing."""
    
    def __init__(self, name: str, capabilities: list[str]):
        self._name = name
        self._capabilities = capabilities
        self.prepare_called = False
        self.run_called = False
        self.cleanup_called = False
    
    @property
    def name(self) -> str:
        return self._name
    
    @property 
    def capabilities(self) -> list[str]:
        return self._capabilities
    
    async def prepare(self, job: JobAssignment) -> None:
        self.prepare_called = True
    
    async def run(self, job: JobAssignment, **kwargs) -> RunResult:
        self.run_called = True
        return RunResult(success=True, exit_code=0)
    
    async def cleanup(self, job_id: int) -> None:
        self.cleanup_called = True


@pytest.fixture
def mock_job_assignment():
    """Create a mock job assignment for testing."""
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
    
    return JobAssignment(
        job_id=1001,
        run_id=2001,
        run_attempt=1,
        repository=repo,
        labels=["test", "mock"],
        runner_registration=token,
        executor="mock"
    )


@pytest.mark.asyncio
async def test_mock_executor_lifecycle(mock_job_assignment):
    """Test the complete executor lifecycle with a mock executor."""
    executor = MockExecutor("mock", ["test", "fast"])
    
    # Test properties
    assert executor.name == "mock"
    assert executor.capabilities == ["test", "fast"]
    
    # Test lifecycle
    assert not executor.prepare_called
    assert not executor.run_called
    assert not executor.cleanup_called
    
    await executor.prepare(mock_job_assignment)
    assert executor.prepare_called
    
    result = await executor.run(mock_job_assignment)
    assert executor.run_called
    assert result.success
    assert result.exit_code == 0
    
    await executor.cleanup(mock_job_assignment.job_id)
    assert executor.cleanup_called


def test_executor_protocol_compliance():
    """Test that our mock executor satisfies the protocol."""
    executor = MockExecutor("test", ["capability"])
    
    # This should not raise a type error if the protocol is satisfied
    def check_executor_protocol(e: ExecutorProtocol) -> None:
        assert e.name
        assert e.capabilities
    
    check_executor_protocol(executor)


@pytest.mark.asyncio
async def test_executor_error_handling():
    """Test executor error handling."""
    
    class FailingExecutor:
        @property
        def name(self) -> str:
            return "failing"
        
        @property
        def capabilities(self) -> list[str]:
            return ["fail"]
        
        async def prepare(self, job: JobAssignment) -> None:
            raise RuntimeError("Prepare failed")
        
        async def run(self, job: JobAssignment, **kwargs) -> RunResult:
            raise RuntimeError("Run failed")
        
        async def cleanup(self, job_id: int) -> None:
            raise RuntimeError("Cleanup failed")
    
    executor = FailingExecutor()
    job = Mock()
    
    with pytest.raises(RuntimeError, match="Prepare failed"):
        await executor.prepare(job)
    
    with pytest.raises(RuntimeError, match="Run failed"):
        await executor.run(job)
    
    with pytest.raises(RuntimeError, match="Cleanup failed"):
        await executor.cleanup(123)


def test_executor_capabilities_uniqueness():
    """Test that executor capabilities don't have duplicates."""
    for name, executor in EXECUTORS.items():
        capabilities = executor.capabilities
        assert len(capabilities) == len(set(capabilities)), f"Executor {name} has duplicate capabilities"


def test_executor_names_are_lowercase():
    """Test that executor names follow naming convention."""
    for name, executor in EXECUTORS.items():
        assert name.islower(), f"Executor name '{name}' should be lowercase"
        assert executor.name.islower(), f"Executor.name '{executor.name}' should be lowercase"
