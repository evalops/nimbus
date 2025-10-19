"""Tests for the GPU executor."""

import pytest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from src.nimbus.runners.gpu import GPUExecutor, GPUInfo
from src.nimbus.runners.base import RunResult
from src.nimbus.common.schemas import JobAssignment, GitHubRepository, RunnerRegistrationToken
from src.nimbus.common.settings import HostAgentSettings


@pytest.fixture
def mock_settings():
    """Create mock settings for GPU executor."""
    settings = Mock(spec=HostAgentSettings)
    settings.docker_socket_path = "/var/run/docker.sock"
    settings.docker_workspace_path = Path("/tmp/test-gpu-workspaces")
    settings.docker_container_user = None
    settings.image_allow_list_path = None
    settings.image_deny_list_path = None
    settings.cosign_certificate_authority = None
    settings.provenance_required = False
    settings.gpu_allowed_profiles = []
    settings.gpu_require_mig = False
    settings.provenance_grace_seconds = 0
    settings.gpu_enable_cgroup_enforcement = False
    return settings


@pytest.fixture
def sample_gpu_job():
    """Create a sample GPU job assignment."""
    repo = GitHubRepository(
        id=123,
        name="ml-training",
        full_name="org/ml-training",
        private=False,
        owner_id=456
    )
    
    token = RunnerRegistrationToken(
        token="test-token",
        expires_at=datetime.now(timezone.utc)
    )
    
    return JobAssignment(
        job_id=3001,
        run_id=4001,
        run_attempt=1,
        repository=repo,
        labels=["gpu", "pytorch", "gpu-count:2"],
        runner_registration=token,
        executor="gpu"
    )


@pytest.fixture
def mock_gpu_info():
    """Create mock GPU information."""
    return {
        "index": 0,
        "name": "Tesla V100-SXM2-32GB",
        "uuid": "GPU-12345678-1234-1234-1234-123456789012",
        "memory_total": 32 * 1024 * 1024 * 1024,  # 32GB in bytes
        "memory_free": 30 * 1024 * 1024 * 1024,   # 30GB free
        "compute_capability": "7.0",
        "cuda_version": "12.2",
    }


def test_gpu_info_creation(mock_gpu_info):
    """Test GPUInfo dataclass creation."""
    gpu = GPUInfo(mock_gpu_info)
    
    assert gpu.index == 0
    assert gpu.name == "Tesla V100-SXM2-32GB"
    assert gpu.uuid == "GPU-12345678-1234-1234-1234-123456789012"
    assert gpu.memory_total == 32 * 1024 * 1024 * 1024
    assert gpu.compute_capability == "7.0"
    assert gpu.cuda_version == "12.2"


def test_gpu_executor_properties():
    """Test GPU executor basic properties."""
    executor = GPUExecutor()
    
    assert executor.name == "gpu"
    
    # Initial capabilities (before GPU discovery)
    capabilities = executor.capabilities
    assert "gpu" in capabilities
    assert "nvidia" in capabilities
    assert "cuda" in capabilities
    assert "container" in capabilities


@pytest.mark.asyncio
@patch('src.nimbus.runners.gpu.docker.DockerClient')
@patch('src.nimbus.runners.gpu.subprocess.run')
async def test_gpu_executor_enforces_provenance(mock_run, mock_docker_client, tmp_path, mock_settings, sample_gpu_job):
    mock_run.return_value = Mock(returncode=0, stdout='{"nvidia": {"path": "runtime"}}')

    def run_side_effect(cmd, **kwargs):
        if "nvidia-smi" in cmd:
            return Mock(returncode=0, stdout="0, Tesla V100, GPU-12345, 32768, 30720, 7.0, 470.82")
        return Mock(returncode=0, stdout='{"nvidia": {"path": "runtime"}}')

    mock_run.side_effect = run_side_effect

    mock_client = Mock()
    mock_docker_client.return_value = mock_client
    mock_client.ping.return_value = True
    mock_client.containers.create.return_value = Mock(
        wait=lambda timeout: {'StatusCode': 0},
        logs=lambda **kw: b'',
    )

    cosign_key = tmp_path / "cosign.pub"
    cosign_key.write_text("public key", encoding="utf-8")

    mock_settings.cosign_certificate_authority = cosign_key
    mock_settings.provenance_required = True

    executor = GPUExecutor()
    executor.initialize(mock_settings)

    sample_gpu_job.labels = ["gpu", "pytorch"]

    with patch('src.nimbus.runners.gpu.ensure_provenance') as ensure_mock:
        ensure_mock.return_value = None
        with patch.object(executor, '_ensure_image'):
            await executor.prepare(sample_gpu_job)
            await executor.run(sample_gpu_job, timeout_seconds=1)

        ensure_mock.assert_called()


@patch('subprocess.run')
def test_check_nvidia_docker_available(mock_run):
    """Test nvidia-docker availability check when available."""
    # Mock successful docker info with nvidia runtime
    mock_run.return_value = Mock(
        returncode=0,
        stdout='{"nvidia": {"path": "/usr/bin/nvidia-container-runtime"}}'
    )
    
    executor = GPUExecutor()
    assert executor._check_nvidia_docker() is True


@patch('subprocess.run')
def test_check_nvidia_docker_unavailable(mock_run):
    """Test nvidia-docker availability check when unavailable."""
    # Mock docker info without nvidia runtime
    mock_run.return_value = Mock(
        returncode=0,
        stdout='{"runc": {"path": "/usr/bin/runc"}}'
    )
    
    executor = GPUExecutor()
    assert executor._check_nvidia_docker() is False


@patch('subprocess.run')
def test_check_nvidia_docker_command_fails(mock_run):
    """Test nvidia-docker check when docker command fails."""
    mock_run.side_effect = Exception("Command failed")
    
    executor = GPUExecutor()
    assert executor._check_nvidia_docker() is False


@patch('subprocess.run')
def test_discover_gpus_success(mock_run):
    """Test successful GPU discovery."""
    # Mock nvidia-smi output
    mock_run.return_value = Mock(
        returncode=0,
        stdout="0, Tesla V100-SXM2-32GB, GPU-12345, 32768, 30720, 7.0, 470.82.01\n"
               "1, Tesla V100-SXM2-32GB, GPU-67890, 32768, 31000, 7.0, 470.82.01"
    )
    
    executor = GPUExecutor()
    executor._discover_gpus()
    
    assert len(executor._available_gpus) == 2
    
    gpu0 = executor._available_gpus["GPU-12345"]
    assert gpu0.index == 0
    assert gpu0.name == "Tesla V100-SXM2-32GB"
    assert gpu0.compute_capability == "7.0"


@patch('subprocess.run')
def test_discover_gpus_failure(mock_run):
    """Test GPU discovery failure."""
    mock_run.side_effect = Exception("nvidia-smi failed")
    
    executor = GPUExecutor()
    
    with pytest.raises(RuntimeError, match="GPU discovery failed"):
        executor._discover_gpus()


@patch('src.nimbus.runners.gpu.docker.DockerClient')
@patch.object(GPUExecutor, '_check_nvidia_docker', return_value=True)
@patch.object(GPUExecutor, '_discover_gpus')
def test_gpu_executor_initialization(mock_discover, mock_nvidia_check, mock_docker, mock_settings):
    """Test GPU executor initialization."""
    mock_client = Mock()
    mock_docker.return_value = mock_client
    
    executor = GPUExecutor()
    executor.initialize(mock_settings)
    
    # Verify initialization steps
    mock_nvidia_check.assert_called_once()
    mock_docker.assert_called_once()
    mock_client.ping.assert_called_once()
    mock_discover.assert_called_once()


@patch.object(GPUExecutor, '_check_nvidia_docker', return_value=False)
def test_gpu_executor_initialization_no_nvidia_docker(mock_nvidia_check, mock_settings):
    """Test GPU executor initialization without nvidia-docker."""
    executor = GPUExecutor()
    
    with pytest.raises(RuntimeError, match="nvidia-docker not available"):
        executor.initialize(mock_settings)


def test_get_required_gpu_count(mock_settings, sample_gpu_job):
    """Test GPU count parsing from job labels."""
    executor = GPUExecutor(mock_settings)
    
    # Test explicit gpu-count label
    sample_gpu_job.labels = ["gpu-count:2"]
    assert executor._get_required_gpu_count(sample_gpu_job) == 2
    
    # Test gpus label
    sample_gpu_job.labels = ["gpus:4"]
    assert executor._get_required_gpu_count(sample_gpu_job) == 4
    
    # Test default (no specific count)
    sample_gpu_job.labels = ["gpu", "pytorch"]
    assert executor._get_required_gpu_count(sample_gpu_job) == 1


def test_allocate_gpus_success():
    """Test successful GPU allocation."""
    executor = GPUExecutor()
    
    # Set up available GPUs
    executor._available_gpus = {
        "GPU-1": GPUInfo({"index": 0, "uuid": "GPU-1"}),
        "GPU-2": GPUInfo({"index": 1, "uuid": "GPU-2"}),
        "GPU-3": GPUInfo({"index": 2, "uuid": "GPU-3"}),
    }
    
    # Allocate 2 GPUs
    allocated = executor._allocate_gpus(job_id=123, gpu_count=2, profile=None)
    
    assert len(allocated) == 2
    assert all(uuid in executor._available_gpus for uuid in allocated)


def test_allocate_gpus_insufficient():
    """Test GPU allocation when insufficient GPUs available."""
    executor = GPUExecutor()
    
    # Set up only 1 available GPU
    executor._available_gpus = {
        "GPU-1": GPUInfo({"index": 0, "uuid": "GPU-1"}),
    }
    
    # Try to allocate 2 GPUs
    with pytest.raises(RuntimeError, match="Not enough GPUs available"):
        executor._allocate_gpus(job_id=123, gpu_count=2, profile=None)


def test_allocate_gpus_with_existing_allocation():
    """Test GPU allocation with some GPUs already allocated."""
    executor = GPUExecutor()
    
    # Set up available GPUs
    executor._available_gpus = {
        "GPU-1": GPUInfo({"index": 0, "uuid": "GPU-1"}),
        "GPU-2": GPUInfo({"index": 1, "uuid": "GPU-2"}),
    }
    
    # Allocate GPU-1 to another job
    executor._gpu_allocations[999] = ["GPU-1"]
    
    # Allocate 1 GPU for new job
    allocated = executor._allocate_gpus(job_id=123, gpu_count=1, profile=None)
    
    assert len(allocated) == 1
    assert allocated[0] == "GPU-2"  # GPU-1 should be skipped


def test_get_gpu_container_image_custom():
    """Test GPU container image selection with custom image."""
    executor = GPUExecutor()
    job = Mock(labels=["gpu-image:nvcr.io/nvidia/pytorch:custom"])
    
    image = executor._get_gpu_container_image(job)
    assert image == "nvcr.io/nvidia/pytorch:custom"


def test_get_gpu_container_image_mapped():
    """Test GPU container image selection with mapped labels."""
    executor = GPUExecutor()
    
    test_cases = [
        (["pytorch"], "nvcr.io/nvidia/pytorch:23.10-py3"),
        (["tensorflow"], "nvcr.io/nvidia/tensorflow:23.10-tf2-py3"),
        (["cuda"], "nvcr.io/nvidia/cuda:12.2-devel-ubuntu22.04"),
        (["ml"], "nvcr.io/nvidia/pytorch:23.10-py3"),
    ]
    
    for labels, expected_image in test_cases:
        job = Mock(labels=labels)
        image = executor._get_gpu_container_image(job)
        assert image == expected_image


def test_get_gpu_container_image_default():
    """Test GPU container image selection falls back to default."""
    executor = GPUExecutor()
    job = Mock(labels=["gpu", "some-other-label"])
    
    image = executor._get_gpu_container_image(job)
    assert image == "nvcr.io/nvidia/cuda:12.2-runtime-ubuntu22.04"


def test_allocate_gpus_mig_profile_success():
    executor = GPUExecutor()
    gpu = GPUInfo({"index": 0, "uuid": "GPU-1"})
    gpu.mig_enabled = True
    gpu.mig_profiles = ["1g.5gb"]
    executor._available_gpus = {"GPU-1": gpu}
    allocated = executor._allocate_gpus(job_id=1, gpu_count=1, profile="1g.5gb")
    assert allocated == ["GPU-1"]


def test_allocate_gpus_mig_profile_missing():
    executor = GPUExecutor()
    gpu = GPUInfo({"index": 0, "uuid": "GPU-1"})
    gpu.mig_enabled = True
    gpu.mig_profiles = ["1g.5gb"]
    executor._available_gpus = {"GPU-1": gpu}
    with pytest.raises(RuntimeError):
        executor._allocate_gpus(job_id=1, gpu_count=1, profile="2g.10gb")


def test_allocate_gpus_mig_profile_success():
    executor = GPUExecutor()
    gpu = GPUInfo({"index": 0, "uuid": "GPU-1"})
    gpu.mig_enabled = True
    gpu.mig_profiles = ["1g.5gb"]
    executor._available_gpus = {"GPU-1": gpu}
    allocated = executor._allocate_gpus(job_id=1, gpu_count=1, profile="1g.5gb")
    assert allocated == ["GPU-1"]


def test_allocate_gpus_mig_profile_missing():
    executor = GPUExecutor()
    gpu = GPUInfo({"index": 0, "uuid": "GPU-1"})
    gpu.mig_enabled = True
    gpu.mig_profiles = ["1g.5gb"]
    executor._available_gpus = {"GPU-1": gpu}
    with pytest.raises(RuntimeError):
        executor._allocate_gpus(job_id=1, gpu_count=1, profile="2g.10gb")


def test_build_gpu_environment(mock_settings, sample_gpu_job):
    """Test GPU environment variable building."""
    executor = GPUExecutor(mock_settings)
    allocated_gpus = ["GPU-1", "GPU-2"]
    
    env = executor._build_gpu_environment(sample_gpu_job, allocated_gpus)
    
    # Check standard variables
    assert env["GITHUB_REPOSITORY"] == sample_gpu_job.repository.full_name
    assert env["NIMBUS_EXECUTOR"] == "gpu"
    
    # Check GPU-specific variables
    assert env["CUDA_VISIBLE_DEVICES"] == "0,1"  # Mapped to indices
    assert env["NVIDIA_VISIBLE_DEVICES"] == "GPU-1,GPU-2"
    assert env["NVIDIA_DRIVER_CAPABILITIES"] == "compute,utility"
    assert env["NIMBUS_GPU_COUNT"] == "2"


@pytest.mark.asyncio
@patch('src.nimbus.runners.gpu.docker.DockerClient')
async def test_gpu_executor_prepare(mock_docker, mock_settings, sample_gpu_job):
    """Test GPU executor prepare method."""
    mock_client = Mock()
    mock_docker.return_value = mock_client
    
    executor = GPUExecutor()
    
    # Mock initialization components
    with patch.object(executor, '_check_nvidia_docker', return_value=True), \
         patch.object(executor, '_discover_gpus'), \
         patch.object(executor, '_allocate_gpus', return_value=["GPU-1", "GPU-2"]), \
         patch.object(Path, 'mkdir'):
        
        executor.initialize(mock_settings)
        await executor.prepare(sample_gpu_job)
    
    # Verify job is tracked
    assert sample_gpu_job.job_id in executor._job_workspaces
    assert sample_gpu_job.job_id in executor._gpu_allocations
    assert len(executor._gpu_allocations[sample_gpu_job.job_id]) == 2


@pytest.mark.asyncio
@patch('src.nimbus.runners.gpu.docker.DockerClient')
@patch('src.nimbus.runners.gpu.subprocess.run')
async def test_gpu_executor_cgroup_enforcement(mock_run, mock_docker, mock_settings, sample_gpu_job):
    mock_run.return_value = Mock(returncode=0, stdout='{"nvidia": {"path": "runtime"}}')

    def run_side_effect(cmd, **kwargs):
        if "nvidia-smi" in cmd:
            return Mock(returncode=0, stdout="0, Tesla V100, GPU-12345, 32768, 30720, 7.0, 470.82")
        return Mock(returncode=0, stdout='{"nvidia": {"path": "runtime"}}')

    mock_run.side_effect = run_side_effect

    mock_client = Mock()
    mock_docker.return_value = mock_client
    mock_client.ping.return_value = True
    mock_client.containers.create.return_value = Mock(wait=lambda timeout: {'StatusCode': 0}, logs=lambda **kw: b'')

    mock_settings.gpu_enable_cgroup_enforcement = True

    executor = GPUExecutor()
    executor.initialize(mock_settings)

    with patch('pathlib.Path.mkdir'), patch.object(executor, '_allocate_gpus', return_value=["GPU-1"]):
        await executor.prepare(sample_gpu_job)

    assert sample_gpu_job.job_id in executor._cgroup_constraints


@pytest.mark.asyncio
async def test_gpu_executor_cleanup(mock_settings, sample_gpu_job):
    """Test GPU executor cleanup."""
    executor = GPUExecutor(mock_settings)
    
    # Set up executor state
    mock_container = Mock()
    executor._job_containers[sample_gpu_job.job_id] = mock_container
    executor._job_workspaces[sample_gpu_job.job_id] = Path("/tmp/test")
    executor._gpu_allocations[sample_gpu_job.job_id] = ["GPU-1", "GPU-2"]
    
    with patch('shutil.rmtree'), patch.object(Path, 'exists', return_value=True):
        await executor.cleanup(sample_gpu_job.job_id)
    
    # Verify cleanup
    mock_container.remove.assert_called_once_with(force=True)
    assert sample_gpu_job.job_id not in executor._job_containers
    assert sample_gpu_job.job_id not in executor._job_workspaces
    assert sample_gpu_job.job_id not in executor._gpu_allocations


@pytest.mark.asyncio
@patch('src.nimbus.runners.gpu.docker.DockerClient')
async def test_ensure_gpu_image_pulls_missing(mock_docker, mock_settings):
    """Test GPU image ensure pulls missing images."""
    from docker.errors import ImageNotFound
    
    mock_client = Mock()
    mock_docker.return_value = mock_client
    
    # Mock image not found, then successful pull
    mock_client.images.get.side_effect = ImageNotFound("Image not found")
    mock_client.images.pull.return_value = Mock()
    
    executor = GPUExecutor()
    
    with patch.object(executor, '_check_nvidia_docker', return_value=True), \
         patch.object(executor, '_discover_gpus'):
        executor.initialize(mock_settings)
    
    await executor._ensure_image("nvcr.io/nvidia/pytorch:23.10-py3")
    
    mock_client.images.pull.assert_called_once_with("nvcr.io/nvidia/pytorch:23.10-py3")


def test_gpu_capabilities_with_discovered_gpus():
    """Test GPU capabilities after GPU discovery."""
    executor = GPUExecutor()
    
    # Mock discovered GPUs
    executor._available_gpus = {
        "GPU-1": GPUInfo({
            "cuda_version": "12.2",
            "compute_capability": "8.0"
        }),
        "GPU-2": GPUInfo({
            "cuda_version": "11.8", 
            "compute_capability": "7.5"
        })
    }
    
    capabilities = executor.capabilities
    
    # Check CUDA version capabilities
    assert "cuda-12" in capabilities
    assert "cuda-12.2" in capabilities
    assert "cuda-11" in capabilities
    assert "cuda-11.8" in capabilities
    
    # Check compute capabilities
    assert "sm_8_0" in capabilities
    assert "sm_7_5" in capabilities


@pytest.mark.skipif(True, reason="Requires real nvidia-docker setup")
@pytest.mark.integration
@pytest.mark.asyncio
async def test_gpu_executor_integration():
    """Integration test with real GPU setup (requires nvidia-docker)."""
    # This would be a full integration test but requires:
    # 1. nvidia-docker runtime
    # 2. Actual GPUs
    # 3. CUDA drivers
    # Skip by default, enable for GPU CI environments
    
    executor = GPUExecutor()
    # ... integration test code would go here
    pass
