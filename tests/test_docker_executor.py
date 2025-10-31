"""Tests for the Docker executor."""

import pytest
import os
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, AsyncMock, patch, MagicMock

from src.nimbus.runners.docker import DockerExecutor
from src.nimbus.runners.base import RunResult
from src.nimbus.common.schemas import JobAssignment, GitHubRepository, RunnerRegistrationToken, CacheToken
from src.nimbus.common.settings import HostAgentSettings


@pytest.fixture
def mock_settings():
    """Create mock settings for Docker executor."""
    settings = Mock(spec=HostAgentSettings)
    settings.docker_socket_path = "/var/run/docker.sock"
    settings.docker_network_name = "nimbus-test"
    settings.docker_workspace_path = Path("/tmp/test-workspaces")
    settings.docker_default_image = "ubuntu:22.04"
    settings.docker_container_user = None
    settings.metadata_endpoint_denylist = []
    settings.egress_policy_pack = None
    settings.offline_mode = False
    settings.artifact_registry_allow_list = []
    settings.image_allow_list_path = None
    settings.image_deny_list_path = None
    settings.cosign_certificate_authority = None
    settings.provenance_required = False
    settings.provenance_grace_seconds = 0
    settings.slsa_attestation_dir = None
    settings.slsa_allowed_builders = []
    settings.slsa_predicate_type = "https://slsa.dev/provenance/v1"
    settings.slsa_required = False
    return settings


@pytest.fixture
def sample_job():
    """Create a sample job assignment."""
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
    
    cache_token = CacheToken(
        token="cache-token",
        organization_id=456,
        expires_at=datetime.now(timezone.utc)
    )
    
    return JobAssignment(
        job_id=2001,
        run_id=3001, 
        run_attempt=1,
        repository=repo,
        labels=["nimbus", "docker"],
        runner_registration=token,
        cache_token=cache_token,
        executor="docker"
    )


def test_docker_executor_properties():
    """Test Docker executor basic properties."""
    executor = DockerExecutor()
    
    assert executor.name == "docker"
    
    capabilities = executor.capabilities
    assert "docker" in capabilities
    assert "container" in capabilities
    assert "fast-start" in capabilities


@patch('src.nimbus.runners.docker.docker.DockerClient')
@patch('src.nimbus.runners.docker.EgressPolicyPack')
@patch('src.nimbus.runners.docker.MetadataEndpointDenylist')
def test_docker_executor_initialization(mock_denylist, mock_policy, mock_docker_client, mock_settings):
    """Test Docker executor initialization."""
    # Mock Docker client
    mock_client = Mock()
    mock_docker_client.return_value = mock_client
    
    # Mock network operations
    from docker.errors import NotFound
    mock_network = Mock()
    mock_client.networks.get.side_effect = NotFound("Network not found")
    mock_client.networks.create.return_value = mock_network
    
    executor = DockerExecutor()
    executor.initialize(mock_settings)
    
    # Verify Docker client was created
    mock_docker_client.assert_called_once()
    mock_client.ping.assert_called_once()
    
    # Verify network creation was attempted
    mock_client.networks.create.assert_called_once()


@patch('src.nimbus.runners.docker.docker.DockerClient')
def test_docker_executor_initialization_failure(mock_docker_client, mock_settings):
    """Test Docker executor initialization failure."""
    # Mock Docker client ping to fail after successful creation
    mock_client = Mock()
    mock_client.ping.side_effect = Exception("Docker not available")
    mock_docker_client.return_value = mock_client
    
    executor = DockerExecutor()
    
    with pytest.raises(RuntimeError, match="Docker initialization failed"):
        executor.initialize(mock_settings)


@pytest.mark.asyncio
@patch('src.nimbus.runners.docker.docker.DockerClient')
async def test_docker_executor_prepare(mock_docker_client, mock_settings, sample_job):
    """Test Docker executor prepare method."""
    mock_client = Mock()
    mock_docker_client.return_value = mock_client
    mock_client.networks.get.return_value = Mock()  # Network exists
    
    executor = DockerExecutor()
    executor.initialize(mock_settings)
    
    # Mock Path.mkdir to avoid actual directory creation
    with patch.object(Path, 'mkdir') as mock_mkdir:
        await executor.prepare(sample_job)
    
    # Verify workspace directory creation
    assert mock_mkdir.call_count >= 1
    
    # Verify job is tracked
    assert sample_job.job_id in executor._job_workspaces


@pytest.mark.asyncio  
async def test_docker_executor_prepare_without_initialization(sample_job):
    """Test prepare fails without initialization."""
    executor = DockerExecutor()
    
    with pytest.raises(RuntimeError, match="DockerExecutor not initialized"):
        await executor.prepare(sample_job)


def test_get_container_image_custom_label(mock_settings, sample_job):
    """Test container image selection with custom image label."""
    executor = DockerExecutor(mock_settings)
    
    # Test custom image from label
    sample_job.labels = ["image:python:3.9-slim"]
    image = executor._get_container_image(sample_job)
    assert image == "python:3.9-slim"

    # Prebuilt image alias should map to maintained image
    sample_job.labels = ["image:ubuntu-2204"]
    image = executor._get_container_image(sample_job)
    assert image == "nimbus/ubuntu-2204-runner:latest"


def test_get_container_image_mapped_labels(mock_settings, sample_job):
    """Test container image selection with mapped labels."""
    executor = DockerExecutor(mock_settings)
    
    # Test mapped labels
    test_cases = [
        (["ubuntu-22.04"], "nimbus/ubuntu-2204-runner:latest"),
        (["node"], "nimbus/node-22-runner:latest"),
        (["python"], "nimbus/python-312-runner:latest"),
        (["golang"], "golang:1.21-alpine"),
    ]
    
    for labels, expected_image in test_cases:
        sample_job.labels = labels
        image = executor._get_container_image(sample_job)
        assert image == expected_image


def test_get_container_image_default(mock_settings, sample_job):
    """Test container image selection falls back to default."""
    executor = DockerExecutor(mock_settings) 
    
    # Test with no matching labels
    sample_job.labels = ["random", "labels"]
    image = executor._get_container_image(sample_job)
    assert image == mock_settings.docker_default_image


@pytest.mark.asyncio
@patch('src.nimbus.runners.docker.docker.DockerClient')
async def test_docker_executor_enforces_provenance(mock_docker_client, tmp_path, mock_settings, sample_job, monkeypatch):
    cosign_key = tmp_path / "cosign.pub"
    cosign_key.write_text("public key", encoding="utf-8")

    mock_settings.image_allow_list_path = None
    mock_settings.image_deny_list_path = None
    mock_settings.cosign_certificate_authority = cosign_key
    mock_settings.provenance_required = True

    executor = DockerExecutor()

    mock_client = Mock()
    mock_docker_client.return_value = mock_client
    mock_client.ping.return_value = True
    mock_client.networks.get.return_value = Mock()
    mock_client.containers.create.return_value = Mock(wait=lambda timeout: {'StatusCode': 0}, logs=lambda **kw: b'')

    with patch('src.nimbus.runners.docker.EgressPolicyPack'), patch('src.nimbus.runners.docker.MetadataEndpointDenylist'):
        executor.initialize(mock_settings)

    sample_job.labels = ["nimbus", "docker"]

    with patch('src.nimbus.runners.docker.ensure_provenance') as ensure_mock:
        ensure_mock.return_value = None
        with patch.object(executor, '_ensure_image'):
            await executor.prepare(sample_job)
            await executor.run(sample_job, timeout_seconds=1)

        ensure_mock.assert_called()


def test_build_environment_variables(mock_settings, sample_job):
    """Test environment variable building."""
    executor = DockerExecutor(mock_settings)
    
    env = executor._build_environment(sample_job)
    
    # Check standard GitHub Actions variables
    assert env["CI"] == "true"
    assert env["GITHUB_ACTIONS"] == "true"
    assert env["GITHUB_REPOSITORY"] == sample_job.repository.full_name
    assert env["GITHUB_JOB"] == str(sample_job.job_id)
    assert env["GITHUB_RUN_ID"] == str(sample_job.run_id)
    
    # Check Nimbus-specific variables
    assert env["NIMBUS_JOB_ID"] == str(sample_job.job_id)
    assert env["NIMBUS_EXECUTOR"] == "docker"
    assert env["ACTIONS_RUNNER_TOKEN"] == sample_job.runner_registration.token
    
    # Check cache token
    if sample_job.cache_token:
        assert "ACTIONS_CACHE_URL" in env
        assert "ACTIONS_RUNTIME_TOKEN" in env


@pytest.mark.asyncio
@patch('src.nimbus.runners.docker.docker.DockerClient')
async def test_ensure_image_exists_locally(mock_docker_client, mock_settings):
    """Test image ensure when image exists locally."""
    mock_client = Mock()
    mock_docker_client.return_value = mock_client
    
    # Mock image exists
    mock_image = Mock()
    mock_client.images.get.return_value = mock_image
    
    executor = DockerExecutor()
    executor.initialize(mock_settings)
    
    await executor._ensure_image("ubuntu:22.04")
    
    # Verify get was called but not pull
    mock_client.images.get.assert_called_once_with("ubuntu:22.04")
    mock_client.images.pull.assert_not_called()


@pytest.mark.asyncio
@patch('src.nimbus.runners.docker.docker.DockerClient')
async def test_ensure_image_pulls_missing_image(mock_docker_client, mock_settings):
    """Test image ensure when image needs to be pulled."""
    from docker.errors import ImageNotFound
    
    mock_client = Mock()
    mock_docker_client.return_value = mock_client
    
    # Mock image not found, then successful pull
    mock_client.images.get.side_effect = ImageNotFound("Image not found")
    mock_client.images.pull.return_value = Mock()
    
    executor = DockerExecutor()
    executor.initialize(mock_settings)
    
    await executor._ensure_image("ubuntu:22.04")
    
    # Verify both get and pull were called
    mock_client.images.get.assert_called_once_with("ubuntu:22.04")
    mock_client.images.pull.assert_called_once_with("ubuntu:22.04")


@pytest.mark.asyncio
@patch('src.nimbus.runners.docker.docker.DockerClient')
async def test_ensure_image_pull_failure(mock_docker_client, mock_settings):
    """Test image ensure when pull fails."""
    from docker.errors import ImageNotFound
    
    mock_client = Mock()
    mock_docker_client.return_value = mock_client
    
    # Mock image not found and pull failure
    mock_client.images.get.side_effect = ImageNotFound("Image not found")
    mock_client.images.pull.side_effect = Exception("Pull failed")
    
    executor = DockerExecutor()
    executor.initialize(mock_settings)
    
    with pytest.raises(RuntimeError, match="Failed to pull image"):
        await executor._ensure_image("ubuntu:22.04")


@pytest.mark.asyncio
@patch('src.nimbus.runners.docker.docker.DockerClient')
async def test_docker_executor_cleanup(mock_docker_client, mock_settings, sample_job):
    """Test Docker executor cleanup."""
    mock_client = Mock()
    mock_docker_client.return_value = mock_client
    mock_client.networks.get.return_value = Mock()
    
    # Mock container
    mock_container = Mock()
    
    executor = DockerExecutor()
    executor.initialize(mock_settings)
    
    # Set up executor state
    executor._job_containers[sample_job.job_id] = mock_container
    executor._job_workspaces[sample_job.job_id] = Path("/tmp/test-workspace")
    
    with patch('shutil.rmtree') as mock_rmtree, \
         patch.object(Path, 'exists', return_value=True):
        
        await executor.cleanup(sample_job.job_id)
    
    # Verify container removal
    mock_container.remove.assert_called_once_with(force=True)
    
    # Verify workspace removal
    mock_rmtree.assert_called_once()
    
    # Verify state cleanup
    assert sample_job.job_id not in executor._job_containers
    assert sample_job.job_id not in executor._job_workspaces


@pytest.mark.asyncio
async def test_docker_executor_cleanup_without_initialization(sample_job):
    """Test cleanup works even without initialization."""
    executor = DockerExecutor()
    
    # Should not raise an exception
    await executor.cleanup(sample_job.job_id)


@pytest.mark.asyncio
@patch('src.nimbus.runners.docker.docker.DockerClient')
async def test_docker_executor_cleanup_handles_errors(mock_docker_client, mock_settings, sample_job):
    """Test cleanup handles errors gracefully."""
    mock_client = Mock()
    mock_docker_client.return_value = mock_client
    mock_client.networks.get.return_value = Mock()
    
    # Mock container that fails to remove
    mock_container = Mock()
    mock_container.remove.side_effect = Exception("Remove failed")
    
    executor = DockerExecutor()
    executor.initialize(mock_settings)
    executor._job_containers[sample_job.job_id] = mock_container
    
    # Should handle the error gracefully
    await executor.cleanup(sample_job.job_id)
    
    # Verify cleanup still occurred
    assert sample_job.job_id not in executor._job_containers


@pytest.mark.integration
@pytest.mark.skipif(not os.path.exists("/var/run/docker.sock"), 
                   reason="Docker daemon not available")
@pytest.mark.asyncio
async def test_docker_executor_real_docker_integration():
    """Integration test with real Docker (if available)."""
    # Set up environment
    os.environ.update({
        "NIMBUS_AGENT_ID": "test-agent",
        "NIMBUS_CONTROL_PLANE_URL": "http://localhost:8000",
        "NIMBUS_CONTROL_PLANE_TOKEN": "test-token",
        "NIMBUS_ROOTFS_IMAGE": "/tmp/rootfs.ext4",
        "NIMBUS_KERNEL_IMAGE": "/tmp/kernel",
        "NIMBUS_DOCKER_WORKSPACE": "/tmp/test-docker-workspaces",
        "NIMBUS_DOCKER_DEFAULT_IMAGE": "alpine:latest",
        "NIMBUS_AGENT_STATE_DATABASE_URL": "sqlite+pysqlite:///:memory:",
    })
    
    settings = HostAgentSettings()
    executor = DockerExecutor()
    
    try:
        executor.initialize(settings)
        
        # Create a simple job
        repo = GitHubRepository(id=1, name="test", full_name="test/test", private=False)
        token = RunnerRegistrationToken(token="test", expires_at=datetime.now(timezone.utc))
        job = JobAssignment(
            job_id=999,
            run_id=1,
            run_attempt=1,
            repository=repo,
            labels=["test"],
            runner_registration=token,
            executor="docker"
        )
        
        # Test the lifecycle
        await executor.prepare(job)
        assert job.job_id in executor._job_workspaces
        
        # Cleanup
        await executor.cleanup(job.job_id)
        assert job.job_id not in executor._job_workspaces
        
    except RuntimeError as e:
        if "Docker initialization failed" in str(e):
            pytest.skip("Docker not available for integration test")
        else:
            raise
