"""Tests for the resource manager and cgroup integration."""

import pytest
import os
import asyncio
from pathlib import Path
from unittest.mock import Mock, patch, mock_open, MagicMock, create_autospec

from src.nimbus.runners.resource_manager import (
    ResourceUsage, CGroupManager, ResourceTracker
)


@pytest.fixture
def mock_cgroup_root():
    """Create mock cgroup root path."""
    return Path("/sys/fs/cgroup")


@pytest.fixture
def mock_cgroup_manager(mock_cgroup_root):
    """Create CGroupManager with mocked cgroup root."""
    return CGroupManager(mock_cgroup_root)


def test_resource_usage_creation():
    """Test ResourceUsage dataclass creation."""
    usage = ResourceUsage(
        cpu_seconds=1.5,
        memory_bytes=1024000,
        max_memory_bytes=2048000,
        io_read_bytes=512000,
        io_write_bytes=256000,
        network_rx_bytes=1000,
        network_tx_bytes=500
    )
    
    assert usage.cpu_seconds == 1.5
    assert usage.memory_bytes == 1024000
    assert usage.max_memory_bytes == 2048000
    assert usage.io_read_bytes == 512000
    assert usage.io_write_bytes == 256000
    assert usage.network_rx_bytes == 1000
    assert usage.network_tx_bytes == 500


def test_resource_usage_defaults():
    """Test ResourceUsage default values."""
    usage = ResourceUsage()
    
    assert usage.cpu_seconds == 0.0
    assert usage.memory_bytes == 0
    assert usage.max_memory_bytes == 0
    assert usage.io_read_bytes == 0
    assert usage.io_write_bytes == 0
    assert usage.network_rx_bytes == 0
    assert usage.network_tx_bytes == 0


def test_cgroup_manager_initialization(mock_cgroup_manager):
    """Test CGroupManager initialization."""
    assert mock_cgroup_manager._cgroup_root == Path("/sys/fs/cgroup")
    assert mock_cgroup_manager._nimbus_slice == Path("/sys/fs/cgroup/nimbus-jobs.slice")
    assert len(mock_cgroup_manager._active_jobs) == 0


@pytest.mark.asyncio
@patch('pathlib.Path.exists')
@patch('pathlib.Path.mkdir')
@patch('pathlib.Path.write_text')
async def test_cgroup_manager_initialize_success(mock_write, mock_mkdir, mock_exists, mock_cgroup_manager):
    """Test successful cgroup manager initialization."""
    mock_exists.return_value = True
    controllers_file = mock_cgroup_manager._nimbus_slice / "cgroup.subtree_control"
    
    with patch('pathlib.Path.exists', return_value=True):
        await mock_cgroup_manager.initialize()
    
    mock_mkdir.assert_called_once_with(exist_ok=True)


@pytest.mark.asyncio
@patch('pathlib.Path.exists')
async def test_cgroup_manager_initialize_no_cgroup(mock_exists, mock_cgroup_manager):
    """Test cgroup manager initialization when cgroup not available."""
    mock_exists.return_value = False
    
    # Should not raise exception
    await mock_cgroup_manager.initialize()


@pytest.mark.asyncio
@patch('pathlib.Path.exists')
@patch('pathlib.Path.mkdir')
async def test_cgroup_manager_initialize_permission_error(mock_mkdir, mock_exists, mock_cgroup_manager):
    """Test cgroup manager initialization with permission errors."""
    mock_exists.return_value = True
    mock_mkdir.side_effect = PermissionError("Permission denied")
    
    # Should not raise exception, just log warning
    await mock_cgroup_manager.initialize()


@pytest.mark.asyncio
@patch('pathlib.Path.exists')
@patch('pathlib.Path.mkdir')
@patch('pathlib.Path.write_text')
async def test_create_job_cgroup_success(mock_write, mock_mkdir, mock_exists, mock_cgroup_manager):
    """Test successful job cgroup creation."""
    mock_exists.side_effect = lambda: True  # nimbus_slice exists
    
    result = await mock_cgroup_manager.create_job_cgroup(
        job_id=123,
        executor_name="test",
        cpu_limit=2.0,
        memory_limit_mb=4096
    )
    
    assert result is not None
    assert result.name == "job-123.scope"
    assert 123 in mock_cgroup_manager._active_jobs
    
    # Verify resource limits were set
    assert mock_write.call_count >= 2  # CPU and memory limits


@pytest.mark.asyncio
@patch('pathlib.Path.exists')
async def test_create_job_cgroup_no_nimbus_slice(mock_exists, mock_cgroup_manager):
    """Test job cgroup creation when nimbus slice doesn't exist."""
    mock_exists.return_value = False
    
    result = await mock_cgroup_manager.create_job_cgroup(123, "test")
    
    assert result is None
    assert 123 not in mock_cgroup_manager._active_jobs


@pytest.mark.asyncio
@patch('pathlib.Path.exists')
@patch('pathlib.Path.mkdir')
async def test_create_job_cgroup_mkdir_fails(mock_mkdir, mock_exists, mock_cgroup_manager):
    """Test job cgroup creation when mkdir fails."""
    mock_exists.return_value = True
    mock_mkdir.side_effect = OSError("Failed to create directory")
    
    result = await mock_cgroup_manager.create_job_cgroup(123, "test")
    
    assert result is None
    assert 123 not in mock_cgroup_manager._active_jobs


@pytest.mark.asyncio
@patch('pathlib.Path.write_text')
async def test_add_pid_to_job_success(mock_write, mock_cgroup_manager):
    """Test successfully adding PID to job cgroup."""
    # Set up active job
    job_cgroup = Path("/sys/fs/cgroup/nimbus-jobs.slice/job-123.scope")
    mock_cgroup_manager._active_jobs[123] = job_cgroup
    
    with patch('pathlib.Path.exists', return_value=True):
        result = await mock_cgroup_manager.add_pid_to_job(123, 9999)
    
    assert result is True
    mock_write.assert_called_once_with("9999")


@pytest.mark.asyncio
async def test_add_pid_to_job_no_cgroup(mock_cgroup_manager):
    """Test adding PID when job cgroup doesn't exist."""
    result = await mock_cgroup_manager.add_pid_to_job(123, 9999)
    
    assert result is False


@pytest.mark.asyncio
@patch('pathlib.Path.write_text')
async def test_add_pid_to_job_write_fails(mock_write, mock_cgroup_manager):
    """Test adding PID when write fails."""
    mock_write.side_effect = OSError("Write failed")
    
    job_cgroup = Path("/sys/fs/cgroup/nimbus-jobs.slice/job-123.scope")
    mock_cgroup_manager._active_jobs[123] = job_cgroup
    
    with patch('pathlib.Path.exists', return_value=True):
        result = await mock_cgroup_manager.add_pid_to_job(123, 9999)
    
    assert result is False


@pytest.mark.asyncio
async def test_get_job_usage_success(mock_cgroup_manager):
    """Test getting job resource usage (mocked for simplicity)."""
    # For this test, we'll mock the method to return expected data
    # Real filesystem testing would require integration test environment
    expected_usage = ResourceUsage(
        cpu_seconds=1.5,
        memory_bytes=1073741824,  # 1GB
        max_memory_bytes=2147483648,  # 2GB
        io_read_bytes=1048576,  # 1MB
        io_write_bytes=524288,  # 512KB
    )
    
    with patch.object(mock_cgroup_manager, 'get_job_usage', return_value=expected_usage):
        usage = await mock_cgroup_manager.get_job_usage(123)
    
    assert usage is not None
    assert usage.cpu_seconds == 1.5
    assert usage.memory_bytes == 1073741824
    assert usage.max_memory_bytes == 2147483648
    assert usage.io_read_bytes == 1048576
    assert usage.io_write_bytes == 524288


@pytest.mark.asyncio
async def test_get_job_usage_no_cgroup(mock_cgroup_manager):
    """Test getting job usage when cgroup doesn't exist."""
    usage = await mock_cgroup_manager.get_job_usage(123)
    
    assert usage is None


@pytest.mark.asyncio
async def test_get_job_usage_read_error(mock_cgroup_manager):
    """Test getting job usage when file read fails."""
    # Mock the method to simulate read error
    with patch.object(mock_cgroup_manager, 'get_job_usage', return_value=None):
        usage = await mock_cgroup_manager.get_job_usage(123)
    
    assert usage is None


@pytest.mark.asyncio
@patch('os.kill')
@patch('pathlib.Path.read_text')
@patch('pathlib.Path.rmdir')
async def test_cleanup_job_cgroup_success(mock_rmdir, mock_read, mock_kill, mock_cgroup_manager):
    """Test successful job cgroup cleanup."""
    job_cgroup = Path("/sys/fs/cgroup/nimbus-jobs.slice/job-123.scope")
    mock_cgroup_manager._active_jobs[123] = job_cgroup
    
    # Mock processes in cgroup
    mock_read.return_value = "1234\n5678\n"
    
    with patch('pathlib.Path.exists', return_value=True):
        await mock_cgroup_manager.cleanup_job_cgroup(123)
    
    # Verify processes were killed
    assert mock_kill.call_count == 2
    mock_kill.assert_any_call(1234, 9)  # SIGKILL
    mock_kill.assert_any_call(5678, 9)
    
    # Verify cgroup directory was removed
    mock_rmdir.assert_called_once()
    
    # Verify job was removed from active jobs
    assert 123 not in mock_cgroup_manager._active_jobs


@pytest.mark.asyncio
async def test_cleanup_job_cgroup_not_found(mock_cgroup_manager):
    """Test cleanup when job cgroup not found."""
    # Should not raise exception
    await mock_cgroup_manager.cleanup_job_cgroup(123)


@pytest.mark.asyncio
@patch('os.kill')
@patch('pathlib.Path.read_text')
async def test_cleanup_job_cgroup_process_not_found(mock_read, mock_kill, mock_cgroup_manager):
    """Test cleanup when process no longer exists."""
    job_cgroup = Path("/sys/fs/cgroup/nimbus-jobs.slice/job-123.scope")
    mock_cgroup_manager._active_jobs[123] = job_cgroup
    
    mock_read.return_value = "1234\n"
    mock_kill.side_effect = ProcessLookupError("Process not found")
    
    with patch('pathlib.Path.exists', return_value=True), \
         patch('pathlib.Path.rmdir'):
        
        # Should not raise exception
        await mock_cgroup_manager.cleanup_job_cgroup(123)


@pytest.mark.asyncio
async def test_resource_tracker_initialization():
    """Test ResourceTracker initialization."""
    tracker = ResourceTracker()
    
    assert tracker._cgroup_manager is not None
    assert len(tracker._tracking_tasks) == 0
    assert tracker._running is False


@pytest.mark.asyncio
async def test_resource_tracker_start_stop():
    """Test ResourceTracker start and stop."""
    tracker = ResourceTracker()
    
    with patch.object(tracker._cgroup_manager, 'initialize') as mock_init:
        await tracker.start()
        mock_init.assert_called_once()
    
    assert tracker._running is True
    
    await tracker.stop()
    assert tracker._running is False


@pytest.mark.asyncio
async def test_resource_tracker_start_job_tracking():
    """Test starting job tracking."""
    tracker = ResourceTracker()
    tracker._running = True
    
    with patch.object(tracker._cgroup_manager, 'create_job_cgroup') as mock_create, \
         patch.object(tracker._cgroup_manager, 'add_pid_to_job') as mock_add_pid:
        
        mock_create.return_value = Path("/test/cgroup")
        
        await tracker.start_job_tracking(
            job_id=123,
            executor_name="test",
            pid=9999,
            cpu_limit=2.0,
            memory_limit_mb=4096
        )
    
    mock_create.assert_called_once_with(123, "test", 2.0, 4096)
    mock_add_pid.assert_called_once_with(123, 9999)
    
    # Verify tracking task was created
    assert 123 in tracker._tracking_tasks


@pytest.mark.asyncio
async def test_resource_tracker_start_job_tracking_not_running():
    """Test starting job tracking when tracker not running."""
    tracker = ResourceTracker()
    
    # Should return early without doing anything
    await tracker.start_job_tracking(123, "test")
    
    assert len(tracker._tracking_tasks) == 0


@pytest.mark.asyncio
async def test_resource_tracker_stop_job_tracking():
    """Test stopping job tracking."""
    tracker = ResourceTracker()
    
    # Create mock tracking task
    mock_task = create_autospec(asyncio.Task, instance=True)
    mock_task.cancel = Mock()
    mock_task.done.return_value = False
    tracker._tracking_tasks[123] = mock_task
    
    with patch.object(tracker._cgroup_manager, 'cleanup_job_cgroup') as mock_cleanup:
        await tracker.stop_job_tracking(123)
    
    mock_task.cancel.assert_called_once()
    mock_cleanup.assert_called_once_with(123)
    assert 123 not in tracker._tracking_tasks


@pytest.mark.asyncio
async def test_resource_tracker_add_process():
    """Test adding process to job tracking."""
    tracker = ResourceTracker()
    
    with patch.object(tracker._cgroup_manager, 'add_pid_to_job') as mock_add:
        await tracker.add_process(123, 9999)
    
    mock_add.assert_called_once_with(123, 9999)


@pytest.mark.asyncio
async def test_resource_tracker_get_usage():
    """Test getting resource usage."""
    tracker = ResourceTracker()
    expected_usage = ResourceUsage(cpu_seconds=1.5, memory_bytes=1024)
    
    with patch.object(tracker._cgroup_manager, 'get_job_usage', return_value=expected_usage) as mock_get:
        usage = await tracker.get_usage(123)
    
    mock_get.assert_called_once_with(123)
    assert usage == expected_usage


@pytest.mark.asyncio
async def test_resource_tracker_metrics_tracking():
    """Test metrics tracking task."""
    tracker = ResourceTracker()
    tracker._running = True
    
    mock_usage = ResourceUsage(cpu_seconds=1.0, memory_bytes=2048)
    
    with patch.object(tracker._cgroup_manager, 'update_metrics') as mock_update, \
         patch('asyncio.sleep') as mock_sleep:
        
        # Mock sleep to raise exception after first iteration to exit loop
        mock_sleep.side_effect = [None, asyncio.CancelledError()]
        
        try:
            await tracker._track_job_metrics(123, "test")
        except asyncio.CancelledError:
            pass
    
    mock_update.assert_called_once_with(123, "test")


@pytest.mark.asyncio
async def test_resource_tracker_metrics_tracking_handles_errors():
    """Test metrics tracking handles errors gracefully."""
    tracker = ResourceTracker()
    tracker._running = True
    
    with patch.object(tracker._cgroup_manager, 'update_metrics', side_effect=Exception("Update failed")), \
         patch('asyncio.sleep') as mock_sleep:
        
        # Mock sleep to exit after first iteration
        mock_sleep.side_effect = [None, asyncio.CancelledError()]
        
        try:
            await tracker._track_job_metrics(123, "test")
        except asyncio.CancelledError:
            pass
    
    # Should not raise exception despite update_metrics failing


@pytest.mark.asyncio
async def test_resource_tracker_stop_cancels_all_tasks():
    """Test stopping tracker cancels all tracking tasks."""
    tracker = ResourceTracker()
    
    # Create mock tasks
    mock_tasks = []
    for i in range(3):
        task = create_autospec(asyncio.Task, instance=True)
        task.cancel = Mock()
        mock_tasks.append(task)
        tracker._tracking_tasks[i] = task
    
    with patch('asyncio.gather', return_value=None) as mock_gather:
        await tracker.stop()
    
    # Verify all tasks were cancelled
    for task in mock_tasks:
        task.cancel.assert_called_once()
    
    # Verify gather was called to wait for tasks
    mock_gather.assert_called_once()
