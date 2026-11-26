"""Tests for how the daemon responds to file watcher events."""

import asyncio
from pathlib import Path
import pytest
from reccmp.project.common import (
    RECCMP_BUILD_CONFIG,
    RECCMP_PROJECT_CONFIG,
    RECCMP_USER_CONFIG,
)
from reccmp.project.config import (
    BuildFile,
    BuildFileTarget,
    Hash,
    ProjectFile,
    ProjectFileTarget,
    UserFile,
    UserFileTarget,
)
from reccmp.project.detect import RecCmpProject
from reccmp.remote.server import DaemonApp, DaemonStatus
from reccmp.remote.watch import WatchEvent
from .constants import LEGO1_SHA256


@pytest.fixture(name="daemon")
def fixture_daemon(tmp_path: Path) -> DaemonApp:
    project_path = tmp_path / "project"
    project_path.mkdir()
    build_path = tmp_path / "build"
    build_path.mkdir()

    ProjectFile(
        targets={
            "ISLE": ProjectFileTarget(
                filename="ISLE.EXE",
                source_root=(Path("src"),),
                hash=Hash(sha256=LEGO1_SHA256),
            )
        }
    ).write_file(project_path / RECCMP_PROJECT_CONFIG)
    UserFile(targets={"ISLE": UserFileTarget(path=Path("ISLE.EXE"))}).write_file(
        project_path / RECCMP_USER_CONFIG
    )
    BuildFile(
        project=project_path,
        targets={"ISLE": BuildFileTarget(path=Path("ISLE.EXE"), pdb=Path("ISLE.PDB"))},
    ).write_file(build_path / RECCMP_BUILD_CONFIG)

    project = RecCmpProject.from_directory(build_path, alert=False)
    return DaemonApp(project, project.get("ISLE"))


def send(daemon: DaemonApp, *events: WatchEvent):
    for event in events:
        daemon.handle_watch_event(event)


def test_code_change_during_cooldown_drops_recompile(daemon: DaemonApp):
    """A code change after the artifacts are written makes the recompile out of date."""
    send(
        daemon,
        WatchEvent.ARTIFACT_CHANGED,
        WatchEvent.CODE_CHANGED,
        WatchEvent.RECOMPILED,
    )
    assert daemon.status is DaemonStatus.STALE
    assert not daemon.reset_requested.is_set()


def test_data_change_while_stale_is_dropped(daemon: DaemonApp):
    """A data change is dropped while the build is stale."""
    send(daemon, WatchEvent.CODE_CHANGED, WatchEvent.DATA_CHANGED)
    assert daemon.status is DaemonStatus.STALE
    assert not daemon.reset_requested.is_set()


def test_data_change_during_cooldown_is_dropped(daemon: DaemonApp):
    """A data change is dropped while a recompile is pending."""
    send(daemon, WatchEvent.ARTIFACT_CHANGED, WatchEvent.DATA_CHANGED)
    assert daemon.status is DaemonStatus.STALE
    assert not daemon.reset_requested.is_set()


def test_data_change_after_deleted_artifact_waits_for_recompile(daemon: DaemonApp):
    """Data changes are dropped from an artifact delete until the next recompile."""
    send(daemon, WatchEvent.ARTIFACT_DELETED, WatchEvent.DATA_CHANGED)
    assert daemon.status is DaemonStatus.STALE
    assert not daemon.reset_requested.is_set()

    send(daemon, WatchEvent.ARTIFACT_CHANGED, WatchEvent.RECOMPILED)
    assert daemon.reset_requested.is_set()


def test_config_failure_drops_other_events(daemon: DaemonApp):
    """CLAUDE SAYS: After a config failure only a config change leaves the failed state."""
    send(
        daemon,
        WatchEvent.CONFIG_FAILED,
        WatchEvent.CODE_CHANGED,
        WatchEvent.ARTIFACT_CHANGED,
        WatchEvent.RECOMPILED,
        WatchEvent.DATA_CHANGED,
    )
    assert daemon.status is DaemonStatus.FAILED
    assert not daemon.reset_requested.is_set()

    send(daemon, WatchEvent.CONFIG_CHANGED)
    assert daemon.status is DaemonStatus.BUILDING


def test_config_change_takes_staleness_from_restart(daemon: DaemonApp):
    """A config change clears the stale state left by an earlier code change."""
    send(daemon, WatchEvent.CODE_CHANGED, WatchEvent.CONFIG_CHANGED)
    # CLAUDE SAYS: Stand in for the reset worker finishing.
    daemon.reset_requested.clear()
    assert daemon.status is DaemonStatus.READY


def test_artifact_write_makes_results_stale(daemon: DaemonApp):
    """Results are stale while the exe and pdb are being written."""
    daemon.handle_watch_event(WatchEvent.ARTIFACT_CHANGED)
    assert daemon.status is DaemonStatus.STALE


def test_code_change_makes_results_stale(daemon: DaemonApp):
    daemon.handle_watch_event(WatchEvent.CODE_CHANGED)
    assert daemon.status is DaemonStatus.STALE
    assert not daemon.reset_requested.is_set()


def test_recompile_after_code_change_resets(daemon: DaemonApp):
    daemon.handle_watch_event(WatchEvent.CODE_CHANGED)
    daemon.handle_watch_event(WatchEvent.ARTIFACT_CHANGED)
    daemon.handle_watch_event(WatchEvent.RECOMPILED)
    assert daemon.reset_requested.is_set()


def test_data_change_resets(daemon: DaemonApp):
    daemon.handle_watch_event(WatchEvent.DATA_CHANGED)
    assert daemon.reset_requested.is_set()


def test_config_change_resets(daemon: DaemonApp):
    daemon.handle_watch_event(WatchEvent.CODE_CHANGED)
    daemon.handle_watch_event(WatchEvent.CONFIG_CHANGED)
    assert daemon.reset_requested.is_set()


def test_config_failure(daemon: DaemonApp):
    daemon.watcher.error = "Traceback"
    daemon.handle_watch_event(WatchEvent.CONFIG_FAILED)
    assert daemon.status is DaemonStatus.FAILED
    assert daemon.error == "Traceback"


def test_config_failure_during_reset(daemon: DaemonApp):
    """A config failure during a reset is still a failure after the reset finishes."""
    daemon.watcher.error = "Traceback"
    daemon.reset = lambda: daemon.handle_watch_event(  # type: ignore[method-assign]
        WatchEvent.CONFIG_FAILED
    )

    async def scenario():
        loop = asyncio.get_running_loop()
        daemon.request_reset()
        worker = asyncio.create_task(daemon.reset_worker())
        await asyncio.sleep(0)
        # The executor has one thread, so this waits for the reset.
        await loop.run_in_executor(daemon.executor, lambda: None)
        await asyncio.sleep(0)
        worker.cancel()
        await worker

    asyncio.run(scenario())
    assert daemon.status is DaemonStatus.FAILED
    assert daemon.error == "Traceback"
