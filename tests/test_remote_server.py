"""Tests for how the daemon responds to file watcher events."""

import asyncio
import textwrap
from collections.abc import AsyncIterator
from pathlib import Path
import pytest
from reccmp.project.common import (
    RECCMP_BUILD_CONFIG,
    RECCMP_PROJECT_CONFIG,
    RECCMP_USER_CONFIG,
)
from reccmp.project.detect import RecCmpProject
from reccmp.remote.fswatch import DiskWatch, TargetFiles
from reccmp.remote.server import DaemonApp, DaemonStatus
from reccmp.remote.watch import TargetWatcher, WatchEvent, target_loader
from .constants import LEGO1_SHA256


class BrokenDisk(DiskWatch):
    def streams(self, files: TargetFiles) -> list[AsyncIterator[set[Path]]]:
        raise RuntimeError


def make_daemon(tmp_path: Path, disk: DiskWatch | None = None) -> DaemonApp:
    project_path = tmp_path / "project"
    project_path.mkdir()
    build_path = tmp_path / "build"
    build_path.mkdir()

    (project_path / RECCMP_PROJECT_CONFIG).write_text(textwrap.dedent(f"""\
        targets:
          ISLE:
            filename: ISLE.EXE
            source-root: src
            hash:
              sha256: {LEGO1_SHA256}
        """))
    (project_path / RECCMP_USER_CONFIG).write_text(textwrap.dedent("""\
        targets:
          ISLE:
            path: ISLE.EXE
        """))
    (build_path / RECCMP_BUILD_CONFIG).write_text(textwrap.dedent(f"""\
        project: {project_path}
        targets:
          ISLE:
            path: ISLE.EXE
            pdb: ISLE.PDB
        """))

    project = RecCmpProject.from_directory(build_path, alert=False)
    target = project.get("ISLE")
    watcher = TargetWatcher(
        target,
        TargetFiles.from_target(project, target),
        target_loader(build_path, "ISLE"),
        disk,
    )
    daemon = DaemonApp(target, watcher)
    daemon.status = DaemonStatus.READY
    return daemon


@pytest.fixture(name="daemon")
def fixture_daemon(tmp_path: Path) -> DaemonApp:
    return make_daemon(tmp_path)


def test_code_change_makes_results_stale(daemon: DaemonApp):
    daemon.handle_watch_event(WatchEvent.CODE_CHANGED)
    assert daemon.status is DaemonStatus.STALE
    assert not daemon.reset_requested.is_set()


def test_recompile_after_code_change_resets(daemon: DaemonApp):
    daemon.handle_watch_event(WatchEvent.CODE_CHANGED)
    daemon.handle_watch_event(WatchEvent.RECOMPILED)
    assert daemon.reset_requested.is_set()


def test_data_change_resets(daemon: DaemonApp):
    daemon.handle_watch_event(WatchEvent.DATA_CHANGED)
    assert daemon.reset_requested.is_set()


def test_config_change_resets(daemon: DaemonApp):
    daemon.handle_watch_event(WatchEvent.CODE_CHANGED)
    daemon.handle_watch_event(WatchEvent.CONFIG_CHANGED)
    assert daemon.reset_requested.is_set()


def test_watcher_failure_stops_daemon(tmp_path: Path):
    daemon = make_daemon(tmp_path, BrokenDisk())
    asyncio.run(daemon.watch_worker())
    assert daemon.stop.is_set()


def test_config_failure(daemon: DaemonApp):
    daemon.watcher.error = "Traceback"
    daemon.handle_watch_event(WatchEvent.CONFIG_FAILED)
    assert daemon.status is DaemonStatus.FAILED
    assert daemon.error == "Traceback"
