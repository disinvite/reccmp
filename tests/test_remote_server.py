"""Tests for how the daemon responds to file watcher events."""

import textwrap
from pathlib import Path
import pytest
from reccmp.project.common import (
    RECCMP_BUILD_CONFIG,
    RECCMP_PROJECT_CONFIG,
    RECCMP_USER_CONFIG,
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
    daemon = DaemonApp(project, project.get("ISLE"))
    daemon.status = DaemonStatus.READY
    return daemon


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


def test_config_failure(daemon: DaemonApp):
    daemon.watcher.error = "Traceback"
    daemon.handle_watch_event(WatchEvent.CONFIG_FAILED)
    assert daemon.status is DaemonStatus.FAILED
    assert daemon.error == "Traceback"
