"""Tests for the events reported by the daemon's file watcher."""

import asyncio
import contextlib
import os
import selectors
import shutil
import threading
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
import pytest
from reccmp.project.common import (
    RECCMP_BUILD_CONFIG,
    RECCMP_PROJECT_CONFIG,
    RECCMP_USER_CONFIG,
)
from reccmp.project.detect import RecCmpProject
from reccmp.remote.watch import (
    TargetWatcher,
    WatchEvent,
)
from .constants import LEGO1_SHA256
from .remote_watch_helpers import DiskTarget


class FakeClockSelector(selectors.DefaultSelector):
    """It never blocks to wait in vain,
    it moves the clock and goes again."""

    def __init__(self):
        super().__init__()
        self.now = 0.0
        self.held = False

    def select(self, timeout=None):
        if self.held:
            # Wait briefly in real time and leave the fake clock alone.
            return super().select(0.01 if timeout is None else min(timeout, 0.01))
        if timeout is not None:
            self.now += timeout
        return super().select(0)


class FakeClockLoop(asyncio.SelectorEventLoop):
    """The timers fire in proper turn,
    no real seconds pass or burn."""

    def __init__(self):
        super().__init__(FakeClockSelector())

    def time(self) -> float:
        return self._selector.now

    def run_in_executor(self, executor, func, *args):
        """No thread will run the call;
        the clock would leap ahead of all."""
        future = self.create_future()
        try:
            future.set_result(func(*args))
        except Exception as e:  # pylint: disable=broad-exception-caught
            future.set_exception(e)
        return future

    @contextlib.contextmanager
    def hold(self):
        """Keep fake time from moving, so timers wait while the loop waits on real I/O."""
        self._selector.held = True
        try:
            yield
        finally:
            self._selector.held = False


SETTLED = 4 * TargetWatcher.SETTLE_MS / 1000
"""Long enough for a cooldown to finish."""

UNSETTLED = 0.6 * TargetWatcher.SETTLE_MS / 1000
"""Too short for a cooldown to finish, but two in a row are not."""


@pytest.fixture(name="disk")
def fixture_disk(tmp_path: Path) -> DiskTarget:
    return DiskTarget(tmp_path.resolve())


def project_yml(source_root: str) -> str:
    return f"""\
targets:
  ISLE:
    filename: ISLE.EXE
    source-root: {source_root}
    data-sources:
      - isle.csv
    hash:
      sha256: {LEGO1_SHA256}
"""


USER_YML = """\
targets:
  ISLE:
    path: ../ISLE.EXE
"""

INVALID_YML = "targets: ["


def build_yml(disk: DiskTarget, exe: str = "ISLE.EXE") -> str:
    return f"""\
project: {disk.csv.parent}
targets:
  ISLE:
    path: {exe}
    pdb: ISLE.PDB
"""


def write_build_yml(disk: DiskTarget, text: str):
    (disk.exe.parent / RECCMP_BUILD_CONFIG).write_text(text)


def make_watcher(disk: DiskTarget, source_root: str = "src") -> TargetWatcher:
    """The ymls are written to disk first,
    then loaded as the daemon would at start."""
    (disk.csv.parent / RECCMP_PROJECT_CONFIG).write_text(project_yml(source_root))
    (disk.csv.parent / RECCMP_USER_CONFIG).write_text(USER_YML)
    write_build_yml(disk, build_yml(disk))
    project = RecCmpProject.from_directory(disk.exe.parent, alert=False)
    return TargetWatcher(project, project.get("ISLE"))


class Events:
    """The watcher always has a request for its next event in flight,
    so the scenario's file changes land while the watches are running."""

    def __init__(self, stream: AsyncIterator[WatchEvent]):
        self.stream = stream
        self.pending = asyncio.ensure_future(anext(stream))

    async def ready(self):
        # The fake clock moves on only once the loop is idle,
        # so the watches are in place before the scenario goes on.
        await asyncio.sleep(0.1)

    async def next(self) -> WatchEvent:
        with asyncio.get_running_loop().hold():
            event = await self.pending
        self.pending = asyncio.ensure_future(anext(self.stream))
        await self.ready()
        return event

    def quiet(self) -> bool:
        """True if no event has arrived since the last next()."""
        return not self.pending.done()

    async def close(self):
        self.pending.cancel()
        with contextlib.suppress(asyncio.CancelledError, StopAsyncIteration):
            await self.pending


Scenario = Callable[[Events], Awaitable[None]]


def run_scenario(source: AsyncIterator[WatchEvent], scenario: Scenario):
    """Runs the scenario against the given event stream on the fake clock."""

    async def run():
        async with contextlib.aclosing(source) as stream:
            events = Events(stream)
            try:
                await events.ready()
                await scenario(events)
            finally:
                await events.close()

    async def guarded():
        # The fake clock would fire a wait_for timeout at once,
        # so a real timer cancels a watch that hangs.
        task = asyncio.current_task()
        assert task is not None
        timer = threading.Timer(
            30, asyncio.get_running_loop().call_soon_threadsafe, (task.cancel,)
        )
        timer.start()
        try:
            await run()
        finally:
            timer.cancel()

    with asyncio.Runner(loop_factory=FakeClockLoop) as runner:
        runner.run(guarded())


def rebuild(disk: DiskTarget):
    disk.exe.write_text("built")
    disk.pdb.write_text("built")


def test_artifacts_settle_to_recompile(disk: DiskTarget):
    """Writing the exe and pdb then waiting out the cooldown is a recompile."""

    async def scenario(events: Events):
        rebuild(disk)
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        await asyncio.sleep(SETTLED)
        assert await events.next() is WatchEvent.RECOMPILED

    run_scenario(make_watcher(disk).events(), scenario)


def test_exe_only_is_not_a_recompile(disk: DiskTarget):
    """Writing the exe without the pdb is not a recompile."""

    async def scenario(events: Events):
        disk.exe.write_text("built")
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        await asyncio.sleep(SETTLED)
        assert events.quiet()

    run_scenario(make_watcher(disk).events(), scenario)


def test_recompile_split_across_timeouts(disk: DiskTarget):
    """The exe and pdb count as a recompile even when written a cooldown apart."""

    async def scenario(events: Events):
        disk.exe.write_text("built")
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        await asyncio.sleep(SETTLED)
        disk.pdb.write_text("built")
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        await asyncio.sleep(SETTLED)
        assert await events.next() is WatchEvent.RECOMPILED

    run_scenario(make_watcher(disk).events(), scenario)


def test_write_restarts_cooldown(disk: DiskTarget):
    """A write during the cooldown starts it over."""

    async def scenario(events: Events):
        rebuild(disk)
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        await asyncio.sleep(UNSETTLED)
        disk.exe.write_text("changed")
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        await asyncio.sleep(UNSETTLED)
        assert events.quiet()

    run_scenario(make_watcher(disk).events(), scenario)


def test_delete_aborts_cooldown(disk: DiskTarget):
    """A delete during the cooldown cancels the recompile."""

    async def scenario(events: Events):
        rebuild(disk)
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        await asyncio.sleep(UNSETTLED)
        disk.exe.unlink()
        assert await events.next() is WatchEvent.ARTIFACT_DELETED
        await asyncio.sleep(SETTLED)
        assert events.quiet()

    run_scenario(make_watcher(disk).events(), scenario)


def test_rewrite_after_delete_is_a_recompile(disk: DiskTarget):
    """Rewriting a deleted exe completes the recompile."""

    async def scenario(events: Events):
        rebuild(disk)
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        disk.exe.unlink()
        assert await events.next() is WatchEvent.ARTIFACT_DELETED
        disk.exe.write_text("changed")
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        await asyncio.sleep(SETTLED)
        assert await events.next() is WatchEvent.RECOMPILED

    run_scenario(make_watcher(disk).events(), scenario)


def test_stale_at_startup_is_a_code_change(disk: DiskTarget):
    """Code newer than the build when the watcher starts is a code change."""
    disk.set_mtime(disk.exe, 1000)
    disk.set_mtime(disk.pdb, 1000)
    disk.set_mtime(disk.code, 2000)

    async def scenario(events: Events):
        assert await events.next() is WatchEvent.CODE_CHANGED

    run_scenario(make_watcher(disk).events(), scenario)


def test_code_change_then_rebuild(disk: DiskTarget):
    """A code edit followed by a rebuild is a code change and then a recompile."""

    async def scenario(events: Events):
        disk.code.write_text("changed")
        assert await events.next() is WatchEvent.CODE_CHANGED
        rebuild(disk)
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        await asyncio.sleep(SETTLED)
        assert await events.next() is WatchEvent.RECOMPILED

    run_scenario(make_watcher(disk).events(), scenario)


def test_data_change(disk: DiskTarget):
    """Writing the csv of an up-to-date build is a data change."""

    async def scenario(events: Events):
        disk.csv.write_text("changed")
        assert await events.next() is WatchEvent.DATA_CHANGED

    run_scenario(make_watcher(disk).events(), scenario)


def test_replaced_source_file_is_a_code_change(disk: DiskTarget):
    """Replacing a source file listed in the project yml by rename is a code change."""
    saved = disk.code.with_suffix(".tmp")

    async def scenario(events: Events):
        saved.write_text("changed")
        os.replace(saved, disk.code)
        assert await events.next() is WatchEvent.CODE_CHANGED

    run_scenario(make_watcher(disk, "src/isle.cpp").events(), scenario)


def test_yml_rewrite_with_same_config(disk: DiskTarget):
    """Rewriting the build yml with the same content is not a config change."""

    async def scenario(events: Events):
        write_build_yml(disk, build_yml(disk))
        disk.csv.write_text("changed")
        assert await events.next() is WatchEvent.DATA_CHANGED

    run_scenario(make_watcher(disk).events(), scenario)


def test_changed_target_is_a_config_change(disk: DiskTarget):
    """Pointing the build yml at a different exe is a config change."""

    async def scenario(events: Events):
        write_build_yml(disk, build_yml(disk, "ISLE2.EXE"))
        assert await events.next() is WatchEvent.CONFIG_CHANGED

    run_scenario(make_watcher(disk).events(), scenario)


def test_invalid_config_is_a_failure(disk: DiskTarget):
    """A build yml that does not parse is a config failure."""

    async def scenario(events: Events):
        write_build_yml(disk, INVALID_YML)
        assert await events.next() is WatchEvent.CONFIG_FAILED

    run_scenario(make_watcher(disk).events(), scenario)


def test_fixed_config_is_a_config_change(disk: DiskTarget):
    """Restoring a broken build yml to the same target is a config change."""

    async def scenario(events: Events):
        write_build_yml(disk, INVALID_YML)
        assert await events.next() is WatchEvent.CONFIG_FAILED
        write_build_yml(disk, build_yml(disk))
        assert await events.next() is WatchEvent.CONFIG_CHANGED

    run_scenario(make_watcher(disk).events(), scenario)


def test_missing_path_is_a_failure_until_reload(disk: DiskTarget):
    """A deleted source directory is a config failure until it is created again."""
    src = disk.code.parent

    async def scenario(events: Events):
        shutil.rmtree(src)
        assert await events.next() is WatchEvent.CONFIG_FAILED
        src.mkdir()
        await asyncio.sleep(TargetWatcher.RETRY_MS / 1000)
        assert await events.next() is WatchEvent.CONFIG_CHANGED

    run_scenario(make_watcher(disk).events(), scenario)


def test_config_change_watches_new_binaries(disk: DiskTarget):
    """After the build yml names a new exe, writing that exe and the pdb is a recompile."""
    new_exe = disk.exe.with_name("ISLE2.EXE")

    async def scenario(events: Events):
        write_build_yml(disk, build_yml(disk, new_exe.name))
        assert await events.next() is WatchEvent.CONFIG_CHANGED
        # The new exe is not built yet, so the restart finds the build stale.
        assert await events.next() is WatchEvent.CODE_CHANGED
        new_exe.write_text("built")
        disk.pdb.write_text("built")
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        await asyncio.sleep(SETTLED)
        assert await events.next() is WatchEvent.RECOMPILED

    run_scenario(make_watcher(disk).events(), scenario)


def test_rebuild_right_after_config_change_is_a_recompile(disk: DiskTarget):
    """A rebuild written as soon as the config change is reported is not missed."""
    new_exe = disk.exe.with_name("ISLE2.EXE")
    new_exe.write_text("built")

    async def scenario(events: Events):
        write_build_yml(disk, build_yml(disk, new_exe.name))
        assert await events.next() is WatchEvent.CONFIG_CHANGED
        new_exe.write_text("rebuilt")
        disk.pdb.write_text("rebuilt")
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        await asyncio.sleep(SETTLED)
        assert await events.next() is WatchEvent.RECOMPILED

    run_scenario(make_watcher(disk).events(), scenario)


def test_deleted_exe_is_an_artifact_delete(disk: DiskTarget):
    """Deleting the exe is an artifact delete."""

    async def scenario(events: Events):
        disk.exe.unlink()
        assert await events.next() is WatchEvent.ARTIFACT_DELETED

    run_scenario(make_watcher(disk).events(), scenario)


def test_other_build_files_are_not_reported(disk: DiskTarget):
    """Writes to other files in the build directory are not reported."""
    ilk = disk.exe.with_suffix(".ILK")

    async def scenario(events: Events):
        ilk.write_text("changed")
        # The pdb delete is reported after the .ILK would be: in a later batch,
        # or in the same batch, where ISLE.ILK sorts before ISLE.PDB.
        disk.pdb.unlink()
        assert await events.next() is WatchEvent.ARTIFACT_DELETED

    run_scenario(make_watcher(disk).events(), scenario)
