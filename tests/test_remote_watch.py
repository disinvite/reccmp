"""Tests for the events reported by the daemon's file watcher."""

import asyncio
import contextlib
import selectors
from collections.abc import AsyncGenerator, Awaitable, Callable
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
from reccmp.remote.watch import (
    ARTIFACT_DELAY_S,
    CONFIG_RETRY_S,
    TargetWatcher,
    WatchEvent,
)
from .constants import LEGO1_SHA256
from .remote_watch_helpers import DiskTarget


class FakeClockSelector(selectors.DefaultSelector):
    """CLAUDE SAYS: A selector that never blocks and holds the fake clock.
    When no callback is ready, it first wakes the idle waiters; if there are
    none, it moves the clock forward to the loop's next timer."""

    # pylint: disable=too-many-ancestors

    TIME_LIMIT = 600.0
    """CLAUDE SAYS: Fake seconds a scenario may run before it counts as hung.
    Only a timer that keeps rescheduling itself can run the clock this far."""

    def __init__(self):
        super().__init__()
        self.now = 0.0
        self.idle_waiters: list[asyncio.Future[None]] = []

    def select(self, timeout=None):
        # CLAUDE SAYS: A nonzero timeout means no callback is ready to run.
        if timeout != 0:
            waiters, self.idle_waiters = self.idle_waiters, []
            for waiter in waiters:
                if not waiter.done():
                    waiter.set_result(None)
            if not waiters:
                if timeout is None:
                    raise RuntimeError("Scenario is waiting with nothing scheduled")
                self.now += timeout
                if self.now > self.TIME_LIMIT:
                    raise RuntimeError(
                        "Scenario did not finish within the fake time limit"
                    )
        return super().select(0)


class FakeClockLoop(asyncio.SelectorEventLoop):
    """The timers fire in proper turn,
    no real seconds pass or burn."""

    def __init__(self):
        self.clock = FakeClockSelector()
        super().__init__(self.clock)

    async def idle(self):
        """CLAUDE SAYS: Returns once no callback is ready."""
        waiter = self.create_future()
        self.clock.idle_waiters.append(waiter)
        await waiter

    def time(self) -> float:
        return self.clock.now

    def run_in_executor(self, _, func, *args):  # type: ignore[override]
        """Allow a real thread to run on our fake clock."""
        future = self.create_future()
        try:
            future.set_result(func(*args))
        except Exception as e:  # pylint: disable=broad-exception-caught
            future.set_exception(e)
        return future


@pytest.fixture(name="disk")
def fixture_disk(tmp_path: Path) -> DiskTarget:
    return DiskTarget(tmp_path.resolve())


INVALID_YML = "targets: ["


def build_yml_path(disk: DiskTarget) -> Path:
    return disk.exe.parent / RECCMP_BUILD_CONFIG


def write_build_yml(disk: DiskTarget, exe: str = "ISLE.EXE"):
    build = BuildFile(
        project=disk.csv.parent,
        targets={"ISLE": BuildFileTarget(path=Path(exe), pdb=Path("ISLE.PDB"))},
    )
    disk.write(build_yml_path(disk), build.to_str())


def make_watcher(disk: DiskTarget, source_root: str = "src") -> TargetWatcher:
    """The ymls are written to disk first,
    then loaded as the daemon would at start."""
    ProjectFile(
        targets={
            "ISLE": ProjectFileTarget(
                filename="ISLE.EXE",
                source_root=(Path(source_root),),
                data_sources=[Path("isle.csv")],
                hash=Hash(sha256=LEGO1_SHA256),
            )
        }
    ).write_file(disk.csv.parent / RECCMP_PROJECT_CONFIG)
    UserFile(targets={"ISLE": UserFileTarget(path=Path("../ISLE.EXE"))}).write_file(
        disk.csv.parent / RECCMP_USER_CONFIG
    )
    write_build_yml(disk)
    project = RecCmpProject.from_directory(disk.exe.parent, alert=False)
    return TargetWatcher(project, project.get("ISLE"))


class Events:
    """The watcher always has a request for its next event in flight,
    so the scenario's file changes land while the watches are running."""

    def __init__(self, stream: AsyncGenerator[WatchEvent, None]):
        self.stream = stream
        self.pending = asyncio.create_task(anext(stream))

    async def ready(self):
        # The fake clock moves on only once the loop is idle,
        # so the watches are in place before the scenario goes on.
        loop = asyncio.get_running_loop()
        assert isinstance(loop, FakeClockLoop)
        await loop.idle()

    async def next(self) -> WatchEvent:
        event = await self.pending
        self.pending = asyncio.create_task(anext(self.stream))
        await self.ready()
        return event

    async def quiet(self) -> bool:
        """True if no event has arrived since the last next()."""
        await self.ready()
        return not self.pending.done()

    async def after(self, seconds: float) -> WatchEvent | None:
        """CLAUDE SAYS: Waits the given fake seconds, then returns the first event
        that arrived in that time, or None."""
        await asyncio.sleep(seconds)
        if await self.quiet():
            return None
        return await self.next()

    async def close(self):
        self.pending.cancel()
        with contextlib.suppress(asyncio.CancelledError, StopAsyncIteration):
            await self.pending


Scenario = Callable[[Events], Awaitable[None]]


def run_scenario(source: AsyncGenerator[WatchEvent, None], scenario: Scenario):
    """Runs the scenario against the given event stream on the fake clock."""

    async def run():
        async with contextlib.aclosing(source) as stream:
            events = Events(stream)
            try:
                await events.ready()
                await scenario(events)
            finally:
                await events.close()

    with asyncio.Runner(loop_factory=FakeClockLoop) as runner:
        runner.run(run())


def rebuild(disk: DiskTarget):
    disk.write(disk.exe, "built")
    disk.write(disk.pdb, "built")


def test_artifacts_settle_to_recompile(disk: DiskTarget):
    """Writing the exe and pdb then waiting out the cooldown is a recompile."""

    async def scenario(events: Events):
        rebuild(disk)
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.after(4 * ARTIFACT_DELAY_S) is WatchEvent.RECOMPILED

    run_scenario(make_watcher(disk).events(), scenario)


def test_exe_only_is_not_a_recompile(disk: DiskTarget):
    """Writing the exe without the pdb is not a recompile."""

    async def scenario(events: Events):
        disk.write(disk.exe, "built")
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.after(4 * ARTIFACT_DELAY_S) is None

    run_scenario(make_watcher(disk).events(), scenario)


def test_recompile_split_across_timeouts(disk: DiskTarget):
    """The exe and pdb count as a recompile even when written a cooldown apart."""

    async def scenario(events: Events):
        disk.write(disk.exe, "built")
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.after(4 * ARTIFACT_DELAY_S) is None
        disk.write(disk.pdb, "built")
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.after(4 * ARTIFACT_DELAY_S) is WatchEvent.RECOMPILED

    run_scenario(make_watcher(disk).events(), scenario)


def test_write_restarts_cooldown(disk: DiskTarget):
    """A write during the cooldown starts it over."""

    async def scenario(events: Events):
        rebuild(disk)
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.after(0.6 * ARTIFACT_DELAY_S) is None
        disk.write(disk.exe, "changed")
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.after(0.6 * ARTIFACT_DELAY_S) is None

    run_scenario(make_watcher(disk).events(), scenario)


def test_delete_aborts_cooldown(disk: DiskTarget):
    """A delete during the cooldown cancels the recompile."""

    async def scenario(events: Events):
        rebuild(disk)
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.after(0.6 * ARTIFACT_DELAY_S) is None
        disk.unlink(disk.exe)
        assert await events.next() is WatchEvent.ARTIFACT_DELETED
        assert await events.after(4 * ARTIFACT_DELAY_S) is None

    run_scenario(make_watcher(disk).events(), scenario)


def test_rewrite_after_delete_is_a_recompile(disk: DiskTarget):
    """Rewriting a deleted exe completes the recompile."""

    async def scenario(events: Events):
        rebuild(disk)
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        disk.unlink(disk.exe)
        assert await events.next() is WatchEvent.ARTIFACT_DELETED
        disk.write(disk.exe, "changed")
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.after(4 * ARTIFACT_DELAY_S) is WatchEvent.RECOMPILED

    run_scenario(make_watcher(disk).events(), scenario)


def test_relink_in_one_batch_is_a_recompile(disk: DiskTarget):
    """CLAUDE SAYS: An exe deleted and rewritten in the same batch as the pdb write
    is a recompile with no artifact delete."""

    async def scenario(events: Events):
        disk.unlink(disk.exe)
        rebuild(disk)
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.after(4 * ARTIFACT_DELAY_S) is WatchEvent.RECOMPILED

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
        disk.write(disk.code, "changed")
        assert await events.next() is WatchEvent.CODE_CHANGED
        rebuild(disk)
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.after(4 * ARTIFACT_DELAY_S) is WatchEvent.RECOMPILED

    run_scenario(make_watcher(disk).events(), scenario)


def test_data_change(disk: DiskTarget):
    """Writing the csv of an up-to-date build is a data change."""

    async def scenario(events: Events):
        disk.write(disk.csv, "changed")
        assert await events.next() is WatchEvent.DATA_CHANGED

    run_scenario(make_watcher(disk).events(), scenario)


def test_replaced_source_file_is_a_code_change(disk: DiskTarget):
    """Replacing a source file listed in the project yml by rename is a code change."""
    saved = disk.code.with_suffix(".tmp")

    async def scenario(events: Events):
        disk.write(saved, "changed")
        disk.replace(saved, disk.code)
        assert await events.next() is WatchEvent.CODE_CHANGED

    run_scenario(make_watcher(disk, "src/isle.cpp").events(), scenario)


def test_yml_rewrite_with_same_config(disk: DiskTarget):
    """Rewriting the build yml with the same content is not a config change."""

    async def scenario(events: Events):
        write_build_yml(disk)
        disk.write(disk.csv, "changed")
        assert await events.next() is WatchEvent.DATA_CHANGED

    run_scenario(make_watcher(disk).events(), scenario)


def test_changed_target_is_a_config_change(disk: DiskTarget):
    """Pointing the build yml at a different exe is a config change."""

    async def scenario(events: Events):
        write_build_yml(disk, "ISLE2.EXE")
        assert await events.next() is WatchEvent.CONFIG_CHANGED

    run_scenario(make_watcher(disk).events(), scenario)


def test_invalid_config_is_a_failure(disk: DiskTarget):
    """A build yml that does not parse is a config failure."""

    async def scenario(events: Events):
        disk.write(build_yml_path(disk), INVALID_YML)
        assert await events.next() is WatchEvent.CONFIG_FAILED

    run_scenario(make_watcher(disk).events(), scenario)


def test_fixed_config_is_a_config_change(disk: DiskTarget):
    """Restoring a broken build yml to the same target is a config change."""

    async def scenario(events: Events):
        disk.write(build_yml_path(disk), INVALID_YML)
        assert await events.next() is WatchEvent.CONFIG_FAILED
        write_build_yml(disk)
        assert await events.next() is WatchEvent.CONFIG_CHANGED

    run_scenario(make_watcher(disk).events(), scenario)


def test_missing_path_is_a_failure_until_reload(disk: DiskTarget):
    """A deleted source directory is a config failure until it is created again."""
    src = disk.code.parent

    async def scenario(events: Events):
        disk.rmtree(src)
        assert await events.next() is WatchEvent.CONFIG_FAILED
        disk.mkdir(src)
        assert await events.after(CONFIG_RETRY_S) is WatchEvent.CONFIG_CHANGED

    run_scenario(make_watcher(disk).events(), scenario)


def test_yml_change_ends_wait_for_missing_path(disk: DiskTarget):
    """CLAUDE SAYS: A yml change while a watched path is missing reloads the config
    without waiting for the path to return."""

    async def scenario(events: Events):
        disk.rmtree(disk.code.parent)
        assert await events.next() is WatchEvent.CONFIG_FAILED
        write_build_yml(disk, "ISLE2.EXE")
        assert await events.after(CONFIG_RETRY_S) is WatchEvent.CONFIG_CHANGED
        # CLAUDE SAYS: The path is still missing, so the new session fails too.
        assert await events.next() is WatchEvent.CONFIG_FAILED

    run_scenario(make_watcher(disk).events(), scenario)


def test_config_change_watches_new_binaries(disk: DiskTarget):
    """After the build yml names a new exe, writing that exe and the pdb is a recompile."""
    new_exe = disk.exe.with_name("ISLE2.EXE")

    async def scenario(events: Events):
        write_build_yml(disk, new_exe.name)
        assert await events.next() is WatchEvent.CONFIG_CHANGED
        # The new exe is not built yet, so the restart finds the build stale.
        assert await events.next() is WatchEvent.CODE_CHANGED
        disk.write(new_exe, "built")
        disk.write(disk.pdb, "built")
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.after(4 * ARTIFACT_DELAY_S) is WatchEvent.RECOMPILED

    run_scenario(make_watcher(disk).events(), scenario)


def test_rebuild_right_after_config_change_is_a_recompile(disk: DiskTarget):
    """A rebuild written as soon as the config change is reported is not missed."""
    new_exe = disk.exe.with_name("ISLE2.EXE")
    new_exe.write_text("built")

    async def scenario(events: Events):
        write_build_yml(disk, new_exe.name)
        assert await events.next() is WatchEvent.CONFIG_CHANGED
        disk.write(new_exe, "rebuilt")
        disk.write(disk.pdb, "rebuilt")
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.after(4 * ARTIFACT_DELAY_S) is WatchEvent.RECOMPILED

    run_scenario(make_watcher(disk).events(), scenario)


def test_deleted_exe_is_an_artifact_delete(disk: DiskTarget):
    """Deleting the exe is an artifact delete."""

    async def scenario(events: Events):
        disk.unlink(disk.exe)
        assert await events.next() is WatchEvent.ARTIFACT_DELETED

    run_scenario(make_watcher(disk).events(), scenario)


def test_other_build_files_are_not_reported(disk: DiskTarget):
    """Writes to other files in the build directory are not reported."""
    ilk = disk.exe.with_suffix(".ILK")

    async def scenario(events: Events):
        disk.write(ilk, "changed")
        # The pdb delete is reported after the .ILK would be: in a later batch,
        # or in the same batch, where ISLE.ILK sorts before ISLE.PDB.
        disk.unlink(disk.pdb)
        assert await events.next() is WatchEvent.ARTIFACT_DELETED

    run_scenario(make_watcher(disk).events(), scenario)
