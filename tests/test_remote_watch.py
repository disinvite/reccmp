"""Tests for the events reported by the daemon's file watcher."""

import asyncio
import contextlib
import os
import selectors
import shutil
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
import pytest
from watchfiles import Change
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


class FakeClockLoop(asyncio.SelectorEventLoop):
    """The timers fire in proper turn,
    no real seconds pass or burn."""

    TIME_LIMIT = 600.0
    """CLAUDE SAYS: Fake seconds a scenario may run before it counts as hung.
    Only a timer that keeps rescheduling itself can run the clock this far."""

    def __init__(self):
        self.now = 0.0
        self.idle_waiters: list[asyncio.Future[None]] = []
        selector = selectors.DefaultSelector()
        real_select = selector.select

        def select(timeout=None):
            """It never blocks to wait in vain,
            it moves the clock and goes again."""
            # CLAUDE SAYS: A nonzero timeout means no callback is ready to run.
            if timeout != 0 and not self.wake_idle():
                if timeout is None:
                    raise RuntimeError("Scenario is waiting with nothing scheduled")
                self.now += timeout
                if self.now > self.TIME_LIMIT:
                    raise RuntimeError(
                        "Scenario did not finish within the fake time limit"
                    )
            return real_select(0)

        selector.select = select
        super().__init__(selector)

    def wake_idle(self) -> bool:
        """CLAUDE SAYS: Called when no callback is ready, before the clock moves.
        Returns True if it made a callback ready."""
        waiters, self.idle_waiters = self.idle_waiters, []
        for waiter in waiters:
            if not waiter.done():
                waiter.set_result(None)
        return bool(waiters)

    async def idle(self):
        """CLAUDE SAYS: Returns once no callback is ready."""
        waiter = self.create_future()
        self.idle_waiters.append(waiter)
        await waiter

    def time(self) -> float:
        return self.now

    def run_in_executor(self, _, func, *args):
        """No thread will run the call;
        the clock would leap ahead of all."""
        future = self.create_future()
        try:
            future.set_result(func(*args))
        except Exception as e:  # pylint: disable=broad-exception-caught
            future.set_exception(e)
        return future


def snapshot(
    roots: tuple[Path, ...], recursive: bool
) -> dict[Path, tuple[int, int, int]]:
    found = {}
    for root in roots:
        if not root.exists():
            # CLAUDE SAYS: fswatch's inode check reports the missing root.
            continue
        # CLAUDE SAYS: The roots are in the snapshot so that replacing one
        # wakes the watch, as the real awatch's timeout yield would.
        for path in (root, *(root.rglob("*") if recursive else root.iterdir())):
            st = path.stat()
            found[path] = (st.st_ino, st.st_size, st.st_mtime_ns)
    return found


WATCHES: list[Callable[[], None]] = []
"""CLAUDE SAYS: The scan of each running fake awatch."""


async def scan_awatch(
    *roots: Path, watch_filter, recursive: bool, yield_on_timeout: bool
):
    """CLAUDE SAYS: Stands in for watchfiles.awatch. It reports a change only
    when the scenario scans, so each batch is everything changed since the last scan."""
    assert yield_on_timeout
    changes: asyncio.Queue[set[tuple[Change, str]]] = asyncio.Queue()
    before = snapshot(roots, recursive)

    def scan():
        nonlocal before
        after = snapshot(roots, recursive)
        if after != before:
            changes.put_nowait(
                {
                    (Change.modified, str(path))
                    for path in before.keys() | after.keys()
                    if before.get(path) != after.get(path)
                    and watch_filter(None, str(path))
                }
            )
            before = after

    WATCHES.append(scan)
    try:
        while True:
            yield await changes.get()
    finally:
        WATCHES.remove(scan)


@pytest.fixture(autouse=True)
def fixture_scan_awatch(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("reccmp.remote.fswatch.awatch", scan_awatch)


@pytest.fixture(name="disk")
def fixture_disk(tmp_path: Path) -> DiskTarget:
    return DiskTarget(tmp_path.resolve())


INVALID_YML = "targets: ["


def build_yml_path(disk: DiskTarget) -> Path:
    return disk.exe.parent / RECCMP_BUILD_CONFIG


def write_build_yml(disk: DiskTarget, exe: str = "ISLE.EXE"):
    BuildFile(
        project=disk.csv.parent,
        targets={"ISLE": BuildFileTarget(path=Path(exe), pdb=Path("ISLE.PDB"))},
    ).write_file(build_yml_path(disk))


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

    def __init__(self, stream: AsyncIterator[WatchEvent]):
        self.stream = stream
        self.pending = asyncio.ensure_future(anext(stream))

    async def ready(self):
        # The fake clock moves on only once the loop is idle,
        # so the watches are in place before the scenario goes on.
        loop = asyncio.get_running_loop()
        assert isinstance(loop, FakeClockLoop)
        await loop.idle()

    def scan(self):
        """CLAUDE SAYS: Hands the scenario's file changes to the fake watches."""
        for scan in WATCHES:
            scan()

    async def next(self) -> WatchEvent:
        self.scan()
        event = await self.pending
        self.pending = asyncio.ensure_future(anext(self.stream))
        await self.ready()
        return event

    async def quiet(self) -> bool:
        """True if no event has arrived since the last next()."""
        self.scan()
        await self.ready()
        return not self.pending.done()

    async def after(self, seconds: float) -> WatchEvent | None:
        """CLAUDE SAYS: Waits the given fake seconds, then returns the first event
        that arrived in that time, or None."""
        self.scan()
        await asyncio.sleep(seconds)
        if await self.quiet():
            return None
        return await self.next()

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

    with asyncio.Runner(loop_factory=FakeClockLoop) as runner:
        runner.run(run())


def rebuild(disk: DiskTarget):
    disk.exe.write_text("built")
    disk.pdb.write_text("built")


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
        disk.exe.write_text("built")
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.after(4 * ARTIFACT_DELAY_S) is None

    run_scenario(make_watcher(disk).events(), scenario)


def test_recompile_split_across_timeouts(disk: DiskTarget):
    """The exe and pdb count as a recompile even when written a cooldown apart."""

    async def scenario(events: Events):
        disk.exe.write_text("built")
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.after(4 * ARTIFACT_DELAY_S) is None
        disk.pdb.write_text("built")
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
        disk.exe.write_text("changed")
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
        disk.exe.unlink()
        assert await events.next() is WatchEvent.ARTIFACT_DELETED
        assert await events.after(4 * ARTIFACT_DELAY_S) is None

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
        assert await events.after(4 * ARTIFACT_DELAY_S) is WatchEvent.RECOMPILED

    run_scenario(make_watcher(disk).events(), scenario)


def test_relink_in_one_batch_is_a_recompile(disk: DiskTarget):
    """CLAUDE SAYS: An exe deleted and rewritten in the same batch as the pdb write
    is a recompile with no artifact delete."""

    async def scenario(events: Events):
        disk.exe.unlink()
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
        disk.code.write_text("changed")
        assert await events.next() is WatchEvent.CODE_CHANGED
        rebuild(disk)
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.after(4 * ARTIFACT_DELAY_S) is WatchEvent.RECOMPILED

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
        write_build_yml(disk)
        disk.csv.write_text("changed")
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
        build_yml_path(disk).write_text(INVALID_YML)
        assert await events.next() is WatchEvent.CONFIG_FAILED

    run_scenario(make_watcher(disk).events(), scenario)


def test_fixed_config_is_a_config_change(disk: DiskTarget):
    """Restoring a broken build yml to the same target is a config change."""

    async def scenario(events: Events):
        build_yml_path(disk).write_text(INVALID_YML)
        assert await events.next() is WatchEvent.CONFIG_FAILED
        write_build_yml(disk)
        assert await events.next() is WatchEvent.CONFIG_CHANGED

    run_scenario(make_watcher(disk).events(), scenario)


def test_missing_path_is_a_failure_until_reload(disk: DiskTarget):
    """A deleted source directory is a config failure until it is created again."""
    src = disk.code.parent

    async def scenario(events: Events):
        shutil.rmtree(src)
        assert await events.next() is WatchEvent.CONFIG_FAILED
        src.mkdir()
        assert await events.after(CONFIG_RETRY_S) is WatchEvent.CONFIG_CHANGED

    run_scenario(make_watcher(disk).events(), scenario)


def test_yml_change_ends_wait_for_missing_path(disk: DiskTarget):
    """CLAUDE SAYS: A yml change while a watched path is missing reloads the config
    without waiting for the path to return."""

    async def scenario(events: Events):
        shutil.rmtree(disk.code.parent)
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
        new_exe.write_text("built")
        disk.pdb.write_text("built")
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
        new_exe.write_text("rebuilt")
        disk.pdb.write_text("rebuilt")
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.after(4 * ARTIFACT_DELAY_S) is WatchEvent.RECOMPILED

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
