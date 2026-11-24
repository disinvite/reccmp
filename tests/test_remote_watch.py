"""Tests for the events reported by the daemon's file watcher."""

import asyncio
import contextlib
import dataclasses
import os
import selectors
import shutil
import threading
from collections.abc import AsyncIterator, Callable
from pathlib import Path
import pytest
from reccmp.project.common import (
    RECCMP_BUILD_CONFIG,
    RECCMP_PROJECT_CONFIG,
    RECCMP_USER_CONFIG,
)
from reccmp.project.detect import RecCmpProject
from reccmp.remote.fswatch import TargetFiles, watch_streams
from reccmp.remote.watch import (
    BuildTracker,
    TargetWatcher,
    WatchEvent,
    watch_artifacts,
)
from .constants import LEGO1_SHA256
from .remote_watch_helpers import DiskTarget, first_after

BUILD_PATH = Path("build")
EXE_PATH = BUILD_PATH / "ISLE.EXE"
PDB_PATH = BUILD_PATH / "ISLE.PDB"


class ScriptDone(Exception):
    """The fake watches have no more changes to report."""


class FakeClockSelector(selectors.DefaultSelector):
    """It never blocks to wait in vain,
    it moves the clock and goes again."""

    def __init__(self):
        super().__init__()
        self.now = 0.0

    def select(self, timeout=None):
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


def track(*events: WatchEvent, stale: bool = False) -> list[WatchEvent]:
    tracker = BuildTracker()
    if stale:
        events = (WatchEvent.CODE_CHANGED, *events)
    passed = [tracker.step(event) for event in events]
    return [event for event in passed if event is not None]


def test_recompile():
    """A written artifact followed by a recompile reports only the recompile."""
    assert track(WatchEvent.ARTIFACT_CHANGED, WatchEvent.RECOMPILED) == [
        WatchEvent.RECOMPILED
    ]


def test_code_change_then_recompile():
    """A recompile after a code change is reported after the code change."""
    assert track(
        WatchEvent.CODE_CHANGED, WatchEvent.ARTIFACT_CHANGED, WatchEvent.RECOMPILED
    ) == [WatchEvent.CODE_CHANGED, WatchEvent.RECOMPILED]


def test_code_change_during_cooldown_drops_recompile():
    """A code change after the artifacts are written makes the recompile out of date."""
    assert track(
        WatchEvent.ARTIFACT_CHANGED, WatchEvent.CODE_CHANGED, WatchEvent.RECOMPILED
    ) == [WatchEvent.CODE_CHANGED]


def test_stale_at_startup_is_a_code_change():
    """A build that is stale at startup is reported as a code change."""
    assert track(stale=True) == [WatchEvent.CODE_CHANGED]


def test_data_change():
    """A data change on a ready build is reported."""
    assert track(WatchEvent.DATA_CHANGED) == [WatchEvent.DATA_CHANGED]


def test_data_change_while_stale_is_dropped():
    """A data change is dropped while the build is stale."""
    assert track(WatchEvent.CODE_CHANGED, WatchEvent.DATA_CHANGED) == [
        WatchEvent.CODE_CHANGED
    ]


def test_data_change_during_cooldown_is_dropped():
    """A data change is dropped while a recompile is pending."""
    assert track(WatchEvent.ARTIFACT_CHANGED, WatchEvent.DATA_CHANGED) == []


def test_data_change_after_deleted_artifact_waits_for_recompile():
    """Data changes are dropped from an artifact delete until the next recompile."""
    assert track(
        WatchEvent.ARTIFACT_DELETED,
        WatchEvent.DATA_CHANGED,
        WatchEvent.ARTIFACT_CHANGED,
        WatchEvent.RECOMPILED,
        WatchEvent.DATA_CHANGED,
    ) == [WatchEvent.RECOMPILED, WatchEvent.DATA_CHANGED]


def test_config_failure_drops_other_events():
    """After a config failure only config events are reported."""
    assert track(
        WatchEvent.CONFIG_FAILED,
        WatchEvent.CODE_CHANGED,
        WatchEvent.ARTIFACT_CHANGED,
        WatchEvent.RECOMPILED,
        WatchEvent.DATA_CHANGED,
        WatchEvent.CONFIG_CHANGED,
    ) == [WatchEvent.CONFIG_FAILED, WatchEvent.CONFIG_CHANGED]


def test_config_change_takes_staleness_from_restart():
    """A config change clears the stale state left by an earlier code change."""
    tracker = BuildTracker()
    tracker.step(WatchEvent.CODE_CHANGED)
    tracker.step(WatchEvent.CONFIG_CHANGED)
    assert tracker.step(WatchEvent.DATA_CHANGED) is WatchEvent.DATA_CHANGED


SETTLED = 4 * TargetWatcher.SETTLE_MS / 1000
"""Long enough for a cooldown to finish."""

UNSETTLED = 0.6 * TargetWatcher.SETTLE_MS / 1000
"""Too short for a cooldown to finish, but two in a row are not."""


def settle(*steps: tuple[WatchEvent, Path] | float) -> list[WatchEvent]:
    """Each step is an artifact change, or a number of seconds to wait."""
    binaries = {EXE_PATH, PDB_PATH}

    async def script() -> AsyncIterator[tuple[Path, bool]]:
        for step in steps:
            if isinstance(step, float):
                await asyncio.sleep(step)
                continue
            event, path = step
            yield path, event is WatchEvent.ARTIFACT_CHANGED
        raise ScriptDone

    async def run():
        events = []
        with pytest.raises(ScriptDone):
            await watch_artifacts(
                script(), binaries, TargetWatcher.SETTLE_MS / 1000, events.append
            )
        return events

    with asyncio.Runner(loop_factory=FakeClockLoop) as runner:
        return runner.run(asyncio.wait_for(run(), timeout=60))


def test_artifacts_settle_to_recompile():
    """Writing the exe and pdb then waiting out the cooldown is a recompile."""
    assert settle(
        (WatchEvent.ARTIFACT_CHANGED, EXE_PATH),
        (WatchEvent.ARTIFACT_CHANGED, PDB_PATH),
        SETTLED,
    ) == [
        WatchEvent.ARTIFACT_CHANGED,
        WatchEvent.ARTIFACT_CHANGED,
        WatchEvent.RECOMPILED,
    ]


def test_exe_only_is_not_a_recompile():
    """Writing the exe without the pdb is not a recompile."""
    assert settle((WatchEvent.ARTIFACT_CHANGED, EXE_PATH), SETTLED) == [
        WatchEvent.ARTIFACT_CHANGED
    ]


def test_recompile_split_across_timeouts():
    """The exe and pdb count as a recompile even when written a cooldown apart."""
    assert settle(
        (WatchEvent.ARTIFACT_CHANGED, EXE_PATH),
        SETTLED,
        (WatchEvent.ARTIFACT_CHANGED, PDB_PATH),
        SETTLED,
    ) == [
        WatchEvent.ARTIFACT_CHANGED,
        WatchEvent.ARTIFACT_CHANGED,
        WatchEvent.RECOMPILED,
    ]


def test_write_restarts_cooldown():
    """A write during the cooldown starts it over."""
    assert settle(
        (WatchEvent.ARTIFACT_CHANGED, EXE_PATH),
        (WatchEvent.ARTIFACT_CHANGED, PDB_PATH),
        UNSETTLED,
        (WatchEvent.ARTIFACT_CHANGED, EXE_PATH),
        UNSETTLED,
    ) == [
        WatchEvent.ARTIFACT_CHANGED,
        WatchEvent.ARTIFACT_CHANGED,
        WatchEvent.ARTIFACT_CHANGED,
    ]


def test_delete_aborts_cooldown():
    """A delete during the cooldown cancels the recompile."""
    assert settle(
        (WatchEvent.ARTIFACT_CHANGED, EXE_PATH),
        (WatchEvent.ARTIFACT_CHANGED, PDB_PATH),
        UNSETTLED,
        (WatchEvent.ARTIFACT_DELETED, EXE_PATH),
        SETTLED,
    ) == [
        WatchEvent.ARTIFACT_CHANGED,
        WatchEvent.ARTIFACT_CHANGED,
        WatchEvent.ARTIFACT_DELETED,
    ]


def test_rewrite_after_delete_is_a_recompile():
    """Rewriting a deleted exe completes the recompile."""
    assert settle(
        (WatchEvent.ARTIFACT_CHANGED, EXE_PATH),
        (WatchEvent.ARTIFACT_CHANGED, PDB_PATH),
        (WatchEvent.ARTIFACT_DELETED, EXE_PATH),
        (WatchEvent.ARTIFACT_CHANGED, EXE_PATH),
        SETTLED,
    ) == [
        WatchEvent.ARTIFACT_CHANGED,
        WatchEvent.ARTIFACT_CHANGED,
        WatchEvent.ARTIFACT_DELETED,
        WatchEvent.ARTIFACT_CHANGED,
        WatchEvent.RECOMPILED,
    ]


@pytest.fixture(name="disk")
def fixture_disk(tmp_path: Path) -> DiskTarget:
    return DiskTarget(tmp_path.resolve())


PROJECT_YML = f"""\
targets:
  ISLE:
    filename: ISLE.EXE
    source-root: src
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


def make_watcher(disk: DiskTarget) -> TargetWatcher:
    """The ymls are written to disk first,
    then loaded as the daemon would at start."""
    (disk.csv.parent / RECCMP_PROJECT_CONFIG).write_text(PROJECT_YML)
    (disk.csv.parent / RECCMP_USER_CONFIG).write_text(USER_YML)
    write_build_yml(disk, build_yml(disk))
    project = RecCmpProject.from_directory(disk.exe.parent, alert=False)
    return TargetWatcher(project, project.get("ISLE"))


def reloads(disk: DiskTarget, *build_ymls: str) -> list[WatchEvent | None]:
    """Each text is written to the build yml before one reload."""
    watcher = make_watcher(disk)
    results = []
    for text in build_ymls:
        write_build_yml(disk, text)
        results.append(watcher.reload())
    return results


def test_yml_rewrite_with_same_config(disk: DiskTarget):
    """Rewriting the build yml with the same content is not a config change."""
    assert reloads(disk, build_yml(disk)) == [None]


def test_changed_target_is_a_config_change(disk: DiskTarget):
    """Pointing the build yml at a different exe is a config change."""
    assert reloads(disk, build_yml(disk, "ISLE2.EXE")) == [WatchEvent.CONFIG_CHANGED]


def test_invalid_config_is_a_failure(disk: DiskTarget):
    """A build yml that does not parse is a config failure."""
    assert reloads(disk, INVALID_YML) == [WatchEvent.CONFIG_FAILED]


def test_fixed_config_is_a_config_change(disk: DiskTarget):
    """Restoring a broken build yml to the same target is a config change."""
    assert reloads(disk, INVALID_YML, build_yml(disk)) == [
        WatchEvent.CONFIG_FAILED,
        WatchEvent.CONFIG_CHANGED,
    ]


def watch_events(
    watcher: TargetWatcher, *actions: Callable[[], None] | None
) -> list[WatchEvent]:
    """Each action runs while the watcher waits for its next event,
    and the event that follows is returned for it."""

    async def run():
        events = []
        async with contextlib.aclosing(watcher.events()) as stream:
            for action in actions:
                pending = asyncio.ensure_future(anext(stream))
                await asyncio.sleep(0.1)
                if action is not None:
                    action()
                events.append(await pending)
        return events

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
            return await run()
        finally:
            timer.cancel()

    with asyncio.Runner(loop_factory=FakeClockLoop) as runner:
        return runner.run(guarded())


def test_missing_path_is_a_failure_until_reload(disk: DiskTarget):
    """A deleted source directory is a config failure until it is created again."""
    src = disk.code.parent
    assert watch_events(make_watcher(disk), lambda: shutil.rmtree(src), src.mkdir) == [
        WatchEvent.CONFIG_FAILED,
        WatchEvent.CONFIG_CHANGED,
    ]


def test_config_change_watches_new_binaries(disk: DiskTarget):
    """After the build yml names a new exe, writing that exe and the pdb is a recompile."""
    new_exe = disk.exe.with_name("ISLE2.EXE")

    def build():
        new_exe.write_text("changed")
        disk.pdb.write_text("changed")

    assert watch_events(
        make_watcher(disk),
        lambda: write_build_yml(disk, build_yml(disk, new_exe.name)),
        None,
        build,
    ) == [WatchEvent.CONFIG_CHANGED, WatchEvent.CODE_CHANGED, WatchEvent.RECOMPILED]


def watch_disk(disk: DiskTarget, files: TargetFiles) -> AsyncIterator[WatchEvent]:
    return make_watcher(disk)._watch(files, watch_streams(files))


def test_replaced_source_file_is_a_code_change(disk: DiskTarget):
    """Replacing a watched source file by rename is a code change."""
    saved = disk.code.with_suffix(".tmp")

    def replace():
        saved.write_text("changed")
        os.replace(saved, disk.code)

    files = dataclasses.replace(disk.files, sources=(disk.code,))
    assert first_after(watch_disk(disk, files), replace) is WatchEvent.CODE_CHANGED


def test_written_exe_is_an_artifact_change(disk: DiskTarget):
    """Writing the exe is an artifact change."""
    assert (
        first_after(
            watch_disk(disk, disk.files), lambda: disk.exe.write_text("changed")
        )
        is WatchEvent.ARTIFACT_CHANGED
    )


def test_deleted_exe_is_an_artifact_delete(disk: DiskTarget):
    """Deleting the exe is an artifact delete."""
    assert (
        first_after(watch_disk(disk, disk.files), disk.exe.unlink)
        is WatchEvent.ARTIFACT_DELETED
    )


def test_other_build_files_do_not_delay_recompile(disk: DiskTarget):
    """Writes to other files in the build directory do not restart the cooldown."""
    ilk = disk.exe.with_suffix(".ILK")

    async def build():
        await asyncio.sleep(0.1)
        disk.exe.write_text("changed")
        disk.pdb.write_text("changed")
        for i in range(int(SETTLED / UNSETTLED)):
            await asyncio.sleep(UNSETTLED)
            ilk.write_text(str(i))

    async def run() -> bool:
        building = asyncio.create_task(build())
        async with contextlib.aclosing(watch_disk(disk, disk.files)) as events:
            async for event in events:
                if event is WatchEvent.RECOMPILED:
                    break
        still_building = not building.done()
        building.cancel()
        return still_building

    assert asyncio.run(asyncio.wait_for(run(), timeout=30))
