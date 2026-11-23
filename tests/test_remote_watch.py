"""Tests for the events reported by the daemon's file watcher."""

import asyncio
import contextlib
import dataclasses
import os
import selectors
from collections.abc import AsyncIterator, Callable
from pathlib import Path
import pytest
from reccmp.project.common import RECCMP_BUILD_CONFIG, RECCMP_PROJECT_CONFIG
from reccmp.project.detect import RecCmpPartialTarget, RecCmpProject, RecCmpTarget
from reccmp.remote.fswatch import DiskWatch, TargetFiles, watch_streams
from reccmp.remote.watch import (
    BuildTracker,
    TargetWatcher,
    WatchEvent,
    watch_artifacts,
)
from .constants import LEGO1_SHA256
from .remote_watch_helpers import DiskTarget, first_after

# Never created: the project is built in memory and the watches are faked.
ROOT_PATH = Path("isle").resolve()
PROJECT_PATH = Path("project")
BUILD_PATH = Path("build")
EXE_PATH = BUILD_PATH / "ISLE.EXE"
PDB_PATH = BUILD_PATH / "ISLE.PDB"
BUILD_YML_PATH = BUILD_PATH / RECCMP_BUILD_CONFIG
CSV_PATH = PROJECT_PATH / "isle.csv"


class ScriptDone(Exception):
    """The fake watches have no more changes to report."""


class InvalidConfig(Exception):
    """Raised by the fake from_directory in place of a yml parse error."""


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


def make_project(exe: str = "ISLE.EXE") -> RecCmpProject:
    project = RecCmpProject(
        project_config_path=ROOT_PATH / PROJECT_PATH / RECCMP_PROJECT_CONFIG,
        build_config_path=ROOT_PATH / BUILD_YML_PATH,
    )
    project.targets["ISLE"] = RecCmpPartialTarget(
        target_id="ISLE",
        filename="ISLE.EXE",
        sha256=LEGO1_SHA256,
        source_paths=(ROOT_PATH / PROJECT_PATH / "src",),
        original_path=ROOT_PATH / "ISLE.EXE",
        recompiled_path=ROOT_PATH / BUILD_PATH / exe,
        recompiled_pdb=ROOT_PATH / PDB_PATH,
        data_sources=[ROOT_PATH / CSV_PATH],
    )
    return project


def invalid_project() -> RecCmpProject:
    raise InvalidConfig


def loaded(project: RecCmpProject) -> tuple[RecCmpTarget, TargetFiles]:
    target = project.get("ISLE")
    return target, TargetFiles.from_target(project, target)


def make_watcher(
    *loads: Callable[[], RecCmpProject], disk: DiskWatch | None = None
) -> TargetWatcher:
    """Each reload of the project config returns the next load."""
    script = iter(loads)
    target, files = loaded(make_project())
    return TargetWatcher(target, files, lambda: loaded(next(script)()), disk)


def track(*events: WatchEvent, stale: bool = False) -> list[WatchEvent]:
    tracker = BuildTracker()
    if stale:
        events = (WatchEvent.CODE_CHANGED, *events)
    passed = [tracker.step(event) for event in events]
    return [event for event in passed if event is not None]


def test_recompile():
    assert track(WatchEvent.ARTIFACT_CHANGED, WatchEvent.RECOMPILED) == [
        WatchEvent.RECOMPILED
    ]


def test_code_change_then_recompile():
    assert track(
        WatchEvent.CODE_CHANGED, WatchEvent.ARTIFACT_CHANGED, WatchEvent.RECOMPILED
    ) == [WatchEvent.CODE_CHANGED, WatchEvent.RECOMPILED]


def test_code_change_during_cooldown_drops_recompile():
    assert track(
        WatchEvent.ARTIFACT_CHANGED, WatchEvent.CODE_CHANGED, WatchEvent.RECOMPILED
    ) == [WatchEvent.CODE_CHANGED]


def test_stale_at_startup_is_a_code_change():
    assert track(stale=True) == [WatchEvent.CODE_CHANGED]


def test_data_change():
    assert track(WatchEvent.DATA_CHANGED) == [WatchEvent.DATA_CHANGED]


def test_data_change_while_stale_is_dropped():
    assert track(WatchEvent.CODE_CHANGED, WatchEvent.DATA_CHANGED) == [
        WatchEvent.CODE_CHANGED
    ]


def test_data_change_during_cooldown_is_dropped():
    assert track(WatchEvent.ARTIFACT_CHANGED, WatchEvent.DATA_CHANGED) == []


def test_data_change_after_deleted_artifact_waits_for_recompile():
    assert track(
        WatchEvent.ARTIFACT_DELETED,
        WatchEvent.DATA_CHANGED,
        WatchEvent.ARTIFACT_CHANGED,
        WatchEvent.RECOMPILED,
        WatchEvent.DATA_CHANGED,
    ) == [WatchEvent.RECOMPILED, WatchEvent.DATA_CHANGED]


def test_config_failure_drops_other_events():
    assert track(
        WatchEvent.CONFIG_FAILED,
        WatchEvent.CODE_CHANGED,
        WatchEvent.ARTIFACT_CHANGED,
        WatchEvent.RECOMPILED,
        WatchEvent.DATA_CHANGED,
        WatchEvent.CONFIG_CHANGED,
    ) == [WatchEvent.CONFIG_FAILED, WatchEvent.CONFIG_CHANGED]


def test_config_change_takes_staleness_from_restart():
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
    assert settle((WatchEvent.ARTIFACT_CHANGED, EXE_PATH), SETTLED) == [
        WatchEvent.ARTIFACT_CHANGED
    ]


def test_recompile_split_across_timeouts():
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


def reloads(*loads: Callable[[], RecCmpProject]) -> list[WatchEvent | None]:
    watcher = make_watcher(*loads)
    return [watcher.reload() for _ in loads]


def test_yml_rewrite_with_same_config():
    assert reloads(make_project) == [None]


def test_changed_target_is_a_config_change():
    assert reloads(lambda: make_project("ISLE2.EXE")) == [WatchEvent.CONFIG_CHANGED]


def test_invalid_config_is_a_failure():
    assert reloads(invalid_project) == [WatchEvent.CONFIG_FAILED]


def test_fixed_config_is_a_config_change():
    assert reloads(invalid_project, make_project) == [
        WatchEvent.CONFIG_FAILED,
        WatchEvent.CONFIG_CHANGED,
    ]


WatcherRun = Callable[[], AsyncIterator[set[Path]]]


async def done() -> AsyncIterator[set[Path]]:
    raise ScriptDone
    yield  # pylint: disable=unreachable


class ScriptedDisk(DiskWatch):
    """Each run is the only input for one start of the watches."""

    def __init__(self, *runs: WatcherRun):
        self.runs = iter(runs)
        self.started: list[TargetFiles] = []

    def streams(self, files: TargetFiles) -> list[AsyncIterator[set[Path]]]:
        self.started.append(files)
        return [next(self.runs, done)()]

    async def presence(self, paths: set[Path]) -> AsyncIterator[tuple[Path, bool]]:
        await asyncio.Event().wait()
        yield  # pylint: disable=unreachable

    def is_stale(self, files: TargetFiles) -> bool:
        return False

    async def wait_for_files(self, files: TargetFiles, retry_seconds: float):
        pass


def run_watcher(
    loads: list[Callable[[], RecCmpProject]], *runs: WatcherRun
) -> tuple[list[WatchEvent], list[TargetFiles]]:
    """Returns the events and the files for each start."""
    disk = ScriptedDisk(*runs)
    watcher = make_watcher(*loads, disk=disk)

    async def run():
        events = []
        with pytest.raises(ScriptDone):
            async for event in watcher.events():
                events.append(event)
        return events

    return asyncio.run(asyncio.wait_for(run(), timeout=30)), disk.started


def test_missing_path_is_a_failure_until_reload():
    async def lose_path() -> AsyncIterator[set[Path]]:
        raise FileNotFoundError
        yield  # pylint: disable=unreachable

    events, _ = run_watcher([make_project], lose_path)
    assert events == [WatchEvent.CONFIG_FAILED, WatchEvent.CONFIG_CHANGED]


def test_config_change_watches_new_binaries():
    async def change_config() -> AsyncIterator[set[Path]]:
        yield {ROOT_PATH / BUILD_YML_PATH}

    events, started = run_watcher([lambda: make_project("ISLE2.EXE")], change_config)
    assert events == [WatchEvent.CONFIG_CHANGED]
    assert ROOT_PATH / BUILD_PATH / "ISLE2.EXE" in started[1].binaries


@pytest.fixture(name="disk")
def fixture_disk(tmp_path: Path) -> DiskTarget:
    return DiskTarget(tmp_path.resolve())


def watch_disk(files: TargetFiles) -> AsyncIterator[WatchEvent]:
    return make_watcher()._watch(files, watch_streams(files))


def test_replaced_source_file_is_a_code_change(disk: DiskTarget):
    saved = disk.code.with_suffix(".tmp")

    def replace():
        saved.write_text("changed")
        os.replace(saved, disk.code)

    files = dataclasses.replace(disk.files, sources=(disk.code,))
    assert first_after(watch_disk(files), replace) is WatchEvent.CODE_CHANGED


def test_finished_stream_is_an_error(disk: DiskTarget):
    async def finished() -> AsyncIterator[set[Path]]:
        return
        yield  # pylint: disable=unreachable

    with pytest.raises(RuntimeError):
        first_after(make_watcher()._watch(disk.files, [finished()]), lambda: None)


def test_written_exe_is_an_artifact_change(disk: DiskTarget):
    assert (
        first_after(watch_disk(disk.files), lambda: disk.exe.write_text("changed"))
        is WatchEvent.ARTIFACT_CHANGED
    )


def test_deleted_exe_is_an_artifact_delete(disk: DiskTarget):
    assert (
        first_after(watch_disk(disk.files), disk.exe.unlink)
        is WatchEvent.ARTIFACT_DELETED
    )


def test_other_build_files_do_not_delay_recompile(disk: DiskTarget):
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
        async with contextlib.aclosing(watch_disk(disk.files)) as events:
            async for event in events:
                if event is WatchEvent.RECOMPILED:
                    break
        still_building = not building.done()
        building.cancel()
        return still_building

    assert asyncio.run(asyncio.wait_for(run(), timeout=30))
