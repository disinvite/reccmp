"""Tests for the events reported by the daemon's file watcher."""

import asyncio
import contextlib
import dataclasses
import os
import selectors
import shutil
import tempfile
from collections.abc import AsyncIterator, Callable
from pathlib import Path
import pytest
from reccmp.project.common import RECCMP_BUILD_CONFIG, RECCMP_PROJECT_CONFIG
from reccmp.project.detect import RecCmpPartialTarget, RecCmpProject
from reccmp.remote.watch import (
    BuildTracker,
    TargetFiles,
    TargetWatcher,
    WatchEvent,
    is_stale,
    watch_artifacts,
    watch_files,
    watch_streams,
)
from .constants import LEGO1_SHA256

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


def make_watcher() -> TargetWatcher:
    project = make_project()
    return TargetWatcher(project, project.get("ISLE"))


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

    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp).resolve()
        (root / BUILD_PATH).mkdir()
        binaries = {root / EXE_PATH, root / PDB_PATH}

        async def script() -> AsyncIterator[set[Path]]:
            for step in steps:
                if isinstance(step, float):
                    await asyncio.sleep(step)
                    continue
                event, path = step
                path = root / path
                if event is WatchEvent.ARTIFACT_CHANGED:
                    path.write_text("")
                else:
                    path.unlink()
                yield {path}
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


def patch_loads(monkeypatch: pytest.MonkeyPatch, *loads: Callable[[], RecCmpProject]):
    """Each reload of the project config returns the next load."""
    script = iter(loads)

    def fake_from_directory(directory: Path, alert: bool = True) -> RecCmpProject:
        assert directory == ROOT_PATH / BUILD_PATH
        assert not alert
        return next(script)()

    monkeypatch.setattr(
        RecCmpProject, "from_directory", staticmethod(fake_from_directory)
    )


def reloads(
    monkeypatch: pytest.MonkeyPatch, *loads: Callable[[], RecCmpProject]
) -> list[WatchEvent | None]:
    patch_loads(monkeypatch, *loads)
    watcher = make_watcher()
    return [watcher.reload() for _ in loads]


def test_yml_rewrite_with_same_config(monkeypatch: pytest.MonkeyPatch):
    assert reloads(monkeypatch, make_project) == [None]


def test_changed_target_is_a_config_change(monkeypatch: pytest.MonkeyPatch):
    assert reloads(monkeypatch, lambda: make_project("ISLE2.EXE")) == [
        WatchEvent.CONFIG_CHANGED
    ]


def test_invalid_config_is_a_failure(monkeypatch: pytest.MonkeyPatch):
    assert reloads(monkeypatch, invalid_project) == [WatchEvent.CONFIG_FAILED]


def test_fixed_config_is_a_config_change(monkeypatch: pytest.MonkeyPatch):
    assert reloads(monkeypatch, invalid_project, make_project) == [
        WatchEvent.CONFIG_FAILED,
        WatchEvent.CONFIG_CHANGED,
    ]


WatcherRun = Callable[[], AsyncIterator[set[Path]]]


def run_watcher(
    monkeypatch: pytest.MonkeyPatch, *runs: WatcherRun
) -> tuple[list[WatchEvent], list[TargetFiles]]:
    """Each run is the only input for one start of the watches.
    Returns the events and the files for each start."""
    started: list[TargetFiles] = []
    script = iter(runs)

    async def done() -> AsyncIterator[set[Path]]:
        raise ScriptDone
        yield  # pylint: disable=unreachable

    def fake_streams(files: TargetFiles):
        started.append(files)
        return [next(script, done)()]

    async def no_artifacts(*_args):
        pass

    monkeypatch.setattr("reccmp.remote.watch.watch_streams", fake_streams)
    monkeypatch.setattr("reccmp.remote.watch.watch_artifacts", no_artifacts)
    monkeypatch.setattr("reccmp.remote.watch.is_stale", lambda _files: False)
    monkeypatch.setattr("reccmp.remote.watch.watch_roots", lambda _files: set())
    watcher = make_watcher()

    async def run():
        events = []
        with pytest.raises(ScriptDone):
            async for event in watcher.events():
                events.append(event)
        return events

    return asyncio.run(asyncio.wait_for(run(), timeout=30)), started


def test_missing_path_is_a_failure_until_reload(monkeypatch: pytest.MonkeyPatch):
    patch_loads(monkeypatch, make_project)

    async def lose_path() -> AsyncIterator[set[Path]]:
        raise FileNotFoundError
        yield  # pylint: disable=unreachable

    events, _ = run_watcher(monkeypatch, lose_path)
    assert events == [WatchEvent.CONFIG_FAILED, WatchEvent.CONFIG_CHANGED]


def test_config_change_watches_new_binaries(monkeypatch: pytest.MonkeyPatch):
    patch_loads(monkeypatch, lambda: make_project("ISLE2.EXE"))

    async def change_config() -> AsyncIterator[set[Path]]:
        yield {ROOT_PATH / BUILD_YML_PATH}

    events, started = run_watcher(monkeypatch, change_config)
    assert events == [WatchEvent.CONFIG_CHANGED]
    assert ROOT_PATH / BUILD_PATH / "ISLE2.EXE" in started[1].binaries


class DiskTarget:
    """Real files for a target, with mtimes set by hand."""

    def __init__(self, root: Path):
        self.exe = root / "build" / "ISLE.EXE"
        self.pdb = root / "build" / "ISLE.PDB"
        self.csv = root / "project" / "isle.csv"
        self.code = root / "project" / "src" / "isle.cpp"
        # The code goes first, so the build starts up to date.
        for path in (self.code, self.csv, self.exe, self.pdb):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("")
        self.files = TargetFiles(
            binaries={self.exe, self.pdb},
            ymls=set(),
            csvs={self.csv},
            sources=(self.code.parent,),
        )

    def set_mtime(self, path: Path, seconds: int):
        os.utime(path, (seconds, seconds))


@pytest.fixture(name="disk")
def fixture_disk(tmp_path: Path) -> DiskTarget:
    return DiskTarget(tmp_path.resolve())


def first_after(events: AsyncIterator, action: Callable[[], None]):
    """The first item from a real watch, once the action has run."""

    async def run():
        async with contextlib.aclosing(events) as stream:
            pending = asyncio.ensure_future(anext(stream))
            await asyncio.sleep(0.1)
            action()
            return await pending

    return asyncio.run(asyncio.wait_for(run(), timeout=30))


def watch_disk(files: TargetFiles) -> AsyncIterator[WatchEvent]:
    return make_watcher()._watch(files, watch_streams(files))


def test_code_newer_than_build_is_stale(disk: DiskTarget):
    disk.set_mtime(disk.exe, 1000)
    disk.set_mtime(disk.pdb, 1000)
    disk.set_mtime(disk.code, 2000)
    assert is_stale(disk.files)


def test_build_running_at_startup_is_stale(disk: DiskTarget):
    disk.set_mtime(disk.pdb, 1000)
    disk.set_mtime(disk.code, 2000)
    disk.set_mtime(disk.exe, 3000)
    assert is_stale(disk.files)


def test_missing_exe_is_stale(disk: DiskTarget):
    disk.exe.unlink()
    assert is_stale(disk.files)


def test_build_newer_than_code_is_not_stale(disk: DiskTarget):
    disk.set_mtime(disk.code, 1000)
    disk.set_mtime(disk.exe, 2000)
    disk.set_mtime(disk.pdb, 2000)
    assert not is_stale(disk.files)


def test_replaced_source_file_is_a_code_change(disk: DiskTarget):
    saved = disk.code.with_suffix(".tmp")

    def replace():
        saved.write_text("changed")
        os.replace(saved, disk.code)

    files = dataclasses.replace(disk.files, sources=(disk.code,))
    assert first_after(watch_disk(files), replace) is WatchEvent.CODE_CHANGED


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


def test_missing_directory_raises(disk: DiskTarget):
    shutil.rmtree(disk.exe.parent)
    with pytest.raises(FileNotFoundError):
        first_after(watch_files(disk.files.binaries), lambda: None)


def test_missing_source_file_raises(disk: DiskTarget):
    disk.code.unlink()
    with pytest.raises(FileNotFoundError):
        watch_streams(dataclasses.replace(disk.files, sources=(disk.code,)))


def test_deleted_directory_raises(disk: DiskTarget):
    def recreate():
        shutil.rmtree(disk.exe.parent)
        disk.exe.parent.mkdir()

    with pytest.raises(FileNotFoundError):
        first_after(watch_files(disk.files.binaries), recreate)
