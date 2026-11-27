"""Tests for the events reported by the daemon's file watcher."""

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
    TargetWatcher,
    WatchEvent,
)
from .constants import LEGO1_SHA256
from .remote_watch_helpers import DiskTarget, Events, run_scenario


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
    build.write_file(build_yml_path(disk))


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
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.after(4 * ARTIFACT_DELAY_S) is None

    run_scenario(make_watcher(disk).events(), scenario)


def test_rewrite_after_delete_is_a_recompile(disk: DiskTarget):
    """Rewriting a deleted exe completes the recompile."""

    async def scenario(events: Events):
        rebuild(disk)
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        disk.unlink(disk.exe)
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
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


def test_build_running_at_startup_is_a_code_change(disk: DiskTarget):
    """CLAUDE SAYS: Code newer than the pdb but older than the exe when the watcher
    starts is a code change."""
    disk.set_mtime(disk.pdb, 1000)
    disk.set_mtime(disk.code, 2000)
    disk.set_mtime(disk.exe, 3000)

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


def test_code_change_during_config_failure_is_reported_after_fix(disk: DiskTarget):
    """CLAUDE SAYS: Code edited while the config is broken is still a code change
    once the config is fixed."""

    async def scenario(events: Events):
        disk.write(build_yml_path(disk), INVALID_YML)
        assert await events.next() is WatchEvent.CONFIG_FAILED
        disk.write(disk.code, "changed")
        # CLAUDE SAYS: The watcher still reports the edit during the failure.
        # The server drops this event while the config is broken.
        assert await events.next() is WatchEvent.CODE_CHANGED
        write_build_yml(disk)
        assert await events.next() is WatchEvent.CONFIG_CHANGED
        # CLAUDE SAYS: This one comes from the staleness check after the reload.
        # It is the event that marks the build stale once the config is fixed.
        assert await events.next() is WatchEvent.CODE_CHANGED

    run_scenario(make_watcher(disk).events(), scenario)


def test_rebuild_during_config_failure_is_not_stale_after_fix(disk: DiskTarget):
    """CLAUDE SAYS: Code edited and rebuilt while the config is broken is not a
    code change once the config is fixed."""

    async def scenario(events: Events):
        disk.write(build_yml_path(disk), INVALID_YML)
        assert await events.next() is WatchEvent.CONFIG_FAILED
        disk.write(disk.code, "changed")
        assert await events.next() is WatchEvent.CODE_CHANGED
        rebuild(disk)
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED
        assert await events.after(4 * ARTIFACT_DELAY_S) is WatchEvent.RECOMPILED
        write_build_yml(disk)
        assert await events.next() is WatchEvent.CONFIG_CHANGED
        assert await events.after(4 * ARTIFACT_DELAY_S) is None

    run_scenario(make_watcher(disk).events(), scenario)


def test_restored_source_directory_is_a_code_change(disk: DiskTarget):
    """CLAUDE SAYS: The code files of a deleted source directory are reported again
    when it is restored."""
    src = disk.code.parent

    async def scenario(events: Events):
        disk.rmtree(src)
        assert await events.next() is WatchEvent.CODE_CHANGED
        disk.mkdir(src)
        disk.write(disk.code, "restored")
        assert await events.next() is WatchEvent.CODE_CHANGED

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


def test_other_build_files_are_not_reported(disk: DiskTarget):
    """Writes to other files in the build directory are not reported."""
    ilk = disk.exe.with_suffix(".ILK")

    async def scenario(events: Events):
        disk.write(ilk, "changed")
        # The pdb delete is reported after the .ILK would be: in a later batch,
        # or in the same batch, where ISLE.ILK sorts before ISLE.PDB.
        disk.unlink(disk.pdb)
        assert await events.next() is WatchEvent.ARTIFACT_CHANGED

    run_scenario(make_watcher(disk).events(), scenario)
