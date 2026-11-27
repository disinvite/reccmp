"""Tests for the parts of the daemon's file watcher that read the disk."""

import shutil
from pathlib import Path
import pytest
from reccmp.remote.fswatch import changed_paths, is_stale, scan_target
from .remote_watch_helpers import DiskTarget


@pytest.fixture(name="disk")
def fixture_disk(tmp_path: Path) -> DiskTarget:
    return DiskTarget(tmp_path.resolve())


def test_code_newer_than_build_is_stale(disk: DiskTarget):
    disk.set_mtime(disk.exe, 1000)
    disk.set_mtime(disk.pdb, 1000)
    disk.set_mtime(disk.code, 2000)
    assert is_stale(disk.files, scan_target(disk.files))


def test_build_running_at_startup_is_stale(disk: DiskTarget):
    disk.set_mtime(disk.pdb, 1000)
    disk.set_mtime(disk.code, 2000)
    disk.set_mtime(disk.exe, 3000)
    assert is_stale(disk.files, scan_target(disk.files))


def test_missing_exe_is_stale(disk: DiskTarget):
    disk.exe.unlink()
    assert is_stale(disk.files, scan_target(disk.files))


def test_build_newer_than_code_is_not_stale(disk: DiskTarget):
    disk.set_mtime(disk.code, 1000)
    disk.set_mtime(disk.exe, 2000)
    disk.set_mtime(disk.pdb, 2000)
    assert not is_stale(disk.files, scan_target(disk.files))


def test_source_write_is_reported(disk: DiskTarget):
    old = scan_target(disk.files)
    disk.code.write_text("changed")
    assert changed_paths(old, scan_target(disk.files)) == {disk.code}


def test_source_delete_is_reported(disk: DiskTarget):
    old = scan_target(disk.files)
    disk.code.unlink()
    assert changed_paths(old, scan_target(disk.files)) == {disk.code}


def test_missing_source_path_has_no_files(disk: DiskTarget):
    shutil.rmtree(disk.code.parent)
    assert scan_target(disk.files).keys() == {disk.exe, disk.pdb, disk.csv}


def test_deleted_build_directory_reports_binaries(disk: DiskTarget):
    # CLAUDE SAYS: The directory is replaced between scans. A scan running
    # during rmtree could see the exe gone and the pdb not yet.
    old = scan_target(disk.files)
    shutil.rmtree(disk.exe.parent)
    disk.exe.parent.mkdir()
    assert changed_paths(old, scan_target(disk.files)) == {disk.exe, disk.pdb}
