"""Tests for the parts of the daemon's file watcher that read the disk."""

import dataclasses
import shutil
from pathlib import Path
import pytest
from reccmp.remote.fswatch import (
    is_stale,
    watch_files,
    watch_listed,
    watch_source_dirs,
)
from .remote_watch_helpers import DiskTarget, first_after


@pytest.fixture(name="disk")
def fixture_disk(tmp_path: Path) -> DiskTarget:
    return DiskTarget(tmp_path.resolve())


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


def test_source_write_is_reported(disk: DiskTarget):
    sources = watch_source_dirs(disk.files)
    assert first_after(sources, lambda: disk.code.write_text("changed")) == {disk.code}


def test_missing_directory_raises(disk: DiskTarget):
    shutil.rmtree(disk.exe.parent)
    with pytest.raises(FileNotFoundError):
        first_after(watch_files(disk.files.binaries), lambda: None)


def test_missing_source_file_raises(disk: DiskTarget):
    disk.code.unlink()
    with pytest.raises(FileNotFoundError):
        watch_listed(dataclasses.replace(disk.files, sources=(disk.code,)))


def test_deleted_directory_raises(disk: DiskTarget):
    def recreate():
        shutil.rmtree(disk.exe.parent)
        disk.exe.parent.mkdir()

    with pytest.raises(FileNotFoundError):
        first_after(watch_files(disk.files.binaries), recreate)
