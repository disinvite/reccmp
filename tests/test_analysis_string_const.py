"""Test string detection for PE images"""
import pytest
from reccmp.isledecomp.analysis import find_8bit_strings


def test_latin1_strings(isle_exe):
    addrs = [addr for addr, _ in find_8bit_strings(isle_exe)]
    assert 0x410130 in addrs  # Lego(R)


def test_string_search(isle_exe, binfile):
    isle_addrs = [addr for addr, _ in find_8bit_strings(isle_exe)]
    assert 0x410344 in isle_addrs  # SmartHeap version string

    lego_strings = [*find_8bit_strings(binfile)]
    # Not in relocation table
    assert (0x100DABB8, b"runtime error \x00") in lego_strings
    assert (0x100F41C8, b"dammo%d\x00") in lego_strings


@pytest.mark.xfail(reason="TODO")
def test_eatdn(binfile):
    lego_strings = [*find_8bit_strings(binfile)]
    # Don't return: b"`\xbfeatdn\x00"
    assert (0x100F41C0, b"eatdn\x00") in lego_strings
