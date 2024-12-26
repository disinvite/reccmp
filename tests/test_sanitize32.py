"""Tests for asm sanitize, 32-bit pointers."""

from unittest.mock import patch
from typing import Optional
import pytest
from reccmp.isledecomp.compare.asm.parse import DisasmLiteInst, ParseAsm


def mock_inst(mnemonic: str, op_str: str) -> DisasmLiteInst:
    """Mock up the named tuple DisasmLite from just a mnemonic and op_str.
    To be used for tests on sanitize that do not require the instruction address
    or size. i.e. any non-jump instruction."""
    # TODO: This isn't really ideal. We could have a separate function just for jumps
    # and then use the address and size fields in that function only.
    return DisasmLiteInst(0, 0, mnemonic, op_str)


SMALL_INSTRUCTIONS = (
    b"\xfb",  # sti
    b"\x53",  # push ebx
    b"\xc3",  # ret
    b"\xc2\x04\x00",  # ret 0x4
    b"\x66\x3d\x00\x01",  # cmp ax, 0x100
)


@pytest.mark.parametrize("code", SMALL_INSTRUCTIONS)
def test_skip_small_instructions(code: bytes):
    """One of our optimizations is to skip small (in bytes) instructions that
    we know could not contain an address.
    For PE binaries in 32-bit, the starting virtual address is either 0x10000000
    or 0x4000000, so the instruction must be at least 5 bytes.
    (1 for the opcode, 4 for the operand)"""
    with patch("reccmp.isledecomp.compare.asm.parse.ParseAsm.sanitize") as mock:
        p = ParseAsm()
        p.parse_asm(code)
        mock.assert_not_called()


@pytest.mark.xfail(reason="Known issue. Needs a refactor.")
def test_should_skip_regardless_of_register():
    """Known limitation of the above optimization: using a different register
    changes the size of the instruction. Ideally we are consistent."""
    with patch("reccmp.isledecomp.compare.asm.parse.ParseAsm.sanitize") as mock:
        p = ParseAsm()
        p.parse_asm(b"\x66\x3d\x00\x01")  # cmp ax, 0x100
        p.parse_asm(b"\x66\x81\xf9\x00\x01")  # cmp cx, 0x100
        mock.assert_not_called()


def test_no_placeholder_for_jumps():
    """Jumps probably point to a label inside the current function. It is more
    helpful to the reader to not use a placeholder string. However, some JMP
    instructions point at the start of another function (e.g. destructors
    called in the SEH Unwind section.) These would be candidates for a placeholder
    but doing this would cause the placeholder number to vary with annotation
    coverage. The compromise is to use the name if we have it, but not use a
    placeholder OR bump the placeholder number."""

    p = ParseAsm()
    # No name lookup means no replacement
    (_, op_str) = p.sanitize(DisasmLiteInst(0x1000, 5, "jmp", "0x1000"))
    # Replace with jump displacement
    assert op_str == "-0x5"
    assert len(p.replacements) == 0

    # No name for 0x1000, use placeholder
    (_, op_str) = p.sanitize(DisasmLiteInst(0x1000, 5, "call", "0x1000"))
    assert op_str == "<OFFSET1>"
    assert len(p.replacements) == 1

    # Do not use placeholder even if we have one for the address.
    (_, op_str) = p.sanitize(DisasmLiteInst(0x1000, 5, "jmp", "0x1000"))
    assert op_str == "-0x5"

    def name_lookup(addr: int, **_) -> Optional[str]:
        return {0x1000: "Hello"}.get(addr)

    # Use name if we have it
    p.name_lookup = name_lookup
    (_, op_str) = p.sanitize(DisasmLiteInst(0x1000, 5, "jmp", "0x1000"))
    assert op_str == "Hello"


def test_no_placeholder_for_cmp():
    """Similar to the situation with JMP instructions, we intentionally do not
    use a placeholder for a CMP on an immediate value, even if we know it is an address.
    The reason is that a diff may be hidden behind the placholder. Loops on an array of
    structs might use an arbitrary address past the end of the array for the range check.
    We want to see when this happens because it means variables are probably out of order.
    """

    p = ParseAsm()
    # No name lookup means no replacement
    (_, op_str) = p.sanitize(DisasmLiteInst(0x1000, 5, "cmp", "eax, 0x1000"))
    assert op_str == "eax, 0x1000"
    assert len(p.replacements) == 0

    # Set placeholder
    (_, op_str) = p.sanitize(DisasmLiteInst(0x1000, 5, "call", "0x1000"))
    assert op_str == "<OFFSET1>"
    assert len(p.replacements) == 1

    # Ignore the placeholder
    (_, op_str) = p.sanitize(DisasmLiteInst(0x1000, 5, "cmp", "eax, 0x1000"))
    assert op_str == "eax, 0x1000"

    def name_lookup(addr: int, **_) -> Optional[str]:
        return {0x1000: "Hello"}.get(addr)

    # Use name if we have it
    p.name_lookup = name_lookup
    (_, op_str) = p.sanitize(DisasmLiteInst(0x1000, 5, "cmp", "eax, 0x1000"))
    assert op_str == "eax, Hello"
