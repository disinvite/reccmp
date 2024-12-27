"""Tests for asm sanitize, 32-bit pointers."""

from unittest.mock import Mock, patch
import pytest
from reccmp.isledecomp.compare.asm.parse import DisasmLiteInst, ParseAsm
from reccmp.isledecomp.compare.asm.replacement import (
    AddrTestProtocol,
    NameReplacementProtocol,
)


REGISTER_ONLY_INSTRUCTIONS = (
    # No operands
    DisasmLiteInst(0x1000, 1, "sti", ""),
    DisasmLiteInst(0x1000, 1, "ret", ""),
    # One operand
    DisasmLiteInst(0x1000, 1, "push", "eax"),
    DisasmLiteInst(0x1000, 2, "call", "eax"),
    # Two operands
    DisasmLiteInst(0x1000, 2, "cmp", "eax, edx"),
)


@pytest.mark.parametrize("inst", REGISTER_ONLY_INSTRUCTIONS)
def test_instructions_with_nothing_to_replace(inst: DisasmLiteInst):
    """There's no pointer or address value in these instructions,
    so your operand string should not be manipulated."""
    p = ParseAsm()
    (_, op_str) = p.sanitize(inst)
    assert op_str == inst.op_str


# There is one pointer in these instructions and we always replace it.
POINTER_INSTRUCTIONS = (
    # One operand
    DisasmLiteInst(0x1000, 6, "inc", "byte ptr [0x1234]"),
    DisasmLiteInst(0x1000, 6, "inc", "word ptr [0x1234]"),
    DisasmLiteInst(0x1000, 6, "inc", "dword ptr [0x1234]"),
    DisasmLiteInst(0x1000, 6, "inc", "qword ptr [0x1234]"),
    # Two operands
    DisasmLiteInst(0x1000, 5, "mov", "eax, dword ptr [0x1234]"),
    DisasmLiteInst(0x1000, 5, "mov", "dword ptr [0x1234], eax"),
)


@pytest.mark.parametrize("inst", POINTER_INSTRUCTIONS)
def test_sanitize_pointer_instructions(inst: DisasmLiteInst):
    """Can identify the pointer and insert a placeholder, regardless of the size
    of the pointed-at-item or the operand position."""
    p = ParseAsm()
    (_, op_str) = p.sanitize(inst)
    assert "0x1234" not in op_str
    assert "<OFFSET1>" in op_str


DISPLACE_INSTRUCTIONS = (
    # One operand
    DisasmLiteInst(0x1000, 6, "inc", "byte ptr [eax + 0x1234]"),
    # Two operands
    DisasmLiteInst(0x1000, 6, "mov", "eax, dword ptr [ecx + 0x1234]"),
    DisasmLiteInst(0x1000, 6, "mov", "dword ptr [ecx + 0x1234], eax"),
    # Jump table
    DisasmLiteInst(0x1000, 7, "jmp", "dword ptr [eax*4 + 0x1234]"),
)


@pytest.mark.parametrize("inst", DISPLACE_INSTRUCTIONS)
def test_sanitize_displacement_instructions(inst: DisasmLiteInst):
    """Can identify displacement operand (i.e. register plus address)
    but we only replace the value if it passes the address test."""
    p = ParseAsm()
    (_, op_str) = p.sanitize(inst)
    # No address test function provided, should not replace.
    assert op_str == inst.op_str

    # Assume all values are addreses
    p.addr_test = lambda _: True
    (_, op_str) = p.sanitize(inst)
    assert "0x1234" not in op_str
    assert "<OFFSET1>" in op_str


IMMEDIATE_VALUE_INSTRUCTIONS = (
    # One operand
    DisasmLiteInst(0x1000, 5, "push", "0x1234"),
    # Two operands
    DisasmLiteInst(0x1000, 5, "mov", "eax, 0x1234"),
)


@pytest.mark.parametrize("inst", IMMEDIATE_VALUE_INSTRUCTIONS)
def test_sanitize_immediate_value_instructions(inst: DisasmLiteInst):
    """If an operand is just a number, we will substitute the name
    or placeholder if it passes the address test."""
    p = ParseAsm()
    (_, op_str) = p.sanitize(inst)
    # No address test function provided, should not replace.
    assert "0x1234" in op_str

    # Assume all values are addresses
    p.addr_test = lambda _: True
    (_, op_str) = p.sanitize(inst)
    assert "0x1234" not in op_str
    assert "<OFFSET1>" in op_str


def test_sanitize_pointer_and_immediate():
    """Can handle instructions where two replacements are possible."""
    p = ParseAsm()
    inst = DisasmLiteInst(0x1000, 10, "mov", "dword ptr [0x1234], 0x5555")

    (_, op_str) = p.sanitize(inst)

    # Should only replace the pointer if we cannot test the address.
    assert op_str == "dword ptr [<OFFSET1>], 0x5555"

    # Assume all values are addresses
    p.addr_test = lambda _: True
    (_, op_str) = p.sanitize(inst)
    assert op_str == "dword ptr [<OFFSET1>], <OFFSET2>"


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
    For 32-bit PE binaries, the starting virtual address is either 0x10000000
    or 0x4000000, so the instruction must be at least 5 bytes.
    (1 for the opcode, 4 for the operand)"""
    with patch("reccmp.isledecomp.compare.asm.parse.ParseAsm.sanitize") as mock:
        p = ParseAsm()
        p.parse_asm(code)
        mock.assert_not_called()


@pytest.mark.xfail(reason="Known issue.")
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

    # Establish placeholder for address 0x1000
    (_, op_str) = p.sanitize(DisasmLiteInst(0x1000, 5, "call", "0x1000"))
    assert op_str == "<OFFSET1>"
    assert len(p.replacements) == 1

    # Do not use placeholder for a JMP to 0x1000
    (_, op_str) = p.sanitize(DisasmLiteInst(0x1000, 5, "jmp", "0x1000"))
    assert op_str == "-0x5"

    # Use name if we have it
    # Require exact match here: this should be the start of a function or asm label
    p.name_lookup = Mock(spec=NameReplacementProtocol, return_value="Hello")
    (_, op_str) = p.sanitize(DisasmLiteInst(0x1000, 5, "jmp", "0x1000"))
    p.name_lookup.assert_called_with(0x1000, exact=True)
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

    # Establish placeholder for address 0x1000
    (_, op_str) = p.sanitize(DisasmLiteInst(0x1000, 5, "call", "0x1000"))
    assert op_str == "<OFFSET1>"
    assert len(p.replacements) == 1

    # Ignore the placeholder
    (_, op_str) = p.sanitize(DisasmLiteInst(0x1000, 5, "cmp", "eax, 0x1000"))
    assert op_str == "eax, 0x1000"

    # Use name if we have it
    p.name_lookup = Mock(spec=NameReplacementProtocol, return_value="Hello")
    (_, op_str) = p.sanitize(DisasmLiteInst(0x1000, 5, "cmp", "eax, 0x1000"))
    p.name_lookup.assert_called_with(0x1000, exact=False)
    assert op_str == "eax, Hello"


def test_call_replacement():
    """CALL 0x____ instructions always use a placeholder.
    We require an exact address match from the database to use the name."""

    p = ParseAsm()
    # Always use placeholder even without callback methods
    (_, op_str) = p.sanitize(DisasmLiteInst(0x1000, 5, "call", "0x2000"))
    assert op_str == "<OFFSET1>"

    p.name_lookup = Mock(spec=NameReplacementProtocol, return_value=None)

    # Use cached placeholder
    p.sanitize(DisasmLiteInst(0x1000, 5, "call", "0x2000"))
    p.name_lookup.assert_not_called()

    # Require exact match from lookup
    (_, op_str) = p.sanitize(DisasmLiteInst(0x1000, 5, "call", "0x3000"))
    p.name_lookup.assert_called_with(0x3000, exact=True)
    # No name given, use placeholder again
    assert op_str == "<OFFSET2>"

    # Use cached placeholder, don't call lookup again
    assert len(p.name_lookup.mock_calls) == 1
    p.sanitize(DisasmLiteInst(0x1000, 5, "call", "0x3000"))
    assert len(p.name_lookup.mock_calls) == 1


def test_push_replacement():
    """PUSH 0x____ instructions use a placeholder but we need to check
    whether the value is an address."""
    p = ParseAsm()

    # Do not replace if we cannot test the address.
    p.name_lookup = Mock(spec=NameReplacementProtocol, return_value="Hello")
    (_, op_str) = p.sanitize(DisasmLiteInst(0x1000, 5, "push", "0x2000"))
    p.name_lookup.assert_not_called()
    assert op_str == "0x2000"

    # Set addr test method, should now call lookup and use name.
    p.addr_test = Mock(spec=AddrTestProtocol, return_value=True)
    (_, op_str) = p.sanitize(DisasmLiteInst(0x1000, 5, "push", "0x2000"))
    p.addr_test.assert_called_with(0x2000)
    p.name_lookup.assert_called_with(0x2000, exact=False)
    assert op_str == "Hello"

    # Simulate failed name lookup. Use placeholder.
    p.name_lookup = Mock(spec=NameReplacementProtocol, return_value=None)
    (_, op_str) = p.sanitize(DisasmLiteInst(0x1000, 5, "push", "0x3000"))
    p.addr_test.assert_called_with(0x3000)
    p.name_lookup.assert_called_with(0x3000, exact=False)
    assert op_str == "<OFFSET2>"  # Second replacement, 'Hello' cached above


def test_pointer_replacement():
    """A value in brackets (dword ptr [0x5555]) is obviously an address, so
    we always replace these with a placeholder."""

    p = ParseAsm()
    # Add address test, but we won't use it
    p.addr_test = Mock(spec=AddrTestProtocol, return_value=False)

    (_, op_str) = p.sanitize(DisasmLiteInst(0x1000, 6, "inc", "dword ptr [0x5555]"))
    assert op_str == "dword ptr [<OFFSET1>]"

    # Add name lookup
    p.name_lookup = Mock(spec=NameReplacementProtocol, return_value="Hello")
    (_, op_str) = p.sanitize(DisasmLiteInst(0x1000, 6, "inc", "dword ptr [0x1234]"))
    p.name_lookup.assert_called_with(0x1234, exact=False)
    assert op_str == "dword ptr [Hello]"

    # Can replace with two operands
    (_, op_str) = p.sanitize(
        DisasmLiteInst(0x1000, 6, "mov", "eax, dword ptr [0x2000]")
    )
    p.name_lookup.assert_called_with(0x2000, exact=False)
    assert op_str == "eax, dword ptr [Hello]"

    # We always replace these pointer values, no need to check if it's an address
    p.addr_test.assert_not_called()


def test_displace_replacement():
    """Need to test values used in pointer displacement (dword ptr[register + value])
    because many are struct offset or vtable calls."""
    p = ParseAsm()
    inst = DisasmLiteInst(0x1000, 3, "mov", "eax, dword ptr [ecx + 0x1000]")

    # Should not replace
    p.addr_test = Mock(spec=AddrTestProtocol, return_value=False)
    (_, op_str) = p.sanitize(inst)
    p.addr_test.assert_called_with(0x1000)
    assert op_str == inst.op_str
    assert len(p.replacements) == 0

    # Should replace
    p.addr_test = Mock(spec=AddrTestProtocol, return_value=True)
    (_, op_str) = p.sanitize(inst)
    p.addr_test.assert_called_with(0x1000)
    assert op_str == "eax, dword ptr [ecx + <OFFSET1>]"
    assert len(p.replacements) == 1
