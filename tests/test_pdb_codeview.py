from reccmp.formats.pdb.codeview import CodeViewRecord


def test_align_to_end_of_buffer():
    """Iteration stops if alignment moves the offset to the end of the buffer."""
    data = b"\x04\x00\x0c\x11\x00\x00\x00\x00"
    records = list(CodeViewRecord.from_bytes(data, align=True))
    assert records == [CodeViewRecord(0, 0x110C, 6)]
