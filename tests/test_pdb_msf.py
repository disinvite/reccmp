from struct import pack
from reccmp.formats.pdb.msf import MSFContainer, MSF_200_MAGIC

PAGE_SIZE = 0x200


def test_nil_stream_keeps_stream_id():
    """A nil stream (size -1) does not shift the ids of the streams after it."""
    header = pack("<44sIHHI4xH", MSF_200_MAGIC, PAGE_SIZE, 0, 4, 32, 1)
    # Stream sizes 4, -1, 4. Streams 0 and 2 are on pages 2 and 3.
    directory = pack("<H2xi4xi4xi4xHH", 3, 4, -1, 4, 2, 3)
    pages = (header, directory, b"AAAA", b"BBBB")
    data = b"".join(page.ljust(PAGE_SIZE, b"\x00") for page in pages)

    msf = MSFContainer.from_bytes(data)
    assert msf.get_stream(0) == b"AAAA"
    assert msf.get_stream(1) == b""
    assert msf.get_stream(2) == b"BBBB"
