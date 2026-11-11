import math
from enum import IntEnum
from struct import calcsize, iter_unpack, unpack_from
from typing import Iterable, NamedTuple, Protocol, Sequence


class StreamIndex(IntEnum):
    """PDB information with a fixed stream id."""

    OLD_DIRECTORY = 0
    PDB = 1
    TPI = 2
    DBI = 3


PDB_100_MAGIC = (
    b"Microsoft C/C++ program database 1.00\r\n\x1a\x4a\x47\x00\x00"  # char[0x2c]
)
MSF_200_MAGIC = (
    b"Microsoft C/C++ program database 2.00\r\n\x1a\x4a\x47\x00\x00"  # char[0x2c]
)
MSF_700_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00"  # char[0x1e]


class MSFStream(NamedTuple):
    size: int
    pages: tuple[int, ...]


def _join_pages(data: bytes, page_size: int, pages: Iterable[int]) -> bytes:
    """Combine the given pages into a contiguous block."""
    return b"".join(data[page_size * page : page_size * (page + 1)] for page in pages)


def _read_directory(
    directory: bytes, page_size: int, count_fmt: str, size_fmt: str, page_fmt: str
) -> list[MSFStream]:
    (n_streams,) = unpack_from(count_fmt, directory)
    offset = calcsize(count_fmt)
    sizes_end = offset + n_streams * calcsize(size_fmt)
    sizes = [size for size, in iter_unpack(size_fmt, directory[offset:sizes_end])]

    # Nil streams (size -1) have no pages.
    counts = [math.ceil(max(size, 0) / page_size) for size in sizes]
    pages = unpack_from(f"<{sum(counts)}{page_fmt}", directory, offset=sizes_end)

    streams = []
    start = 0
    for size, count in zip(sizes, counts):
        streams.append(MSFStream(size, pages[start : start + count]))
        start += count

    return streams


def _read_msf_200(data: bytes) -> tuple[int, list[MSFStream]]:
    page_size, dir_size = unpack_from("<44xI4xI", data)
    dir_pages = unpack_from(f"<{math.ceil(dir_size / page_size)}H", data, offset=0x3C)
    directory = _join_pages(data, page_size, dir_pages)
    # The stream count is followed by a reserved word.
    # Each stream size is followed by a reserved dword.
    return page_size, _read_directory(directory, page_size, "<H2x", "<i4x", "H")


def _read_msf_700(data: bytes) -> tuple[int, list[MSFStream]]:
    page_size, dir_size = unpack_from("<32xI8xI", data)
    n_dir_pages = math.ceil(dir_size / page_size)
    # In "big" MSF containers, the directory page list can span multiple pages.
    map_pages = unpack_from(
        f"<{math.ceil(n_dir_pages * 4 / page_size)}I", data, offset=0x34
    )
    dir_pages = unpack_from(f"<{n_dir_pages}I", _join_pages(data, page_size, map_pages))
    directory = _join_pages(data, page_size, dir_pages)
    return page_size, _read_directory(directory, page_size, "<I", "<i", "I")


class MSFContainer:
    def __init__(
        self, data: bytes, page_size: int, streams: Sequence[MSFStream]
    ) -> None:
        self.data = data
        self.page_size = page_size
        self.streams = tuple(streams)

    @classmethod
    def from_bytes(cls, data: bytes) -> "MSFContainer":
        if data.startswith(MSF_200_MAGIC):
            return cls(data, *_read_msf_200(data))

        if data.startswith(MSF_700_MAGIC):
            return cls(data, *_read_msf_700(data))

        raise ValueError("Not an MSF file")

    def get_stream(self, stream_id: int) -> bytes:
        size, pages = self.streams[stream_id]
        return _join_pages(self.data, self.page_size, pages)[:size]


class PDB100File:
    """PDB 1.00 (MSVC 1.x era) predates the MSF format. It only contains type records (TPI stream).
    We take some liberties here to make it compatible with the newer MSF format PDBs.
    Reference: `struct RTPDB10HDR` from `virtualbox/include/iprt/formats/pdb.h`."""

    def __init__(self, data: bytes) -> None:
        self.data = data

    def get_stream(self, stream_id: int) -> bytes:
        if stream_id != StreamIndex.TPI:
            raise KeyError(stream_id)

        # Semi-hack: splice the file's version constant into the spot where newer formats place the TPI version.
        # This makes the version visible to the TPI reader so we can vary its behavior.
        return self.data[0x2C:0x30] + self.data[0x38:]


class PDBStreams(Protocol):
    def get_stream(self, stream_id: int) -> bytes: ...


def open_pdb(data: bytes) -> PDBStreams:
    if data.startswith(PDB_100_MAGIC):
        return PDB100File(data)

    return MSFContainer.from_bytes(data)
