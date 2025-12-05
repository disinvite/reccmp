import math
from dataclasses import dataclass
from enum import IntEnum
from struct import calcsize, unpack_from
from typing import Iterable, Iterator, NamedTuple


class StreamIndex(IntEnum):
    """PDB information with a fixed stream id."""

    OLD_DIRECTORY = 0
    PDB = 1
    TPI = 2
    DBI = 3


class MSFMagic:
    # szHdrOld = b"Microsoft C/C++ program database 1.00\r\n\x1a\x4a\x47\x00\x00" # char[0x2c]
    szHdrMagic = (
        b"Microsoft C/C++ program database 2.00\r\n\x1a\x4a\x47\x00\x00"  # char[0x2c]
    )
    szBigHdrMagic = b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00"  # char[0x1e]


@dataclass(frozen=True)
class MSFHeader:
    magic: bytes
    page_size: int
    fpm_page_no: int  # free page map
    num_pages: int
    stream_dir_size: int
    block_maps: tuple[int, ...]  # Page numbers for block map

    @classmethod
    def from_bytes(cls, buf: bytes) -> "MSFHeader":
        is_big_header = False

        if buf[: len(MSFMagic.szHdrMagic)] == MSFMagic.szHdrMagic:
            is_big_header = False
        elif buf[: len(MSFMagic.szBigHdrMagic)] == MSFMagic.szBigHdrMagic:
            is_big_header = True
        else:
            raise ValueError  # TODO: exception

        fmt = "30s4I4x" if is_big_header else "44sI2HI4x"

        (magic_str, page_size, fpm_page_no, num_pages, stream_dir_size) = unpack_from(
            fmt, buf
        )
        n_block_maps = math.ceil(stream_dir_size * 1.0 / page_size)

        block_fmt = f"<{n_block_maps}I" if is_big_header else f"<{n_block_maps}H"
        block_maps: tuple[int, ...] = unpack_from(block_fmt, buf, offset=calcsize(fmt))

        return cls(
            magic=magic_str,
            page_size=page_size,
            fpm_page_no=fpm_page_no,
            num_pages=num_pages,
            stream_dir_size=stream_dir_size,
            block_maps=block_maps,
        )


class MSFStream(NamedTuple):
    size: int
    pages: tuple[int, ...]


def get_stream_directory(block_map_data: bytes, page_size: int) -> Iterator[MSFStream]:
    offset = 0

    (n_streams,) = unpack_from("<H2x", block_map_data, offset=offset)
    offset += 4  # skip reserved word

    stream_sizes = []

    for _ in range(n_streams):
        (stream_size,) = unpack_from("<i", block_map_data, offset=offset)
        stream_sizes.append(stream_size)
        offset += 8  # skip reserved dword

    for size in stream_sizes:
        if size < 0:
            continue

        n_pages = math.ceil(size / page_size)
        pages = unpack_from(f"<{n_pages}H", block_map_data, offset=offset)
        yield MSFStream(size, pages)
        offset += 2 * n_pages


class MSFContainer:
    data: bytes
    header: MSFHeader
    stream_dir: tuple[MSFStream, ...]

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.header = MSFHeader.from_bytes(self.data)
        block_map_data = self.combine_pages(self.header.block_maps)
        self.stream_dir = tuple(
            get_stream_directory(block_map_data, self.header.page_size)
        )

    def get_page(self, page_no: int) -> bytes:
        return self.data[
            self.header.page_size * page_no : self.header.page_size * (page_no + 1)
        ]

    def get_stream(self, stream_id: int) -> bytes:
        (size, pages) = self.stream_dir[stream_id]
        return self.combine_pages(pages)[:size]

    def combine_pages(self, pages: Iterable[int]):
        """Combine all pages for a stream into a contiguous block."""
        return b"".join((self.get_page(page) for page in pages))
