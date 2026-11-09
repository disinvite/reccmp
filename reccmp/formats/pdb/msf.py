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
    # Page numbers for block map. For MSF 7.00, these are the pages that
    # hold the list of block map page numbers.
    block_maps: tuple[int, ...]


class MSFStream(NamedTuple):
    size: int
    pages: tuple[int, ...]


class MSFContainer:
    data: bytes
    header: MSFHeader
    stream_dir: tuple[MSFStream, ...]

    # Struct format from the magic string through the stream directory size.
    _HEADER_FMT: str
    # Page number type.
    _PAGE_NO_FMT: str
    # Stream count at the start of the stream directory.
    _STREAM_COUNT_FMT: str
    # Size of each entry in the stream size array.
    _STREAM_SIZE_STRIDE: int

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.header = self._read_header()
        block_map_data = self.combine_pages(self._directory_pages())
        self.stream_dir = tuple(self._read_stream_directory(block_map_data))

    @staticmethod
    def from_bytes(data: bytes) -> "MSFContainer":
        if data.startswith(MSFMagic.szHdrMagic):
            return SmallMSFContainer(data)

        if data.startswith(MSFMagic.szBigHdrMagic):
            return BigMSFContainer(data)

        raise ValueError  # TODO: exception

    def _n_header_pages(self, stream_dir_size: int, page_size: int) -> int:
        """Number of page numbers in the header."""
        raise NotImplementedError

    def _directory_pages(self) -> tuple[int, ...]:
        """Page numbers for the stream directory."""
        raise NotImplementedError

    def _read_header(self) -> MSFHeader:
        magic_str, page_size, fpm_page_no, num_pages, stream_dir_size = unpack_from(
            self._HEADER_FMT, self.data
        )
        n_block_maps = self._n_header_pages(stream_dir_size, page_size)
        block_maps: tuple[int, ...] = unpack_from(
            f"<{n_block_maps}{self._PAGE_NO_FMT}",
            self.data,
            offset=calcsize(self._HEADER_FMT),
        )

        return MSFHeader(
            magic=magic_str,
            page_size=page_size,
            fpm_page_no=fpm_page_no,
            num_pages=num_pages,
            stream_dir_size=stream_dir_size,
            block_maps=block_maps,
        )

    def _read_stream_directory(self, block_map_data: bytes) -> Iterator[MSFStream]:
        offset = 0

        (n_streams,) = unpack_from(
            self._STREAM_COUNT_FMT, block_map_data, offset=offset
        )
        offset += 4

        stream_sizes = []

        for _ in range(n_streams):
            (stream_size,) = unpack_from("<i", block_map_data, offset=offset)
            stream_sizes.append(stream_size)
            offset += self._STREAM_SIZE_STRIDE

        page_no_size = calcsize(self._PAGE_NO_FMT)

        for size in stream_sizes:
            if size < 0:
                # Nil stream
                yield MSFStream(size, ())
                continue

            n_pages = math.ceil(size / self.header.page_size)
            pages = unpack_from(
                f"<{n_pages}{self._PAGE_NO_FMT}", block_map_data, offset=offset
            )
            yield MSFStream(size, pages)
            offset += page_no_size * n_pages

    def get_page(self, page_no: int) -> bytes:
        return self.data[
            self.header.page_size * page_no : self.header.page_size * (page_no + 1)
        ]

    def get_stream(self, stream_id: int) -> bytes:
        size, pages = self.stream_dir[stream_id]
        return self.combine_pages(pages)[:size]

    def combine_pages(self, pages: Iterable[int]):
        """Combine all pages for a stream into a contiguous block."""
        return b"".join((self.get_page(page) for page in pages))


class SmallMSFContainer(MSFContainer):
    _HEADER_FMT = "44sI2HI4x"
    _PAGE_NO_FMT = "H"
    # Skip reserved word.
    _STREAM_COUNT_FMT = "<H2x"
    # Skip reserved dword after each size.
    _STREAM_SIZE_STRIDE = 8

    def _n_header_pages(self, stream_dir_size: int, page_size: int) -> int:
        return math.ceil(stream_dir_size / page_size)

    def _directory_pages(self) -> tuple[int, ...]:
        return self.header.block_maps


class BigMSFContainer(MSFContainer):
    _HEADER_FMT = "30s4I4x"
    _PAGE_NO_FMT = "I"
    _STREAM_COUNT_FMT = "<I"
    _STREAM_SIZE_STRIDE = 4

    def _n_header_pages(self, stream_dir_size: int, page_size: int) -> int:
        # The header lists the pages that hold the directory's page list.
        return math.ceil(math.ceil(stream_dir_size / page_size) * 4 / page_size)

    def _directory_pages(self) -> tuple[int, ...]:
        n_pages = math.ceil(self.header.stream_dir_size / self.header.page_size)
        return unpack_from(f"<{n_pages}I", self.combine_pages(self.header.block_maps))
