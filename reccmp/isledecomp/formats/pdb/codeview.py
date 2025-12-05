from dataclasses import dataclass
from struct import unpack_from
from typing import Iterator


@dataclass(frozen=True)
class CodeViewRecord:
    """Extract CV record data common to all records.
    Further parsing is required, depending on the record type."""

    offset: int
    type: int
    size: int

    @classmethod
    def from_bytes(cls, buf: bytes, align: bool = True) -> Iterator["CodeViewRecord"]:
        offset = 0
        while offset < len(buf):
            # Maintain 4-byte alignment.
            if align and (offset % 4 != 0):
                offset += 4 - offset % 4

            (record_size, record_type) = unpack_from("<2H", buf, offset=offset)
            if record_size == 0:
                break

            # Record size does not include the 2-byte size itself.
            record_size += 2

            # REFSYM, cvinfo.h
            if record_type in (0x400, 0x401, 0x403):
                # For these record types, the size does not include the
                # name, a pascal string.
                record_size += buf[offset + record_size] + 1

            yield cls(offset, record_type, record_size)
            offset += record_size
