import re
from typing import Iterator
from reccmp.isledecomp.formats import PEImage

# Ignores strings with unprintable characters.
r_likely_ascii = re.compile(rb"([\t\r\n\x20-\x7f]+\x00)")


def find_ascii_strings_in_buffer(
    buf: bytes, base_addr: int = 0
) -> Iterator[tuple[int, bytes]]:
    for match in r_likely_ascii.finditer(buf):
        yield (base_addr + match.start(), match.group(1))


def find_ascii_strings(image: PEImage) -> Iterator[tuple[int, bytes]]:
    # TODO: Should check all non-code sections.
    data_sections = (
        image.get_section_by_name(".rdata"),
        image.get_section_by_name(".data"),
    )

    for sect in data_sections:
        yield from find_ascii_strings_in_buffer(sect.view, sect.virtual_address)
