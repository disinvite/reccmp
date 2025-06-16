import re
from typing import Iterator
from reccmp.isledecomp.formats import PEImage

# Ignores strings with unprintable characters.
# Matches Latin1 (ISO/IEC 8859-1) character set except for the first character.
# To eliminate noise we assume it is regular ASCII.
r_likely_string = re.compile(rb"([\t\r\n\x20-\x7f][\t\r\n\x20-\x7f\xa0-\xff]*\x00)")


def find_8bit_strings_in_buffer(
    buf: bytes, base_addr: int = 0
) -> Iterator[tuple[int, bytes]]:
    for match in r_likely_string.finditer(buf):
        yield (base_addr + match.start(), match.group(1))


def find_8bit_strings(image: PEImage) -> Iterator[tuple[int, bytes]]:
    # TODO: Should check all non-code sections.
    data_sections = (
        image.get_section_by_name(".rdata"),
        image.get_section_by_name(".data"),
    )

    for sect in data_sections:
        yield from find_8bit_strings_in_buffer(sect.view, sect.virtual_address)
