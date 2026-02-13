import math


PRINTABLE_RANGE = range(31, 128)


def debug_print(buf: bytes, *, offset: int = 0, size: int | None = None):
    section = buf[offset:]
    if isinstance(size, int):
        section = section[:size]

    for i in range(int(math.ceil(len(section) / 16.0))):
        data = section[i * 16 : i * 16 + 16]
        row = data.hex(" ")
        text = "".join([chr(b) if b in PRINTABLE_RANGE else "." for b in data])
        print(f"{16*i + offset:08x}  {row:48}  {text}")
