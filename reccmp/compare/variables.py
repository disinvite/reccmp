import re
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, NamedTuple
from struct import calcsize, unpack, error as StructError
from typing_extensions import Self
from reccmp.formats import Image
from reccmp.formats.exceptions import InvalidVirtualReadError
from reccmp.compare.db import EntityDb, ReccmpMatch
from reccmp.cvdump.cvinfo import CvdumpTypeKey, CvdumpTypeMap
from reccmp.cvdump.types import (
    CvdumpTypesParser,
    CvdumpKeyError,
    CvdumpIntegrityError,
    FieldListItem,
)
from reccmp.types import ImageId
from .type_layout import get_name_for_offset, get_scalars

logger = logging.getLogger(__name__)


#
# A note about initialized and uninitialized data:
#
# The binary's section header contains the physical and virtual size for each section.
# The physical size corresponds to physical bytes in the file on disk (i.e. the image).
# The virtual size is the actual size of the section in memory. If virtual size is greater than physical
# size, the difference is considered to be uninitialized data. Windows allocates a buffer for the
# virtual size of the section, copies physical data to the start, and sets the remaining bytes to zero.
#
# Reference (PE format):
#     https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
#
# Since the virtual memory for a particular section is made up of both initialized and uninitialized
# data, we can divide it into these regions:
#
# ┌───────────────────────────────────────────────┬─────────────────────────────────┐
# │ Initialized data                              │ Uninitialized data              │
# │ (zero and non-zero bytes)                     │ (Set to zero during image load) │
# └───────────────────────────────────────────────┴─────────────────────────────────┘
#
# Keep in mind: physical size can be zero, meaning the section is entirely uninitialized.
# Physical size can also match or exceed virtual size, meaning the section is fully initialized.
# (The virtual size sets the memory footprint even if physical size is larger.)
#
# Due to the requirement that physical data be aligned to a particular offset, there may be zero bytes
# in the physical data to pad the end of a section where this would otherwise not be necessary.
#
# This means we can subdivide the section further:
#
# ┌───────────────────────────┬───────────────────┬─────────────────────────────────┐
# │ Initialized data          │ Initialized data  │ Uninitialized data              │
# │ (zero and non-zero bytes) │ (only zero bytes) │ (Set to zero during image load) │
# └───────────────────────────┴───────────────────┴─────────────────────────────────┘
#
# Call these memory regions 1, 2, and 3.
#
# A global variable is initialized if its declaration includes an initial value.
#
#     Initialized:   int g_hello = 5;
#   Uninitialized:   int g_hello;
#
# While there is no requirement for a variable to be in a particular spot, we have observed that:
# - Region 1 contains only initialized variables.
# - Region 3 contains only uninitialized variables.
#
# Datacmp will report a diff if a variable resides in region 1 in ORIG and region 3 in RECOMP, or vice versa.
# The user can correct this by providing an initial value or removing it, depending on what ORIG does.
# We cannot make this determination if the variable resides in region 2 in either ORIG or RECOMP.
#


class BssState(Enum):
    """Determination of whether this variable is uninitialized.
    These values correspond to memory regions 1, 2, and 3 in the block comment above.
    BSS refers to a section of memory that is entirely uninitialized.
    - NO:    At least one byte between the variable's start and the
             end of the section is non-zero.
    - MAYBE: The variable is fully initialized to zero. All remaining
             initialized bytes in the section are zero.
    - YES:   All or part of the variable is uninitialized.
    """

    NO = 0
    MAYBE = 1
    YES = 2


class CompareResult(Enum):
    MATCH = 1
    DIFF = 2
    ERROR = 3
    WARN = 4


class DataBlock(NamedTuple):
    addr: int
    data: bytes
    bss: BssState

    @classmethod
    def read(cls, addr: int, size: int, image: Image) -> Self:
        data = image.read(addr, size)
        # Per the seek() API, phys_data is a memoryview of the remaining
        # physical bytes in this section.
        phys_data, _ = image.seek(addr)

        # If we find any non-zero bytes then this variable must be initialized
        # even if all of the variable's values are zero.
        init_bytes_remain = re.search(b"[^\x00]", phys_data) is not None

        if init_bytes_remain:
            bss = BssState.NO
        elif len(phys_data) < size:
            # If there are not enough physical bytes to cover
            # the entire variable, it is definitely uninitialized.
            bss = BssState.YES
        else:
            # Due to section alignment, there may be enough physical
            # zero bytes to cover this entire variable.
            bss = BssState.MAYBE

        return cls(addr, data, bss)


class DataOffset(NamedTuple):
    offset: int
    name: str
    fmt: str
    """Format character for struct.unpack"""
    pointer: bool


def to_data_offsets(scalars: Iterable[FieldListItem]) -> list[DataOffset]:
    """Add the struct.unpack format char for each scalar."""
    output: list[DataOffset] = []
    for scalar in scalars:
        cvinfo = CvdumpTypeMap[scalar.type]
        output.append(
            DataOffset(
                scalar.offset, scalar.name, cvinfo.fmt, cvinfo.pointer is not None
            )
        )

    return output


def fill_gaps(scalars: list[DataOffset], total_size: int) -> list[DataOffset]:
    """Fill any gap in the list of scalars with unsigned chars,
    so the list covers every byte of the type."""
    output: list[DataOffset] = []
    next_offset = 0
    for scalar in scalars:
        output.extend(
            DataOffset(i, "(padding)", "B", False)
            for i in range(next_offset, scalar.offset)
        )
        output.append(scalar)
        next_offset = scalar.offset + calcsize(f"<{scalar.fmt}")

    output.extend(
        DataOffset(i, "(padding)", "B", False) for i in range(next_offset, total_size)
    )
    return output


def get_format_string(scalars: list[DataOffset]) -> str:
    """Create a string for use with struct.unpack"""
    format_string = "".join(s.fmt for s in scalars)
    if len(format_string) > 0:
        return "<" + format_string

    return ""


class ComparedOffset(NamedTuple):
    offset: int
    # name is None for scalar types
    name: str | None
    match: bool
    values: tuple[str, str]


class ComparisonItem(NamedTuple):
    """Each variable that was compared"""

    orig_addr: int
    recomp_addr: int
    name: str

    # The list of items that were compared.
    # For a complex type, these are the members.
    # For a scalar type, this is a list of size one.
    # If we could not retrieve type information, this is
    # a list of size one but without any specific type.
    compared: list[ComparedOffset]

    # If present, the error message from the types parser.
    error: str | None = None

    # If true, there is no type specified for this variable. (i.e. non-public)
    # In this case, we can only compare the raw bytes.
    # This is different from the situation where a type id _is_ given, but
    # we could not retrieve it for some reason. (This is an error.)
    raw_only: bool = False

    @property
    def result(self) -> CompareResult:
        if self.error is not None:
            return CompareResult.ERROR

        if all(c.match for c in self.compared):
            return CompareResult.MATCH

        # Prefer WARN for a diff without complete type information.
        return CompareResult.WARN if self.raw_only else CompareResult.DIFF


def create_comparison_item(
    var: ReccmpMatch,
    compared: list[ComparedOffset] | None = None,
    error: str | None = None,
    raw_only: bool = False,
) -> ComparisonItem:
    """Helper to create the ComparisonItem from the fields in the reccmp database."""
    if compared is None:
        compared = []
    assert var.name is not None

    return ComparisonItem(
        orig_addr=var.orig_addr,
        recomp_addr=var.recomp_addr,
        name=var.name,
        compared=compared,
        error=error,
        raw_only=raw_only,
    )


def pointer_display(
    db: EntityDb, types: CvdumpTypesParser, img: ImageId, addr: int
) -> str:
    """Helper to streamline pointer textual display."""
    if addr == 0:
        return "nullptr"

    entity = db.get(img, addr, exact=False)

    if entity is not None:
        name = None

        base_addr = entity.addr(img)
        assert isinstance(base_addr, int)

        offset = addr - base_addr
        if offset == 0:
            name = entity.match_name()
        else:
            type_key = entity.get("data_type")
            if type_key:
                suffix = get_name_for_offset(types, CvdumpTypeKey(type_key), offset)
                name = entity.match_name(suffix)
            else:
                name = entity.match_name(f"+{offset}")

        if name:
            return f"Pointer to {name}"

    # This variable did not match if we do not have
    # the pointer target in our DB.
    return f"Unknown pointer 0x{addr:x}"


def get_compare_items(
    types: CvdumpTypesParser, var: ReccmpMatch
) -> tuple[int | None, list[DataOffset]]:
    """Return the size of the variable and its components for comparison.
    For a primitive type, this is a list with one item. For a struct, these are the struct members.
    Prefer to use the size for the variable's type, then any size from either address space.
    If we cannot produce any items to compare, we will diff the raw bytes."""
    data_type = var.get("data_type")
    if not data_type:
        return var.any_size(), []

    type_key = CvdumpTypeKey(data_type)

    try:
        size = types.get(type_key).size
        # This is a valid type, but it has no size.
        # (e.g. forward ref we cannot resolve)
        if size is None:
            return var.any_size(), []

        scalars = to_data_offsets(get_scalars(types, type_key))

    except (CvdumpKeyError, CvdumpIntegrityError):
        # This may occur even when nothing is wrong, so permit a raw comparison here.
        # For example: we do not handle bitfields and this complicates fieldlist parsing
        # where they are used. (GH #299)
        logger.error(
            "Could not materialize type '0x%x' used by variable '%s' (0x%x). Comparing raw data.",
            type_key,
            var.name,
            var.orig_addr,
        )
        return var.any_size(), []

    if not scalars:
        # An empty struct has been observed to have a size of 1.
        logger.info(
            "No struct members for type '0x%x' used by variable '%s' (0x%x). Comparing raw data.",
            type_key,
            var.name,
            var.orig_addr,
        )
        return size, []

    return size, fill_gaps(scalars, size)


@dataclass
class VariableComparator:
    db: EntityDb
    types: CvdumpTypesParser
    orig_bin: Image
    recomp_bin: Image

    def is_pointer_match(self, orig_addr: int, recomp_addr: int) -> bool:
        """Check whether these pointers point at the same thing"""

        # Null pointers considered matching
        if orig_addr == 0 and recomp_addr == 0:
            return True

        return self.db.is_match(orig_addr, recomp_addr)

    def is_pointer_match_to_offset(self, orig_addr: int, recomp_addr: int) -> bool:
        """Check whether these pointers point at the same offset of the same matched entity."""
        orig_ent = self.db.get(ImageId.ORIG, orig_addr, exact=False)
        recomp_ent = self.db.get(ImageId.RECOMP, recomp_addr, exact=False)

        if orig_ent is None or recomp_ent is None:
            return False

        # Are both entities matched?
        if not isinstance(orig_ent, ReccmpMatch) or not isinstance(
            recomp_ent, ReccmpMatch
        ):
            return False

        # Are they matched to each other?
        if orig_ent.orig_addr != recomp_ent.orig_addr:
            return False

        # Are we at the same offset?
        return (orig_addr - orig_ent.orig_addr) == (
            recomp_addr - recomp_ent.recomp_addr
        )

    def compare_variable(self, var: ReccmpMatch) -> ComparisonItem:
        # pylint: disable=too-many-locals
        assert var.name is not None
        data_size, compare_items = get_compare_items(self.types, var)
        assert data_size is not None
        raw_only = not compare_items

        try:
            orig_block = DataBlock.read(var.orig_addr, data_size, self.orig_bin)
        except InvalidVirtualReadError as ex:
            # Reading from orig can fail if the recomp variable is too large
            return create_comparison_item(var, error=repr(ex))

        # Reading from recomp should never fail, so if it does, raising an exception is correct
        recomp_block = DataBlock.read(var.recomp_addr, data_size, self.recomp_bin)

        if raw_only:
            # If there is no specific type information available
            # (i.e. if this is a static or non-public variable)
            # then we can only compare the raw bytes.
            compare_items = [
                DataOffset(offset=i, name="", fmt="B", pointer=False)
                for i in range(data_size)
            ]
            orig_data = tuple(orig_block.data)
            recomp_data = tuple(recomp_block.data)
        else:
            format_str = get_format_string(compare_items)

            try:
                orig_data = unpack(format_str, orig_block.data)
                recomp_data = unpack(format_str, recomp_block.data)
            except StructError as e:
                return create_comparison_item(var, error=f"Failed to unpack data: {e}")

        compared = []
        for orig_val, recomp_val, member in zip(orig_data, recomp_data, compare_items):
            if member.pointer:
                match = self.is_pointer_match(orig_val, recomp_val)

                if not match:
                    match = self.is_pointer_match_to_offset(orig_val, recomp_val)

                value_a = pointer_display(self.db, self.types, ImageId.ORIG, orig_val)
                value_b = pointer_display(
                    self.db, self.types, ImageId.RECOMP, recomp_val
                )
            else:
                match = orig_val == recomp_val
                value_a = str(orig_val)
                value_b = str(recomp_val)

            # Invalidate the match if there is a definite conflict between
            # the initialized state in orig and recomp.
            if (orig_block.bss == BssState.NO and recomp_block.bss == BssState.YES) or (
                recomp_block.bss == BssState.NO and orig_block.bss == BssState.YES
            ):
                match = False

            if orig_block.bss == BssState.YES:
                value_a = "(uninitialized)"

            if recomp_block.bss == BssState.YES:
                value_b = "(uninitialized)"

            compared.append(
                ComparedOffset(
                    offset=member.offset,
                    name=member.name,
                    match=match,
                    values=(value_a, value_b),
                )
            )

        return create_comparison_item(
            var,
            compared=compared,
            raw_only=raw_only,
        )
